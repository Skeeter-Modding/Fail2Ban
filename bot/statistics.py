#!/usr/bin/env python3
"""
Ban Statistics and Attack Detection for Fail2Ban Discord Bot
Tracks ban history, generates reports, and detects potential attacks.
"""

import json
import logging
import os
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "/var/lib/fail2ban-discord/statistics.db"


class BanStatistics:
    """Tracks and analyzes Fail2Ban ban statistics."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.environ.get(
            "FAIL2BAN_STATS_DB", DEFAULT_DB_PATH
        )
        self._init_db()

        # Attack detection settings
        self.alert_threshold = 10  # Bans per minute to trigger alert
        self.alert_window = 60  # Seconds to check for attack
        self.alert_cooldown = 300  # Seconds between alerts
        self._last_alert_time = None

    def _init_db(self):
        """Initialize the SQLite database."""
        # Ensure directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                jail TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                action TEXT DEFAULT 'ban',
                country TEXT,
                abuse_score INTEGER,
                reported_to_abuseipdb INTEGER DEFAULT 0
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT NOT NULL,
                message TEXT,
                ban_count INTEGER,
                acknowledged INTEGER DEFAULT 0
            )
        """)

        # Create indexes for faster queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_bans_timestamp ON bans(timestamp)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans(ip)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_bans_jail ON bans(jail)
        """)

        conn.commit()
        conn.close()

    def record_ban(self, ip: str, jail: str, country: str = None,
                   abuse_score: int = None, reported: bool = False):
        """Record a ban event."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO bans (ip, jail, action, country, abuse_score, reported_to_abuseipdb)
            VALUES (?, ?, 'ban', ?, ?, ?)
        """, (ip, jail, country, abuse_score, 1 if reported else 0))

        conn.commit()
        conn.close()

    def record_unban(self, ip: str, jail: str):
        """Record an unban event."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO bans (ip, jail, action)
            VALUES (?, ?, 'unban')
        """, (ip, jail))

        conn.commit()
        conn.close()

    def get_stats(self, hours: int = 24) -> dict:
        """Get ban statistics for the specified time period."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        since = datetime.now() - timedelta(hours=hours)
        since_str = since.strftime("%Y-%m-%d %H:%M:%S")

        # Total bans
        cursor.execute("""
            SELECT COUNT(*) FROM bans
            WHERE action = 'ban' AND timestamp >= ?
        """, (since_str,))
        total_bans = cursor.fetchone()[0]

        # Total unbans
        cursor.execute("""
            SELECT COUNT(*) FROM bans
            WHERE action = 'unban' AND timestamp >= ?
        """, (since_str,))
        total_unbans = cursor.fetchone()[0]

        # Bans by jail
        cursor.execute("""
            SELECT jail, COUNT(*) as count FROM bans
            WHERE action = 'ban' AND timestamp >= ?
            GROUP BY jail ORDER BY count DESC
        """, (since_str,))
        by_jail = dict(cursor.fetchall())

        # Top banned IPs
        cursor.execute("""
            SELECT ip, COUNT(*) as count FROM bans
            WHERE action = 'ban' AND timestamp >= ?
            GROUP BY ip ORDER BY count DESC LIMIT 10
        """, (since_str,))
        top_ips = cursor.fetchall()

        # Bans by country
        cursor.execute("""
            SELECT country, COUNT(*) as count FROM bans
            WHERE action = 'ban' AND timestamp >= ? AND country IS NOT NULL
            GROUP BY country ORDER BY count DESC LIMIT 10
        """, (since_str,))
        by_country = cursor.fetchall()

        # High risk bans (abuse score >= 50)
        cursor.execute("""
            SELECT COUNT(*) FROM bans
            WHERE action = 'ban' AND timestamp >= ? AND abuse_score >= 50
        """, (since_str,))
        high_risk_bans = cursor.fetchone()[0]

        # Reported to AbuseIPDB
        cursor.execute("""
            SELECT COUNT(*) FROM bans
            WHERE action = 'ban' AND timestamp >= ? AND reported_to_abuseipdb = 1
        """, (since_str,))
        reported_count = cursor.fetchone()[0]

        # Hourly distribution
        cursor.execute("""
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
            FROM bans WHERE action = 'ban' AND timestamp >= ?
            GROUP BY hour ORDER BY hour
        """, (since_str,))
        hourly = dict(cursor.fetchall())

        conn.close()

        return {
            "period_hours": hours,
            "total_bans": total_bans,
            "total_unbans": total_unbans,
            "by_jail": by_jail,
            "top_ips": top_ips,
            "by_country": by_country,
            "high_risk_bans": high_risk_bans,
            "reported_to_abuseipdb": reported_count,
            "hourly_distribution": hourly,
        }

    def get_ip_history(self, ip: str, limit: int = 20) -> list:
        """Get ban history for a specific IP."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT timestamp, jail, action, country, abuse_score
            FROM bans WHERE ip = ?
            ORDER BY timestamp DESC LIMIT ?
        """, (ip, limit))

        results = cursor.fetchall()
        conn.close()

        return [
            {
                "timestamp": row[0],
                "jail": row[1],
                "action": row[2],
                "country": row[3],
                "abuse_score": row[4]
            }
            for row in results
        ]

    def get_repeat_offenders(self, min_bans: int = 3, hours: int = 168) -> list:
        """Get IPs that have been banned multiple times."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        since = datetime.now() - timedelta(hours=hours)
        since_str = since.strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            SELECT ip, COUNT(*) as ban_count,
                   MAX(abuse_score) as max_abuse_score,
                   GROUP_CONCAT(DISTINCT jail) as jails
            FROM bans
            WHERE action = 'ban' AND timestamp >= ?
            GROUP BY ip
            HAVING ban_count >= ?
            ORDER BY ban_count DESC
            LIMIT 20
        """, (since_str, min_bans))

        results = cursor.fetchall()
        conn.close()

        return [
            {
                "ip": row[0],
                "ban_count": row[1],
                "max_abuse_score": row[2],
                "jails": row[3].split(",") if row[3] else []
            }
            for row in results
        ]

    def check_attack_condition(self) -> Optional[dict]:
        """
        Check if current ban rate indicates a potential attack.

        Returns:
            dict with attack info if detected, None otherwise
        """
        # Check cooldown
        if self._last_alert_time:
            if datetime.now() - self._last_alert_time < timedelta(seconds=self.alert_cooldown):
                return None

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        since = datetime.now() - timedelta(seconds=self.alert_window)
        since_str = since.strftime("%Y-%m-%d %H:%M:%S")

        # Count recent bans
        cursor.execute("""
            SELECT COUNT(*) FROM bans
            WHERE action = 'ban' AND timestamp >= ?
        """, (since_str,))
        recent_bans = cursor.fetchone()[0]

        # Get breakdown by jail
        cursor.execute("""
            SELECT jail, COUNT(*) as count FROM bans
            WHERE action = 'ban' AND timestamp >= ?
            GROUP BY jail ORDER BY count DESC
        """, (since_str,))
        by_jail = dict(cursor.fetchall())

        # Get unique IPs
        cursor.execute("""
            SELECT COUNT(DISTINCT ip) FROM bans
            WHERE action = 'ban' AND timestamp >= ?
        """, (since_str,))
        unique_ips = cursor.fetchone()[0]

        conn.close()

        # Check threshold
        if recent_bans >= self.alert_threshold:
            self._last_alert_time = datetime.now()

            # Record alert
            self._record_alert("high_ban_rate", recent_bans)

            return {
                "ban_count": recent_bans,
                "window_seconds": self.alert_window,
                "unique_ips": unique_ips,
                "by_jail": by_jail,
                "bans_per_minute": round(recent_bans / (self.alert_window / 60), 1)
            }

        return None

    def _record_alert(self, alert_type: str, ban_count: int, message: str = None):
        """Record an alert event."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO alerts (alert_type, message, ban_count)
            VALUES (?, ?, ?)
        """, (alert_type, message, ban_count))

        conn.commit()
        conn.close()

    def get_recent_alerts(self, limit: int = 10) -> list:
        """Get recent alerts."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT timestamp, alert_type, message, ban_count, acknowledged
            FROM alerts ORDER BY timestamp DESC LIMIT ?
        """, (limit,))

        results = cursor.fetchall()
        conn.close()

        return [
            {
                "timestamp": row[0],
                "alert_type": row[1],
                "message": row[2],
                "ban_count": row[3],
                "acknowledged": bool(row[4])
            }
            for row in results
        ]

    def generate_daily_report(self) -> dict:
        """Generate a daily statistics report."""
        return self.get_stats(hours=24)

    def generate_weekly_report(self) -> dict:
        """Generate a weekly statistics report."""
        return self.get_stats(hours=168)


def format_stats_embed(stats: dict) -> dict:
    """Format statistics into Discord embed fields."""
    fields = [
        {
            "name": "Total Bans",
            "value": str(stats["total_bans"]),
            "inline": True
        },
        {
            "name": "Total Unbans",
            "value": str(stats["total_unbans"]),
            "inline": True
        },
        {
            "name": "High Risk Bans",
            "value": str(stats.get("high_risk_bans", 0)),
            "inline": True
        },
    ]

    # Bans by jail
    if stats.get("by_jail"):
        jail_list = "\n".join([f"`{j}`: {c}" for j, c in list(stats["by_jail"].items())[:5]])
        fields.append({
            "name": "By Jail",
            "value": jail_list or "None",
            "inline": True
        })

    # Top IPs
    if stats.get("top_ips"):
        ip_list = "\n".join([f"`{ip}`: {c} bans" for ip, c in stats["top_ips"][:5]])
        fields.append({
            "name": "Top Offenders",
            "value": ip_list or "None",
            "inline": True
        })

    # Top countries
    if stats.get("by_country"):
        country_list = "\n".join([
            f":flag_{c.lower()}: {c}: {cnt}"
            for c, cnt in stats["by_country"][:5] if c
        ])
        fields.append({
            "name": "By Country",
            "value": country_list or "N/A",
            "inline": True
        })

    # Reported to AbuseIPDB
    if stats.get("reported_to_abuseipdb"):
        fields.append({
            "name": "Reported to AbuseIPDB",
            "value": str(stats["reported_to_abuseipdb"]),
            "inline": True
        })

    return {"fields": fields}


def format_attack_alert(attack_info: dict) -> dict:
    """Format attack detection alert for Discord."""
    fields = [
        {
            "name": "Bans Detected",
            "value": str(attack_info["ban_count"]),
            "inline": True
        },
        {
            "name": "Time Window",
            "value": f"{attack_info['window_seconds']}s",
            "inline": True
        },
        {
            "name": "Rate",
            "value": f"{attack_info['bans_per_minute']}/min",
            "inline": True
        },
        {
            "name": "Unique IPs",
            "value": str(attack_info["unique_ips"]),
            "inline": True
        },
    ]

    if attack_info.get("by_jail"):
        jail_list = ", ".join([f"`{j}`: {c}" for j, c in attack_info["by_jail"].items()])
        fields.append({
            "name": "Affected Jails",
            "value": jail_list,
            "inline": False
        })

    return {"fields": fields}
