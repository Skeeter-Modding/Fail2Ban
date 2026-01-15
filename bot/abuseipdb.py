#!/usr/bin/env python3
"""
AbuseIPDB Integration for Fail2Ban Discord Bot
Provides IP reputation lookup and automatic reporting of malicious IPs.
"""

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2"

# AbuseIPDB category mappings
CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}

# Map jail names to AbuseIPDB categories
JAIL_TO_CATEGORIES = {
    "sshd": [18, 22],  # Brute-Force, SSH
    "ssh": [18, 22],
    "arma-reforger": [14, 15, 18],  # Port Scan, Hacking, Brute-Force
    "arma-reforger-rcon": [15, 18],  # Hacking, Brute-Force
    "nginx-http-auth": [18, 21],  # Brute-Force, Web App Attack
    "nginx-botsearch": [19, 21],  # Bad Web Bot, Web App Attack
    "nginx-badbots": [19],  # Bad Web Bot
    "apache-auth": [18, 21],  # Brute-Force, Web App Attack
    "apache-badbots": [19],  # Bad Web Bot
    "postfix": [11, 18],  # Email Spam, Brute-Force
    "dovecot": [11, 18],  # Email Spam, Brute-Force
    "recidive": [15, 18],  # Hacking, Brute-Force
}


class AbuseIPDBClient:
    """Client for interacting with the AbuseIPDB API."""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        self._cache = {}
        self._cache_ttl = timedelta(hours=1)

    def _make_request(self, endpoint: str, method: str = "GET",
                      params: dict = None, data: dict = None) -> dict:
        """Make a request to the AbuseIPDB API."""
        if not self.api_key:
            raise ValueError("AbuseIPDB API key not configured")

        url = f"{ABUSEIPDB_API_URL}/{endpoint}"

        if params:
            url += "?" + urlencode(params)

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }

        body = None
        if data:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urlencode(data).encode("utf-8")

        request = Request(url, data=body, headers=headers, method=method)

        try:
            with urlopen(request, timeout=10) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as e:
            error_body = e.read().decode("utf-8")
            logger.error(f"AbuseIPDB API error: {e.code} - {error_body}")
            raise
        except URLError as e:
            logger.error(f"AbuseIPDB connection error: {e.reason}")
            raise

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        """
        Check an IP address against AbuseIPDB.

        Returns:
            dict with keys:
            - ip: The IP address
            - is_public: Whether it's a public IP
            - abuse_confidence_score: 0-100 confidence it's malicious
            - country_code: Country code
            - isp: ISP name
            - domain: Domain
            - total_reports: Total number of reports
            - last_reported_at: When it was last reported
            - is_whitelisted: Whether it's on AbuseIPDB whitelist
        """
        # Check cache first
        cache_key = f"check_{ip}"
        if cache_key in self._cache:
            cached_time, cached_data = self._cache[cache_key]
            if datetime.now() - cached_time < self._cache_ttl:
                return cached_data

        try:
            result = self._make_request("check", params={
                "ipAddress": ip,
                "maxAgeInDays": max_age_days,
                "verbose": ""
            })
            data = result.get("data", {})

            # Cache the result
            self._cache[cache_key] = (datetime.now(), data)

            return data
        except Exception as e:
            logger.error(f"Failed to check IP {ip}: {e}")
            return {}

    def report_ip(self, ip: str, categories: list, comment: str = "") -> bool:
        """
        Report an IP address to AbuseIPDB.

        Args:
            ip: The IP address to report
            categories: List of category IDs (see CATEGORIES dict)
            comment: Optional comment describing the abuse

        Returns:
            True if report was successful
        """
        if not categories:
            categories = [15, 18]  # Default: Hacking, Brute-Force

        category_str = ",".join(str(c) for c in categories)

        try:
            data = {
                "ip": ip,
                "categories": category_str,
            }
            if comment:
                data["comment"] = comment[:1024]  # Max 1024 chars

            result = self._make_request("report", method="POST", data=data)

            if result.get("data", {}).get("abuseConfidenceScore") is not None:
                logger.info(f"Successfully reported {ip} to AbuseIPDB")
                return True

            return False
        except Exception as e:
            logger.error(f"Failed to report IP {ip}: {e}")
            return False

    def get_blacklist(self, confidence_minimum: int = 90, limit: int = 10000) -> list:
        """
        Get the AbuseIPDB blacklist.

        Args:
            confidence_minimum: Minimum abuse confidence score (1-100)
            limit: Maximum number of IPs to return

        Returns:
            List of IP addresses
        """
        try:
            result = self._make_request("blacklist", params={
                "confidenceMinimum": confidence_minimum,
                "limit": limit
            })
            return [entry.get("ipAddress") for entry in result.get("data", [])]
        except Exception as e:
            logger.error(f"Failed to get blacklist: {e}")
            return []

    def clear_cache(self):
        """Clear the IP check cache."""
        self._cache.clear()


def get_risk_level(score: int) -> tuple:
    """
    Get risk level description and color based on abuse confidence score.

    Returns:
        Tuple of (risk_level_str, color_hex)
    """
    if score >= 80:
        return "Critical", 0xff0000  # Red
    elif score >= 50:
        return "High", 0xff6600  # Orange
    elif score >= 25:
        return "Medium", 0xffcc00  # Yellow
    elif score > 0:
        return "Low", 0x99ff00  # Yellow-green
    else:
        return "Clean", 0x00ff00  # Green


def get_categories_for_jail(jail_name: str) -> list:
    """Get AbuseIPDB categories for a jail name."""
    # Try exact match first
    if jail_name in JAIL_TO_CATEGORIES:
        return JAIL_TO_CATEGORIES[jail_name]

    # Try partial match
    jail_lower = jail_name.lower()
    for key, categories in JAIL_TO_CATEGORIES.items():
        if key in jail_lower or jail_lower in key:
            return categories

    # Default categories
    return [15, 18]  # Hacking, Brute-Force


def format_ip_report(data: dict) -> dict:
    """
    Format AbuseIPDB check data into a Discord-friendly structure.

    Returns:
        dict with 'fields' list for Discord embed
    """
    if not data:
        return {"fields": [{"name": "Status", "value": "No data available", "inline": False}]}

    score = data.get("abuseConfidenceScore", 0)
    risk_level, color = get_risk_level(score)

    fields = [
        {
            "name": "Abuse Confidence",
            "value": f"**{score}%** ({risk_level})",
            "inline": True
        },
        {
            "name": "Total Reports",
            "value": str(data.get("totalReports", 0)),
            "inline": True
        },
    ]

    if data.get("countryCode"):
        fields.append({
            "name": "Country",
            "value": f":flag_{data['countryCode'].lower()}: {data.get('countryCode')}",
            "inline": True
        })

    if data.get("isp"):
        fields.append({
            "name": "ISP",
            "value": data["isp"][:50],
            "inline": True
        })

    if data.get("domain"):
        fields.append({
            "name": "Domain",
            "value": data["domain"],
            "inline": True
        })

    if data.get("usageType"):
        fields.append({
            "name": "Usage Type",
            "value": data["usageType"],
            "inline": True
        })

    if data.get("lastReportedAt"):
        fields.append({
            "name": "Last Reported",
            "value": data["lastReportedAt"][:10],
            "inline": True
        })

    if data.get("isWhitelisted"):
        fields.append({
            "name": "Whitelisted",
            "value": "Yes (trusted IP)",
            "inline": True
        })

    return {"fields": fields, "color": color, "risk_level": risk_level}
