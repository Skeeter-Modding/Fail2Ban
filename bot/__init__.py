"""
Fail2Ban Discord Integration Bot

This module provides Discord bot and webhook functionality for Fail2Ban.
Includes AbuseIPDB integration, statistics tracking, and attack detection.
"""

__version__ = "2.0.0"
__author__ = "Fail2Ban Discord Integration"

from .discord_bot import Fail2BanBot, Fail2BanManager, Config
from .webhook_notifier import send_webhook, notify_ban, notify_unban
from .abuseipdb import AbuseIPDBClient, get_risk_level, format_ip_report
from .statistics import BanStatistics, format_stats_embed, format_attack_alert

__all__ = [
    # Core bot
    "Fail2BanBot",
    "Fail2BanManager",
    "Config",
    # Webhook
    "send_webhook",
    "notify_ban",
    "notify_unban",
    # AbuseIPDB
    "AbuseIPDBClient",
    "get_risk_level",
    "format_ip_report",
    # Statistics
    "BanStatistics",
    "format_stats_embed",
    "format_attack_alert",
]
