"""
Fail2Ban Discord Integration Bot

This module provides Discord bot and webhook functionality for Fail2Ban.
"""

__version__ = "1.0.0"
__author__ = "Fail2Ban Discord Integration"

from .discord_bot import Fail2BanBot, Fail2BanManager, Config
from .webhook_notifier import send_webhook, notify_ban, notify_unban

__all__ = [
    "Fail2BanBot",
    "Fail2BanManager",
    "Config",
    "send_webhook",
    "notify_ban",
    "notify_unban",
]
