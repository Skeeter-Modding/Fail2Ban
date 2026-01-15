#!/usr/bin/env python3
"""
Fail2Ban Discord Webhook Notifier
Standalone script for sending Fail2Ban notifications via Discord webhook.
Can be used independently of the full Discord bot.
"""

import argparse
import configparser
import json
import os
import sys
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# Optional GeoIP support
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


def load_config(config_path: str = None) -> dict:
    """Load configuration from file."""
    if config_path is None:
        config_path = os.environ.get(
            'FAIL2BAN_DISCORD_CONFIG',
            '/etc/fail2ban-discord/config.ini'
        )

    config = configparser.ConfigParser()

    if os.path.exists(config_path):
        config.read(config_path)
        return {
            'webhook_url': config.get('discord', 'webhook_url', fallback=''),
            'ban_color': int(config.get('notifications', 'ban_color', fallback='ff0000'), 16),
            'unban_color': int(config.get('notifications', 'unban_color', fallback='00ff00'), 16),
            'info_color': int(config.get('notifications', 'info_color', fallback='0099ff'), 16),
            'include_geoip': config.getboolean('notifications', 'include_geoip', fallback=True),
            'geoip_db': '/usr/share/GeoIP/GeoLite2-City.mmdb'
        }

    return {
        'webhook_url': os.environ.get('DISCORD_WEBHOOK_URL', ''),
        'ban_color': 0xff0000,
        'unban_color': 0x00ff00,
        'info_color': 0x0099ff,
        'include_geoip': True,
        'geoip_db': '/usr/share/GeoIP/GeoLite2-City.mmdb'
    }


def get_geoip_info(ip: str, db_path: str) -> dict:
    """Get GeoIP information for an IP address."""
    if not GEOIP_AVAILABLE or not os.path.exists(db_path):
        return {}

    try:
        reader = geoip2.database.Reader(db_path)
        response = reader.city(ip)
        result = {
            'country': response.country.name or 'Unknown',
            'country_code': response.country.iso_code or 'XX',
            'city': response.city.name or 'Unknown',
        }
        reader.close()
        return result
    except Exception:
        return {}


def send_webhook(webhook_url: str, embed: dict) -> bool:
    """Send a Discord webhook message."""
    if not webhook_url:
        print("Error: No webhook URL configured", file=sys.stderr)
        return False

    payload = {
        "embeds": [embed]
    }

    data = json.dumps(payload).encode('utf-8')

    request = Request(
        webhook_url,
        data=data,
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'Fail2Ban-Discord-Notifier/1.0'
        }
    )

    try:
        with urlopen(request, timeout=10) as response:
            return response.status == 204
    except HTTPError as e:
        print(f"HTTP Error: {e.code} - {e.reason}", file=sys.stderr)
        return False
    except URLError as e:
        print(f"URL Error: {e.reason}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error sending webhook: {e}", file=sys.stderr)
        return False


def notify_ban(webhook_url: str, jail: str, ip: str, matches: int = 0,
               failures: int = 0, config: dict = None):
    """Send a ban notification."""
    config = config or {}

    fields = [
        {'name': 'IP Address', 'value': f'`{ip}`', 'inline': True},
        {'name': 'Jail', 'value': f'`{jail}`', 'inline': True},
    ]

    if matches:
        fields.append({'name': 'Matches', 'value': str(matches), 'inline': True})

    if failures:
        fields.append({'name': 'Failures', 'value': str(failures), 'inline': True})

    if config.get('include_geoip', True):
        geo = get_geoip_info(ip, config.get('geoip_db', '/usr/share/GeoIP/GeoLite2-City.mmdb'))
        if geo:
            country_code_raw = geo.get('country_code') or 'xx'
            country_code = str(country_code_raw).lower()
            location = f":flag_{country_code}: {geo.get('country', 'Unknown')}"
            if geo.get('city') and geo.get('city') != 'Unknown':
                location += f", {geo['city']}"
            fields.append({'name': 'Location', 'value': location, 'inline': True})

    embed = {
        'title': 'IP Banned',
        'description': 'An IP address has been banned by Fail2Ban.',
        'color': config.get('ban_color', 0xff0000),
        'fields': fields,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'footer': {'text': 'Fail2Ban Discord Notifier'}
    }

    return send_webhook(webhook_url, embed)


def notify_unban(webhook_url: str, jail: str, ip: str, config: dict = None):
    """Send an unban notification."""
    config = config or {}

    fields = [
        {'name': 'IP Address', 'value': f'`{ip}`', 'inline': True},
        {'name': 'Jail', 'value': f'`{jail}`', 'inline': True},
    ]

    embed = {
        'title': 'IP Unbanned',
        'description': 'An IP address has been unbanned.',
        'color': config.get('unban_color', 0x00ff00),
        'fields': fields,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'footer': {'text': 'Fail2Ban Discord Notifier'}
    }

    return send_webhook(webhook_url, embed)


def notify_start(webhook_url: str, jail: str, config: dict = None):
    """Send a jail start notification."""
    config = config or {}

    embed = {
        'title': 'Fail2Ban Jail Started',
        'description': f'Jail `{jail}` has been started.',
        'color': config.get('info_color', 0x0099ff),
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'footer': {'text': 'Fail2Ban Discord Notifier'}
    }

    return send_webhook(webhook_url, embed)


def notify_stop(webhook_url: str, jail: str, config: dict = None):
    """Send a jail stop notification."""
    config = config or {}

    embed = {
        'title': 'Fail2Ban Jail Stopped',
        'description': f'Jail `{jail}` has been stopped.',
        'color': config.get('info_color', 0x0099ff),
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'footer': {'text': 'Fail2Ban Discord Notifier'}
    }

    return send_webhook(webhook_url, embed)


def main():
    """Main entry point for CLI usage."""
    parser = argparse.ArgumentParser(description='Fail2Ban Discord Webhook Notifier')
    parser.add_argument('action', choices=['ban', 'unban', 'start', 'stop'],
                        help='Action type')
    parser.add_argument('--jail', '-j', required=True, help='Jail name')
    parser.add_argument('--ip', '-i', help='IP address (required for ban/unban)')
    parser.add_argument('--matches', '-m', type=int, default=0, help='Number of matches')
    parser.add_argument('--failures', '-f', type=int, default=0, help='Number of failures')
    parser.add_argument('--webhook', '-w', help='Discord webhook URL (overrides config)')
    parser.add_argument('--config', '-c', help='Path to config file')

    args = parser.parse_args()

    config = load_config(args.config)
    webhook_url = args.webhook or config.get('webhook_url')

    if not webhook_url:
        print("Error: No webhook URL provided", file=sys.stderr)
        sys.exit(1)

    if args.action == 'ban':
        if not args.ip:
            print("Error: IP address required for ban action", file=sys.stderr)
            sys.exit(1)
        success = notify_ban(webhook_url, args.jail, args.ip, args.matches, args.failures, config)

    elif args.action == 'unban':
        if not args.ip:
            print("Error: IP address required for unban action", file=sys.stderr)
            sys.exit(1)
        success = notify_unban(webhook_url, args.jail, args.ip, config)

    elif args.action == 'start':
        success = notify_start(webhook_url, args.jail, config)

    elif args.action == 'stop':
        success = notify_stop(webhook_url, args.jail, config)

    else:
        success = False

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
