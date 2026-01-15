#!/usr/bin/env python3
"""
Fail2Ban Discord Bot
A Discord bot for managing Fail2Ban and receiving ban notifications.
Includes AbuseIPDB integration, statistics tracking, and attack detection.
"""

import configparser
import ipaddress
import logging
import os
import subprocess
import sys
from datetime import datetime, time
from typing import Tuple, List

import discord
from discord import app_commands
from discord.ext import commands, tasks

# Optional GeoIP support
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# Import our modules
try:
    from .abuseipdb import AbuseIPDBClient, format_ip_report, get_categories_for_jail, get_risk_level
    from .statistics import BanStatistics, format_stats_embed, format_attack_alert
except ImportError:
    from abuseipdb import AbuseIPDBClient, format_ip_report, get_categories_for_jail, get_risk_level
    from statistics import BanStatistics, format_stats_embed, format_attack_alert


class Config:
    """Configuration manager for the bot."""

    def __init__(self, config_path: str = None):
        self.config = configparser.ConfigParser()

        if config_path is None:
            config_path = os.environ.get(
                'FAIL2BAN_DISCORD_CONFIG',
                '/etc/fail2ban-discord/config.ini'
            )

        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")

        self.config.read(config_path)

    def get(self, section: str, key: str, fallback=None):
        return self.config.get(section, key, fallback=fallback)

    def getboolean(self, section: str, key: str, fallback=False):
        return self.config.getboolean(section, key, fallback=fallback)

    def getint(self, section: str, key: str, fallback=0):
        return self.config.getint(section, key, fallback=fallback)

    def getlist(self, section: str, key: str, fallback=None):
        value = self.config.get(section, key, fallback='')
        if not value:
            return fallback or []
        return [item.strip() for item in value.split(',') if item.strip()]


class Fail2BanManager:
    """Interface for Fail2Ban operations."""

    def __init__(self, client_path: str = "/usr/bin/fail2ban-client"):
        self.client_path = client_path
        self._whitelist_file = "/etc/fail2ban-discord/whitelist.txt"
        # Check if we need to use sudo (when not running as root)
        self.use_sudo = os.geteuid() != 0

    def _run_command(self, *args) -> Tuple[bool, str]:
        """Run a fail2ban-client command and return success status and output."""
        try:
            # Prepend sudo if not running as root
            cmd = ["sudo", self.client_path] if self.use_sudo else [self.client_path]
            cmd.extend(list(args))
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                return True, result.stdout.strip()
            return False, result.stderr.strip() or result.stdout.strip()
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    def get_status(self) -> Tuple[bool, str]:
        """Get overall Fail2Ban status."""
        return self._run_command("status")

    def get_jail_status(self, jail: str) -> Tuple[bool, str]:
        """Get status of a specific jail."""
        return self._run_command("status", jail)

    def ban_ip(self, jail: str, ip: str) -> Tuple[bool, str]:
        """Manually ban an IP in a jail."""
        return self._run_command("set", jail, "banip", ip)

    def unban_ip(self, jail: str, ip: str) -> Tuple[bool, str]:
        """Unban an IP from a jail."""
        return self._run_command("set", jail, "unbanip", ip)

    def unban_all(self, jail: str = None) -> Tuple[bool, str]:
        """Unban all IPs from a jail or all jails."""
        if jail:
            return self._run_command("set", jail, "unbanip", "--all")
        return self._run_command("unban", "--all")

    def get_banned_ips(self, jail: str) -> Tuple[bool, List]:
        """Get list of banned IPs in a jail."""
        success, output = self._run_command("get", jail, "banip")
        if success:
            ips = output.split() if output else []
            return True, ips
        return False, []

    def get_jails(self) -> Tuple[bool, List]:
        """Get list of all jails."""
        success, output = self.get_status()
        if success:
            for line in output.split('\n'):
                if 'Jail list:' in line:
                    jails = line.split(':')[1].strip()
                    return True, [j.strip() for j in jails.split(',') if j.strip()]
        return False, []

    def reload(self, jail: str = None) -> Tuple[bool, str]:
        """Reload Fail2Ban configuration."""
        if jail:
            return self._run_command("reload", jail)
        return self._run_command("reload")

    def ping(self) -> bool:
        """Check if Fail2Ban server is running."""
        success, output = self._run_command("ping")
        return success and "pong" in output.lower()

    # Whitelist management
    def get_whitelist(self) -> list:
        """Get the current whitelist."""
        try:
            if os.path.exists(self._whitelist_file):
                with open(self._whitelist_file, 'r') as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception:
            # Silently ignore errors reading whitelist file (file may not exist or be inaccessible)
            pass
        return []

    def add_to_whitelist(self, ip: str) -> Tuple[bool, str]:
        """Add an IP to the whitelist."""
        try:
            # Validate IP
            ipaddress.ip_address(ip)

            whitelist = self.get_whitelist()
            if ip in whitelist:
                return False, "IP already in whitelist"

            # Ensure directory exists
            whitelist_dir = os.path.dirname(self._whitelist_file)
            if whitelist_dir:
                os.makedirs(whitelist_dir, exist_ok=True)

            with open(self._whitelist_file, 'a') as f:
                f.write(f"{ip}\n")

            return True, f"Added {ip} to whitelist"
        except ValueError:
            return False, "Invalid IP address"
        except Exception as e:
            return False, str(e)

    def remove_from_whitelist(self, ip: str) -> Tuple[bool, str]:
        """Remove an IP from the whitelist."""
        try:
            whitelist = self.get_whitelist()
            if ip not in whitelist:
                return False, "IP not in whitelist"

            whitelist.remove(ip)

            with open(self._whitelist_file, 'w') as f:
                for item in whitelist:
                    f.write(f"{item}\n")

            return True, f"Removed {ip} from whitelist"
        except Exception as e:
            return False, str(e)

    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is whitelisted."""
        return ip in self.get_whitelist()


class GeoIPLookup:
    """GeoIP lookup for IP addresses."""

    def __init__(self, db_path: str = "/usr/share/GeoIP/GeoLite2-City.mmdb"):
        self.db_path = db_path
        self.reader = None
        if GEOIP_AVAILABLE and os.path.exists(db_path):
            try:
                self.reader = geoip2.database.Reader(db_path)
            except Exception:
                # Silently ignore GeoIP database initialization errors (database may be corrupted or incompatible)
                pass

    def lookup(self, ip: str) -> dict:
        """Look up geographical information for an IP."""
        if not self.reader:
            return {}

        try:
            response = self.reader.city(ip)
            return {
                'country': response.country.name or 'Unknown',
                'country_code': response.country.iso_code or 'XX',
                'city': response.city.name or 'Unknown',
                'region': response.subdivisions.most_specific.name if response.subdivisions else 'Unknown'
            }
        except Exception:
            return {}

    def close(self):
        if self.reader:
            self.reader.close()


class Fail2BanBot(commands.Bot):
    """Discord bot for Fail2Ban management."""

    def __init__(self, config: Config):
        intents = discord.Intents.default()
        intents.message_content = True

        super().__init__(
            command_prefix='!f2b ',
            intents=intents,
            description="Fail2Ban Discord Bot"
        )

        self.config = config
        self.f2b = Fail2BanManager(config.get('fail2ban', 'fail2ban_client', '/usr/bin/fail2ban-client'))
        self.geoip = GeoIPLookup() if config.getboolean('notifications', 'include_geoip', True) else None
        self.notification_channel_id = config.getint('discord', 'channel_id')
        self.admin_role_id = config.getint('discord', 'admin_role_id', 0) or None
        self.guild_id = config.getint('discord', 'guild_id')

        # AbuseIPDB client
        abuseipdb_key = config.get('abuseipdb', 'api_key', '')
        self.abuseipdb = AbuseIPDBClient(abuseipdb_key) if abuseipdb_key else None
        self.auto_report = config.getboolean('abuseipdb', 'auto_report', False)
        self.report_threshold = config.getint('abuseipdb', 'report_threshold', 50)

        # Statistics
        self.stats = BanStatistics()
        self.stats.alert_threshold = config.getint('attack_detection', 'alert_threshold', 10)
        self.stats.alert_window = config.getint('attack_detection', 'alert_window', 60)

        # Scheduled reports
        self.daily_report_enabled = config.getboolean('reports', 'daily_report', False)
        self.weekly_report_enabled = config.getboolean('reports', 'weekly_report', False)

    async def setup_hook(self):
        """Set up the bot's slash commands."""
        await self.add_cog(Fail2BanCommands(self))
        await self.add_cog(AbuseIPDBCommands(self))
        await self.add_cog(StatisticsCommands(self))
        await self.add_cog(WhitelistCommands(self))

        if self.guild_id:
            guild = discord.Object(id=self.guild_id)
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
        else:
            await self.tree.sync()

        # Start background tasks
        self.attack_monitor.start()
        if self.daily_report_enabled:
            self.daily_report_task.start()
        if self.weekly_report_enabled:
            self.weekly_report_task.start()

    async def on_ready(self):
        logging.info(f"Bot connected as {self.user}")

        if self.config.getboolean('notifications', 'notify_on_start', True):
            await self.send_notification(
                title="Fail2Ban Bot Started",
                description="Bot is now online and monitoring.",
                color=int(self.config.get('notifications', 'info_color', '0099ff'), 16)
            )

    async def send_notification(self, title: str, description: str, color: int, fields: list = None):
        """Send a notification embed to the configured channel."""
        if not self.notification_channel_id:
            return

        channel = self.get_channel(self.notification_channel_id)
        if not channel:
            try:
                channel = await self.fetch_channel(self.notification_channel_id)
            except Exception as e:
                logging.error(f"Could not fetch notification channel: {e}")
                return

        embed = discord.Embed(
            title=title,
            description=description,
            color=color,
            timestamp=datetime.utcnow()
        )

        if fields:
            for field in fields:
                embed.add_field(
                    name=field.get('name', ''),
                    value=field.get('value', ''),
                    inline=field.get('inline', True)
                )

        embed.set_footer(text="Fail2Ban Discord Bot")

        try:
            await channel.send(embed=embed)
        except Exception as e:
            logging.error(f"Failed to send notification: {e}")

    async def notify_ban(self, jail: str, ip: str, matches: int = 0, log_lines: list = None):
        """Send a ban notification with optional AbuseIPDB info."""
        if not self.config.getboolean('notifications', 'notify_on_ban', True):
            return

        # Check whitelist
        if self.f2b.is_whitelisted(ip):
            logging.info(f"Skipping ban notification for whitelisted IP: {ip}")
            return

        fields = [
            {'name': 'IP Address', 'value': f'`{ip}`', 'inline': True},
            {'name': 'Jail', 'value': f'`{jail}`', 'inline': True},
        ]

        if matches:
            fields.append({'name': 'Matches', 'value': str(matches), 'inline': True})

        country_code = None

        # GeoIP lookup
        if self.geoip:
            geo = self.geoip.lookup(ip)
            if geo:
                country_code = geo.get('country_code')
                country_code_raw = geo.get('country_code') or 'xx'
                country_code = str(country_code_raw).lower()
                location = f":flag_{country_code}: {geo.get('country', 'Unknown')}"
                if geo.get('city') and geo.get('city') != 'Unknown':
                    location += f", {geo['city']}"
                fields.append({'name': 'Location', 'value': location, 'inline': True})

        # AbuseIPDB lookup
        abuse_score = None
        if self.abuseipdb:
            try:
                abuse_data = self.abuseipdb.check_ip(ip)
                if abuse_data:
                    abuse_score = abuse_data.get('abuseConfidenceScore', 0)
                    risk_level, _ = get_risk_level(abuse_score)
                    fields.append({
                        'name': 'Abuse Score',
                        'value': f"**{abuse_score}%** ({risk_level})",
                        'inline': True
                    })
                    if abuse_data.get('totalReports'):
                        fields.append({
                            'name': 'Total Reports',
                            'value': str(abuse_data['totalReports']),
                            'inline': True
                        })

                    if not country_code:
                        country_code = abuse_data.get('countryCode')

                    # Auto-report if enabled and score is below threshold
                    if self.auto_report and abuse_score < self.report_threshold:
                        categories = get_categories_for_jail(jail)
                        self.abuseipdb.report_ip(ip, categories, f"Banned by Fail2Ban jail: {jail}")
                        fields.append({
                            'name': 'Reported',
                            'value': 'Reported to AbuseIPDB',
                            'inline': True
                        })

            except Exception as e:
                logging.error(f"AbuseIPDB lookup failed: {e}")

        # Record in statistics
        self.stats.record_ban(ip, jail, country_code, abuse_score, self.auto_report)

        if log_lines:
            log_preview = '\n'.join(log_lines[:3])
            if len(log_preview) > 1000:
                log_preview = log_preview[:997] + '...'
            fields.append({'name': 'Log Preview', 'value': f'```\n{log_preview}\n```', 'inline': False})

        color = int(self.config.get('notifications', 'ban_color', 'ff0000'), 16)
        await self.send_notification(
            title="IP Banned",
            description="An IP address has been banned by Fail2Ban.",
            color=color,
            fields=fields
        )

    async def notify_unban(self, jail: str, ip: str):
        """Send an unban notification."""
        if not self.config.getboolean('notifications', 'notify_on_unban', True):
            return

        # Record in statistics
        self.stats.record_unban(ip, jail)

        fields = [
            {'name': 'IP Address', 'value': f'`{ip}`', 'inline': True},
            {'name': 'Jail', 'value': f'`{jail}`', 'inline': True},
        ]

        color = int(self.config.get('notifications', 'unban_color', '00ff00'), 16)
        await self.send_notification(
            title="IP Unbanned",
            description="An IP address has been unbanned.",
            color=color,
            fields=fields
        )

    async def notify_attack(self, attack_info: dict):
        """Send an attack detection alert."""
        alert_data = format_attack_alert(attack_info)

        await self.send_notification(
            title="Potential Attack Detected",
            description="High ban rate detected - possible brute force or DDoS attack in progress.",
            color=0xff0000,
            fields=alert_data['fields']
        )

    def is_admin(self, member: discord.Member) -> bool:
        """Check if a member has admin permissions for the bot."""
        if member.guild_permissions.administrator:
            return True
        if self.admin_role_id:
            return any(role.id == self.admin_role_id for role in member.roles)
        return True  # If no admin role set, allow all users

    @tasks.loop(seconds=30)
    async def attack_monitor(self):
        """Monitor for potential attacks."""
        try:
            attack_info = self.stats.check_attack_condition()
            if attack_info:
                await self.notify_attack(attack_info)
        except Exception as e:
            logging.error(f"Attack monitor error: {e}")

    @attack_monitor.before_loop
    async def before_attack_monitor(self):
        await self.wait_until_ready()

    @tasks.loop(time=time(hour=8, minute=0))  # 8 AM daily
    async def daily_report_task(self):
        """Send daily statistics report."""
        try:
            stats = self.stats.generate_daily_report()
            stats_embed = format_stats_embed(stats)

            await self.send_notification(
                title="Daily Fail2Ban Report",
                description=f"Statistics for the last 24 hours",
                color=int(self.config.get('notifications', 'info_color', '0099ff'), 16),
                fields=stats_embed['fields']
            )
        except Exception as e:
            logging.error(f"Daily report error: {e}")

    @daily_report_task.before_loop
    async def before_daily_report(self):
        await self.wait_until_ready()

    @tasks.loop(time=time(hour=8, minute=0))  # 8 AM, runs on Mondays via check
    async def weekly_report_task(self):
        """Send weekly statistics report."""
        if datetime.now().weekday() != 0:  # Only on Monday
            return

        try:
            stats = self.stats.generate_weekly_report()
            stats_embed = format_stats_embed(stats)

            await self.send_notification(
                title="Weekly Fail2Ban Report",
                description=f"Statistics for the last 7 days",
                color=int(self.config.get('notifications', 'info_color', '0099ff'), 16),
                fields=stats_embed['fields']
            )
        except Exception as e:
            logging.error(f"Weekly report error: {e}")

    @weekly_report_task.before_loop
    async def before_weekly_report(self):
        await self.wait_until_ready()


class Fail2BanCommands(commands.Cog):
    """Slash commands for Fail2Ban management."""

    def __init__(self, bot: Fail2BanBot):
        self.bot = bot

    def check_admin(self, interaction: discord.Interaction) -> bool:
        """Check if the user has admin permissions."""
        return self.bot.is_admin(interaction.user)

    @app_commands.command(name="status", description="Get Fail2Ban status")
    @app_commands.describe(jail="Specific jail to check (optional)")
    async def status(self, interaction: discord.Interaction, jail: str = None):
        """Get Fail2Ban status."""
        await interaction.response.defer()

        if jail:
            success, output = self.bot.f2b.get_jail_status(jail)
            title = f"Jail Status: {jail}"
        else:
            success, output = self.bot.f2b.get_status()
            title = "Fail2Ban Status"

        if success:
            embed = discord.Embed(
                title=title,
                description=f"```\n{output}\n```",
                color=discord.Color.green()
            )
        else:
            embed = discord.Embed(
                title="Error",
                description=f"Failed to get status: {output}",
                color=discord.Color.red()
            )

        await interaction.followup.send(embed=embed)

    @app_commands.command(name="jails", description="List all jails")
    async def jails(self, interaction: discord.Interaction):
        """List all available jails."""
        await interaction.response.defer()

        success, jails = self.bot.f2b.get_jails()

        if success and jails:
            jail_list = '\n'.join([f"- `{jail}`" for jail in jails])
            embed = discord.Embed(
                title="Available Jails",
                description=jail_list,
                color=discord.Color.blue()
            )
        else:
            embed = discord.Embed(
                title="Error",
                description="Failed to retrieve jail list or no jails configured.",
                color=discord.Color.red()
            )

        await interaction.followup.send(embed=embed)

    @app_commands.command(name="banned", description="List banned IPs in a jail")
    @app_commands.describe(jail="Jail to check")
    async def banned(self, interaction: discord.Interaction, jail: str):
        """List banned IPs in a jail."""
        await interaction.response.defer()

        success, ips = self.bot.f2b.get_banned_ips(jail)

        if success:
            if ips:
                ip_list = '\n'.join([f"- `{ip}`" for ip in ips[:50]])
                if len(ips) > 50:
                    ip_list += f"\n... and {len(ips) - 50} more"
                description = ip_list
            else:
                description = "No IPs currently banned in this jail."

            embed = discord.Embed(
                title=f"Banned IPs in {jail}",
                description=description,
                color=discord.Color.orange()
            )
            embed.set_footer(text=f"Total: {len(ips)} banned IPs")
        else:
            embed = discord.Embed(
                title="Error",
                description=f"Failed to get banned IPs. Is '{jail}' a valid jail?",
                color=discord.Color.red()
            )

        await interaction.followup.send(embed=embed)

    @app_commands.command(name="ban", description="Ban an IP address")
    @app_commands.describe(jail="Jail to ban the IP in", ip="IP address to ban")
    async def ban(self, interaction: discord.Interaction, jail: str, ip: str):
        """Manually ban an IP address."""
        if not self.check_admin(interaction):
            await interaction.response.send_message(
                "You don't have permission to ban IPs.",
                ephemeral=True
            )
            return

        await interaction.response.defer()

        # Check whitelist
        if self.bot.f2b.is_whitelisted(ip):
            embed = discord.Embed(
                title="Cannot Ban",
                description=f"IP `{ip}` is whitelisted and cannot be banned.",
                color=discord.Color.orange()
            )
            await interaction.followup.send(embed=embed)
            return

        success, output = self.bot.f2b.ban_ip(jail, ip)

        if success:
            embed = discord.Embed(
                title="IP Banned",
                description=f"Successfully banned `{ip}` in jail `{jail}`.",
                color=discord.Color.red()
            )
            logging.info(f"Manual ban: {ip} in {jail} by {interaction.user}")
        else:
            embed = discord.Embed(
                title="Ban Failed",
                description=f"Failed to ban IP: {output}",
                color=discord.Color.red()
            )

        await interaction.followup.send(embed=embed)

    @app_commands.command(name="unban", description="Unban an IP address")
    @app_commands.describe(jail="Jail to unban the IP from", ip="IP address to unban")
    async def unban(self, interaction: discord.Interaction, jail: str, ip: str):
        """Unban an IP address."""
        if not self.check_admin(interaction):
            await interaction.response.send_message(
                "You don't have permission to unban IPs.",
                ephemeral=True
            )
            return

        await interaction.response.defer()

        success, output = self.bot.f2b.unban_ip(jail, ip)

        if success:
            embed = discord.Embed(
                title="IP Unbanned",
                description=f"Successfully unbanned `{ip}` from jail `{jail}`.",
                color=discord.Color.green()
            )
            logging.info(f"Manual unban: {ip} from {jail} by {interaction.user}")
        else:
            embed = discord.Embed(
                title="Unban Failed",
                description=f"Failed to unban IP: {output}",
                color=discord.Color.red()
            )

        await interaction.followup.send(embed=embed)

    @app_commands.command(name="unbanall", description="Unban all IPs from a jail")
    @app_commands.describe(jail="Jail to unban all IPs from (leave empty for all jails)")
    async def unbanall(self, interaction: discord.Interaction, jail: str = None):
        """Unban all IPs from a jail or all jails."""
        if not self.check_admin(interaction):
            await interaction.response.send_message(
                "You don't have permission to unban IPs.",
                ephemeral=True
            )
            return

        await interaction.response.defer()

        success, output = self.bot.f2b.unban_all(jail)

        target = f"jail `{jail}`" if jail else "all jails"

        if success:
            embed = discord.Embed(
                title="All IPs Unbanned",
                description=f"Successfully unbanned all IPs from {target}.",
                color=discord.Color.green()
            )
            logging.info(f"Unban all from {target} by {interaction.user}")
        else:
            embed = discord.Embed(
                title="Unban Failed",
                description=f"Failed to unban all IPs: {output}",
                color=discord.Color.red()
            )

        await interaction.followup.send(embed=embed)

    @app_commands.command(name="reload", description="Reload Fail2Ban configuration")
    @app_commands.describe(jail="Specific jail to reload (optional)")
    async def reload(self, interaction: discord.Interaction, jail: str = None):
        """Reload Fail2Ban configuration."""
        if not self.check_admin(interaction):
            await interaction.response.send_message(
                "You don't have permission to reload Fail2Ban.",
                ephemeral=True
            )
            return

        await interaction.response.defer()

        success, output = self.bot.f2b.reload(jail)

        if success:
            target = f"jail `{jail}`" if jail else "all configuration"
            embed = discord.Embed(
                title="Reload Successful",
                description=f"Successfully reloaded {target}.",
                color=discord.Color.green()
            )
            logging.info(f"Reload {target} by {interaction.user}")
        else:
            embed = discord.Embed(
                title="Reload Failed",
                description=f"Failed to reload: {output}",
                color=discord.Color.red()
            )

        await interaction.followup.send(embed=embed)

    @app_commands.command(name="ping", description="Check if Fail2Ban is running")
    async def ping(self, interaction: discord.Interaction):
        """Check if Fail2Ban server is running."""
        is_running = self.bot.f2b.ping()

        if is_running:
            embed = discord.Embed(
                title="Fail2Ban Status",
                description="Fail2Ban server is **running**.",
                color=discord.Color.green()
            )
        else:
            embed = discord.Embed(
                title="Fail2Ban Status",
                description="Fail2Ban server is **not running** or not accessible.",
                color=discord.Color.red()
            )

        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="help", description="Show help for Fail2Ban bot commands")
    async def help_command(self, interaction: discord.Interaction):
        """Show help for all commands."""
        embed = discord.Embed(
            title="Fail2Ban Bot Commands",
            description="Available commands for managing Fail2Ban:",
            color=discord.Color.blue()
        )

        commands_list = [
            ("**Core Commands**", ""),
            ("/status [jail]", "Get Fail2Ban status"),
            ("/jails", "List all available jails"),
            ("/banned <jail>", "List banned IPs in a jail"),
            ("/ban <jail> <ip>", "Manually ban an IP"),
            ("/unban <jail> <ip>", "Unban an IP"),
            ("/unbanall [jail]", "Unban all IPs"),
            ("/reload [jail]", "Reload configuration"),
            ("/ping", "Check if Fail2Ban is running"),
            ("", ""),
            ("**IP Intelligence**", ""),
            ("/checkip <ip>", "Check IP reputation on AbuseIPDB"),
            ("/reportip <ip> <jail>", "Report IP to AbuseIPDB"),
            ("", ""),
            ("**Statistics**", ""),
            ("/stats [hours]", "View ban statistics"),
            ("/history <ip>", "View ban history for an IP"),
            ("/offenders", "List repeat offenders"),
            ("", ""),
            ("**Whitelist**", ""),
            ("/whitelist", "View whitelisted IPs"),
            ("/whitelist-add <ip>", "Add IP to whitelist"),
            ("/whitelist-remove <ip>", "Remove IP from whitelist"),
        ]

        for cmd, desc in commands_list:
            if cmd:
                embed.add_field(name=cmd, value=desc or "\u200b", inline=False)

        await interaction.response.send_message(embed=embed)


class AbuseIPDBCommands(commands.Cog):
    """Commands for AbuseIPDB integration."""

    def __init__(self, bot: Fail2BanBot):
        self.bot = bot

    @app_commands.command(name="checkip", description="Check IP reputation on AbuseIPDB")
    @app_commands.describe(ip="IP address to check")
    async def checkip(self, interaction: discord.Interaction, ip: str):
        """Check IP reputation on AbuseIPDB."""
        if not self.bot.abuseipdb:
            await interaction.response.send_message(
                "AbuseIPDB is not configured. Add your API key to the config.",
                ephemeral=True
            )
            return

        await interaction.response.defer()

        try:
            data = self.bot.abuseipdb.check_ip(ip)

            if data:
                report = format_ip_report(data)
                embed = discord.Embed(
                    title=f"IP Reputation: {ip}",
                    color=report.get('color', discord.Color.blue())
                )

                for field in report['fields']:
                    embed.add_field(
                        name=field['name'],
                        value=field['value'],
                        inline=field.get('inline', True)
                    )

                embed.set_footer(text="Data from AbuseIPDB")
            else:
                embed = discord.Embed(
                    title=f"IP Reputation: {ip}",
                    description="No data found for this IP address.",
                    color=discord.Color.grey()
                )

        except Exception as e:
            embed = discord.Embed(
                title="Error",
                description=f"Failed to check IP: {str(e)}",
                color=discord.Color.red()
            )

        await interaction.followup.send(embed=embed)

    @app_commands.command(name="reportip", description="Report IP to AbuseIPDB")
    @app_commands.describe(ip="IP address to report", jail="Jail/category for the report")
    async def reportip(self, interaction: discord.Interaction, ip: str, jail: str):
        """Report an IP to AbuseIPDB."""
        if not self.bot.is_admin(interaction.user):
            await interaction.response.send_message(
                "You don't have permission to report IPs.",
                ephemeral=True
            )
            return

        if not self.bot.abuseipdb:
            await interaction.response.send_message(
                "AbuseIPDB is not configured.",
                ephemeral=True
            )
            return

        await interaction.response.defer()

        try:
            categories = get_categories_for_jail(jail)
            success = self.bot.abuseipdb.report_ip(
                ip, categories, f"Reported via Discord - Jail: {jail}"
            )

            if success:
                embed = discord.Embed(
                    title="IP Reported",
                    description=f"Successfully reported `{ip}` to AbuseIPDB.",
                    color=discord.Color.green()
                )
                logging.info(f"Reported {ip} to AbuseIPDB by {interaction.user}")
            else:
                embed = discord.Embed(
                    title="Report Failed",
                    description="Failed to report IP to AbuseIPDB.",
                    color=discord.Color.red()
                )

        except Exception as e:
            embed = discord.Embed(
                title="Error",
                description=f"Failed to report IP: {str(e)}",
                color=discord.Color.red()
            )

        await interaction.followup.send(embed=embed)


class StatisticsCommands(commands.Cog):
    """Commands for viewing ban statistics."""

    def __init__(self, bot: Fail2BanBot):
        self.bot = bot

    @app_commands.command(name="stats", description="View ban statistics")
    @app_commands.describe(hours="Time period in hours (default: 24)")
    async def stats(self, interaction: discord.Interaction, hours: int = 24):
        """View ban statistics."""
        await interaction.response.defer()

        try:
            stats = self.bot.stats.get_stats(hours)
            stats_embed = format_stats_embed(stats)

            embed = discord.Embed(
                title=f"Ban Statistics (Last {hours} hours)",
                color=discord.Color.blue()
            )

            for field in stats_embed['fields']:
                embed.add_field(
                    name=field['name'],
                    value=field['value'],
                    inline=field.get('inline', True)
                )

        except Exception as e:
            embed = discord.Embed(
                title="Error",
                description=f"Failed to get statistics: {str(e)}",
                color=discord.Color.red()
            )

        await interaction.followup.send(embed=embed)

    @app_commands.command(name="history", description="View ban history for an IP")
    @app_commands.describe(ip="IP address to check")
    async def history(self, interaction: discord.Interaction, ip: str):
        """View ban history for an IP."""
        await interaction.response.defer()

        try:
            history = self.bot.stats.get_ip_history(ip)

            if history:
                history_list = []
                for entry in history[:15]:
                    action = "Banned" if entry['action'] == 'ban' else "Unbanned"
                    line = f"`{entry['timestamp'][:16]}` - {action} in `{entry['jail']}`"
                    if entry.get('abuse_score'):
                        line += f" (Score: {entry['abuse_score']}%)"
                    history_list.append(line)

                embed = discord.Embed(
                    title=f"Ban History: {ip}",
                    description="\n".join(history_list),
                    color=discord.Color.blue()
                )
                embed.set_footer(text=f"Total events: {len(history)}")
            else:
                embed = discord.Embed(
                    title=f"Ban History: {ip}",
                    description="No history found for this IP.",
                    color=discord.Color.grey()
                )

        except Exception as e:
            embed = discord.Embed(
                title="Error",
                description=f"Failed to get history: {str(e)}",
                color=discord.Color.red()
            )

        await interaction.followup.send(embed=embed)

    @app_commands.command(name="offenders", description="List repeat offenders")
    @app_commands.describe(min_bans="Minimum number of bans (default: 3)")
    async def offenders(self, interaction: discord.Interaction, min_bans: int = 3):
        """List repeat offenders."""
        await interaction.response.defer()

        try:
            offenders = self.bot.stats.get_repeat_offenders(min_bans)

            if offenders:
                offender_list = []
                for o in offenders[:15]:
                    line = f"`{o['ip']}` - **{o['ban_count']}** bans"
                    if o.get('max_abuse_score'):
                        line += f" (Max score: {o['max_abuse_score']}%)"
                    if o.get('jails'):
                        line += f"\n  Jails: {', '.join(o['jails'][:3])}"
                    offender_list.append(line)

                embed = discord.Embed(
                    title="Repeat Offenders (Last 7 days)",
                    description="\n".join(offender_list),
                    color=discord.Color.orange()
                )
            else:
                embed = discord.Embed(
                    title="Repeat Offenders",
                    description=f"No IPs with {min_bans}+ bans found.",
                    color=discord.Color.grey()
                )

        except Exception as e:
            embed = discord.Embed(
                title="Error",
                description=f"Failed to get offenders: {str(e)}",
                color=discord.Color.red()
            )

        await interaction.followup.send(embed=embed)


class WhitelistCommands(commands.Cog):
    """Commands for managing IP whitelist."""

    def __init__(self, bot: Fail2BanBot):
        self.bot = bot

    @app_commands.command(name="whitelist", description="View whitelisted IPs")
    async def whitelist(self, interaction: discord.Interaction):
        """View the current whitelist."""
        whitelist = self.bot.f2b.get_whitelist()

        if whitelist:
            ip_list = '\n'.join([f"- `{ip}`" for ip in whitelist[:50]])
            if len(whitelist) > 50:
                ip_list += f"\n... and {len(whitelist) - 50} more"

            embed = discord.Embed(
                title="Whitelisted IPs",
                description=ip_list,
                color=discord.Color.green()
            )
            embed.set_footer(text=f"Total: {len(whitelist)} IPs")
        else:
            embed = discord.Embed(
                title="Whitelisted IPs",
                description="No IPs in whitelist.",
                color=discord.Color.grey()
            )

        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="whitelist-add", description="Add IP to whitelist")
    @app_commands.describe(ip="IP address to whitelist")
    async def whitelist_add(self, interaction: discord.Interaction, ip: str):
        """Add an IP to the whitelist."""
        if not self.bot.is_admin(interaction.user):
            await interaction.response.send_message(
                "You don't have permission to modify the whitelist.",
                ephemeral=True
            )
            return

        success, message = self.bot.f2b.add_to_whitelist(ip)

        if success:
            embed = discord.Embed(
                title="IP Whitelisted",
                description=f"Successfully added `{ip}` to whitelist.",
                color=discord.Color.green()
            )
            logging.info(f"Whitelist add: {ip} by {interaction.user}")
        else:
            embed = discord.Embed(
                title="Failed",
                description=message,
                color=discord.Color.red()
            )

        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="whitelist-remove", description="Remove IP from whitelist")
    @app_commands.describe(ip="IP address to remove")
    async def whitelist_remove(self, interaction: discord.Interaction, ip: str):
        """Remove an IP from the whitelist."""
        if not self.bot.is_admin(interaction.user):
            await interaction.response.send_message(
                "You don't have permission to modify the whitelist.",
                ephemeral=True
            )
            return

        success, message = self.bot.f2b.remove_from_whitelist(ip)

        if success:
            embed = discord.Embed(
                title="IP Removed",
                description=f"Successfully removed `{ip}` from whitelist.",
                color=discord.Color.green()
            )
            logging.info(f"Whitelist remove: {ip} by {interaction.user}")
        else:
            embed = discord.Embed(
                title="Failed",
                description=message,
                color=discord.Color.red()
            )

        await interaction.response.send_message(embed=embed)


def main():
    """Main entry point for the bot."""
    # Ensure log directory exists
    log_file = '/var/log/fail2ban-discord.log'
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file)
        ]
    )

    config_path = os.environ.get('FAIL2BAN_DISCORD_CONFIG', '/etc/fail2ban-discord/config.ini')

    try:
        config = Config(config_path)
    except FileNotFoundError as e:
        logging.error(f"Configuration error: {e}")
        sys.exit(1)

    token = config.get('discord', 'bot_token')
    if not token or token == 'YOUR_BOT_TOKEN_HERE':
        logging.error("Discord bot token not configured!")
        sys.exit(1)

    bot = Fail2BanBot(config)
    bot.run(token)


if __name__ == "__main__":
    main()
