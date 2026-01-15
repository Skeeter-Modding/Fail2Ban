#!/usr/bin/env python3
"""
Fail2Ban Discord Bot
A Discord bot for managing Fail2Ban and receiving ban notifications.
"""

import asyncio
import configparser
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

# Optional GeoIP support
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


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


class Fail2BanManager:
    """Interface for Fail2Ban operations."""

    def __init__(self, client_path: str = "/usr/bin/fail2ban-client"):
        self.client_path = client_path

    def _run_command(self, *args) -> tuple[bool, str]:
        """Run a fail2ban-client command and return success status and output."""
        try:
            result = subprocess.run(
                [self.client_path] + list(args),
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

    def get_status(self) -> tuple[bool, str]:
        """Get overall Fail2Ban status."""
        return self._run_command("status")

    def get_jail_status(self, jail: str) -> tuple[bool, str]:
        """Get status of a specific jail."""
        return self._run_command("status", jail)

    def ban_ip(self, jail: str, ip: str) -> tuple[bool, str]:
        """Manually ban an IP in a jail."""
        return self._run_command("set", jail, "banip", ip)

    def unban_ip(self, jail: str, ip: str) -> tuple[bool, str]:
        """Unban an IP from a jail."""
        return self._run_command("set", jail, "unbanip", ip)

    def unban_all(self, jail: str = None) -> tuple[bool, str]:
        """Unban all IPs from a jail or all jails."""
        if jail:
            return self._run_command("set", jail, "unbanip", "--all")
        return self._run_command("unban", "--all")

    def get_banned_ips(self, jail: str) -> tuple[bool, list]:
        """Get list of banned IPs in a jail."""
        success, output = self._run_command("get", jail, "banip")
        if success:
            ips = output.split() if output else []
            return True, ips
        return False, []

    def get_jails(self) -> tuple[bool, list]:
        """Get list of all jails."""
        success, output = self.get_status()
        if success:
            for line in output.split('\n'):
                if 'Jail list:' in line:
                    jails = line.split(':')[1].strip()
                    return True, [j.strip() for j in jails.split(',') if j.strip()]
        return False, []

    def reload(self, jail: str = None) -> tuple[bool, str]:
        """Reload Fail2Ban configuration."""
        if jail:
            return self._run_command("reload", jail)
        return self._run_command("reload")

    def ping(self) -> bool:
        """Check if Fail2Ban server is running."""
        success, output = self._run_command("ping")
        return success and "pong" in output.lower()


class GeoIPLookup:
    """GeoIP lookup for IP addresses."""

    def __init__(self, db_path: str = "/usr/share/GeoIP/GeoLite2-City.mmdb"):
        self.db_path = db_path
        self.reader = None
        if GEOIP_AVAILABLE and os.path.exists(db_path):
            try:
                self.reader = geoip2.database.Reader(db_path)
            except Exception:
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
        self.geoip = GeoIPLookup() if config.getboolean('notifications', 'include_geoip', False) else None
        self.notification_channel_id = config.getint('discord', 'channel_id')
        self.admin_role_id = config.getint('discord', 'admin_role_id', 0) or None
        self.guild_id = config.getint('discord', 'guild_id')

    async def setup_hook(self):
        """Set up the bot's slash commands."""
        await self.add_cog(Fail2BanCommands(self))

        if self.guild_id:
            guild = discord.Object(id=self.guild_id)
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
        else:
            await self.tree.sync()

    async def on_ready(self):
        logging.info(f"Bot connected as {self.user}")

        if self.config.getboolean('notifications', 'notify_on_start', True):
            await self.send_notification(
                title="Fail2Ban Bot Started",
                description=f"Bot is now online and monitoring.",
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
        """Send a ban notification."""
        if not self.config.getboolean('notifications', 'notify_on_ban', True):
            return

        fields = [
            {'name': 'IP Address', 'value': f'`{ip}`', 'inline': True},
            {'name': 'Jail', 'value': f'`{jail}`', 'inline': True},
        ]

        if matches:
            fields.append({'name': 'Matches', 'value': str(matches), 'inline': True})

        if self.geoip:
            geo = self.geoip.lookup(ip)
            if geo:
                location = f":flag_{geo.get('country_code', 'xx').lower()}: {geo.get('country', 'Unknown')}"
                if geo.get('city') and geo.get('city') != 'Unknown':
                    location += f", {geo['city']}"
                fields.append({'name': 'Location', 'value': location, 'inline': True})

        if log_lines:
            log_preview = '\n'.join(log_lines[:3])
            if len(log_preview) > 1000:
                log_preview = log_preview[:997] + '...'
            fields.append({'name': 'Log Preview', 'value': f'```\n{log_preview}\n```', 'inline': False})

        color = int(self.config.get('notifications', 'ban_color', 'ff0000'), 16)
        await self.send_notification(
            title="IP Banned",
            description=f"An IP address has been banned by Fail2Ban.",
            color=color,
            fields=fields
        )

    async def notify_unban(self, jail: str, ip: str):
        """Send an unban notification."""
        if not self.config.getboolean('notifications', 'notify_on_unban', True):
            return

        fields = [
            {'name': 'IP Address', 'value': f'`{ip}`', 'inline': True},
            {'name': 'Jail', 'value': f'`{jail}`', 'inline': True},
        ]

        color = int(self.config.get('notifications', 'unban_color', '00ff00'), 16)
        await self.send_notification(
            title="IP Unbanned",
            description=f"An IP address has been unbanned.",
            color=color,
            fields=fields
        )

    def is_admin(self, member: discord.Member) -> bool:
        """Check if a member has admin permissions for the bot."""
        if member.guild_permissions.administrator:
            return True
        if self.admin_role_id:
            return any(role.id == self.admin_role_id for role in member.roles)
        return True  # If no admin role set, allow all users


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
            jail_list = '\n'.join([f"• `{jail}`" for jail in jails])
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
                ip_list = '\n'.join([f"• `{ip}`" for ip in ips[:50]])
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
            ("/status [jail]", "Get Fail2Ban status or specific jail status"),
            ("/jails", "List all available jails"),
            ("/banned <jail>", "List banned IPs in a jail"),
            ("/ban <jail> <ip>", "Manually ban an IP address"),
            ("/unban <jail> <ip>", "Unban an IP address"),
            ("/unbanall [jail]", "Unban all IPs from a jail or all jails"),
            ("/reload [jail]", "Reload Fail2Ban configuration"),
            ("/ping", "Check if Fail2Ban is running"),
        ]

        for cmd, desc in commands_list:
            embed.add_field(name=cmd, value=desc, inline=False)

        await interaction.response.send_message(embed=embed)


def main():
    """Main entry point for the bot."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('/var/log/fail2ban-discord.log')
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
