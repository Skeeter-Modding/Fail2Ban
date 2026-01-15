# Fail2Ban Discord Integration

A comprehensive integration between Fail2Ban and Discord for server security monitoring and management. Features real-time ban notifications, Discord slash commands for remote management, and custom filters for Arma Reforger game servers.

## Features

- **Real-time Notifications**: Get instant Discord alerts when IPs are banned/unbanned
- **Discord Bot Commands**: Manage Fail2Ban remotely via Discord slash commands
- **GeoIP Support**: See geographic location of banned IPs
- **Arma Reforger Support**: Custom filters for Arma Reforger dedicated servers
- **Docker Support**: Bridge logs from Docker containers to Fail2Ban
- **Flexible Setup**: Use full bot or webhook-only notifications

## Quick Start

### Prerequisites

- Linux server with Fail2Ban installed
- Python 3.8 or higher
- Discord server with admin access

### Installation

```bash
# Clone the repository
git clone https://github.com/Skeeter-Modding/Fail2Ban.git
cd Fail2Ban

# Run the installer
sudo ./scripts/install.sh
```

### Configuration

1. Edit the configuration file:
   ```bash
   sudo nano /etc/fail2ban-discord/config.ini
   ```

2. Add your Discord credentials (see [Discord Setup](#discord-setup) below)

3. Restart the services:
   ```bash
   sudo systemctl restart fail2ban
   sudo systemctl start fail2ban-discord
   ```

## Discord Setup

### Option 1: Full Bot (Recommended)

The full bot allows two-way communication - notifications AND remote command execution.

1. **Create a Discord Application**
   - Go to [Discord Developer Portal](https://discord.com/developers/applications)
   - Click "New Application" and give it a name
   - Go to the "Bot" section and click "Add Bot"

2. **Configure Bot Settings**
   - Under "Privileged Gateway Intents", enable:
     - Message Content Intent
   - Copy the bot token (keep this secret!)

3. **Invite the Bot**
   - Go to "OAuth2" > "URL Generator"
   - Select scopes: `bot`, `applications.commands`
   - Select permissions:
     - Send Messages
     - Embed Links
     - Use Slash Commands
   - Copy and open the generated URL to invite the bot

4. **Get Channel and Guild IDs**
   - Enable Developer Mode in Discord (Settings > App Settings > Advanced)
   - Right-click your server > Copy ID (this is your Guild ID)
   - Right-click the channel for notifications > Copy ID (this is your Channel ID)

5. **Update Configuration**
   ```ini
   [discord]
   bot_token = YOUR_BOT_TOKEN
   channel_id = YOUR_CHANNEL_ID
   guild_id = YOUR_GUILD_ID
   ```

### Option 2: Webhook Only

For simple notifications without command support:

1. **Create a Webhook**
   - Go to Server Settings > Integrations > Webhooks
   - Click "New Webhook"
   - Choose the target channel
   - Copy the Webhook URL

2. **Update Configuration**
   ```ini
   [discord]
   webhook_url = YOUR_WEBHOOK_URL
   ```

3. **Install webhook-only**
   ```bash
   sudo ./scripts/install.sh --webhook-only
   ```

## Bot Commands

| Command | Description |
|---------|-------------|
| `/status [jail]` | Get Fail2Ban status or specific jail status |
| `/jails` | List all available jails |
| `/banned <jail>` | List banned IPs in a jail |
| `/ban <jail> <ip>` | Manually ban an IP address |
| `/unban <jail> <ip>` | Unban an IP address |
| `/unbanall [jail]` | Unban all IPs from a jail or all jails |
| `/reload [jail]` | Reload Fail2Ban configuration |
| `/ping` | Check if Fail2Ban is running |
| `/help` | Show help for all commands |

## Arma Reforger Setup

### Standard Installation

If your Arma Reforger server writes logs to the filesystem:

1. **Configure the jail**
   ```bash
   sudo nano /etc/fail2ban/jail.d/arma-reforger.local
   ```

2. **Update the log path**
   ```ini
   [arma-reforger]
   enabled = true
   logpath = /path/to/your/arma-reforger/logs/console.log
   ```

3. **Restart Fail2Ban**
   ```bash
   sudo systemctl restart fail2ban
   ```

### Docker Installation

For Arma Reforger servers running in Docker containers:

1. **Start the log bridge**
   ```bash
   sudo cp scripts/docker-log-bridge.sh /opt/fail2ban-discord/
   sudo cp scripts/docker-log-bridge.service /etc/systemd/system/

   # Configure container pattern
   sudo systemctl edit docker-log-bridge
   # Add: Environment=CONTAINER_PATTERN=your-container-name

   sudo systemctl enable --now docker-log-bridge
   ```

2. **Configure Fail2Ban to use bridged logs**
   ```ini
   [arma-reforger]
   logpath = /var/log/arma-reforger/*.log
   ```

### Custom Filter Patterns

The included filter covers common patterns. To add custom patterns:

```bash
sudo nano /etc/fail2ban/filter.d/arma-reforger.conf
```

Add your patterns to the `failregex` section:
```ini
failregex = ^<HOST> - Your custom pattern here
            ^Another pattern with <HOST>
```

## Configuration Reference

### Full Configuration File

```ini
[discord]
# Discord Bot Token (required for bot functionality)
bot_token = YOUR_BOT_TOKEN_HERE

# Discord Webhook URL (for notifications only)
webhook_url = YOUR_WEBHOOK_URL_HERE

# Channel ID for notifications and commands
channel_id = YOUR_CHANNEL_ID_HERE

# Role ID that can execute admin commands (optional)
admin_role_id =

# Guild/Server ID (required for slash commands)
guild_id = YOUR_GUILD_ID_HERE

[fail2ban]
# Path to fail2ban-client
fail2ban_client = /usr/bin/fail2ban-client

# Jails to monitor (comma-separated, empty for all)
monitored_jails = sshd,arma-reforger

# Log file for the bot
log_file = /var/log/fail2ban-discord.log

[notifications]
# Notification toggles
notify_on_ban = true
notify_on_unban = true
notify_on_start = true
notify_on_stop = true

# GeoIP lookup (requires geoip2 package)
include_geoip = true

# Embed colors (hex without #)
ban_color = ff0000
unban_color = 00ff00
info_color = 0099ff

[arma_reforger]
# Log path for Arma Reforger servers
log_path = /var/log/arma-reforger/

# Docker container name pattern
container_pattern = arma-reforger-*

# Ban thresholds
max_retry = 5
find_time = 600
ban_time = 3600
```

## Adding Discord Notifications to Existing Jails

To add Discord notifications to any Fail2Ban jail:

### Using the Python Notifier (Recommended)

Edit your jail configuration:
```ini
[sshd]
enabled = true
action = %(action_)s
         discord[name=%(name)s]
```

### Using curl (No Dependencies)

```ini
[sshd]
enabled = true
action = %(action_)s
         discord-curl[name=%(name)s, webhook_url=YOUR_WEBHOOK_URL]
```

## Troubleshooting

### Bot not responding to commands

1. Check if the bot is running:
   ```bash
   sudo systemctl status fail2ban-discord
   ```

2. Check logs:
   ```bash
   sudo journalctl -u fail2ban-discord -f
   ```

3. Ensure the bot has proper permissions in Discord

### Notifications not appearing

1. Verify webhook URL or bot token
2. Check channel permissions
3. Test webhook manually:
   ```bash
   /usr/local/bin/fail2ban-discord-notify ban --jail test --ip 1.2.3.4
   ```

### Fail2Ban not banning IPs

1. Check if the jail is active:
   ```bash
   sudo fail2ban-client status arma-reforger
   ```

2. Test the filter:
   ```bash
   sudo fail2ban-regex /path/to/log /etc/fail2ban/filter.d/arma-reforger.conf
   ```

3. Check Fail2Ban logs:
   ```bash
   sudo tail -f /var/log/fail2ban.log
   ```

### Docker logs not being captured

1. Check if the bridge is running:
   ```bash
   sudo systemctl status docker-log-bridge
   ```

2. Verify container pattern matches:
   ```bash
   docker ps --format '{{.Names}}' | grep arma-reforger
   ```

## Service Management

```bash
# Discord Bot
sudo systemctl start fail2ban-discord
sudo systemctl stop fail2ban-discord
sudo systemctl restart fail2ban-discord
sudo systemctl status fail2ban-discord

# Docker Log Bridge
sudo systemctl start docker-log-bridge
sudo systemctl stop docker-log-bridge
sudo systemctl status docker-log-bridge

# Fail2Ban
sudo systemctl restart fail2ban
sudo fail2ban-client reload
```

## Uninstallation

```bash
sudo ./scripts/install.sh --uninstall
```

This removes the integration but keeps your configuration files.

## Project Structure

```
Fail2Ban/
├── bot/
│   ├── __init__.py
│   ├── discord_bot.py      # Full Discord bot with commands
│   └── webhook_notifier.py # Standalone webhook notifier
├── config/
│   └── config.example.ini  # Example configuration
├── fail2ban/
│   ├── actions/
│   │   ├── discord.conf      # Python-based action
│   │   └── discord-curl.conf # curl-based action
│   ├── filters/
│   │   └── arma-reforger.conf # Arma Reforger filter
│   └── jails/
│       └── arma-reforger.local # Arma Reforger jail config
├── scripts/
│   ├── install.sh           # Installation script
│   ├── docker-log-bridge.sh # Docker log bridge
│   └── docker-log-bridge.service # Systemd service
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Fail2Ban](https://www.fail2ban.org/) - The intrusion prevention framework
- [discord.py](https://discordpy.readthedocs.io/) - Discord API wrapper for Python
- [Arma Reforger](https://reforger.armaplatform.com/) - The game this was built for
