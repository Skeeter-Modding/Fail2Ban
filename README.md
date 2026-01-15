# Fail2Ban Discord Integration

A comprehensive integration between Fail2Ban and Discord for server security monitoring and management. Features real-time ban notifications, Discord slash commands for remote management, IP reputation checking, statistics tracking, and custom filters for Arma Reforger game servers.

## Features

- **Real-time Notifications**: Get instant Discord alerts when IPs are banned/unbanned
- **Discord Bot Commands**: Manage Fail2Ban remotely via Discord slash commands
- **AbuseIPDB Integration**: Check IP reputation and auto-report malicious IPs
- **Ban Statistics & Reports**: Track ban history, view trends, daily/weekly reports
- **Attack Detection**: Get alerts when ban rate spikes (potential DDoS/brute force)
- **IP Whitelist Management**: Manage whitelisted IPs via Discord
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

### Core Commands

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

### IP Intelligence (AbuseIPDB)

| Command | Description |
|---------|-------------|
| `/checkip <ip>` | Check IP reputation on AbuseIPDB |
| `/reportip <ip> <jail>` | Report an IP to AbuseIPDB |

### Statistics

| Command | Description |
|---------|-------------|
| `/stats [hours]` | View ban statistics for time period |
| `/history <ip>` | View ban history for a specific IP |
| `/offenders [min_bans]` | List repeat offenders |

### Whitelist Management

| Command | Description |
|---------|-------------|
| `/whitelist` | View whitelisted IPs |
| `/whitelist-add <ip>` | Add IP to whitelist |
| `/whitelist-remove <ip>` | Remove IP from whitelist |

## AbuseIPDB Integration

The bot integrates with [AbuseIPDB](https://www.abuseipdb.com/) to provide IP reputation data and contribute to the community database.

### Setup

1. Get a free API key from [AbuseIPDB](https://www.abuseipdb.com/account/api)

2. Add to your config:
   ```ini
   [abuseipdb]
   api_key = YOUR_API_KEY_HERE
   auto_report = true
   report_threshold = 50
   ```

### Features

- **IP Reputation Check**: Ban notifications show abuse confidence score
- **Auto-Report**: Automatically report banned IPs to AbuseIPDB
- **Manual Report**: Use `/reportip` to report IPs manually
- **Risk Levels**: Visual indicators (Critical, High, Medium, Low, Clean)

## Attack Detection

The bot monitors ban rates and alerts you when potential attacks are detected.

### Configuration

```ini
[attack_detection]
enabled = true
alert_threshold = 10    # Bans within window to trigger alert
alert_window = 60       # Time window in seconds
alert_cooldown = 300    # Seconds between alerts
```

When ban rate exceeds the threshold, you'll receive a Discord alert with:
- Number of bans detected
- Bans per minute rate
- Unique IPs involved
- Affected jails

## Statistics & Reports

### On-Demand Statistics

Use `/stats 24` to see statistics for the last 24 hours:
- Total bans/unbans
- Bans by jail
- Top offenders
- Geographic distribution
- High-risk ban count

### Scheduled Reports

Enable automatic reports in config:
```ini
[reports]
daily_report = true    # Daily report at 8 AM
weekly_report = true   # Weekly report on Mondays
```

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

## Additional Filters

The project includes filters for common services:

| Filter | Description |
|--------|-------------|
| `arma-reforger.conf` | Arma Reforger server protection |
| `nginx-auth.conf` | Nginx HTTP authentication failures |
| `nginx-badbots.conf` | Bad bots and vulnerability scanners |
| `gameserver-generic.conf` | Generic game server filter |

Enable additional jails in `/etc/fail2ban/jail.d/common-services.local`:
```ini
[nginx-badbots]
enabled = true

[sshd]
enabled = true
```

## Configuration Reference

### Full Configuration File

```ini
[discord]
bot_token = YOUR_BOT_TOKEN_HERE
webhook_url = YOUR_WEBHOOK_URL_HERE
channel_id = YOUR_CHANNEL_ID_HERE
admin_role_id =
guild_id = YOUR_GUILD_ID_HERE

[fail2ban]
fail2ban_client = /usr/bin/fail2ban-client
monitored_jails = sshd,arma-reforger
log_file = /var/log/fail2ban-discord.log

[notifications]
notify_on_ban = true
notify_on_unban = true
notify_on_start = true
notify_on_stop = true
include_geoip = true
ban_color = ff0000
unban_color = 00ff00
info_color = 0099ff

[abuseipdb]
api_key =
auto_report = false
report_threshold = 50

[attack_detection]
enabled = true
alert_threshold = 10
alert_window = 60
alert_cooldown = 300

[reports]
daily_report = false
weekly_report = false

[arma_reforger]
log_path = /var/log/arma-reforger/
container_pattern = arma-reforger-*
max_retry = 5
find_time = 600
ban_time = 3600
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

### AbuseIPDB not working

1. Verify your API key is correct
2. Check if you've exceeded rate limits (free tier: 1000 checks/day)
3. Test manually:
   ```bash
   curl -G https://api.abuseipdb.com/api/v2/check \
     --data-urlencode "ipAddress=1.2.3.4" \
     -H "Key: YOUR_API_KEY" \
     -H "Accept: application/json"
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
│   ├── webhook_notifier.py # Standalone webhook notifier
│   ├── abuseipdb.py        # AbuseIPDB integration
│   └── statistics.py       # Ban statistics tracking
├── config/
│   └── config.example.ini  # Example configuration
├── fail2ban/
│   ├── actions/
│   │   ├── discord.conf      # Python-based action
│   │   └── discord-curl.conf # curl-based action
│   ├── filters/
│   │   ├── arma-reforger.conf    # Arma Reforger filter
│   │   ├── nginx-auth.conf       # Nginx auth filter
│   │   ├── nginx-badbots.conf    # Bad bots filter
│   │   └── gameserver-generic.conf # Generic game server
│   └── jails/
│       ├── arma-reforger.local   # Arma Reforger jail
│       └── common-services.local # Common services jails
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
- [AbuseIPDB](https://www.abuseipdb.com/) - IP reputation database
- [Arma Reforger](https://reforger.armaplatform.com/) - The game this was built for
