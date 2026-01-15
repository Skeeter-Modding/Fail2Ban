#!/bin/bash
#
# Fail2Ban Discord Integration Installer
# This script installs and configures the Fail2Ban Discord integration.
#
# Usage: sudo ./install.sh [OPTIONS]
#
# Options:
#   --webhook-only    Install webhook notifications only (no bot)
#   --bot-only        Install Discord bot only
#   --full            Install everything (default)
#   --uninstall       Remove the installation
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Installation paths
INSTALL_DIR="/opt/fail2ban-discord"
CONFIG_DIR="/etc/fail2ban-discord"
SYSTEMD_DIR="/etc/systemd/system"
F2B_ACTION_DIR="/etc/fail2ban/action.d"
F2B_FILTER_DIR="/etc/fail2ban/filter.d"
F2B_JAIL_DIR="/etc/fail2ban/jail.d"
BIN_DIR="/usr/local/bin"
LOG_DIR="/var/log"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Default options
INSTALL_BOT=true
INSTALL_WEBHOOK=true

# Print functions
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check for required dependencies
check_dependencies() {
    print_info "Checking dependencies..."

    local missing=()

    # Check for fail2ban
    if ! command -v fail2ban-client &> /dev/null; then
        missing+=("fail2ban")
    fi

    # Check for Python 3
    if ! command -v python3 &> /dev/null; then
        missing+=("python3")
    fi

    # Check for pip
    if ! command -v pip3 &> /dev/null; then
        missing+=("python3-pip")
    fi

    # Check for curl (for webhook-only installs)
    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        print_warning "Missing dependencies: ${missing[*]}"
        print_info "Attempting to install missing dependencies..."

        # Detect package manager
        if command -v apt-get &> /dev/null; then
            apt-get update
            apt-get install -y "${missing[@]}"
        elif command -v dnf &> /dev/null; then
            dnf install -y "${missing[@]}"
        elif command -v yum &> /dev/null; then
            yum install -y "${missing[@]}"
        elif command -v pacman &> /dev/null; then
            pacman -Sy --noconfirm "${missing[@]}"
        else
            print_error "Could not detect package manager. Please install manually: ${missing[*]}"
            exit 1
        fi
    fi

    print_success "All dependencies satisfied"
}

# Install Python packages
install_python_packages() {
    print_info "Installing Python packages..."

    pip3 install --upgrade pip

    if [[ "$INSTALL_BOT" == true ]]; then
        pip3 install "discord.py>=2.0.0"
    fi

    # Optional: GeoIP support
    if pip3 install geoip2 2>/dev/null; then
        print_success "GeoIP support installed"
    else
        print_warning "GeoIP support not installed (optional)"
    fi

    print_success "Python packages installed"
}

# Create directories
create_directories() {
    print_info "Creating directories..."

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$F2B_ACTION_DIR"
    mkdir -p "$F2B_FILTER_DIR"
    mkdir -p "$F2B_JAIL_DIR"

    print_success "Directories created"
}

# Install files
install_files() {
    print_info "Installing files..."

    # Copy bot files
    if [[ "$INSTALL_BOT" == true ]]; then
        cp "$SCRIPT_DIR/bot/discord_bot.py" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/discord_bot.py"
    fi

    # Copy webhook notifier
    if [[ "$INSTALL_WEBHOOK" == true ]]; then
        cp "$SCRIPT_DIR/bot/webhook_notifier.py" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/webhook_notifier.py"

        # Create symlink for easy access
        ln -sf "$INSTALL_DIR/webhook_notifier.py" "$BIN_DIR/fail2ban-discord-notify"
    fi

    # Copy Fail2Ban actions
    cp "$SCRIPT_DIR/fail2ban/actions/discord.conf" "$F2B_ACTION_DIR/"
    cp "$SCRIPT_DIR/fail2ban/actions/discord-curl.conf" "$F2B_ACTION_DIR/"

    # Copy Fail2Ban filters
    cp "$SCRIPT_DIR/fail2ban/filters/arma-reforger.conf" "$F2B_FILTER_DIR/"

    # Copy example config if config doesn't exist
    if [[ ! -f "$CONFIG_DIR/config.ini" ]]; then
        cp "$SCRIPT_DIR/config/config.example.ini" "$CONFIG_DIR/config.ini"
        chmod 600 "$CONFIG_DIR/config.ini"
        print_warning "Configuration file created at $CONFIG_DIR/config.ini"
        print_warning "Please edit this file with your Discord credentials!"
    fi

    print_success "Files installed"
}

# Install jail configuration (optional)
install_jail_config() {
    print_info "Installing jail configuration..."

    # Only copy if it doesn't exist to avoid overwriting user config
    if [[ ! -f "$F2B_JAIL_DIR/arma-reforger.local" ]]; then
        cp "$SCRIPT_DIR/fail2ban/jails/arma-reforger.local" "$F2B_JAIL_DIR/"
        print_success "Arma Reforger jail configuration installed"
        print_warning "Edit $F2B_JAIL_DIR/arma-reforger.local to configure log paths"
    else
        print_info "Jail configuration already exists, skipping"
    fi
}

# Create systemd service for the bot
create_systemd_service() {
    if [[ "$INSTALL_BOT" != true ]]; then
        return
    fi

    print_info "Creating systemd service..."

    cat > "$SYSTEMD_DIR/fail2ban-discord.service" << EOF
[Unit]
Description=Fail2Ban Discord Bot
After=network.target fail2ban.service
Wants=fail2ban.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/python3 $INSTALL_DIR/discord_bot.py
Restart=always
RestartSec=10
Environment=FAIL2BAN_DISCORD_CONFIG=$CONFIG_DIR/config.ini

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR/fail2ban-discord.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_success "Systemd service created"
}

# Post-installation instructions
print_instructions() {
    echo ""
    echo "=================================================="
    echo -e "${GREEN}Installation Complete!${NC}"
    echo "=================================================="
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Edit the configuration file:"
    echo "   sudo nano $CONFIG_DIR/config.ini"
    echo ""

    if [[ "$INSTALL_BOT" == true ]]; then
        echo "2. Add your Discord bot token and channel ID"
        echo "   - Create a bot at https://discord.com/developers/applications"
        echo "   - Enable 'Message Content Intent' in Bot settings"
        echo "   - Invite the bot with appropriate permissions"
        echo ""
        echo "3. Start the Discord bot:"
        echo "   sudo systemctl start fail2ban-discord"
        echo "   sudo systemctl enable fail2ban-discord"
        echo ""
    fi

    if [[ "$INSTALL_WEBHOOK" == true ]]; then
        echo "2. For webhook-only notifications:"
        echo "   - Create a webhook in Discord (Server Settings > Integrations)"
        echo "   - Add the webhook URL to the config file"
        echo ""
    fi

    echo "4. Configure your Fail2Ban jails to use the discord action:"
    echo "   Edit /etc/fail2ban/jail.local and add:"
    echo "   action = %(action_)s"
    echo "            discord[name=%(__name__)s]"
    echo ""
    echo "5. For Arma Reforger servers, edit:"
    echo "   $F2B_JAIL_DIR/arma-reforger.local"
    echo "   Update the logpath to your server's log location"
    echo ""
    echo "6. Reload Fail2Ban:"
    echo "   sudo systemctl restart fail2ban"
    echo ""
    echo "Documentation: See README.md for detailed instructions"
    echo "=================================================="
}

# Uninstall function
uninstall() {
    print_info "Uninstalling Fail2Ban Discord integration..."

    # Stop and disable service
    if systemctl is-active --quiet fail2ban-discord 2>/dev/null; then
        systemctl stop fail2ban-discord
    fi
    if systemctl is-enabled --quiet fail2ban-discord 2>/dev/null; then
        systemctl disable fail2ban-discord
    fi

    # Remove files
    rm -f "$SYSTEMD_DIR/fail2ban-discord.service"
    rm -f "$BIN_DIR/fail2ban-discord-notify"
    rm -f "$F2B_ACTION_DIR/discord.conf"
    rm -f "$F2B_ACTION_DIR/discord-curl.conf"
    rm -f "$F2B_FILTER_DIR/arma-reforger.conf"
    rm -rf "$INSTALL_DIR"

    # Reload systemd
    systemctl daemon-reload

    print_warning "Configuration kept at $CONFIG_DIR"
    print_warning "Jail configuration kept at $F2B_JAIL_DIR"
    print_success "Uninstallation complete"
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --webhook-only)
                INSTALL_BOT=false
                INSTALL_WEBHOOK=true
                shift
                ;;
            --bot-only)
                INSTALL_BOT=true
                INSTALL_WEBHOOK=false
                shift
                ;;
            --full)
                INSTALL_BOT=true
                INSTALL_WEBHOOK=true
                shift
                ;;
            --uninstall)
                check_root
                uninstall
                exit 0
                ;;
            -h|--help)
                echo "Fail2Ban Discord Integration Installer"
                echo ""
                echo "Usage: sudo $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --webhook-only    Install webhook notifications only"
                echo "  --bot-only        Install Discord bot only"
                echo "  --full            Install everything (default)"
                echo "  --uninstall       Remove the installation"
                echo "  -h, --help        Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

# Main installation
main() {
    echo "=================================================="
    echo "  Fail2Ban Discord Integration Installer"
    echo "=================================================="
    echo ""

    parse_args "$@"
    check_root
    check_dependencies
    install_python_packages
    create_directories
    install_files
    install_jail_config
    create_systemd_service
    print_instructions
}

main "$@"
