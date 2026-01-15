#!/bin/bash
#
# Docker Log Bridge for Fail2Ban
# This script extracts logs from Docker containers and writes them
# to files that Fail2Ban can monitor.
#
# Usage: ./docker-log-bridge.sh [OPTIONS]
#
# This is useful when your Arma Reforger servers run in Docker containers
# and you need Fail2Ban to monitor their logs.
#

set -e

# Configuration
LOG_DIR="${LOG_DIR:-/var/log/arma-reforger}"
CONTAINER_PATTERN="${CONTAINER_PATTERN:-arma-reforger}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"
PID_FILE="/var/run/docker-log-bridge.pid"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() { echo -e "[INFO] $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Check if Docker is available
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Cannot connect to Docker daemon. Is it running?"
        exit 1
    fi
}

# Get list of matching containers
get_containers() {
    docker ps --format '{{.Names}}' | grep -E "$CONTAINER_PATTERN" || true
}

# Start log streaming for a container
stream_container_logs() {
    local container="$1"
    local log_file="$LOG_DIR/${container}.log"

    print_info "Streaming logs from $container to $log_file"

    # Create log file if it doesn't exist
    touch "$log_file"

    # Stream logs in background
    docker logs -f "$container" >> "$log_file" 2>&1 &
    echo $! >> "$PID_FILE.pids"
}

# Main monitoring loop
start_monitoring() {
    print_info "Starting Docker log bridge..."
    print_info "Container pattern: $CONTAINER_PATTERN"
    print_info "Log directory: $LOG_DIR"

    # Create log directory
    mkdir -p "$LOG_DIR"

    # Create PID file
    echo $$ > "$PID_FILE"
    > "$PID_FILE.pids"

    # Get initial containers
    local containers
    containers=$(get_containers)

    if [[ -z "$containers" ]]; then
        print_error "No containers found matching pattern: $CONTAINER_PATTERN"
        exit 1
    fi

    # Start streaming for each container
    for container in $containers; do
        stream_container_logs "$container"
    done

    print_success "Log bridge started for $(echo "$containers" | wc -w) container(s)"

    # Monitor for new containers
    while true; do
        sleep "$POLL_INTERVAL"

        # Check for new containers
        local current_containers
        current_containers=$(get_containers)

        for container in $current_containers; do
            local log_file="$LOG_DIR/${container}.log"
            # Check if we're already streaming this container
            if ! pgrep -f "docker logs -f \"$container\"" > /dev/null; then
                print_info "New container detected: $container"
                stream_container_logs "$container"
            fi
        done
    done
}

# Stop monitoring
stop_monitoring() {
    print_info "Stopping Docker log bridge..."

    if [[ -f "$PID_FILE.pids" ]]; then
        while read -r pid; do
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
            fi
        done < "$PID_FILE.pids"
        rm -f "$PID_FILE.pids"
    fi

    if [[ -f "$PID_FILE" ]]; then
        local main_pid
        main_pid=$(cat "$PID_FILE")
        if kill -0 "$main_pid" 2>/dev/null; then
            kill "$main_pid" 2>/dev/null || true
        fi
        rm -f "$PID_FILE"
    fi

    print_success "Log bridge stopped"
}

# Show status
show_status() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            print_success "Docker log bridge is running (PID: $pid)"

            if [[ -f "$PID_FILE.pids" ]]; then
                local count
                count=$(wc -l < "$PID_FILE.pids")
                print_info "Streaming $count container(s)"
            fi
            return 0
        fi
    fi

    print_info "Docker log bridge is not running"
    return 1
}

# Parse arguments
case "${1:-start}" in
    start)
        check_docker
        start_monitoring
        ;;
    stop)
        stop_monitoring
        ;;
    restart)
        stop_monitoring
        sleep 2
        check_docker
        start_monitoring
        ;;
    status)
        show_status
        ;;
    -h|--help)
        echo "Docker Log Bridge for Fail2Ban"
        echo ""
        echo "Usage: $0 [COMMAND]"
        echo ""
        echo "Commands:"
        echo "  start     Start the log bridge (default)"
        echo "  stop      Stop the log bridge"
        echo "  restart   Restart the log bridge"
        echo "  status    Show bridge status"
        echo ""
        echo "Environment variables:"
        echo "  LOG_DIR            Log output directory (default: /var/log/arma-reforger)"
        echo "  CONTAINER_PATTERN  Container name pattern (default: arma-reforger)"
        echo "  POLL_INTERVAL      Seconds between container checks (default: 5)"
        ;;
    *)
        print_error "Unknown command: $1"
        exit 1
        ;;
esac
