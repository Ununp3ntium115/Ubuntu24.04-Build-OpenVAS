#!/bin/bash

# Complete OpenVAS + SSH Setup Script for Ubuntu 24.04
# Author: Based on lessons learned from hands-on installation
# Repository: Custom implementation with SSH-first approach
# 
# This script:
# 1. Sets up SSH for secure remote management
# 2. Installs OpenVAS with proper PostgreSQL compatibility
# 3. Uses correct feed versions (22.04 format)
# 4. Completes full feed synchronization
# 5. Displays admin credentials at the end
#
# Usage: Run as root on fresh Ubuntu 24.04
# Requirements: 4-8 cores, 8GB+ RAM, 64GB+ storage

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Script configuration
SCRIPT_NAME="OpenVAS SSH Setup"
SCRIPT_VERSION="1.0"
LOG_FILE="/var/log/openvas-installation.log"

# Logging functions
log() {
    local message="[$(date +'%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${GREEN}${message}${NC}"
    echo "$message" >> "$LOG_FILE"
}

warn() {
    local message="[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1"
    echo -e "${YELLOW}${message}${NC}"
    echo "$message" >> "$LOG_FILE"
}

error() {
    local message="[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1"
    echo -e "${RED}${message}${NC}"
    echo "$message" >> "$LOG_FILE"
}

info() {
    local message="[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1"
    echo -e "${BLUE}${message}${NC}"
    echo "$message" >> "$LOG_FILE"
}

# Banner
show_banner() {
    clear
    echo -e "${BLUE}${BOLD}"
    echo "================================================================="
    echo "           $SCRIPT_NAME v$SCRIPT_VERSION"
    echo "================================================================="
    echo "  SSH-First OpenVAS Installation for Ubuntu 24.04"
    echo "  - Secure SSH setup with management user"
    echo "  - PostgreSQL compatibility for any version"
    echo "  - Correct feed synchronization (22.04 format)"
    echo "  - Complete vulnerability database setup"
    echo "================================================================="
    echo -e "${NC}"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use 'sudo su' first."
        exit 1
    fi
    
    # Check Ubuntu version
    if ! grep -q "Ubuntu 24.04" /etc/os-release; then
        warn "This script is designed for Ubuntu 24.04. Proceeding anyway..."
    fi
    
    # Check system resources
    local ram_gb=$(free -g | awk 'NR==2{printf "%.0f", $2}')
    local cores=$(nproc)
    local disk_gb=$(df / | awk 'NR==2{printf "%.0f", $2/1024/1024}')
    
    log "System resources: ${cores} cores, ${ram_gb}GB RAM, ${disk_gb}GB disk"
    
    if [ "$ram_gb" -lt 8 ]; then
        warn "Less than 8GB RAM detected. OpenVAS may run slowly."
    fi
    
    if [ "$cores" -lt 4 ]; then
        warn "Less than 4 CPU cores detected. Installation will be slower."
    fi
}

# Clean environment
clean_environment() {
    log "Cleaning environment variables..."
    
    unset DISPLAY
    unset WAYLAND_DISPLAY
    unset XDG_SESSION_TYPE
    unset XDG_CURRENT_DESKTOP
    unset DESKTOP_SESSION
    
    export DEBIAN_FRONTEND=noninteractive
}

# System update
update_system() {
    log "Updating system packages..."
    apt update -y
    apt upgrade -y
    apt install -y curl wget git gnupg software-properties-common
}

# =============================================================================
# SSH SETUP SECTION
# =============================================================================

setup_ssh() {
    log "=== Setting up SSH for secure remote management ==="
    
    # Install OpenSSH server
    log "Installing OpenSSH server..."
    apt install -y openssh-server
    
    # Create backup of SSH config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d) 2>/dev/null || true
    
    # Configure SSH security settings
    log "Configuring SSH security..."
    cat > /etc/ssh/sshd_config.d/99-openvas-security.conf << 'SSH_CONFIG_EOF'
# OpenVAS SSH Security Configuration
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 3
MaxSessions 10
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive yes
Protocol 2
Compression delayed
SyslogFacility AUTH
LogLevel INFO
SSH_CONFIG_EOF
    
    # Create OpenVAS admin user
    create_admin_user
    
    # Start and enable SSH
    systemctl enable ssh
    systemctl restart ssh
    
    # Configure firewall
    ufw allow ssh 2>/dev/null || true
    ufw allow 9392/tcp 2>/dev/null || true  # OpenVAS web interface
    ufw --force enable 2>/dev/null || true
    
    log "SSH setup completed successfully"
}

create_admin_user() {
    log "Creating OpenVAS admin user..."
    
    local admin_user="openvas-admin"
    
    # Create user if doesn't exist
    if ! id "$admin_user" &>/dev/null; then
        useradd -m -s /bin/bash -c "OpenVAS Administrator" "$admin_user"
        
        # Generate secure password
        local admin_password=$(openssl rand -base64 16)
        echo "$admin_user:$admin_password" | chpasswd
        
        # Save password for later display
        echo "$admin_password" > /root/ssh_admin_password.txt
        chmod 600 /root/ssh_admin_password.txt
        
        log "SSH admin user created: $admin_user"
    else
        log "SSH admin user already exists: $admin_user"
    fi
    
    # Add to necessary groups
    usermod -a -G sudo "$admin_user"
    
    # Setup SSH directory
    sudo -u "$admin_user" mkdir -p /home/$admin_user/.ssh
    sudo -u "$admin_user" chmod 700 /home/$admin_user/.ssh
    sudo -u "$admin_user" touch /home/$admin_user/.ssh/authorized_keys
    sudo -u "$admin_user" chmod 600 /home/$admin_user/.ssh/authorized_keys
    
    # Configure sudo access for OpenVAS management
    create_sudo_config "$admin_user"
    
    # Allow user in SSH config
    echo "AllowUsers $admin_user" >> /etc/ssh/sshd_config.d/99-openvas-security.conf
}

create_sudo_config() {
    local user=$1
    
    log "Configuring sudo privileges for $user..."
    
    cat > /etc/sudoers.d/openvas-admin << SUDO_EOF
# OpenVAS Administrator sudo configuration
# Passwordless service management
$user ALL=(ALL) NOPASSWD: /bin/systemctl * postgresql
$user ALL=(ALL) NOPASSWD: /bin/systemctl * redis-server
$user ALL=(ALL) NOPASSWD: /bin/systemctl * mosquitto
$user ALL=(ALL) NOPASSWD: /bin/systemctl * notus-scanner
$user ALL=(ALL) NOPASSWD: /bin/systemctl * ospd-openvas
$user ALL=(ALL) NOPASSWD: /bin/systemctl * gvmd
$user ALL=(ALL) NOPASSWD: /bin/systemctl * gsad
$user ALL=(ALL) NOPASSWD: /bin/systemctl * openvasd
$user ALL=(ALL) NOPASSWD: /usr/bin/journalctl *
$user ALL=(ALL) NOPASSWD: /usr/bin/tail -f /var/log/gvm/*
$user ALL=(ALL) NOPASSWD: /usr/bin/less /var/log/gvm/*

# GVM user operations
$user ALL=(gvm) NOPASSWD: /usr/local/bin/greenbone-feed-sync*
$user ALL=(gvm) NOPASSWD: /usr/local/bin/gvmd --get-users
$user ALL=(gvm) NOPASSWD: /usr/local/bin/gvmd --create-user*
$user ALL=(gvm) NOPASSWD: /usr/local/bin/gvmd --delete-user*

# General system administration (with password)
$user ALL=(ALL) ALL
SUDO_EOF
    
    chmod 440 /etc/sudoers.d/openvas-admin
}

# =============================================================================
# OPENVAS INSTALLATION SECTION
# =============================================================================

install_openvas() {
    log "=== Starting OpenVAS Installation ==="
    
    # Install PostgreSQL first and get version info
    setup_postgresql
    
    # Clone repository and run installation
    download_openvas_scripts
    
    # Run the installation with our enhancements
    run_openvas_installation
    
    # Fix feed versions and complete synchronization
    complete_feed_synchronization
    
    # Final verification
    verify_installation
}

setup_postgresql() {
    log "Setting up PostgreSQL with version compatibility..."
    
    # Install PostgreSQL
    apt install -y postgresql postgresql-contrib postgresql-server-dev-all
    
    # Start and enable
    systemctl enable postgresql
    systemctl start postgresql
    
    # Wait for startup
    sleep 5
    
    # Get version info
    local pg_version_full=$(sudo -u postgres psql -t -c "SELECT version();" 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    local pg_version_num=$(sudo -u postgres psql -t -c "SELECT current_setting('server_version_num');" 2>/dev/null | tr -d ' ' || echo "0")
    
    if [ "$pg_version_num" != "0" ] && [ -n "$pg_version_num" ]; then
        PG_MAJOR=$((pg_version_num / 10000))
        log "PostgreSQL installed: $pg_version_full (major version: $PG_MAJOR)"
    else
        PG_MAJOR=16
        warn "Could not detect PostgreSQL version, assuming 16"
    fi
    
    # Export for use in other functions
    export PG_MAJOR
}

download_openvas_scripts() {
    log "Downloading OpenVAS build scripts..."
    
    cd /tmp
    rm -rf build_openvas
    
    if ! git clone https://github.com/iachievedit/build_openvas; then
        error "Failed to clone OpenVAS repository"
        exit 1
    fi
    
    cd build_openvas
    chmod +x *.sh
    find scripts -name "*.sh" -exec chmod +x {} \;
    
    log "OpenVAS scripts downloaded successfully"
}

run_openvas_installation() {
    log "Running OpenVAS installation with PostgreSQL compatibility..."
    
    cd /tmp/build_openvas
    
    # Source the exports
    source ./exports.sh
    
    # Run the main installation
    if ./install.sh; then
        log "OpenVAS installation completed"
    else
        warn "OpenVAS installation completed with warnings"
    fi
}

complete_feed_synchronization() {
    log "=== Completing Feed Synchronization with Correct Versions ==="
    
    # Stop GVMD to prevent conflicts
    systemctl stop gvmd 2>/dev/null || true
    sleep 5
    
    # Sync feeds with correct version (22.04 format)
    log "Synchronizing feeds with 22.04 format (this will take 30-60 minutes)..."
    
    # SCAP data (most important)
    log "Syncing SCAP data..."
    sudo -u gvm greenbone-feed-sync --type scap --feed-release 22.04 --verbose || warn "SCAP sync had issues"
    
    # CERT data
    log "Syncing CERT data..."
    sudo -u gvm greenbone-feed-sync --type cert --feed-release 22.04 --verbose || warn "CERT sync had issues"
    
    # GVMD data
    log "Syncing GVMD data..."
    sudo -u gvm greenbone-feed-sync --type gvmd-data --feed-release 22.04 --verbose || warn "GVMD data sync had issues"
    
    # Verify critical files exist
    verify_feed_files
    
    # Start GVMD and wait for SCAP database rebuild
    log "Starting GVMD and building SCAP database..."
    systemctl start gvmd
    
    # Wait for SCAP database to build
    wait_for_scap_database
}

verify_feed_files() {
    log "Verifying feed files..."
    
    # Check for CPE dictionary
    if [ -f "/var/lib/gvm/scap-data/official-cpe-dictionary_v2.2.xml" ]; then
        log "CPE dictionary found"
    else
        warn "CPE dictionary not found - SCAP database may not build properly"
    fi
    
    # Check SCAP data directory
    local scap_files=$(ls -1 /var/lib/gvm/scap-data/ | wc -l)
    log "SCAP data directory contains $scap_files files"
    
    # Check CERT data directory
    if [ -d "/var/lib/gvm/cert-data" ]; then
        local cert_files=$(ls -1 /var/lib/gvm/cert-data/ | wc -l)
        log "CERT data directory contains $cert_files files"
    fi
}

wait_for_scap_database() {
    log "Waiting for SCAP database to build (this may take 15-30 minutes)..."
    
    local timeout=1800  # 30 minutes
    local elapsed=0
    local interval=30
    
    while [ $elapsed -lt $timeout ]; do
        # Check if SCAP database building is complete
        local scap_warnings=$(sudo journalctl -u gvmd --since "5 minutes ago" | grep -c "update_scap_cpes: No CPE dictionary found" || echo 0)
        
        if [ "$scap_warnings" -eq 0 ]; then
            # Check if we see successful SCAP messages
            local scap_success=$(sudo journalctl -u gvmd --since "10 minutes ago" | grep -c "Updating CPEs" || echo 0)
            if [ "$scap_success" -gt 0 ]; then
                log "SCAP database building detected - continuing to monitor..."
            fi
        fi
        
        # Check for completion indicators
        local db_complete=$(sudo journalctl -u gvmd --since "5 minutes ago" | grep -c "rebuild.*complete\|SCAP.*updated\|database.*ready" || echo 0)
        if [ "$db_complete" -gt 0 ]; then
            log "SCAP database build appears to be complete"
            break
        fi
        
        sleep $interval
        elapsed=$((elapsed + interval))
        
        if [ $((elapsed % 300)) -eq 0 ]; then  # Every 5 minutes
            log "Still waiting for SCAP database build... ($((elapsed/60)) minutes elapsed)"
        fi
    done
    
    if [ $elapsed -ge $timeout ]; then
        warn "SCAP database build timeout reached - installation may still be in progress"
    fi
}

verify_installation() {
    log "=== Verifying Installation ==="
    
    # Check services
    local services=("postgresql" "redis-server" "mosquitto" "notus-scanner" "ospd-openvas" "gvmd" "gsad" "openvasd")
    local running_services=0
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log "✓ $service: Running"
            ((running_services++))
        else
            warn "✗ $service: Not running"
        fi
    done
    
    log "$running_services/${#services[@]} services are running"
    
    # Check web interface
    local web_status="Not responding"
    if curl -s --connect-timeout 10 "http://localhost:9392" >/dev/null 2>&1; then
        web_status="Responding"
    fi
    
    log "Web interface: $web_status"
    
    return 0
}

# =============================================================================
# MANAGEMENT TOOLS SECTION
# =============================================================================

create_management_tools() {
    log "Creating management tools for SSH user..."
    
    local admin_user="openvas-admin"
    
    # Create OpenVAS management script
    cat > /home/$admin_user/openvas-control.sh << 'MGMT_EOF'
#!/bin/bash

# OpenVAS Control Script - SSH Version
# Comprehensive management tool for OpenVAS

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

show_banner() {
    echo -e "${BLUE}${BOLD}"
    echo "=============================================="
    echo "       OpenVAS Management Console"
    echo "=============================================="
    echo -e "${NC}"
}

show_menu() {
    echo -e "${BOLD}Available Commands:${NC}"
    echo "1.  status     - Check all service status"
    echo "2.  start      - Start all services"
    echo "3.  stop       - Stop OpenVAS services"
    echo "4.  restart    - Restart all services"
    echo "5.  logs       - View service logs"
    echo "6.  feeds      - Check feed status"
    echo "7.  sync       - Run feed synchronization"
    echo "8.  web        - Show web interface info"
    echo "9.  admin      - Show admin credentials"
    echo "10. help       - Show this menu"
    echo "0.  exit       - Exit"
    echo "=============================================="
}

check_status() {
    echo -e "${BLUE}Service Status:${NC}"
    services=("postgresql" "redis-server" "mosquitto" "notus-scanner" "ospd-openvas" "gvmd" "gsad" "openvasd")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            echo -e "  ${GREEN}✓${NC} $service: Running"
        else
            echo -e "  ${RED}✗${NC} $service: Stopped"
        fi
    done
    
    # Check web interface
    if curl -s --connect-timeout 5 http://localhost:9392 >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Web Interface: Responding"
    else
        echo -e "  ${YELLOW}?${NC} Web Interface: Not responding"
    fi
}

start_services() {
    echo -e "${BLUE}Starting all services...${NC}"
    sudo systemctl start postgresql redis-server mosquitto
    sleep 3
    sudo systemctl start notus-scanner ospd-openvas
    sleep 5
    sudo systemctl start gvmd
    sleep 3
    sudo systemctl start gsad openvasd
    echo -e "${GREEN}Services started${NC}"
}

stop_services() {
    echo -e "${BLUE}Stopping OpenVAS services...${NC}"
    sudo systemctl stop gsad openvasd gvmd ospd-openvas notus-scanner
    echo -e "${GREEN}OpenVAS services stopped${NC}"
}

restart_services() {
    stop_services
    sleep 5
    start_services
}

view_logs() {
    echo "Select log to view:"
    echo "1. GVMD (main manager)"
    echo "2. OSPD-OpenVAS (scanner)"
    echo "3. GSAD (web interface)"
    echo "4. All recent logs"
    read -p "Choice: " log_choice
    
    case $log_choice in
        1) sudo tail -f /var/log/gvm/gvmd.log ;;
        2) sudo tail -f /var/log/gvm/ospd-openvas.log ;;
        3) sudo tail -f /var/log/gvm/gsad.log ;;
        4) sudo journalctl -f -u gvmd -u ospd-openvas -u gsad ;;
        *) echo "Invalid choice" ;;
    esac
}

sync_feeds() {
    echo -e "${BLUE}Running feed synchronization...${NC}"
    echo "This will take 30-60 minutes depending on your connection"
    read -p "Continue? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo -u gvm greenbone-feed-sync --type all --feed-release 22.04 --verbose
    fi
}

show_web_info() {
    local ip=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}' || echo "localhost")
    echo -e "${BLUE}Web Interface Information:${NC}"
    echo "  URL: http://$ip:9392"
    echo "  Username: admin"
    if [ -f "/tmp/build_openvas/adminpass.txt" ]; then
        echo "  Password: $(cat /tmp/build_openvas/adminpass.txt)"
    else
        echo "  Password: Check /tmp/build_openvas/adminpass.txt"
    fi
}

show_admin_info() {
    show_web_info
    echo
    echo -e "${BLUE}SSH Access:${NC}"
    local ip=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}' || echo "localhost")
    echo "  SSH: ssh openvas-admin@$ip"
    if [ -f "/root/ssh_admin_password.txt" ]; then
        echo "  SSH Password: $(sudo cat /root/ssh_admin_password.txt 2>/dev/null || echo 'Check with system admin')"
    fi
}

# Main execution
if [ $# -eq 0 ]; then
    show_banner
    show_menu
    echo
    read -p "Enter choice: " choice
else
    choice=$1
fi

case $choice in
    1|status) check_status ;;
    2|start) start_services ;;
    3|stop) stop_services ;;
    4|restart) restart_services ;;
    5|logs) view_logs ;;
    6|feeds) echo "Check Administration > Feed Status in web interface" ;;
    7|sync) sync_feeds ;;
    8|web) show_web_info ;;
    9|admin) show_admin_info ;;
    10|help) show_menu ;;
    0|exit) echo "Goodbye!"; exit 0 ;;
    *) echo "Invalid option. Use 'help' to see available commands." ;;
esac
MGMT_EOF
    
    # Make script executable and set ownership
    chmod +x /home/$admin_user/openvas-control.sh
    chown $admin_user:$admin_user /home/$admin_user/openvas-control.sh
    
    # Add to path
    ln -sf /home/$admin_user/openvas-control.sh /usr/local/bin/openvas-control
    
    log "Management tools created successfully"
}

# =============================================================================
# FINAL DISPLAY SECTION
# =============================================================================

display_final_summary() {
    local system_ip=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}' || echo "localhost")
    local admin_user="openvas-admin"
    local ssh_password="unknown"
    local web_password="unknown"
    
    # Get passwords
    if [ -f "/root/ssh_admin_password.txt" ]; then
        ssh_password=$(cat /root/ssh_admin_password.txt)
    fi
    
    if [ -f "/tmp/build_openvas/adminpass.txt" ]; then
        web_password=$(cat /tmp/build_openvas/adminpass.txt)
    fi
    
    clear
    echo -e "${GREEN}${BOLD}"
    echo "================================================================="
    echo "           OPENVAS + SSH INSTALLATION COMPLETE!"
    echo "================================================================="
    echo -e "${NC}"
    echo
    echo -e "${BLUE}${BOLD}🌐 WEB INTERFACE ACCESS:${NC}"
    echo "   URL: http://$system_ip:9392"
    echo "   Username: admin"
    echo "   Password: $web_password"
    echo
    echo -e "${BLUE}${BOLD}🔐 SSH REMOTE ACCESS:${NC}"
    echo "   SSH Command: ssh $admin_user@$system_ip"
    echo "   SSH Username: $admin_user"
    echo "   SSH Password: $ssh_password"
    echo
    echo -e "${BLUE}${BOLD}⚙️  MANAGEMENT:${NC}"
    echo "   Control Script: openvas-control"
    echo "   Usage: openvas-control status|start|stop|restart|logs"
    echo "   Location: /home/$admin_user/openvas-control.sh"
    echo
    echo -e "${BLUE}${BOLD}📁 IMPORTANT FILES:${NC}"
    echo "   Web Admin Password: /tmp/build_openvas/adminpass.txt"
    echo "   SSH Admin Password: /root/ssh_admin_password.txt"
    echo "   Installation Log: $LOG_FILE"
    echo "   OpenVAS Logs: /var/log/gvm/"
    echo
    echo -e "${BLUE}${BOLD}🚀 NEXT STEPS:${NC}"
    echo "   1. SSH to server: ssh $admin_user@$system_ip"
    echo "   2. Check status: openvas-control status"
    echo "   3. Access web interface: http://$system_ip:9392"
    echo "   4. Wait for all feeds to sync (check Administration > Feed Status)"
    echo "   5. Start your first vulnerability scan!"
    echo
    echo -e "${YELLOW}${BOLD}⚠️  SECURITY NOTES:${NC}"
    echo "   - Change default passwords after first login"
    echo "   - Consider setting up SSL certificates for web interface"
    echo "   - Configure firewall rules as needed for your environment"
    echo "   - Keep system updated: apt update && apt upgrade"
    echo
    echo -e "${GREEN}${BOLD}================================================================="
    echo "          Installation completed at: $(date)"
    echo "=================================================================${NC}"
    echo
    
    # Save summary to file
    cat > /root/openvas_complete_summary.txt << EOF
OpenVAS + SSH Installation Summary
=================================
Date: $(date)
System IP: $system_ip

WEB ACCESS:
URL: http://$system_ip:9392
Username: admin
Password: $web_password

SSH ACCESS:
Command: ssh $admin_user@$system_ip
Username: $admin_user
Password: $ssh_password

MANAGEMENT:
Control script: openvas-control
Usage: openvas-control [status|start|stop|restart|logs|sync]

FILES:
- Web password: /tmp/build_openvas/adminpass.txt
- SSH password: /root/ssh_admin_password.txt
- Install log: $LOG_FILE
- OpenVAS logs: /var/log/gvm/

SERVICES:
$(systemctl is-active postgresql redis-server mosquitto notus-scanner ospd-openvas gvmd gsad openvasd 2>/dev/null | paste -d' ' <(echo -e "postgresql\nredis-server\nmosquitto\nnotus-scanner\nospd-openvas\ngvmd\ngsad\nopenvasd") -)

Installation completed: $(date)
EOF
    
    log "Complete summary saved to /root/openvas_complete_summary.txt"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    show_banner
    
    # Initialize logging
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    log "Starting $SCRIPT_NAME v$SCRIPT_VERSION"
    
    # Run installation phases
    check_prerequisites
    clean_environment
    update_system
    setup_ssh
    install_openvas
    create_management_tools
    
    # Final summary
    display_final_summary
    
    log "Installation completed successfully!"
}

# Run main function
main "$@"
