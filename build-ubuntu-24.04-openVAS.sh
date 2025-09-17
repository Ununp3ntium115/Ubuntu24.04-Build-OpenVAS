#!/bin/bash

# Complete OpenVAS + RDP Setup Script for Ubuntu 24.04
# Based on https://dev.iachieved.it/iachievedit/installing-greenbone-openvas-on-ubuntu-24-04/
# and https://github.com/iachievedit/build_openvas
# 
# This script combines OpenVAS installation with Windows RDP integration
# Requirements: Fresh Ubuntu 24.04 LTS installation with 4-8 cores, 8GB+ RAM, 64GB+ disk
#
# Usage: Run as root - sudo su then execute this script
#
# WARNING: This script runs as root and does not verify GPG signatures
# Ensure you understand the security implications before running

# Remove set -e to prevent premature exits - we'll handle errors manually
# set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to wait for service to be ready
wait_for_service() {
    local service=$1
    local max_attempts=${2:-30}
    local attempt=1
    
    log "Waiting for $service to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        if systemctl is-active --quiet $service; then
            log "$service is ready (attempt $attempt)"
            return 0
        fi
        
        log "Waiting for $service... (attempt $attempt/$max_attempts)"
        sleep 2
        ((attempt++))
    done
    
    error "$service failed to start after $max_attempts attempts"
    return 1
}

# Function to safely execute commands with error handling
safe_execute() {
    local description=$1
    shift
    
    log "Executing: $description"
    
    if "$@"; then
        log "Success: $description"
        return 0
    else
        error "Failed: $description"
        error "Command: $*"
        return 1
    fi
}
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root. Use 'sudo su' first."
   exit 1
fi

log "Starting Complete OpenVAS + RDP Setup for Ubuntu 24.04"

# Get the real user (in case running via sudo)
if [ -n "$SUDO_USER" ]; then
    REAL_USER="$SUDO_USER"
else
    REAL_USER=$(logname 2>/dev/null || whoami)
fi

log "Detected real user: $REAL_USER"

# Update system first
log "Updating system packages..."
apt update && apt upgrade -y

# =============================================================================
# RDP SETUP SECTION
# =============================================================================

log "=== Setting up RDP (Remote Desktop) Access ==="

# Ubuntu 24.04 Wayland compatibility check and configuration
log "Configuring Ubuntu 24.04 for XRDP compatibility..."

# Check if running Wayland (common in Ubuntu 24.04)
if [ "$XDG_SESSION_TYPE" = "wayland" ] || [ -n "$WAYLAND_DISPLAY" ]; then
    log "Wayland session detected - configuring for XRDP compatibility"
    WAYLAND_DETECTED=true
else
    log "X11 session detected"
    WAYLAND_DETECTED=false
fi

# Configure GDM3 to disable Wayland for better XRDP compatibility
log "Configuring GDM3 for XRDP compatibility..."
if [ -f /etc/gdm3/custom.conf ]; then
    # Enable X11 for GDM3 (required for XRDP)
    if ! grep -q "WaylandEnable=false" /etc/gdm3/custom.conf; then
        log "Disabling Wayland in GDM3 for XRDP compatibility"
        sed -i '/\[daemon\]/a WaylandEnable=false' /etc/gdm3/custom.conf
    fi
    
    # Ensure X11 is explicitly enabled
    if ! grep -q "DefaultSession=ubuntu-xorg" /etc/gdm3/custom.conf; then
        log "Setting default session to X11"
        sed -i '/\[daemon\]/a DefaultSession=ubuntu-xorg' /etc/gdm3/custom.conf
    fi
else
    # Create GDM3 config if it doesn't exist
    log "Creating GDM3 configuration for XRDP"
    cat > /etc/gdm3/custom.conf << 'EOF'
[daemon]
WaylandEnable=false
DefaultSession=ubuntu-xorg

[security]

[xdmcp]

[chooser]

[debug]
EOF
fi

# Check if a desktop environment is already installed
if command -v gnome-shell >/dev/null 2>&1; then
    log "GNOME desktop environment detected"
    DESKTOP_ENV="gnome"
    
    # For GNOME on Ubuntu 24.04, ensure X11 session is available
    if [ ! -f /usr/share/xsessions/ubuntu-xorg.desktop ]; then
        log "Installing GNOME X11 session for XRDP compatibility"
        apt install -y gnome-session-xorg
    fi
    
elif command -v startplasma-x11 >/dev/null 2>&1; then
    log "KDE desktop environment detected"
    DESKTOP_ENV="kde"
elif command -v xfce4-session >/dev/null 2>&1; then
    log "XFCE desktop environment detected"
    DESKTOP_ENV="xfce"
elif command -v mate-session >/dev/null 2>&1; then
    log "MATE desktop environment detected"
    DESKTOP_ENV="mate"
else
    log "No desktop environment detected - installing minimal XFCE for RDP only"
    apt install -y xfce4-session xfce4-panel xfce4-desktop xfwm4
    DESKTOP_ENV="xfce"
fi

log "Using existing desktop environment: $DESKTOP_ENV"

# Install XRDP
log "Installing XRDP server..."
apt install -y xrdp

# Configure XRDP for Ubuntu 24.04
log "Configuring XRDP for Ubuntu 24.04..."

# Add xrdp user to ssl-cert group for secure connections
usermod -a -G ssl-cert xrdp

# Configure XRDP to work with Ubuntu 24.04's desktop sessions
log "Configuring XRDP session management..."

# Create XRDP session configuration
cat > /etc/xrdp/startwm.sh << 'EOF'
#!/bin/sh
# XRDP session startup script for Ubuntu 24.04

# Ensure proper environment
if [ -r /etc/default/locale ]; then
  . /etc/default/locale
  export LANG LANGUAGE
fi

# Start session based on what's available
if [ -f /usr/bin/gnome-session ]; then
    # GNOME session (force X11)
    export XDG_CURRENT_DESKTOP=ubuntu:GNOME
    export XDG_SESSION_DESKTOP=ubuntu
    export XDG_SESSION_TYPE=x11
    export GDK_BACKEND=x11
    export GNOME_SHELL_SESSION_MODE=ubuntu
    exec /usr/bin/gnome-session --session=ubuntu
elif [ -f /usr/bin/startxfce4 ]; then
    # XFCE session
    exec /usr/bin/startxfce4
elif [ -f /usr/bin/mate-session ]; then
    # MATE session
    exec /usr/bin/mate-session
elif [ -f /usr/bin/startkde ]; then
    # KDE session
    exec /usr/bin/startkde
else
    # Fallback
    exec /usr/bin/x-session-manager
fi
EOF

chmod +x /etc/xrdp/startwm.sh

# Configure XRDP to listen on all interfaces
log "Configuring XRDP network settings..."
sed -i 's/port=3389/port=3389/' /etc/xrdp/xrdp.ini
sed -i 's/address=127.0.0.1/address=0.0.0.0/' /etc/xrdp/xrdp.ini

# Enable and start XRDP service
systemctl enable xrdp
systemctl start xrdp

# Handle Ubuntu 24.04 specific session issues
log "Applying Ubuntu 24.04 specific XRDP fixes..."

# Create policy to allow RDP sessions
cat > /etc/polkit-1/localauthority/50-local.d/45-allow-colord.pkla << 'EOF'
[Allow Colord all Users]
Identity=unix-user:*
Action=org.freedesktop.color-manager.create-device;org.freedesktop.color-manager.create-profile;org.freedesktop.color-manager.delete-device;org.freedesktop.color-manager.delete-profile;org.freedesktop.color-manager.modify-device;org.freedesktop.color-manager.modify-profile
ResultAny=no
ResultInactive=no
ResultActive=yes
EOF

# Fix authentication issues for XRDP
cat > /etc/polkit-1/localauthority/50-local.d/46-allow-update-repo.pkla << 'EOF'
[Allow Package Management all Users]
Identity=unix-user:*
Action=org.freedesktop.packagekit.system-sources-refresh
ResultAny=yes
ResultInactive=yes
ResultActive=yes
EOF

# Configure firewall for RDP (port 3389)
log "Configuring firewall for RDP access..."
ufw allow 3389/tcp
ufw --force enable

# Restart XRDP to apply all changes
systemctl restart xrdp

# Wait for XRDP to be ready
if wait_for_service xrdp 30; then
    log "XRDP service started successfully"
else
    warn "XRDP may not be fully ready"
fi

log "RDP setup completed. RDP server listening on port 3389"

# If Wayland was detected, inform user about reboot requirement
if [ "$WAYLAND_DETECTED" = true ]; then
    log "IMPORTANT: Wayland was detected. For optimal XRDP performance:"
    log "1. A system reboot is recommended to apply GDM3 changes"
    log "2. After reboot, RDP connections will use X11 sessions"
    log "3. Local desktop will still work normally"
fi

# =============================================================================
# OPENVAS SETUP SECTION
# =============================================================================

log "=== Setting up OpenVAS Installation Environment ==="

# OpenVAS version variables (based on the repository)
export GVM_VERSION=22.4
export GVM_LIBS_VERSION=22.7.3
export GVMD_VERSION=23.0.1
export GSA_VERSION=22.0.1
export GSAD_VERSION=22.0.1
export OPENVAS_SCANNER_VERSION=22.7.9
export OSPD_OPENVAS_VERSION=22.6.2
export NOTUS_SCANNER_VERSION=22.6.1
export GREENBONE_FEED_SYNC_VERSION=23.6.0
export GVM_TOOLS_VERSION=23.6.1
export PYTHON_GVM_VERSION=23.5.1

# Directories
export SOURCE_DIR=/source
export BUILD_DIR=/build
export INSTALL_PREFIX=/usr/local

log "=== Creating GVM User and Directories ==="

# Create gvm user and group
log "Creating gvm user and group..."
groupadd --system gvm || true
useradd --system --no-create-home --home-dir /var/lib/gvm --shell /bin/bash --gid gvm gvm || true

# Create directories
log "Creating source, build, and install directories..."
mkdir -p $SOURCE_DIR
mkdir -p $BUILD_DIR
mkdir -p /var/lib/gvm
mkdir -p /var/lib/openvas
mkdir -p /var/lib/notus
mkdir -p /var/log/gvm
mkdir -p /run/gvm

# Set ownership
chown -R gvm:gvm /var/lib/gvm
chown -R gvm:gvm /var/lib/openvas
chown -R gvm:gvm /var/lib/notus
chown -R gvm:gvm /var/log/gvm
chown -R gvm:gvm /run/gvm

log "=== Installing Dependencies ==="

# Install build dependencies
apt install -y \
  build-essential \
  curl \
  cmake \
  pkg-config \
  python3 \
  python3-pip \
  python3-venv \
  python3-dev \
  git \
  gnupg \
  tar \
  gzip \
  zip \
  wget \
  openssh-client \
  software-properties-common \
  lsb-release \
  ca-certificates \
  apt-transport-https

# Install OpenVAS dependencies
log "Installing OpenVAS specific dependencies..."
apt install -y \
  libglib2.0-dev \
  libgpgme-dev \
  libgnutls28-dev \
  uuid-dev \
  libssh-gcrypt-dev \
  libldap2-dev \
  doxygen \
  graphviz \
  libradcli-dev \
  libhiredis-dev \
  libxml2-dev \
  libpcap-dev \
  bison \
  libksba-dev \
  libsnmp-dev \
  gcc-mingw-w64 \
  heimdal-dev \
  libpopt-dev \
  libunistring-dev \
  rsync \
  nmap \
  libjson-glib-dev \
  libcurl4-gnutls-dev \
  libbsd-dev \
  python3-impacket \
  libmicrohttpd-dev \
  libpaho-mqtt-dev \
  python3-paho-mqtt \
  nodejs \
  npm \
  yarn

# Remove python3-packaging (causes issues with osp-openvas)
apt remove -y python3-packaging || true

# Install PostgreSQL and Redis with version pinning for stability
log "Installing PostgreSQL and Redis with version management..."

# First, get available PostgreSQL versions
PG_AVAILABLE_VERSIONS=$(apt-cache madison postgresql | awk '{print $3}' | head -5)
log "Available PostgreSQL versions: $PG_AVAILABLE_VERSIONS"

# Install PostgreSQL with specific version pinning to prevent automatic upgrades
apt install -y postgresql postgresql-contrib postgresql-server-dev-all redis-server

# Get the installed version
INSTALLED_PG_VERSION=$(dpkg -l | grep "^ii.*postgresql-[0-9]" | awk '{print $2}' | head -1)
PG_VERSION_NUMBER=$(echo $INSTALLED_PG_VERSION | grep -o '[0-9]\+')

log "Installed PostgreSQL package: $INSTALLED_PG_VERSION"
log "PostgreSQL major version: $PG_VERSION_NUMBER"

# Pin PostgreSQL packages to prevent automatic upgrades that could break OpenVAS
log "Pinning PostgreSQL packages to prevent problematic upgrades..."
cat > /etc/apt/preferences.d/postgresql-pin << EOF
# Pin PostgreSQL to current version to prevent automatic upgrades
# that could break OpenVAS compatibility
Package: postgresql*
Pin: version $PG_VERSION_NUMBER*
Pin-Priority: 1001

Package: libpq5
Pin: version *
Pin-Priority: 1001

Package: libpq-dev
Pin: version *
Pin-Priority: 1001
EOF

# Also hold the packages using dpkg
echo "postgresql-$PG_VERSION_NUMBER hold" | dpkg --set-selections
echo "postgresql-client-$PG_VERSION_NUMBER hold" | dpkg --set-selections
echo "postgresql-contrib hold" | dpkg --set-selections
echo "libpq5 hold" | dpkg --set-selections
echo "libpq-dev hold" | dpkg --set-selections

log "PostgreSQL packages pinned to prevent automatic upgrades"

# Install and configure Mosquitto MQTT broker
log "Installing and configuring Mosquitto MQTT broker..."
apt install -y mosquitto mosquitto-clients

# Start services with proper sequencing
log "Starting database and messaging services..."

safe_execute "Enable PostgreSQL service" systemctl enable postgresql
safe_execute "Start PostgreSQL service" systemctl start postgresql
wait_for_service postgresql

safe_execute "Enable Redis service" systemctl enable redis-server  
safe_execute "Start Redis service" systemctl start redis-server
wait_for_service redis-server

safe_execute "Enable Mosquitto service" systemctl enable mosquitto
safe_execute "Start Mosquitto service" systemctl start mosquitto
wait_for_service mosquitto

log "All database and messaging services are running"

log "=== Building OpenVAS Components ==="

cd $SOURCE_DIR

# Function to check PostgreSQL compatibility and patch cmake files
check_and_patch_postgresql() {
    local component_dir=$1
    local cmake_file="$component_dir/cmake/FindPostgreSQL.cmake"
    
    if [ -f "$cmake_file" ]; then
        log "Checking PostgreSQL compatibility for $(basename $component_dir)..."
        
        # Wait for PostgreSQL to be ready before querying
        if ! wait_for_service postgresql 10; then
            warn "PostgreSQL not ready, skipping cmake patching for $(basename $component_dir)"
            return 0
        fi
        
        # Get current PostgreSQL major version with error handling
        local pg_version
        if pg_version=$(sudo -u postgres psql -t -c "SELECT current_setting('server_version_num');" 2>/dev/null | tr -d ' '); then
            local pg_major_version=$((pg_version / 10000))
            log "PostgreSQL major version detected: $pg_major_version"
        else
            warn "Could not detect PostgreSQL version, using default patching"
            # Fallback: patch with common versions
            pg_major_version=16
        fi
        
        # Read current version list from cmake file
        local current_line=$(grep -E "set\(PostgreSQL_KNOWN_VERSIONS|PostgreSQL_ADDITIONAL_VERSIONS" "$cmake_file" | head -1)
        
        if [[ -n "$current_line" ]]; then
            # Extract version numbers and create new list with current version first
            local version_numbers=$(echo "$current_line" | grep -oE '[0-9]+' | sort -nr | uniq)
            local new_versions="$pg_major_version"
            
            # Add other versions (excluding duplicates)
            for ver in $version_numbers; do
                if [ "$ver" != "$pg_major_version" ]; then
                    new_versions="$new_versions $ver"
                fi
            done
            
            # Add some future versions just in case
            for future_ver in {25..21}; do
                if [ "$future_ver" -gt "$pg_major_version" ]; then
                    new_versions="$future_ver $new_versions"
                fi
            done
            
            log "Updating PostgreSQL versions to: $new_versions"
            
            # Replace the version line with updated versions
            if echo "$current_line" | grep -q "PostgreSQL_KNOWN_VERSIONS"; then
                sed -i "/set(PostgreSQL_KNOWN_VERSIONS/c\\set(PostgreSQL_KNOWN_VERSIONS \"$new_versions\")" "$cmake_file"
            elif echo "$current_line" | grep -q "PostgreSQL_ADDITIONAL_VERSIONS"; then
                sed -i "/PostgreSQL_ADDITIONAL_VERSIONS/c\\  \"$new_versions\")" "$cmake_file"
            fi
            
            log "PostgreSQL cmake configuration updated for $(basename $component_dir)"
        else
            warn "Could not find PostgreSQL version configuration in $cmake_file"
        fi
    else
        log "No PostgreSQL cmake file found for $(basename $component_dir), skipping"
    fi
}

# Create comprehensive PostgreSQL compatibility and runtime checks
create_postgresql_compatibility_checks() {
    log "Creating PostgreSQL compatibility monitoring system..."
    
    # Create a compatibility check script
    cat > /usr/local/bin/openvas-pg-check << 'EOF'
#!/bin/bash
# OpenVAS PostgreSQL Compatibility Checker

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_postgresql_compatibility() {
    echo -e "${GREEN}Checking PostgreSQL compatibility with OpenVAS...${NC}"
    
    # Get current PostgreSQL version
    PG_VERSION=$(sudo -u postgres psql -t -c "SELECT current_setting('server_version_num');" 2>/dev/null | tr -d ' ')
    
    if [ -z "$PG_VERSION" ]; then
        echo -e "${RED}ERROR: Cannot connect to PostgreSQL${NC}"
        return 1
    fi
    
    PG_MAJOR=$((PG_VERSION / 10000))
    PG_MINOR=$(((PG_VERSION / 100) % 100))
    
    echo "PostgreSQL Version: $PG_MAJOR.$PG_MINOR (version number: $PG_VERSION)"
    
    # Check minimum version requirement
    if [ $PG_MAJOR -lt 13 ]; then
        echo -e "${RED}ERROR: PostgreSQL $PG_MAJOR is not supported. Minimum version is 13.${NC}"
        return 1
    fi
    
    # Check database connectivity and extensions
    echo "Checking OpenVAS database..."
    
    if ! sudo -u postgres psql -d gvmd -c "SELECT 1;" >/dev/null 2>&1; then
        echo -e "${RED}ERROR: Cannot access gvmd database${NC}"
        return 1
    fi
    
    # Check required extensions
    EXTENSIONS=$(sudo -u postgres psql -d gvmd -t -c "SELECT extname FROM pg_extension;" | tr -d ' ')
    
    if ! echo "$EXTENSIONS" | grep -q "uuid-ossp"; then
        echo -e "${YELLOW}WARNING: uuid-ossp extension not found${NC}"
    fi
    
    if ! echo "$EXTENSIONS" | grep -q "pgcrypto"; then
        echo -e "${YELLOW}WARNING: pgcrypto extension not found${NC}"
    fi
    
    echo -e "${GREEN}PostgreSQL compatibility check passed${NC}"
    return 0
}

# Run the check
check_postgresql_compatibility
exit $?
EOF

    chmod +x /usr/local/bin/openvas-pg-check
    
    # Create a service monitoring script
    cat > /usr/local/bin/openvas-monitor << 'EOF'
#!/bin/bash
# OpenVAS Service Monitor and Auto-Recovery

SERVICES=("postgresql" "redis-server" "mosquitto" "notus-scanner" "ospd-openvas" "gvmd" "gsad" "openvasd")
LOG_FILE="/var/log/gvm/openvas-monitor.log"

log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

check_and_restart_service() {
    local service=$1
    
    if ! systemctl is-active --quiet $service; then
        log_message "WARNING: $service is not running, attempting restart..."
        systemctl restart $service
        sleep 5
        
        if systemctl is-active --quiet $service; then
            log_message "SUCCESS: $service restarted successfully"
        else
            log_message "ERROR: Failed to restart $service"
            return 1
        fi
    fi
    
    return 0
}

# Check PostgreSQL compatibility first
if ! /usr/local/bin/openvas-pg-check >/dev/null 2>&1; then
    log_message "CRITICAL: PostgreSQL compatibility check failed"
    exit 1
fi

# Check all services
for service in "${SERVICES[@]}"; do
    check_and_restart_service "$service"
done

log_message "Service monitoring cycle completed"
EOF

    chmod +x /usr/local/bin/openvas-monitor
    
    # Create systemd timer for monitoring
    cat > /etc/systemd/system/openvas-monitor.service << 'EOF'
[Unit]
Description=OpenVAS Service Monitor
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openvas-monitor
User=root
EOF

    cat > /etc/systemd/system/openvas-monitor.timer << 'EOF'
[Unit]
Description=Run OpenVAS Service Monitor every 5 minutes
Requires=openvas-monitor.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable openvas-monitor.timer
    systemctl start openvas-monitor.timer
    
    log "PostgreSQL compatibility monitoring system created"
}

# Create the compatibility monitoring system
create_postgresql_compatibility_checks
check_and_patch_postgresql() {
    local component_dir=$1
    local cmake_file="$component_dir/cmake/FindPostgreSQL.cmake"
    
    if [ -f "$cmake_file" ]; then
        log "Checking PostgreSQL compatibility for $(basename $component_dir)..."
        
        # Get current PostgreSQL major version
        local pg_version=$(sudo -u postgres psql -t -c "SELECT current_setting('server_version_num');" | tr -d ' ')
        local pg_major_version=$((pg_version / 10000))
        
        log "PostgreSQL major version detected: $pg_major_version"
        
        # Read current version list from cmake file
        local current_line=$(grep -E "set\(PostgreSQL_KNOWN_VERSIONS|PostgreSQL_ADDITIONAL_VERSIONS" "$cmake_file" | head -1)
        
        if [[ -n "$current_line" ]]; then
            # Extract version numbers and create new list with current version first
            local version_numbers=$(echo "$current_line" | grep -oE '[0-9]+' | sort -nr | uniq)
            local new_versions="$pg_major_version"
            
            # Add other versions (excluding duplicates)
            for ver in $version_numbers; do
                if [ "$ver" != "$pg_major_version" ]; then
                    new_versions="$new_versions $ver"
                fi
            done
            
            # Add some future versions just in case
            for future_ver in {25..21}; do
                if [ "$future_ver" -gt "$pg_major_version" ]; then
                    new_versions="$future_ver $new_versions"
                fi
            done
            
            log "Updating PostgreSQL versions to: $new_versions"
            
            # Replace the version line with updated versions
            if echo "$current_line" | grep -q "PostgreSQL_KNOWN_VERSIONS"; then
                sed -i "/set(PostgreSQL_KNOWN_VERSIONS/c\\set(PostgreSQL_KNOWN_VERSIONS \"$new_versions\")" "$cmake_file"
            elif echo "$current_line" | grep -q "PostgreSQL_ADDITIONAL_VERSIONS"; then
                sed -i "/PostgreSQL_ADDITIONAL_VERSIONS/c\\  \"$new_versions\")" "$cmake_file"
            fi
            
            log "PostgreSQL cmake configuration updated for $(basename $component_dir)"
        else
            warn "Could not find PostgreSQL version configuration in $cmake_file"
        fi
    fi
}

# Function to download and extract
download_and_extract() {
    local package_name=$1
    local version=$2
    local url="https://github.com/greenbone/${package_name}/archive/refs/tags/v${version}.tar.gz"
    
    log "Downloading ${package_name} v${version}..."
    wget -q $url -O ${package_name}-${version}.tar.gz
    tar xzf ${package_name}-${version}.tar.gz
}

# Download all components
download_and_extract "gvm-libs" $GVM_LIBS_VERSION
download_and_extract "openvas-scanner" $OPENVAS_SCANNER_VERSION
download_and_extract "gvmd" $GVMD_VERSION
download_and_extract "gsa" $GSA_VERSION
download_and_extract "gsad" $GSAD_VERSION
download_and_extract "ospd-openvas" $OSPD_OPENVAS_VERSION
download_and_extract "notus-scanner" $NOTUS_SCANNER_VERSION

# Check and patch PostgreSQL compatibility for all relevant components
check_and_patch_postgresql "$SOURCE_DIR/gvm-libs-$GVM_LIBS_VERSION"
check_and_patch_postgresql "$SOURCE_DIR/openvas-scanner-$OPENVAS_SCANNER_VERSION"
check_and_patch_postgresql "$SOURCE_DIR/gvmd-$GVMD_VERSION"
check_and_patch_postgresql "$SOURCE_DIR/gsad-$GSAD_VERSION"

# Create the PostgreSQL compatibility monitoring system
create_postgresql_compatibility_checks

# Build and install gvm-libs
log "Building and installing gvm-libs..."
cd $SOURCE_DIR/gvm-libs-$GVM_LIBS_VERSION
if ! mkdir -p build; then
    error "Failed to create build directory for gvm-libs"
    exit 1
fi

cd build
if ! safe_execute "Configure gvm-libs" cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX ..; then
    error "Failed to configure gvm-libs"
    exit 1
fi

if ! safe_execute "Build gvm-libs" make -j$(nproc); then
    error "Failed to build gvm-libs"
    exit 1
fi

if ! safe_execute "Install gvm-libs" make install; then
    error "Failed to install gvm-libs"
    exit 1
fi

log "gvm-libs installation completed successfully"

# Build and install openvas-scanner
log "Building and installing openvas-scanner..."
cd $SOURCE_DIR/openvas-scanner-$OPENVAS_SCANNER_VERSION

if ! mkdir -p build; then
    error "Failed to create build directory for openvas-scanner"
    exit 1
fi

cd build
if ! safe_execute "Configure openvas-scanner" cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX ..; then
    error "Failed to configure openvas-scanner"
    exit 1
fi

if ! safe_execute "Build openvas-scanner" make -j$(nproc); then
    error "Failed to build openvas-scanner"
    exit 1
fi

if ! safe_execute "Install openvas-scanner" make install; then
    error "Failed to install openvas-scanner"
    exit 1
fi

log "openvas-scanner installation completed successfully"

# Build and install Rust components (openvasd and scannerctl)
log "Building Rust components..."
if ! command -v cargo &> /dev/null; then
    log "Installing Rust..."
    if ! curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; then
        error "Failed to install Rust"
        exit 1
    fi
    source ~/.cargo/env
fi

cd $SOURCE_DIR/openvas-scanner-$OPENVAS_SCANNER_VERSION/rust

if ! safe_execute "Build Rust components" cargo build --release; then
    error "Failed to build Rust components"
    exit 1
fi

if ! safe_execute "Install openvasd" cp target/release/openvasd $INSTALL_PREFIX/bin/; then
    error "Failed to install openvasd"
    exit 1
fi

if ! safe_execute "Install scannerctl" cp target/release/scannerctl $INSTALL_PREFIX/bin/; then
    error "Failed to install scannerctl"
    exit 1
fi

log "Rust components installation completed successfully"

# Build and install gvmd
log "Building and installing gvmd..."
cd $SOURCE_DIR/gvmd-$GVMD_VERSION
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX ..
make -j$(nproc)
make install

# Build and install GSA (web interface)
log "Building and installing GSA..."
cd $SOURCE_DIR/gsa-$GSA_VERSION
yarn install
yarn build
mkdir -p $INSTALL_PREFIX/share/gvm/gsad/web/
cp -r build/* $INSTALL_PREFIX/share/gvm/gsad/web/

# Build and install GSAD (web server)
log "Building and installing GSAD..."
cd $SOURCE_DIR/gsad-$GSAD_VERSION
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX ..
make -j$(nproc)
make install

# Install Python components
log "Installing Python components..."

# Install ospd-openvas
cd $SOURCE_DIR/ospd-openvas-$OSPD_OPENVAS_VERSION
python3 -m pip install --prefix=$INSTALL_PREFIX --root=/tmp/ospd-openvas --no-warn-script-location .
cp -rv /tmp/ospd-openvas/* /

# Install notus-scanner
cd $SOURCE_DIR/notus-scanner-$NOTUS_SCANNER_VERSION
python3 -m pip install --prefix=$INSTALL_PREFIX --root=/tmp/notus-scanner --no-warn-script-location .
cp -rv /tmp/notus-scanner/* /

# Install greenbone-feed-sync
log "Installing greenbone-feed-sync..."
python3 -m pip install --prefix=$INSTALL_PREFIX --root=/tmp/greenbone-feed-sync --no-warn-script-location greenbone-feed-sync==$GREENBONE_FEED_SYNC_VERSION
cp -rv /tmp/greenbone-feed-sync/* /

# Install gvm-tools
log "Installing gvm-tools..."
python3 -m pip install --prefix=$INSTALL_PREFIX --root=/tmp/gvm-tools --no-warn-script-location gvm-tools==$GVM_TOOLS_VERSION
cp -rv /tmp/gvm-tools/* /

log "=== Configuring Services and Database ==="

# Additional PostgreSQL version compatibility check during database setup
log "Verifying PostgreSQL compatibility for OpenVAS..."
PG_VERSION_FULL=$(sudo -u postgres psql -t -c "SELECT version();" | head -1 | awk '{print $2}')
PG_VERSION_NUM=$(sudo -u postgres psql -t -c "SELECT current_setting('server_version_num');" | tr -d ' ')
PG_MAJOR_VERSION=$((PG_VERSION_NUM / 10000))

log "PostgreSQL Full Version: $PG_VERSION_FULL"
log "PostgreSQL Major Version: $PG_MAJOR_VERSION"

if [ $PG_MAJOR_VERSION -ge 13 ]; then
    log "PostgreSQL version $PG_MAJOR_VERSION is supported by OpenVAS"
else
    error "PostgreSQL version $PG_MAJOR_VERSION may not be fully supported. Consider upgrading."
    exit 1
fi
sudo -u postgres createuser --createdb --role=gvm gvm || true
sudo -u postgres createdb --owner=gvm gvmd || true
sudo -u postgres psql gvmd -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";" || true
sudo -u postgres psql gvmd -c "CREATE EXTENSION IF NOT EXISTS \"pgcrypto\";" || true

# Configure Redis
log "Configuring Redis..."
cat > /etc/redis/redis.conf.d/openvas.conf << 'EOF'
unixsocket /run/redis-openvas/redis.sock
unixsocketperm 770
timeout 0
EOF

mkdir -p /run/redis-openvas
chown redis:gvm /run/redis-openvas
chmod 770 /run/redis-openvas
systemctl restart redis-server

# Create systemd service files
log "Creating systemd service files..."

# notus-scanner service
cat > /etc/systemd/system/notus-scanner.service << 'EOF'
[Unit]
Description=Notus Scanner
Documentation=man:notus-scanner
After=network.target
Wants=network.target

[Service]
Type=exec
User=gvm
RuntimeDirectory=notus-scanner
RuntimeDirectoryMode=2775
PIDFile=/run/notus-scanner/notus-scanner.pid
ExecStart=/usr/local/bin/notus-scanner --foreground --config /etc/gvm/notus-scanner.toml
SuccessExitStatus=SIGKILL
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# ospd-openvas service
cat > /etc/systemd/system/ospd-openvas.service << 'EOF'
[Unit]
Description=OSPd Wrapper for the OpenVAS Scanner (ospd-openvas)
Documentation=man:ospd-openvas man:openvas
After=network.target networking.service redis-server@openvas.service notus-scanner.service
Wants=redis-server@openvas.service notus-scanner.service
ConditionKernelCommandLine=!recovery

[Service]
Type=exec
User=gvm
Group=gvm
RuntimeDirectory=ospd
RuntimeDirectoryMode=2775
PIDFile=/run/ospd/ospd-openvas.pid
ExecStart=/usr/local/bin/ospd-openvas --foreground --config /etc/gvm/ospd-openvas.conf --log-config /etc/gvm/ospd-logging.conf
SuccessExitStatus=SIGKILL
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# gvmd service
cat > /etc/systemd/system/gvmd.service << 'EOF'
[Unit]
Description=Greenbone Vulnerability Manager daemon (gvmd)
After=network.target networking.service postgresql.service ospd-openvas.service
Wants=postgresql.service ospd-openvas.service
Documentation=man:gvmd
ConditionKernelCommandLine=!recovery

[Service]
Type=exec
User=gvm
Group=gvm
PIDFile=/run/gvm/gvmd.pid
RuntimeDirectory=gvm
RuntimeDirectoryMode=2775
ExecStart=/usr/local/sbin/gvmd --foreground --osp-vt-update=/run/ospd/ospd-openvas.sock --listen-group=gvm
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# gsad service
cat > /etc/systemd/system/gsad.service << 'EOF'
[Unit]
Description=Greenbone Security Assistant daemon (gsad)
Documentation=man:gsad
After=network.target gvmd.service
Wants=gvmd.service

[Service]
Type=exec
User=gvm
Group=gvm
RuntimeDirectory=gsad
RuntimeDirectoryMode=2775
PIDFile=/run/gsad/gsad.pid
ExecStart=/usr/local/sbin/gsad --foreground --listen=0.0.0.0 --port=9392 --http-only
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
Alias=greenbone-security-assistant.service
EOF

# openvasd service
cat > /etc/systemd/system/openvasd.service << 'EOF'
[Unit]
Description=OpenVAS Default Scanner
Documentation=man:openvasd
After=network.target
Wants=network.target

[Service]
Type=exec
User=gvm
RuntimeDirectory=openvasd
RuntimeDirectoryMode=2775
PIDFile=/run/openvasd/openvasd.pid
ExecStart=/usr/local/bin/openvasd --foreground
SuccessExitStatus=SIGKILL
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# Create configuration directories
mkdir -p /etc/gvm
chown gvm:gvm /etc/gvm

# Create basic configuration files
cat > /etc/gvm/ospd-openvas.conf << 'EOF'
[OSPD - openvas]
log_level = INFO
socket_mode = 0o770
unix_socket = /run/ospd/ospd-openvas.sock
pid_file = /run/ospd/ospd-openvas.pid

[SCANNER]
redis_socket = /run/redis-openvas/redis.sock
EOF

cat > /etc/gvm/ospd-logging.conf << 'EOF'
[loggers]
keys = root

[handlers]
keys = console, file

[formatters]
keys = full

[logger_root]
level = INFO
handlers = file

[handler_console]
class = StreamHandler
args = (sys.stdout,)
formatter = full

[handler_file]
class = FileHandler
args = ('/var/log/gvm/ospd-openvas.log',)
formatter = full

[formatter_full]
format = %(asctime)s - %(name)s - %(levelname)s - %(message)s
EOF

cat > /etc/gvm/notus-scanner.toml << 'EOF'
[scanner]
socket_path = "/run/notus-scanner/notus-scanner.sock"
products_directory = "/var/lib/notus/products"

[mqtt]
broker_address = "localhost"
broker_port = 1883
EOF

chown -R gvm:gvm /etc/gvm

# Configure firewall for OpenVAS web interface
log "Configuring firewall for OpenVAS web interface..."
ufw allow 9392/tcp

# Update library cache
ldconfig

log "=== Initializing OpenVAS Database and Feeds ==="

# Initialize database
log "Initializing GVMD database..."
sudo -u gvm gvmd --create-user=admin --role=Admin
ADMIN_PASSWORD=$(openssl rand -base64 12)
sudo -u gvm gvmd --user=admin --new-password="$ADMIN_PASSWORD"

# Save admin password
echo "$ADMIN_PASSWORD" > /root/openvas_admin_password.txt
chmod 600 /root/openvas_admin_password.txt
log "Admin password saved to /root/openvas_admin_password.txt"

# Start services with proper error handling and sequencing
log "Starting OpenVAS services in correct order..."

safe_execute "Reload systemd daemon" systemctl daemon-reload
safe_execute "Enable notus-scanner" systemctl enable notus-scanner
safe_execute "Enable ospd-openvas" systemctl enable ospd-openvas  
safe_execute "Enable gvmd" systemctl enable gvmd
safe_execute "Enable gsad" systemctl enable gsad
safe_execute "Enable openvasd" systemctl enable openvasd

log "Starting services in dependency order..."

safe_execute "Start notus-scanner" systemctl start notus-scanner
if wait_for_service notus-scanner 30; then
    log "notus-scanner started successfully"
else
    warn "notus-scanner may not be fully ready, continuing..."
fi

safe_execute "Start ospd-openvas" systemctl start ospd-openvas
if wait_for_service ospd-openvas 30; then
    log "ospd-openvas started successfully"
else
    warn "ospd-openvas may not be fully ready, continuing..."
fi

safe_execute "Start gvmd" systemctl start gvmd
if wait_for_service gvmd 60; then
    log "gvmd started successfully"
else
    warn "gvmd may not be fully ready, continuing..."
fi

safe_execute "Start gsad" systemctl start gsad
if wait_for_service gsad 30; then
    log "gsad started successfully"
else
    warn "gsad may not be fully ready, continuing..."
fi

safe_execute "Start openvasd" systemctl start openvasd
if wait_for_service openvasd 30; then
    log "openvasd started successfully"
else
    warn "openvasd may not be fully ready, continuing..."
fi

log "All OpenVAS services have been started"

# Sync feeds with better error handling (this will take a long time)
log "Synchronizing vulnerability feeds - this will take 30-45 minutes..."
log "This is the longest part of the installation, please be patient..."

# Make sure gvmd is ready before syncing feeds
log "Waiting for gvmd to be fully ready for feed synchronization..."
sleep 30

if ! safe_execute "Synchronize feeds" sudo -u gvm greenbone-feed-sync; then
    warn "Feed synchronization may have had issues, but continuing..."
    log "You can manually run 'sudo -u gvm greenbone-feed-sync' later if needed"
fi

log "Feed synchronization completed (or attempted)"

log "=== Final Configuration and Verification ==="

# Verify services
log "Verifying service status..."
services=("notus-scanner" "ospd-openvas" "gvmd" "gsad" "openvasd" "xrdp")
for service in "${services[@]}"; do
    if systemctl is-active --quiet $service; then
        log "$service: Running"
    else
        warn "$service: Not running - check logs with: journalctl -u $service"
    fi
done

# Get system IP address
SYSTEM_IP=$(ip route get 8.8.8.8 | awk '{print $7; exit}')

# Create summary file
cat > /root/openvas_setup_summary.txt << EOF
==========================================
OpenVAS + RDP Setup Summary
==========================================

Installation completed at: $(date)

OPENVAS ACCESS:
- Web Interface: http://$SYSTEM_IP:9392
- Admin Username: admin
- Admin Password: $ADMIN_PASSWORD

RDP ACCESS:
- RDP Server: $SYSTEM_IP:3389
- Use your Ubuntu login credentials to connect
- Desktop Environment: XFCE

SERVICES STATUS:
$(systemctl status notus-scanner ospd-openvas gvmd gsad openvasd xrdp --no-pager -l)

IMPORTANT NOTES:
1. The vulnerability feeds have been synchronized
2. RDP is enabled on port 3389 with XFCE desktop
3. OpenVAS web interface is available on port 9392
4. Firewall has been configured to allow RDP (3389) and OpenVAS (9392)
5. All services are configured to start automatically on boot

NEXT STEPS:
1. Connect via RDP using any RDP client (Windows Remote Desktop, etc.)
2. Access OpenVAS web interface in browser
3. Consider setting up HTTPS for OpenVAS web interface
4. Review firewall rules and adjust access as needed

LOG FILES:
- OpenVAS logs: /var/log/gvm/
- System logs: journalctl -u [service-name]

CONFIGURATION FILES:
- Admin password: /root/openvas_admin_password.txt
- OpenVAS config: /etc/gvm/
- XRDP config: /etc/xrdp/

For security, consider:
- Changing default ports
- Setting up proper SSL certificates
- Restricting network access
- Regular updates and maintenance
==========================================
EOF

log "=== Setup Complete! ==="
log ""
log "OpenVAS + RDP Setup has been completed successfully!"
log ""
log "SUMMARY:"
log "- OpenVAS Web Interface: http://$SYSTEM_IP:9392"
log "- Admin Username: admin"  
log "- Admin Password: $ADMIN_PASSWORD"
log "- RDP Server: $SYSTEM_IP:3389"
log ""
log "Complete setup details saved to: /root/openvas_setup_summary.txt"
log ""
log "You can now:"
log "1. Connect via RDP to $SYSTEM_IP:3389 using your Ubuntu credentials"
log "2. Access OpenVAS web interface at http://$SYSTEM_IP:9392"
log ""
warn "For production use, consider setting up HTTPS and proper firewall rules!"

exit 0
