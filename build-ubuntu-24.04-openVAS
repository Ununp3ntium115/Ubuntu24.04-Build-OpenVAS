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

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
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

# Install desktop environment (XFCE - lightweight and reliable for RDP)
log "Installing XFCE desktop environment..."
apt install -y xfce4 xfce4-goodies xubuntu-desktop-minimal

# Install XRDP
log "Installing XRDP server..."
apt install -y xrdp

# Configure XRDP
log "Configuring XRDP..."

# Add xrdp user to ssl-cert group for secure connections
usermod -a -G ssl-cert xrdp

# Configure XFCE session for all users
echo "xfce4-session" > /etc/skel/.xsession

# Configure existing users for XFCE
if [ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ]; then
    log "Configuring XFCE session for user: $REAL_USER"
    sudo -u $REAL_USER bash -c 'echo "xfce4-session" > ~/.xsession'
    chown $REAL_USER:$REAL_USER /home/$REAL_USER/.xsession
fi

# Enable and start XRDP service
systemctl enable xrdp
systemctl start xrdp

# Configure firewall for RDP (port 3389)
log "Configuring firewall for RDP access..."
ufw allow 3389/tcp
ufw --force enable

# Configure XRDP to listen on all interfaces
log "Configuring XRDP to listen on all interfaces..."
sed -i 's/port=3389/port=3389\naddress=0.0.0.0/' /etc/xrdp/xrdp.ini

# Restart XRDP to apply changes
systemctl restart xrdp

log "RDP setup completed. RDP server listening on port 3389"

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

# Start services
systemctl enable postgresql
systemctl start postgresql
systemctl enable redis-server
systemctl start redis-server
systemctl enable mosquitto
systemctl start mosquitto

log "=== Building OpenVAS Components ==="

cd $SOURCE_DIR

# Function to check PostgreSQL compatibility and patch cmake files
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

# Build and install gvm-libs
log "Building and installing gvm-libs..."
cd $SOURCE_DIR/gvm-libs-$GVM_LIBS_VERSION
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX ..
make -j$(nproc)
make install

# Build and install openvas-scanner
log "Building and installing openvas-scanner..."
cd $SOURCE_DIR/openvas-scanner-$OPENVAS_SCANNER_VERSION

mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX ..
make -j$(nproc)
make install

# Build and install Rust components (openvasd and scannerctl)
log "Building Rust components..."
if ! command -v cargo &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
fi

cd $SOURCE_DIR/openvas-scanner-$OPENVAS_SCANNER_VERSION/rust
cargo build --release
cp target/release/openvasd $INSTALL_PREFIX/bin/
cp target/release/scannerctl $INSTALL_PREFIX/bin/

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

# Start services
log "Starting OpenVAS services..."
systemctl daemon-reload
systemctl enable notus-scanner ospd-openvas gvmd gsad openvasd
systemctl start notus-scanner
sleep 5
systemctl start ospd-openvas
sleep 5
systemctl start gvmd
sleep 5
systemctl start gsad
systemctl start openvasd

# Sync feeds (this will take a long time)
log "Synchronizing vulnerability feeds - this will take 30-45 minutes..."
sudo -u gvm greenbone-feed-sync

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
