Key Features:
1. SSH-First Approach

Sets up secure SSH with dedicated admin user
No desktop interference or session conflicts
Passwordless sudo for OpenVAS service management
Management tools accessible via SSH



PostgreSQL compatibility for any version (auto-detects and adapts)
Correct feed versioning (22.04 format to avoid JSON/XML mismatch)
Proper service sequencing to prevent startup issues
SCAP database monitoring to wait for completion

3. Complete Automation

Downloads from official repository
Handles all dependencies and compatibility issues
Monitors feed synchronization progress
Creates management tools for ongoing administration

4. Professional Management

openvas-control command for service management
Comprehensive logging and status checking
Password management and display
Complete installation summary

Usage:
bash# Save as openvas-complete-setup.sh
wget <script-url>
chmod +x openvas-complete-setup.sh

# Run on fresh Ubuntu 24.04 as root
sudo su
./openvas-complete-setup.sh
What You Get:

SSH access: ssh openvas-admin@[IP]
Web interface: http://[IP]:9392
Management command: openvas-control status|start|stop|restart
All passwords displayed at the end and saved to files

Based on Real Experience:
This script incorporates all the lessons learned:

Feed version compatibility issues ✓
PostgreSQL version detection ✓
Service startup dependencies ✓
SCAP database build monitoring ✓
SSH-only approach (no RDP complications) ✓

The script will give you the same working result you achieved manually, but fully automated and reproducible!
