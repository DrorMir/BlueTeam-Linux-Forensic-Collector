# Linux Forensic Collector

The script is designed to quietly and efficiently collect forensic artifacts from a Linux endpoint as part of a security investigation process.
It performs a series of actions to gather essential system data such as running processes, open network connections, active services and daemons, system logs, user activity, and configuration files from critical directories. 
All the collected data is then packaged into a well-structured archive, ready for secure transfer or offline analysis. 
The primary goal is to support rapid incident response, even in situations where direct access to the machine is limited, while giving security teams a comprehensive view of what’s happening on the system — without disrupting users or relying on third-party tools.
It’s a lightweight, proactive, and precise solution that fits seamlessly into any Linux-based incident response workflow.

## Requirements

- Linux system (Debian, Ubuntu, CentOS, RHEL, or other distributions)
- Bash shell
- Root privileges
- At least 5GB of free disk space (depending on system size)

## Usage

### Basic Usage

1. Download the script to the target system
2. Make the script executable:
   ```bash
   chmod +x LinuxForensicCollector.sh
   ```
3. Run the script with root privileges:
   ```bash
   sudo ./LinuxForensicCollector.sh
   ```

### Advanced Usage

You can specify a custom output path:

```bash
sudo ./LinuxForensicCollector.sh /path/to/output/directory
```

## Collected Artifacts

The script collects the following categories of artifacts:

### System Information
- Hostname and kernel version
- OS release information
- CPU and memory details
- Disk usage and mounted filesystems
- Hardware information
- Loaded kernel modules

### Processes
- Running processes with command lines
- Process tree
- Process environment variables
- Open files
- Process limits and status

### Memory
- Memory usage statistics
- Swap information
- Virtual memory statistics
- RAM dumps (if LiME is available)

### Network
- Network interfaces configuration
- Active connections
- Listening ports
- ARP cache
- DNS configuration
- Firewall rules (iptables, nftables)
- Routing tables

### File System
- Disk usage and inode information
- Mount points and fstab configuration
- MBR backups
- SUID/SGID files
- Hidden files and directories
- Recently modified files
- Partition tables

### Users
- User accounts and groups
- Login records and current sessions
- Bash history for each user
- SSH keys and configurations
- Sudo configuration

### Authentication
- PAM configuration
- LDAP and Kerberos settings
- Authentication logs

### Logs
- System logs (syslog, messages)
- Authentication logs
- Application logs (Apache, Nginx)
- Audit logs
- Journal logs (if systemd is used)

### Kernel
- Kernel version and configuration
- Loaded modules
- Kernel parameters
- dmesg output

### Services
- Systemd units and services
- Init scripts
- Socket and timer information
- Service configuration files

### Cron Jobs
- System crontab
- User crontabs
- Scheduled tasks in cron.d, cron.daily, etc.
- Systemd timers

### Installed Software
- Package listings (dpkg, rpm)
- Repository information
- Package manager history
- Programming language packages (Python, Ruby, Node.js)
- Compiler versions

### Startup Items
- rc.local configuration
- Profile.d scripts
- Systemd enabled services
- SysV init startup items

### Security
- SELinux configuration and status
- AppArmor profiles
- File capabilities
- Malware scan results (if ClamAV is available)
- Rootkit scan results (if rkhunter/chkrootkit is available)

### Web Servers
- Apache configuration and modules
- Nginx configuration
- Virtual hosts
- Service status

### Databases
- MySQL/MariaDB configuration
- PostgreSQL configuration
- SQLite database files

### Docker
- Docker version and information
- Container listings
- Image listings
- Volume information

### Temporary Files
- Files in /tmp
- Files in /var/tmp
- Files in /dev/shm

### Browser Data
- Firefox history, cookies, and form data
- Chrome/Chromium history, cookies, and login data

## Output Structure

The script creates a structured output directory with the following organization:

```
YYYY-MM-DD/
├── System_Information/
├── Processes/
├── Memory/
│   ├── Process_Memory/
│   └── RAM_Dump/
├── Network/
│   ├── Connections/
│   ├── Interfaces/
│   ├── Routing/
│   ├── DNS/
│   ├── Firewall/
│   └── ARP/
├── File_System/
│   ├── MBR/
│   ├── Partition_Tables/
│   ├── Mount_Points/
│   ├── Open_Files/
│   ├── SUID_SGID/
│   ├── Hidden_Files/
│   └── Recently_Modified/
├── Users/
│   ├── Home_Directories/
│   ├── Bash_History/
│   ├── SSH_Keys/
│   └── Sudo_Config/
├── Authentication/
├── Logs/
│   ├── System/
│   ├── Authentication/
│   ├── Application/
│   ├── Audit/
│   └── Journal/
├── Kernel/
├── Services/
├── Cron_Jobs/
├── Installed_Software/
├── Startup_Items/
├── Security/
│   ├── SELinux/
│   ├── AppArmor/
│   ├── Capabilities/
│   └── Malware_Scan/
├── Web_Servers/
│   ├── Apache/
│   └── Nginx/
├── Databases/
│   ├── MySQL/
│   ├── PostgreSQL/
│   └── SQLite/
├── Docker/
│   ├── Images/
│   ├── Containers/
│   └── Volumes/
├── Temporary_Files/
└── Browser_Data/
    ├── Firefox/
    └── Chrome/
```
