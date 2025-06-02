#!/bin/bash

# Linux Enhanced Forensic Collector
# Version: 1.0
# A comprehensive bash script for collecting forensic artifacts from Linux systems

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root"
  exit 1
fi

# Set default output path
OUTPUT_PATH="/forensic_evidence"
if [ ! -z "$1" ]; then
  OUTPUT_PATH="$1"
fi

# Create timestamp for the collection
DATE_STRING=$(date +"%Y-%m-%d")
TIME_STRING=$(date +"%H-%M-%S")
COLLECTION_ID=$(cat /proc/sys/kernel/random/uuid)

# Create the base output directory
BASE_DIR="${OUTPUT_PATH}/${DATE_STRING}"
mkdir -p "$BASE_DIR"

# Create the directory structure
declare -a DIRECTORIES=(
  "System_Information"
  "Processes"
  "Memory"
  "Network"
  "File_System"
  "Users"
  "Authentication"
  "Logs"
  "Kernel"
  "Services"
  "Cron_Jobs"
  "Installed_Software"
  "Startup_Items"
  "Security"
  "Web_Servers"
  "Databases"
  "Docker"
  "Temporary_Files"
  "Browser_Data"
)

# Create main directories
for DIR in "${DIRECTORIES[@]}"; do
  mkdir -p "${BASE_DIR}/${DIR}"
  echo "Created directory: ${BASE_DIR}/${DIR}"
done

# Create subdirectories
mkdir -p "${BASE_DIR}/File_System/MBR"
mkdir -p "${BASE_DIR}/File_System/Partition_Tables"
mkdir -p "${BASE_DIR}/File_System/Mount_Points"
mkdir -p "${BASE_DIR}/File_System/Open_Files"
mkdir -p "${BASE_DIR}/File_System/SUID_SGID"
mkdir -p "${BASE_DIR}/File_System/Hidden_Files"
mkdir -p "${BASE_DIR}/File_System/Recently_Modified"

mkdir -p "${BASE_DIR}/Memory/Process_Memory"
mkdir -p "${BASE_DIR}/Memory/RAM_Dump"

mkdir -p "${BASE_DIR}/Network/Connections"
mkdir -p "${BASE_DIR}/Network/Interfaces"
mkdir -p "${BASE_DIR}/Network/Routing"
mkdir -p "${BASE_DIR}/Network/DNS"
mkdir -p "${BASE_DIR}/Network/Firewall"
mkdir -p "${BASE_DIR}/Network/ARP"

mkdir -p "${BASE_DIR}/Users/Home_Directories"
mkdir -p "${BASE_DIR}/Users/Bash_History"
mkdir -p "${BASE_DIR}/Users/SSH_Keys"
mkdir -p "${BASE_DIR}/Users/Sudo_Config"

mkdir -p "${BASE_DIR}/Logs/System"
mkdir -p "${BASE_DIR}/Logs/Authentication"
mkdir -p "${BASE_DIR}/Logs/Application"
mkdir -p "${BASE_DIR}/Logs/Audit"
mkdir -p "${BASE_DIR}/Logs/Journal"

mkdir -p "${BASE_DIR}/Security/SELinux"
mkdir -p "${BASE_DIR}/Security/AppArmor"
mkdir -p "${BASE_DIR}/Security/Capabilities"
mkdir -p "${BASE_DIR}/Security/Malware_Scan"

mkdir -p "${BASE_DIR}/Web_Servers/Apache"
mkdir -p "${BASE_DIR}/Web_Servers/Nginx"

mkdir -p "${BASE_DIR}/Databases/MySQL"
mkdir -p "${BASE_DIR}/Databases/PostgreSQL"
mkdir -p "${BASE_DIR}/Databases/SQLite"

mkdir -p "${BASE_DIR}/Docker/Images"
mkdir -p "${BASE_DIR}/Docker/Containers"
mkdir -p "${BASE_DIR}/Docker/Volumes"

mkdir -p "${BASE_DIR}/Browser_Data/Firefox"
mkdir -p "${BASE_DIR}/Browser_Data/Chrome"

# Create summary file
SUMMARY_FILE="${BASE_DIR}/ForensicCollectionSummary.csv"
echo "Timestamp,Command,Status,Error" > "$SUMMARY_FILE"

# Create notification file
NOTIFICATION_FILE="${BASE_DIR}/CollectionNotification.txt"
cat << EOF > "$NOTIFICATION_FILE"
Linux Enhanced Forensic Collection
===================================
Collection Date: $DATE_STRING
Collection Time: $TIME_STRING
Collection ID: $COLLECTION_ID
Script Version: 1.0

This package contains comprehensive forensic artifacts collected from this system.
The collection includes system information, memory data, file system artifacts,
user activity, network information, and many other forensic artifacts.

Collection started at: $(date)
EOF

# Function to execute a command and log the result
execute_command() {
  local COMMAND_NAME="$1"
  local COMMAND="$2"
  local OUTPUT_FILE="$3"
  
  # Create directory for output file if it doesn't exist
  mkdir -p "$(dirname "$OUTPUT_FILE")"
  
  # Log the start of the command
  echo "Executing: $COMMAND_NAME"
  
  # Execute the command
  TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
  ERROR_CODE=0
  
  # Run the command and capture output
  eval "$COMMAND" > "$OUTPUT_FILE" 2> "${OUTPUT_FILE}.error" || ERROR_CODE=$?
  
  # Determine status
  if [ $ERROR_CODE -eq 0 ]; then
    STATUS="Completed"
    # Remove error file if empty
    if [ ! -s "${OUTPUT_FILE}.error" ]; then
      rm "${OUTPUT_FILE}.error"
    fi
  else
    STATUS="Failed"
  fi
  
  # Log to summary CSV
  echo "$TIMESTAMP,\"$COMMAND\",$STATUS,$ERROR_CODE" >> "$SUMMARY_FILE"
  
  # Return status
  echo "$STATUS"
}

# Function to collect system information
collect_system_info() {
  echo "Collecting system information..."
  
  # Basic system info
  execute_command "Hostname" "hostname" "${BASE_DIR}/System_Information/hostname.txt"
  execute_command "Kernel_Version" "uname -a" "${BASE_DIR}/System_Information/kernel_version.txt"
  execute_command "OS_Release" "cat /etc/os-release" "${BASE_DIR}/System_Information/os_release.txt"
  execute_command "CPU_Info" "cat /proc/cpuinfo" "${BASE_DIR}/System_Information/cpu_info.txt"
  execute_command "Memory_Info" "cat /proc/meminfo" "${BASE_DIR}/System_Information/memory_info.txt"
  execute_command "Disk_Usage" "df -h" "${BASE_DIR}/System_Information/disk_usage.txt"
  execute_command "Mounted_Filesystems" "mount" "${BASE_DIR}/System_Information/mounted_filesystems.txt"
  execute_command "Block_Devices" "lsblk -a" "${BASE_DIR}/System_Information/block_devices.txt"
  execute_command "PCI_Devices" "lspci" "${BASE_DIR}/System_Information/pci_devices.txt"
  execute_command "USB_Devices" "lsusb" "${BASE_DIR}/System_Information/usb_devices.txt"
  execute_command "Environment_Variables" "env" "${BASE_DIR}/System_Information/environment_variables.txt"
  execute_command "System_Uptime" "uptime" "${BASE_DIR}/System_Information/uptime.txt"
  execute_command "System_Date" "date" "${BASE_DIR}/System_Information/date.txt"
  execute_command "Timezone" "timedatectl" "${BASE_DIR}/System_Information/timezone.txt"
  execute_command "Hardware_Info" "lshw" "${BASE_DIR}/System_Information/hardware_info.txt"
  execute_command "DMI_Info" "dmidecode" "${BASE_DIR}/System_Information/dmi_info.txt"
  execute_command "Loaded_Kernel_Modules" "lsmod" "${BASE_DIR}/System_Information/loaded_kernel_modules.txt"
}

# Function to collect process information
collect_process_info() {
  echo "Collecting process information..."
  
  # Process listings
  execute_command "Process_List" "ps aux" "${BASE_DIR}/Processes/process_list.txt"
  execute_command "Process_Tree" "ps auxf" "${BASE_DIR}/Processes/process_tree.txt"
  execute_command "Process_Environment" "for pid in \$(ls /proc/ | grep -E '^[0-9]+$'); do echo \"PID: \$pid\"; cat /proc/\$pid/environ 2>/dev/null | tr '\\0' '\\n'; echo; done" "${BASE_DIR}/Processes/process_environment.txt"
  execute_command "Open_Files" "lsof" "${BASE_DIR}/Processes/open_files.txt"
  execute_command "Process_Limits" "for pid in \$(ls /proc/ | grep -E '^[0-9]+$'); do echo \"PID: \$pid\"; cat /proc/\$pid/limits 2>/dev/null; echo; done" "${BASE_DIR}/Processes/process_limits.txt"
  execute_command "Process_Maps" "for pid in \$(ls /proc/ | grep -E '^[0-9]+$' | head -20); do echo \"PID: \$pid\"; cat /proc/\$pid/maps 2>/dev/null; echo; done" "${BASE_DIR}/Processes/process_maps_sample.txt"
  execute_command "Process_Status" "for pid in \$(ls /proc/ | grep -E '^[0-9]+$'); do echo \"PID: \$pid\"; cat /proc/\$pid/status 2>/dev/null; echo; done" "${BASE_DIR}/Processes/process_status.txt"
  execute_command "Process_Stack" "for pid in \$(ls /proc/ | grep -E '^[0-9]+$' | head -20); do echo \"PID: \$pid\"; cat /proc/\$pid/stack 2>/dev/null; echo; done" "${BASE_DIR}/Processes/process_stack_sample.txt"
  execute_command "Process_FD" "for pid in \$(ls /proc/ | grep -E '^[0-9]+$' | head -20); do echo \"PID: \$pid\"; ls -la /proc/\$pid/fd/ 2>/dev/null; echo; done" "${BASE_DIR}/Processes/process_fd_sample.txt"
}

# Function to collect memory information
collect_memory_info() {
  echo "Collecting memory information..."
  
  # Memory information
  execute_command "Memory_Info" "free -m" "${BASE_DIR}/Memory/memory_info.txt"
  execute_command "Swap_Info" "swapon -s" "${BASE_DIR}/Memory/swap_info.txt"
  execute_command "Virtual_Memory_Stats" "vmstat 1 5" "${BASE_DIR}/Memory/vmstat.txt"
  execute_command "Slabinfo" "cat /proc/slabinfo" "${BASE_DIR}/Memory/slabinfo.txt"
  execute_command "Dirty_Memory" "cat /proc/vmstat | grep dirty" "${BASE_DIR}/Memory/dirty_memory.txt"
  
  # Check if LiME (Linux Memory Extractor) is available
  if command -v insmod &> /dev/null && [ -f "/usr/src/lime-forensics/lime.ko" ]; then
    echo "LiME memory acquisition module found, attempting memory dump..."
    execute_command "Memory_Dump_LiME" "insmod /usr/src/lime-forensics/lime.ko \"path=${BASE_DIR}/Memory/RAM_Dump/memory.lime format=lime\"" "${BASE_DIR}/Memory/RAM_Dump/lime_execution.log"
  else
    echo "LiME not found. Memory dump not performed."
    echo "LiME not found. To perform memory acquisition, install the Linux Memory Extractor module." > "${BASE_DIR}/Memory/RAM_Dump/lime_not_available.txt"
  fi
  
  # Check if memory analysis tools are available
  if command -v volatility &> /dev/null; then
    echo "Volatility found, but not used for acquisition. It can be used later for analysis."
    echo "Volatility found. Use this tool for analyzing memory dumps." > "${BASE_DIR}/Memory/RAM_Dump/volatility_info.txt"
  fi
}

# Function to collect network information
collect_network_info() {
  echo "Collecting network information..."
  
  # Network configuration
  execute_command "Network_Interfaces" "ip addr" "${BASE_DIR}/Network/Interfaces/ip_addr.txt"
  execute_command "Network_Interfaces_Config" "ifconfig -a" "${BASE_DIR}/Network/Interfaces/ifconfig.txt"
  execute_command "Network_Statistics" "netstat -s" "${BASE_DIR}/Network/network_statistics.txt"
  execute_command "Socket_Statistics" "ss -tuapn" "${BASE_DIR}/Network/socket_statistics.txt"
  execute_command "IP_Tables" "iptables-save" "${BASE_DIR}/Network/Firewall/iptables.txt"
  execute_command "IP6_Tables" "ip6tables-save" "${BASE_DIR}/Network/Firewall/ip6tables.txt"
  execute_command "NFT_Tables" "nft list ruleset" "${BASE_DIR}/Network/Firewall/nft_ruleset.txt"
  execute_command "Routing_Table" "route -n" "${BASE_DIR}/Network/Routing/route.txt"
  execute_command "IP_Route" "ip route" "${BASE_DIR}/Network/Routing/ip_route.txt"
  execute_command "ARP_Cache" "arp -a" "${BASE_DIR}/Network/ARP/arp_cache.txt"
  execute_command "IP_Neighbor" "ip neigh" "${BASE_DIR}/Network/ARP/ip_neighbor.txt"
  execute_command "Network_Connections" "netstat -anp" "${BASE_DIR}/Network/Connections/netstat.txt"
  execute_command "Network_Connections_SS" "ss -anp" "${BASE_DIR}/Network/Connections/ss.txt"
  execute_command "LSOF_Network" "lsof -i" "${BASE_DIR}/Network/Connections/lsof_network.txt"
  execute_command "DNS_Resolv_Conf" "cat /etc/resolv.conf" "${BASE_DIR}/Network/DNS/resolv_conf.txt"
  execute_command "DNS_Hosts" "cat /etc/hosts" "${BASE_DIR}/Network/DNS/hosts.txt"
  execute_command "Network_Interfaces_Config_Files" "find /etc/network/ /etc/sysconfig/network-scripts/ -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Network/Interfaces/config_files.txt"
  execute_command "Network_Manager_Connections" "find /etc/NetworkManager/system-connections/ -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Network/Interfaces/networkmanager_connections.txt"
  execute_command "Wireless_Info" "iwconfig 2>/dev/null" "${BASE_DIR}/Network/Interfaces/wireless_info.txt"
}

# Function to collect file system information
collect_filesystem_info() {
  echo "Collecting file system information..."
  
  # File system information
  execute_command "Disk_Usage" "df -h" "${BASE_DIR}/File_System/disk_usage.txt"
  execute_command "Disk_Inodes" "df -i" "${BASE_DIR}/File_System/disk_inodes.txt"
  execute_command "Mount_Points" "mount" "${BASE_DIR}/File_System/Mount_Points/mount_points.txt"
  execute_command "Fstab" "cat /etc/fstab" "${BASE_DIR}/File_System/Mount_Points/fstab.txt"
  execute_command "Open_Files" "lsof" "${BASE_DIR}/File_System/Open_Files/lsof_all.txt"
  execute_command "Open_Files_By_User" "for user in \$(cut -d: -f1 /etc/passwd); do echo \"User: \$user\"; lsof -u \$user 2>/dev/null; echo; done" "${BASE_DIR}/File_System/Open_Files/lsof_by_user.txt"
  execute_command "SUID_Files" "find / -type f -perm -4000 -ls 2>/dev/null" "${BASE_DIR}/File_System/SUID_SGID/suid_files.txt"
  execute_command "SGID_Files" "find / -type f -perm -2000 -ls 2>/dev/null" "${BASE_DIR}/File_System/SUID_SGID/sgid_files.txt"
  execute_command "Hidden_Files_Root" "find / -type f -name \".*\" -ls 2>/dev/null | head -1000" "${BASE_DIR}/File_System/Hidden_Files/hidden_files_root_sample.txt"
  execute_command "Hidden_Directories" "find / -type d -name \".*\" -ls 2>/dev/null" "${BASE_DIR}/File_System/Hidden_Files/hidden_directories.txt"
  execute_command "Recently_Modified_Files" "find / -type f -mtime -7 -not -path \"/proc/*\" -not -path \"/sys/*\" -not -path \"/run/*\" -not -path \"/dev/*\" -not -path \"/var/log/*\" -ls 2>/dev/null | head -1000" "${BASE_DIR}/File_System/Recently_Modified/recent_files_sample.txt"
  execute_command "Partition_Tables" "fdisk -l" "${BASE_DIR}/File_System/Partition_Tables/fdisk.txt"
  execute_command "Block_Devices" "lsblk -f" "${BASE_DIR}/File_System/Partition_Tables/lsblk.txt"
  
  # MBR backup (for each disk)
  for disk in $(lsblk -d -o NAME | grep -v NAME); do
    execute_command "MBR_Backup_${disk}" "dd if=/dev/${disk} of=${BASE_DIR}/File_System/MBR/mbr_${disk}.bin bs=512 count=1" "${BASE_DIR}/File_System/MBR/mbr_${disk}_dd.log"
  done
  
  # File system journal info
  if command -v debugfs &> /dev/null; then
    for fs in $(mount | grep "type ext" | cut -d' ' -f1); do
      fs_name=$(basename $fs)
      execute_command "Journal_Info_${fs_name}" "echo 'journal_info' | debugfs $fs" "${BASE_DIR}/File_System/journal_${fs_name}.txt"
    done
  fi
}

# Function to collect user information
collect_user_info() {
  echo "Collecting user information..."
  
  # User information
  execute_command "User_List" "cat /etc/passwd" "${BASE_DIR}/Users/passwd.txt"
  execute_command "Group_List" "cat /etc/group" "${BASE_DIR}/Users/group.txt"
  execute_command "Shadow_File" "cat /etc/shadow" "${BASE_DIR}/Users/shadow.txt"
  execute_command "Sudoers_File" "cat /etc/sudoers" "${BASE_DIR}/Users/Sudo_Config/sudoers.txt"
  execute_command "Sudoers_Directory" "find /etc/sudoers.d/ -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Users/Sudo_Config/sudoers_d.txt"
  execute_command "Login_Records" "last" "${BASE_DIR}/Users/login_records.txt"
  execute_command "Failed_Logins" "lastb" "${BASE_DIR}/Users/failed_logins.txt"
  execute_command "Current_Logins" "who" "${BASE_DIR}/Users/current_logins.txt"
  execute_command "User_History_Files" "find /home -name \".*history\" -type f -exec ls -la {} \\; 2>/dev/null" "${BASE_DIR}/Users/history_files_list.txt"
  
  # Collect bash history for each user
  for user_home in /home/*; do
    if [ -d "$user_home" ]; then
      user=$(basename "$user_home")
      history_file="${user_home}/.bash_history"
      if [ -f "$history_file" ]; then
        execute_command "Bash_History_${user}" "cat ${history_file}" "${BASE_DIR}/Users/Bash_History/${user}_bash_history.txt"
      fi
    fi
  done
  
  # Root bash history
  if [ -f "/root/.bash_history" ]; then
    execute_command "Bash_History_root" "cat /root/.bash_history" "${BASE_DIR}/Users/Bash_History/root_bash_history.txt"
  fi
  
  # SSH keys and configs
  execute_command "SSH_Config" "cat /etc/ssh/sshd_config" "${BASE_DIR}/Users/SSH_Keys/sshd_config.txt"
  
  # Collect SSH keys for each user
  for user_home in /home/*; do
    if [ -d "$user_home" ]; then
      user=$(basename "$user_home")
      ssh_dir="${user_home}/.ssh"
      if [ -d "$ssh_dir" ]; then
        mkdir -p "${BASE_DIR}/Users/SSH_Keys/${user}"
        execute_command "SSH_Keys_${user}" "find ${ssh_dir} -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Users/SSH_Keys/${user}/ssh_keys.txt"
        execute_command "SSH_Known_Hosts_${user}" "cat ${ssh_dir}/known_hosts 2>/dev/null" "${BASE_DIR}/Users/SSH_Keys/${user}/known_hosts.txt"
      fi
    fi
  done
  
  # Root SSH keys
  if [ -d "/root/.ssh" ]; then
    mkdir -p "${BASE_DIR}/Users/SSH_Keys/root"
    execute_command "SSH_Keys_root" "find /root/.ssh -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Users/SSH_Keys/root/ssh_keys.txt"
    execute_command "SSH_Known_Hosts_root" "cat /root/.ssh/known_hosts 2>/dev/null" "${BASE_DIR}/Users/SSH_Keys/root/known_hosts.txt"
  fi
  
  # Authorized keys
  execute_command "Authorized_Keys" "find /home -name \"authorized_keys\" -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Users/SSH_Keys/all_authorized_keys.txt"
}

# Function to collect authentication information
collect_auth_info() {
  echo "Collecting authentication information..."
  
  # Authentication information
  execute_command "PAM_Configuration" "find /etc/pam.d/ -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Authentication/pam_configuration.txt"
  execute_command "NSSwitch_Configuration" "cat /etc/nsswitch.conf" "${BASE_DIR}/Authentication/nsswitch_conf.txt"
  execute_command "LDAP_Configuration" "find /etc -name \"ldap*.conf\" -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Authentication/ldap_configuration.txt"
  execute_command "Kerberos_Configuration" "find /etc -name \"krb*.conf\" -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Authentication/kerberos_configuration.txt"
  execute_command "Auth_Log" "cat /var/log/auth.log 2>/dev/null || cat /var/log/secure 2>/dev/null" "${BASE_DIR}/Authentication/auth_log.txt"
}

# Function to collect log information
collect_log_info() {
  echo "Collecting log information..."
  
  # System logs
  execute_command "Syslog" "cat /var/log/syslog 2>/dev/null || cat /var/log/messages 2>/dev/null" "${BASE_DIR}/Logs/System/syslog.txt"
  execute_command "Kernel_Log" "cat /var/log/kern.log 2>/dev/null || dmesg" "${BASE_DIR}/Logs/System/kernel_log.txt"
  execute_command "Boot_Log" "cat /var/log/boot.log 2>/dev/null" "${BASE_DIR}/Logs/System/boot_log.txt"
  execute_command "Daemon_Log" "cat /var/log/daemon.log 2>/dev/null" "${BASE_DIR}/Logs/System/daemon_log.txt"
  
  # Authentication logs
  execute_command "Auth_Log" "cat /var/log/auth.log 2>/dev/null || cat /var/log/secure 2>/dev/null" "${BASE_DIR}/Logs/Authentication/auth_log.txt"
  execute_command "SSHD_Log" "grep sshd /var/log/auth.log 2>/dev/null || grep sshd /var/log/secure 2>/dev/null" "${BASE_DIR}/Logs/Authentication/sshd_log.txt"
  execute_command "Sudo_Log" "grep sudo /var/log/auth.log 2>/dev/null || grep sudo /var/log/secure 2>/dev/null" "${BASE_DIR}/Logs/Authentication/sudo_log.txt"
  
  # Application logs
  execute_command "Apache_Access_Log" "find /var/log/apache2/ /var/log/httpd/ -name \"access*\" -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Logs/Application/apache_access_log.txt"
  execute_command "Apache_Error_Log" "find /var/log/apache2/ /var/log/httpd/ -name \"error*\" -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Logs/Application/apache_error_log.txt"
  execute_command "Nginx_Access_Log" "find /var/log/nginx/ -name \"access*\" -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Logs/Application/nginx_access_log.txt"
  execute_command "Nginx_Error_Log" "find /var/log/nginx/ -name \"error*\" -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Logs/Application/nginx_error_log.txt"
  
  # Audit logs
  execute_command "Audit_Log" "cat /var/log/audit/audit.log 2>/dev/null" "${BASE_DIR}/Logs/Audit/audit_log.txt"
  execute_command "Audit_Rules" "auditctl -l 2>/dev/null" "${BASE_DIR}/Logs/Audit/audit_rules.txt"
  
  # Journal logs
  if command -v journalctl &> /dev/null; then
    execute_command "Journal_Boot" "journalctl -b" "${BASE_DIR}/Logs/Journal/journal_boot.txt"
    execute_command "Journal_Kernel" "journalctl -k" "${BASE_DIR}/Logs/Journal/journal_kernel.txt"
    execute_command "Journal_Auth" "journalctl SYSLOG_FACILITY=10" "${BASE_DIR}/Logs/Journal/journal_auth.txt"
    execute_command "Journal_System_Services" "journalctl -u systemd-*" "${BASE_DIR}/Logs/Journal/journal_system_services.txt"
  fi
  
  # Log directory listing
  execute_command "Log_Directory_Listing" "find /var/log -type f -name \"*.log\" -o -name \"*.gz\" | sort" "${BASE_DIR}/Logs/log_files_list.txt"
}

# Function to collect kernel information
collect_kernel_info() {
  echo "Collecting kernel information..."
  
  # Kernel information
  execute_command "Kernel_Version" "uname -a" "${BASE_DIR}/Kernel/kernel_version.txt"
  execute_command "Kernel_Modules" "lsmod" "${BASE_DIR}/Kernel/kernel_modules.txt"
  execute_command "Kernel_Parameters" "sysctl -a" "${BASE_DIR}/Kernel/kernel_parameters.txt"
  execute_command "Kernel_Config" "cat /boot/config-$(uname -r) 2>/dev/null" "${BASE_DIR}/Kernel/kernel_config.txt"
  execute_command "Kernel_Dmesg" "dmesg" "${BASE_DIR}/Kernel/dmesg.txt"
  execute_command "Kernel_Proc_Version" "cat /proc/version" "${BASE_DIR}/Kernel/proc_version.txt"
  execute_command "Kernel_Interrupts" "cat /proc/interrupts" "${BASE_DIR}/Kernel/interrupts.txt"
  execute_command "Kernel_Softirqs" "cat /proc/softirqs" "${BASE_DIR}/Kernel/softirqs.txt"
  execute_command "Kernel_Crypto" "cat /proc/crypto" "${BASE_DIR}/Kernel/crypto.txt"
  execute_command "Kernel_Kallsyms" "cat /proc/kallsyms | head -1000" "${BASE_DIR}/Kernel/kallsyms_sample.txt"
  execute_command "Kernel_Modules_Info" "for module in $(lsmod | tail -n +2 | cut -d' ' -f1); do echo \"Module: $module\"; modinfo $module 2>/dev/null; echo; done" "${BASE_DIR}/Kernel/modules_info.txt"
}

# Function to collect service information
collect_service_info() {
  echo "Collecting service information..."
  
  # Service information
  if command -v systemctl &> /dev/null; then
    execute_command "Systemd_Units" "systemctl list-units" "${BASE_DIR}/Services/systemd_units.txt"
    execute_command "Systemd_Unit_Files" "systemctl list-unit-files" "${BASE_DIR}/Services/systemd_unit_files.txt"
    execute_command "Systemd_Services" "systemctl list-units --type=service" "${BASE_DIR}/Services/systemd_services.txt"
    execute_command "Systemd_Sockets" "systemctl list-units --type=socket" "${BASE_DIR}/Services/systemd_sockets.txt"
    execute_command "Systemd_Timers" "systemctl list-units --type=timer" "${BASE_DIR}/Services/systemd_timers.txt"
    execute_command "Systemd_Failed" "systemctl --failed" "${BASE_DIR}/Services/systemd_failed.txt"
    execute_command "Systemd_Service_Files" "find /etc/systemd/ /usr/lib/systemd/ -name \"*.service\" -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Services/systemd_service_files.txt"
  else
    execute_command "Init_Services" "service --status-all 2>&1" "${BASE_DIR}/Services/init_services.txt"
    execute_command "Init_Scripts" "find /etc/init.d/ -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Services/init_scripts.txt"
  fi
  
  # Upstart (if available)
  if [ -d "/etc/init" ]; then
    execute_command "Upstart_Configs" "find /etc/init/ -name \"*.conf\" -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Services/upstart_configs.txt"
  fi
  
  # Xinetd (if available)
  if [ -d "/etc/xinetd.d" ]; then
    execute_command "Xinetd_Configs" "find /etc/xinetd.d/ -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Services/xinetd_configs.txt"
  fi
}

# Function to collect cron job information
collect_cron_info() {
  echo "Collecting cron job information..."
  
  # Cron job information
  execute_command "Crontab_Files" "find /var/spool/cron/ /var/spool/cron/crontabs/ -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Cron_Jobs/crontab_files.txt"
  execute_command "System_Crontab" "cat /etc/crontab" "${BASE_DIR}/Cron_Jobs/system_crontab.txt"
  execute_command "Cron_Hourly" "find /etc/cron.hourly/ -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Cron_Jobs/cron_hourly.txt"
  execute_command "Cron_Daily" "find /etc/cron.daily/ -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Cron_Jobs/cron_daily.txt"
  execute_command "Cron_Weekly" "find /etc/cron.weekly/ -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Cron_Jobs/cron_weekly.txt"
  execute_command "Cron_Monthly" "find /etc/cron.monthly/ -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Cron_Jobs/cron_monthly.txt"
  execute_command "Cron_D" "find /etc/cron.d/ -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Cron_Jobs/cron_d.txt"
  
  # Systemd timers (if available)
  if command -v systemctl &> /dev/null; then
    execute_command "Systemd_Timers" "systemctl list-timers --all" "${BASE_DIR}/Cron_Jobs/systemd_timers.txt"
  fi
}

# Function to collect installed software information
collect_software_info() {
  echo "Collecting installed software information..."
  
  # Installed software information
  if command -v dpkg &> /dev/null; then
    execute_command "Installed_Packages_Dpkg" "dpkg -l" "${BASE_DIR}/Installed_Software/dpkg_packages.txt"
  fi
  
  if command -v rpm &> /dev/null; then
    execute_command "Installed_Packages_RPM" "rpm -qa" "${BASE_DIR}/Installed_Software/rpm_packages.txt"
  fi
  
  if command -v yum &> /dev/null; then
    execute_command "Yum_Repositories" "yum repolist -v" "${BASE_DIR}/Installed_Software/yum_repositories.txt"
  fi
  
  if command -v apt &> /dev/null; then
    execute_command "APT_Sources" "cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null" "${BASE_DIR}/Installed_Software/apt_sources.txt"
    execute_command "APT_History" "cat /var/log/apt/history.log 2>/dev/null" "${BASE_DIR}/Installed_Software/apt_history.txt"
  fi
  
  # Installed languages and frameworks
  if command -v python &> /dev/null; then
    execute_command "Python_Packages" "pip list 2>/dev/null || pip3 list 2>/dev/null" "${BASE_DIR}/Installed_Software/python_packages.txt"
    execute_command "Python_Version" "python --version 2>&1 || python3 --version 2>&1" "${BASE_DIR}/Installed_Software/python_version.txt"
  fi
  
  if command -v ruby &> /dev/null; then
    execute_command "Ruby_Gems" "gem list" "${BASE_DIR}/Installed_Software/ruby_gems.txt"
    execute_command "Ruby_Version" "ruby --version" "${BASE_DIR}/Installed_Software/ruby_version.txt"
  fi
  
  if command -v npm &> /dev/null; then
    execute_command "NPM_Packages" "npm list -g" "${BASE_DIR}/Installed_Software/npm_packages.txt"
    execute_command "Node_Version" "node --version" "${BASE_DIR}/Installed_Software/node_version.txt"
  fi
  
  if command -v java &> /dev/null; then
    execute_command "Java_Version" "java -version 2>&1" "${BASE_DIR}/Installed_Software/java_version.txt"
  fi
  
  # Compiler information
  if command -v gcc &> /dev/null; then
    execute_command "GCC_Version" "gcc --version" "${BASE_DIR}/Installed_Software/gcc_version.txt"
  fi
  
  if command -v clang &> /dev/null; then
    execute_command "Clang_Version" "clang --version" "${BASE_DIR}/Installed_Software/clang_version.txt"
  fi
}

# Function to collect startup item information
collect_startup_info() {
  echo "Collecting startup item information..."
  
  # Startup item information
  execute_command "RC_Local" "cat /etc/rc.local 2>/dev/null" "${BASE_DIR}/Startup_Items/rc_local.txt"
  execute_command "Profile_D" "find /etc/profile.d/ -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Startup_Items/profile_d.txt"
  execute_command "Bash_RC" "cat /etc/bash.bashrc 2>/dev/null" "${BASE_DIR}/Startup_Items/bash_rc.txt"
  execute_command "Profile" "cat /etc/profile 2>/dev/null" "${BASE_DIR}/Startup_Items/profile.txt"
  
  # Systemd startup items
  if command -v systemctl &> /dev/null; then
    execute_command "Systemd_Startup" "systemctl list-unit-files --state=enabled" "${BASE_DIR}/Startup_Items/systemd_enabled.txt"
  fi
  
  # SysV init startup items
  if [ -d "/etc/rc3.d" ]; then
    execute_command "SysV_Startup" "ls -la /etc/rc*.d/" "${BASE_DIR}/Startup_Items/sysv_startup.txt"
  fi
}

# Function to collect security information
collect_security_info() {
  echo "Collecting security information..."
  
  # SELinux information
  if [ -f "/etc/selinux/config" ]; then
    execute_command "SELinux_Config" "cat /etc/selinux/config" "${BASE_DIR}/Security/SELinux/config.txt"
    execute_command "SELinux_Status" "sestatus" "${BASE_DIR}/Security/SELinux/status.txt"
    execute_command "SELinux_Booleans" "getsebool -a" "${BASE_DIR}/Security/SELinux/booleans.txt"
  fi
  
  # AppArmor information
  if [ -d "/etc/apparmor.d" ]; then
    execute_command "AppArmor_Status" "apparmor_status" "${BASE_DIR}/Security/AppArmor/status.txt"
    execute_command "AppArmor_Profiles" "find /etc/apparmor.d/ -type f -not -name \"*.dpkg-*\" -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Security/AppArmor/profiles.txt"
  fi
  
  # Capabilities
  execute_command "Capabilities" "getcap -r / 2>/dev/null" "${BASE_DIR}/Security/Capabilities/capabilities.txt"
  
  # Malware scan (if available)
  if command -v clamdscan &> /dev/null; then
    execute_command "ClamAV_Scan_Bin" "clamdscan /bin" "${BASE_DIR}/Security/Malware_Scan/clamav_bin.txt"
    execute_command "ClamAV_Scan_Sbin" "clamdscan /sbin" "${BASE_DIR}/Security/Malware_Scan/clamav_sbin.txt"
  elif command -v clamscan &> /dev/null; then
    execute_command "ClamAV_Scan_Bin" "clamscan /bin" "${BASE_DIR}/Security/Malware_Scan/clamav_bin.txt"
    execute_command "ClamAV_Scan_Sbin" "clamscan /sbin" "${BASE_DIR}/Security/Malware_Scan/clamav_sbin.txt"
  else
    echo "ClamAV not found. Malware scan not performed." > "${BASE_DIR}/Security/Malware_Scan/clamav_not_available.txt"
  fi
  
  # Check for rootkits (if available)
  if command -v rkhunter &> /dev/null; then
    execute_command "RKHunter_Check" "rkhunter --check --skip-keypress" "${BASE_DIR}/Security/Malware_Scan/rkhunter_check.txt"
  else
    echo "RKHunter not found. Rootkit scan not performed." > "${BASE_DIR}/Security/Malware_Scan/rkhunter_not_available.txt"
  fi
  
  if command -v chkrootkit &> /dev/null; then
    execute_command "Chkrootkit" "chkrootkit" "${BASE_DIR}/Security/Malware_Scan/chkrootkit.txt"
  else
    echo "Chkrootkit not found. Rootkit scan not performed." > "${BASE_DIR}/Security/Malware_Scan/chkrootkit_not_available.txt"
  fi
}

# Function to collect web server information
collect_webserver_info() {
  echo "Collecting web server information..."
  
  # Apache information
  if [ -d "/etc/apache2" ] || [ -d "/etc/httpd" ]; then
    execute_command "Apache_Config" "find /etc/apache2/ /etc/httpd/ -name \"*.conf\" -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Web_Servers/Apache/config.txt"
    execute_command "Apache_Modules" "apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null" "${BASE_DIR}/Web_Servers/Apache/modules.txt"
    execute_command "Apache_Vhosts" "apache2ctl -S 2>/dev/null || httpd -S 2>/dev/null" "${BASE_DIR}/Web_Servers/Apache/vhosts.txt"
    execute_command "Apache_Status" "service apache2 status 2>/dev/null || service httpd status 2>/dev/null" "${BASE_DIR}/Web_Servers/Apache/status.txt"
  fi
  
  # Nginx information
  if [ -d "/etc/nginx" ]; then
    execute_command "Nginx_Config" "find /etc/nginx/ -name \"*.conf\" -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Web_Servers/Nginx/config.txt"
    execute_command "Nginx_Status" "service nginx status" "${BASE_DIR}/Web_Servers/Nginx/status.txt"
  fi
}

# Function to collect database information
collect_database_info() {
  echo "Collecting database information..."
  
  # MySQL/MariaDB information
  if command -v mysql &> /dev/null; then
    execute_command "MySQL_Status" "service mysql status 2>/dev/null || service mariadb status 2>/dev/null" "${BASE_DIR}/Databases/MySQL/status.txt"
    execute_command "MySQL_Config" "cat /etc/mysql/my.cnf 2>/dev/null || cat /etc/my.cnf 2>/dev/null" "${BASE_DIR}/Databases/MySQL/config.txt"
  fi
  
  # PostgreSQL information
  if command -v psql &> /dev/null; then
    execute_command "PostgreSQL_Status" "service postgresql status" "${BASE_DIR}/Databases/PostgreSQL/status.txt"
    execute_command "PostgreSQL_Config" "find /etc/postgresql/ -name \"*.conf\" -type f -exec cat {} \\; 2>/dev/null" "${BASE_DIR}/Databases/PostgreSQL/config.txt"
  fi
  
  # SQLite databases
  execute_command "SQLite_Databases" "find / -name \"*.db\" -o -name \"*.sqlite\" -o -name \"*.sqlite3\" | grep -v \"/proc/\" | grep -v \"/sys/\" | head -100 2>/dev/null" "${BASE_DIR}/Databases/SQLite/databases_list.txt"
}

# Function to collect Docker information
collect_docker_info() {
  echo "Collecting Docker information..."
  
  # Docker information
  if command -v docker &> /dev/null; then
    execute_command "Docker_Version" "docker version" "${BASE_DIR}/Docker/version.txt"
    execute_command "Docker_Info" "docker info" "${BASE_DIR}/Docker/info.txt"
    execute_command "Docker_Images" "docker images" "${BASE_DIR}/Docker/Images/images.txt"
    execute_command "Docker_Containers" "docker ps -a" "${BASE_DIR}/Docker/Containers/containers.txt"
    execute_command "Docker_Networks" "docker network ls" "${BASE_DIR}/Docker/networks.txt"
    execute_command "Docker_Volumes" "docker volume ls" "${BASE_DIR}/Docker/Volumes/volumes.txt"
  else
    echo "Docker not found. Docker information not collected." > "${BASE_DIR}/Docker/docker_not_available.txt"
  fi
}

# Function to collect temporary files information
collect_temp_files_info() {
  echo "Collecting temporary files information..."
  
  # Temporary files information
  execute_command "Temp_Files" "find /tmp -type f -exec ls -la {} \\; 2>/dev/null | head -1000" "${BASE_DIR}/Temporary_Files/tmp_files_sample.txt"
  execute_command "Var_Tmp_Files" "find /var/tmp -type f -exec ls -la {} \\; 2>/dev/null | head -1000" "${BASE_DIR}/Temporary_Files/var_tmp_files_sample.txt"
  execute_command "Dev_Shm_Files" "find /dev/shm -type f -exec ls -la {} \\; 2>/dev/null" "${BASE_DIR}/Temporary_Files/dev_shm_files.txt"
}

# Function to collect browser data
collect_browser_data() {
  echo "Collecting browser data..."
  
  # Firefox profiles
  for user_home in /home/*; do
    if [ -d "$user_home" ]; then
      user=$(basename "$user_home")
      firefox_dir="${user_home}/.mozilla/firefox"
      if [ -d "$firefox_dir" ]; then
        # Find profile directories
        for profile_dir in $(find "$firefox_dir" -name "*.default*" -type d 2>/dev/null); do
          profile_name=$(basename "$profile_dir")
          mkdir -p "${BASE_DIR}/Browser_Data/Firefox/${user}/${profile_name}"
          
          # Copy key files (not the entire profile as it could be large)
          if [ -f "${profile_dir}/places.sqlite" ]; then
            execute_command "Firefox_Places_${user}_${profile_name}" "cp ${profile_dir}/places.sqlite ${BASE_DIR}/Browser_Data/Firefox/${user}/${profile_name}/" "${BASE_DIR}/Browser_Data/Firefox/${user}/${profile_name}/copy_places.log"
          fi
          
          if [ -f "${profile_dir}/cookies.sqlite" ]; then
            execute_command "Firefox_Cookies_${user}_${profile_name}" "cp ${profile_dir}/cookies.sqlite ${BASE_DIR}/Browser_Data/Firefox/${user}/${profile_name}/" "${BASE_DIR}/Browser_Data/Firefox/${user}/${profile_name}/copy_cookies.log"
          fi
          
          if [ -f "${profile_dir}/formhistory.sqlite" ]; then
            execute_command "Firefox_FormHistory_${user}_${profile_name}" "cp ${profile_dir}/formhistory.sqlite ${BASE_DIR}/Browser_Data/Firefox/${user}/${profile_name}/" "${BASE_DIR}/Browser_Data/Firefox/${user}/${profile_name}/copy_formhistory.log"
          fi
          
          if [ -f "${profile_dir}/downloads.sqlite" ]; then
            execute_command "Firefox_Downloads_${user}_${profile_name}" "cp ${profile_dir}/downloads.sqlite ${BASE_DIR}/Browser_Data/Firefox/${user}/${profile_name}/" "${BASE_DIR}/Browser_Data/Firefox/${user}/${profile_name}/copy_downloads.log"
          fi
        done
      fi
      
      # Chrome/Chromium profiles
      chrome_dir="${user_home}/.config/google-chrome"
      chromium_dir="${user_home}/.config/chromium"
      
      for browser_dir in "$chrome_dir" "$chromium_dir"; do
        if [ -d "$browser_dir" ]; then
          browser_name=$(basename "$browser_dir")
          if [ "$browser_name" = "google-chrome" ]; then
            browser_name="Chrome"
          else
            browser_name="Chromium"
          fi
          
          # Find profile directories (Default and others)
          for profile_dir in $(find "$browser_dir" -name "Default" -o -name "Profile*" -type d 2>/dev/null); do
            profile_name=$(basename "$profile_dir")
            mkdir -p "${BASE_DIR}/Browser_Data/Chrome/${user}/${profile_name}"
            
            # Copy key files (not the entire profile as it could be large)
            if [ -f "${profile_dir}/History" ]; then
              execute_command "${browser_name}_History_${user}_${profile_name}" "cp ${profile_dir}/History ${BASE_DIR}/Browser_Data/Chrome/${user}/${profile_name}/" "${BASE_DIR}/Browser_Data/Chrome/${user}/${profile_name}/copy_history.log"
            fi
            
            if [ -f "${profile_dir}/Cookies" ]; then
              execute_command "${browser_name}_Cookies_${user}_${profile_name}" "cp ${profile_dir}/Cookies ${BASE_DIR}/Browser_Data/Chrome/${user}/${profile_name}/" "${BASE_DIR}/Browser_Data/Chrome/${user}/${profile_name}/copy_cookies.log"
            fi
            
            if [ -f "${profile_dir}/Login Data" ]; then
              execute_command "${browser_name}_LoginData_${user}_${profile_name}" "cp \"${profile_dir}/Login Data\" ${BASE_DIR}/Browser_Data/Chrome/${user}/${profile_name}/" "${BASE_DIR}/Browser_Data/Chrome/${user}/${profile_name}/copy_logindata.log"
            fi
            
            if [ -f "${profile_dir}/Web Data" ]; then
              execute_command "${browser_name}_WebData_${user}_${profile_name}" "cp \"${profile_dir}/Web Data\" ${BASE_DIR}/Browser_Data/Chrome/${user}/${profile_name}/" "${BASE_DIR}/Browser_Data/Chrome/${user}/${profile_name}/copy_webdata.log"
            fi
          done
        fi
      done
    fi
  done
}

# Main collection functions
echo "Starting Linux Enhanced Forensic Collection..."
echo "Output directory: $BASE_DIR"

# Run all collection functions
collect_system_info
collect_process_info
collect_memory_info
collect_network_info
collect_filesystem_info
collect_user_info
collect_auth_info
collect_log_info
collect_kernel_info
collect_service_info
collect_cron_info
collect_software_info
collect_startup_info
collect_security_info
collect_webserver_info
collect_database_info
collect_docker_info
collect_temp_files_info
collect_browser_data

# Update the notification file with completion information
END_TIME=$(date)
echo "" >> "$NOTIFICATION_FILE"
echo "Collection completed at: $END_TIME" >> "$NOTIFICATION_FILE"
DURATION=$(($(date +%s) - $(date -d "$(head -3 "$NOTIFICATION_FILE" | tail -1 | cut -d':' -f2-)" +%s)))
echo "Collection duration: $DURATION seconds" >> "$NOTIFICATION_FILE"

echo "" >> "$NOTIFICATION_FILE"
echo "This collection contains the following artifacts:" >> "$NOTIFICATION_FILE"
echo "- System Information" >> "$NOTIFICATION_FILE"
echo "- Running Processes" >> "$NOTIFICATION_FILE"
echo "- Memory Information" >> "$NOTIFICATION_FILE"
echo "- Network Configuration and Connections" >> "$NOTIFICATION_FILE"
echo "- File System Information" >> "$NOTIFICATION_FILE"
echo "- User Accounts and Activity" >> "$NOTIFICATION_FILE"
echo "- Authentication Information" >> "$NOTIFICATION_FILE"
echo "- System and Application Logs" >> "$NOTIFICATION_FILE"
echo "- Kernel Information" >> "$NOTIFICATION_FILE"
echo "- Services Configuration" >> "$NOTIFICATION_FILE"
echo "- Cron Jobs" >> "$NOTIFICATION_FILE"
echo "- Installed Software" >> "$NOTIFICATION_FILE"
echo "- Startup Items" >> "$NOTIFICATION_FILE"
echo "- Security Information" >> "$NOTIFICATION_FILE"
echo "- Web Server Configuration" >> "$NOTIFICATION_FILE"
echo "- Database Information" >> "$NOTIFICATION_FILE"
echo "- Docker Information" >> "$NOTIFICATION_FILE"
echo "- Temporary Files" >> "$NOTIFICATION_FILE"
echo "- Browser Data" >> "$NOTIFICATION_FILE"
echo "" >> "$NOTIFICATION_FILE"
echo "For a detailed summary of all commands executed and their status," >> "$NOTIFICATION_FILE"
echo "please refer to the ForensicCollectionSummary.csv file." >> "$NOTIFICATION_FILE"

# Create a ZIP file of the collection
ZIP_FILE="${OUTPUT_PATH}/LinuxForensicCollection_${DATE_STRING}.tar.gz"
echo "Creating archive of collected artifacts: $ZIP_FILE"
tar -czf "$ZIP_FILE" -C "$(dirname "$BASE_DIR")" "$(basename "$BASE_DIR")"

if [ $? -eq 0 ]; then
  echo "Collection has been compressed to: $ZIP_FILE" >> "$NOTIFICATION_FILE"
  echo "$(date +"%Y-%m-%d %H:%M:%S"),\"tar -czf $ZIP_FILE -C $(dirname "$BASE_DIR") $(basename "$BASE_DIR")\",Completed,0" >> "$SUMMARY_FILE"
else
  echo "Error creating archive file" >> "$NOTIFICATION_FILE"
  echo "$(date +"%Y-%m-%d %H:%M:%S"),\"tar -czf $ZIP_FILE -C $(dirname "$BASE_DIR") $(basename "$BASE_DIR")\",Failed,$?" >> "$SUMMARY_FILE"
fi

echo "Linux Enhanced Forensic Collection completed. Results are stored in: $BASE_DIR"
echo "A compressed archive has been created at: $ZIP_FILE"
