# 🔍 Arch Linux Forensic Analyzer v2.1

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Arch%20Linux-1793D1.svg)](https://archlinux.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Stable-brightgreen.svg)]()

A complete and optimized forensic analysis tool for Arch Linux systems, developed in Python with a Tkinter graphical interface.

![Screenshot](https://via.placeholder.com/800x450/1793D1/FFFFFF?text=Arch+Linux+Forensic+Analyzer)

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Detailed Functionalities](#-detailed-functionalities)
- [Screenshots](#-screenshots)
- [Architecture](#-architecture)
- [Security](#-security)
- [Data Export](#-data-export)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)
- [Acknowledgments](#-acknowledgments)

## 🎯 Overview

**Arch Linux Forensic Analyzer** is a digital forensic analysis tool developed specifically for Arch Linux systems. It enables system administrators, security analysts, and forensic investigators to perform deep operating system analysis, identifying suspicious activities, tracking user actions, and collecting digital evidence efficiently.

The tool provides an intuitive graphical interface that consolidates information from multiple system sources, including systemd logs, journalctl, running processes, recent files, installed packages, and much more.

### 🎯 Objectives

- Provide a holistic system view in a single dashboard
- Facilitate forensic investigations in Arch Linux environments
- Automate digital evidence collection
- Offer real-time monitoring of suspicious activities
- Generate structured reports for documentation

### 🔬 Use Cases

1. **Incident Response**: Quick identification of malicious activities
2. **Security Auditing**: Compliance verification and best practices
3. **Post-Intrusion Analysis**: Attack timeline reconstruction
4. **Continuous Monitoring**: Proactive anomaly detection
5. **Education**: Teaching digital forensic concepts

## ✨ Features

### Main Functionalities

- **🖥 System Analysis**
  - Detailed hardware and software information
  - Uptime and resource monitoring
  - Architecture and kernel detection
  - CPU and memory analysis
  - Loaded kernel modules identification

- **👥 User Analysis**
  - Complete system user listing
  - Activity level per user (🔥 Very Active / 🟢 Active / 🟡 Low Activity / ⚪ Inactive)
  - Login history and executed commands
  - Processes per user
  - Group and permission details
  - Identification of users with valid shells

- **🔧 Service Monitoring**
  - List of active systemd services
  - Status, PID, and memory consumption
  - Detection of suspicious or masked services
  - Real-time updates
  - Startup and failure history

- **📱 Application Analysis**
  - Complete catalog of installed packages (pacman)
  - Classification by type (Application, Library, Desktop, Language)
  - Real-time search filter
  - Running processes with CPU/Memory usage
  - Identification of orphaned or unnecessary packages

- **📁 File Monitoring**
  - Recent file scanning (last 24h)
  - Creation, modification, and access detection
  - Permissions and ownership
  - Specific home directory analysis
  - Detailed view with double-click
  - Hidden file support

- **📋 Log Visualization**
  - Real-time journalctl monitoring
  - Color highlighting by severity (✅ Success / ⚠️ Warning / ❌ Error)
  - Pattern recognition (systemd, sudo, logins, SSH, authentication)
  - Log search and filtering
  - Selected excerpt export

- **⏱ Forensic Timeline**
  - System event timeline
  - Last 50 journal entries
  - Files modified in last 24h
  - Chronological activity ordering
  - Event and file correlation

- **📊 System Statistics**
  - Real-time CPU and memory usage
  - Disk usage by partition
  - Total processes and packages
  - Active network connections (TCP/UDP)
  - Logged-in users and active sessions
  - Disk I/O statistics

### Advanced Features

- **🔄 Auto-Refresh**: All data can be updated with F5
- **💾 Report Export**: Exports complete data in JSON format
- **🧵 Multi-threaded Processing**: Background analysis without UI freezing
- **🎨 Responsive Interface**: Modern design with organized tabs and adaptive theme
- **🔍 Smart Filters**: Real-time search across all listings with highlighting
- **🛡️ Root/Sudo Mode**: Automatic detection and restart with elevated privileges
- **📊 Graphs and Visualizations**: Visual representation of statistical data (in development)
- **🔔 Alert System**: Notifications for detected critical events
- **📝 Audit Log**: Recording of all actions performed in the tool

## 📦 Requirements

### Operating System
- **Arch Linux** (or derivatives like Manjaro, EndeavourOS, Garuda, ArcoLinux)
- Linux Kernel 5.0 or higher
- Python 3.8 or higher
- systemd (init system and service management)

### Python Dependencies
```bash
# Standard libraries (already included in Python 3)
- tkinter          # Graphical interface
- threading        # Parallel processing
- queue            # Thread communication
- re               # Regular expressions
- json             # Data export
- subprocess       # Command execution
- os               # System operations
- pwd              # User information
- grp              # Group information
- stat             # File permissions
- datetime         # Date manipulation
- collections      # Data structures
- pathlib          # Path manipulation
- time             # Timestamps and delays
System Packages
bash
# Essential for all functionalities
sudo pacman -S systemd          # journalctl, systemctl
sudo pacman -S pacman           # Package manager
sudo pacman -S procps-ng        # ps, free, top, pgrep
sudo pacman -S coreutils        # df, who, last, uptime
sudo pacman -S util-linux       # script, whereis

# Optional (for extra functionalities)
sudo pacman -S net-tools        # netstat (alternative to ss)
sudo pacman -S lsof             # List open files
sudo pacman -S strace           # System call tracing
Disk Space
Minimum: 50 MB for the script

Recommended: 1 GB for cache and temporary logs

Permissions
Root/Sudo: Required for full access to:

/var/log (system logs)

/proc (process information)

/home/* (other users' files)

journalctl (systemd logs)

systemctl (service management)

🚀 Installation
Method 1: Direct Download
bash
# Clone the repository
git clone https://github.com/OtavioTavaresDev/arch-forensic-analyzer.git
cd arch-forensic-analyzer

# Make the script executable
chmod +x FORENSEultra.py

# Run with root privileges
sudo python FORENSEultra.py
Method 2: Quick Install (curl)
bash
# Direct script download
curl -O https://raw.githubusercontent.com/OtavioTavaresDev/arch-forensic-analyzer/main/FORENSEultra.py

# Make executable and run
chmod +x FORENSEultra.py
sudo python3 FORENSEultra.py
Method 3: Quick Install (wget)
bash
# Download using wget
wget https://raw.githubusercontent.com/OtavioTavaresDev/arch-forensic-analyzer/main/FORENSEultra.py

# Run
sudo python3 FORENSEultra.py
Method 4: AUR Installation (coming soon)
bash
# Using yay (AUR helper)
yay -S arch-forensic-analyzer

# Using paru
paru -S arch-forensic-analyzer

# Using pamac (GUI)
pamac install arch-forensic-analyzer
Method 5: Complete Manual Installation
bash
# Create directory for the tool
sudo mkdir -p /opt/arch-forensic-analyzer

# Copy the script
sudo cp FORENSEultra.py /opt/arch-forensic-analyzer/

# Create symbolic link in PATH
sudo ln -s /opt/arch-forensic-analyzer/FORENSEultra.py /usr/local/bin/forense

# Now you can run from anywhere
sudo forense
Installation Verification
bash
# Check if script is accessible
which forense

# Test execution (test mode)
python3 -c "import tkinter; print('Tkinter OK')"

# Check dependencies
python3 -c "import pwd, grp, stat; print('Dependencies OK')"
🎮 Usage
First Run
Run the script with root privileges:

bash
sudo python3 FORENSEultra.py
or, if installed in PATH:

bash
sudo forense
If run without sudo, the tool will automatically detect and ask:

text
⚠️ Root Permission Required
This tool needs root privileges for complete access.
Do you want to restart with sudo automatically?
[Yes] [No]
Main Interface:

Wait for initial data loading (2-5 seconds)

Progress bar will indicate status

Navigate through the 8 main tabs

Use control buttons in the top bar

Commands and Shortcuts
Action	Shortcut	Icon	Description
Start Monitoring	-	▶	Activates real-time log monitoring
Stop Monitoring	-	⏹	Pauses log capture
Refresh All	F5	🔄	Reloads all system data
Export Report	Ctrl+E	💾	Saves complete JSON report
Search Logs	Ctrl+F	🔍	Opens search dialog
Full Analysis	-	🔬	Runs deep forensic scan
Clear Data	-	🧹	Removes all collected data
Exit	Ctrl+Q	-	Closes application
Help	F1	-	Shows documentation
Recommended Workflow
1️⃣ Quick Initial Analysis (5 minutes)
text
Objective: System overview
├── Run as root
├── Check "🖥 System" tab
│   ├── Confirm hostname, kernel, architecture
│   ├── Observe uptime and memory usage
│   └── Identify CPU model
├── Access "📊 Statistics"
│   ├── Check disk usage
│   ├── Observe network connections
│   └── Count active processes
└── Check "⏱ Timeline"
    ├── Latest journal events
    └── Recently modified files
2️⃣ Suspicious User Investigation (10-15 minutes)
text
Objective: Analyze specific user activity
├── Navigate to "👥 Users"
├── Identify users with abnormal activity
│   ├── 🔥 Very Active (many processes)
│   ├── Unusual login times
│   └── Non-standard shells
├── Click user for details
│   ├── Analyze groups and permissions
│   ├── Check active processes
│   ├── Examine command history
│   │   ├── Sudo commands executed
│   │   ├── Access to sensitive files
│   │   └── Privilege escalation attempts
│   └── Review recent logins
│       ├── Source (local/remote)
│       ├── Timestamps
│       └── Session duration
└── Document found evidence
3️⃣ File Analysis (10-20 minutes)
text
Objective: Track file activities
├── Use "📂 Scan Recent Files"
│   ├── Wait for scan (may take 1-2 minutes)
│   ├── Observe files in /home, /etc, /var/log
│   └── Filter by user or period
├── Identify suspicious patterns
│   ├── Files created in system directories
│   ├── Configuration file modifications
│   ├── Scripts in temporary directories
│   └── Changes to system binaries
├── Run "🏠 Analyze Home"
│   ├── Focus on current user
│   ├── Last hour of activity
│   └── Most recent files
└── Double-click for details
    ├── Permissions and ownership
    ├── Complete timestamps
    └── Size and file type
4️⃣ Continuous Monitoring (indefinite time)
text
Objective: Capture real-time activities
├── Click "▶ Start"
├── Observe "📋 Logs" tab
│   ├── Follow journalctl live
│   ├── Identify colored patterns
│   │   ├── 🟢 Green: Services started
│   │   ├── 🟠 Orange: Warnings
│   │   └── 🔴 Red: Errors/Failures
│   └── Use filters to focus
├── Monitor critical events
│   ├── Login attempts
│   ├── Sudo commands
│   ├── Service start/stop
│   └── Authentication errors
└── Keep anomaly records
5️⃣ Documentation and Reporting
text
Objective: Generate documented evidence
├── Click "💾 Export"
├── Choose save location
│   └── Format: forensic_report_YYYYMMDD_HHMMSS.json
├── Report includes:
│   ├── System information
│   ├── User data
│   ├── File activities
│   ├── Installed applications
│   └── Collection timestamp
├── Use JSON for:
│   ├── Later analysis with scripts
│   ├── Import into other tools
│   ├── Incident documentation
│   └── Team sharing
└── Consider hashing the file
    └── sha256sum report.json > report.json.sha256
Command Line Examples
bash
# Run and redirect output to file
sudo forense 2>&1 | tee forensic_session.log

# Run in background
sudo forense &

# Run with higher priority
sudo nice -n -10 forense

# Run in isolated environment (recommended for sensitive analysis)
sudo systemd-run --scope --user forense
📚 Detailed Functionalities
🖥 System Tab
Collected Information:

Hostname and Domain: Machine network name

Kernel Version: Full release and build date

Architecture: x86_64, aarch64, etc.

Uptime: Time since last boot (formatted)

Memory: Total, used, free, cache, swap

CPU: Model, frequency, core count

Kernel Modules: List of loaded modules

Environment Variables: PATH, HOME, SHELL, etc.

Detailed Output Example:

text
================================================================================
SYSTEM INFORMATION
================================================================================

📌 Hostname: archlinux-workstation.localdomain
🐧 Kernel: 6.8.1-arch1-1 (x86_64)
💻 Architecture: x86_64 (64-bit)
⏱ Uptime: 3 days, 14 hours, 23 minutes, 45 seconds

💾 Memory:
              total        used        free      shared  buff/cache   available
Mem:           15Gi       4.2Gi       8.1Gi       456Mi       3.1Gi        10Gi
Swap:         8.0Gi       1.2Gi       6.8Gi

🔲 CPU: Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz
    Cores: 6 physical, 12 logical
    Cache: L1: 384 KiB, L2: 1.5 MiB, L3: 12 MiB

📦 Kernel Modules:
    nvidia, snd_hda_intel, iwlwifi, btusb, ext4, ...

🔄 Processes: 287 total, 2 running, 285 sleeping
👥 Users Tab
Displayed Data:

List of users with UID ≥ 1000 + root

UID, default Shell, and last login

Activity level based on active processes:

🔥 Very Active: > 20 processes

🟢 Active: 11-20 processes

🟡 Low Activity: 1-10 processes

⚪ Inactive: 0 processes

❓ Unknown: Error checking

User Details (double-click):

text
================================================================================
USER DETAILS: johndoe
================================================================================

📋 Basic Information:
   UID: 1000
   GID: 1000
   Home: /home/johndoe
   Shell: /bin/bash
   Groups: wheel, audio, video, storage, docker

🔧 Active Processes:
  PID %CPU %MEM COMMAND
 1234  0.0  0.1 bash
 5678  2.5  3.2 firefox
 9012  0.1  0.3 code

⌨️ Recent Commands:
   sudo pacman -Syu
   git clone https://github.com/...
   cd project/
   python3 script.py
   ssh user@server

🔐 Recent Logins:
johndoe  tty1         Wed Mar 20 09:15   still logged in
johndoe  pts/0        Tue Mar 19 14:30 - 18:45  (04:15)
johndoe  ssh          Mon Mar 18 08:00 - 17:00  (09:00)
📱 Applications Tab
Features:

Package List: All packages installed via pacman

Automatic Classification:

📚 Library: Names containing 'lib', 'library'

🐍 Language: Python, Perl, Ruby, PHP, Node.js, Java

🖥️ Desktop: XFCE, GNOME, KDE, Qt, GTK, themes

🔧 System: Kernel, drivers, system tools

📦 Application: Other packages

Real-Time Filter:

Type to filter the list instantly

Case-insensitive search

Highlights matches

Active Processes:

Top 50 processes by CPU usage

Updates every 5 seconds

Filter by process name

Sort by column (click header)

📁 Files Tab
Functionalities:

Recent Files Scanning:

text
Scanned directories:
├── /home          # Personal directories
├── /etc           # System configurations
└── /var/log       # System logs

Period: Last 24 hours
Maximum depth: 3 levels
Ignored files: > 100 MB (configurable)
Detected Actions:

Created: File didn't exist before period

Modified: Content changed during period

Accessed: Only read during period

Home Directory Analysis:

Focus on current user's directory

Period: Last 1 hour

Limit: 100 most recent files

Includes hidden files (.*)

Detailed View (double-click):

text
📁 FILE DETAILS
============================================================

File: /home/johndoe/document.pdf
Size: 2.5 MB
Permissions: -rw-r--r--
Owner: johndoe
Group: users

📅 Dates:
Created: 2024-03-20 14:30:15
Modified: 2024-03-20 14:35:22
Accessed: 2024-03-20 14:40:10

🔢 Information:
Inode: 12345678
Links: 1
Device: 259.2
Type: Regular file
📋 Logs Tab
Real-Time Monitoring:

Continuous journalctl -f capture

Automatic updates every 100ms

1000 line buffer (scrollable)

Color Highlighting:

🟢 Green (success):

Successfully started services

Successful logins

Completed operations

🟠 Orange (warning):

System warnings

Timeouts

Deprecations

🔴 Red (error):

Critical failures

Failed services

Intrusion attempts

Recognized Patterns:

regex
systemd_service: Started|Starting|Stopped|Failed
sudo_command:    sudo: user : TTY=... ; COMMAND=...
login_success:   Accepted password|publickey for user
session_open:    New session \d+ of user
file_access:     openat\(..., "file"
⏱ Timeline Tab
Content:

text
================================================================================
RECENT EVENTS TIMELINE
================================================================================

📋 Latest system logs:
Mar 20 14:30:15 archlinux systemd[1]: Started User Manager for UID 1000.
Mar 20 14:31:22 archlinux sudo[1234]: johndoe : TTY=pts/0 ; COMMAND=/usr/bin/pacman -Syu
Mar 20 14:35:10 archlinux sshd[5678]: Accepted publickey for johndoe from 192.168.1.100

📁 Files modified in last 24h (sample):
2024-03-20 14:30:15 - johndoe - Modified: /home/johndoe/.bash_history
2024-03-20 14:25:30 - root - Created: /etc/systemd/system/custom.service
2024-03-20 13:15:45 - johndoe - Accessed: /home/johndoe/Documents/confidential.txt
Utility:

Temporal event reconstruction

Action sequence identification

Log and file correlation

Detection of off-hours activities

📊 Statistics Tab
Real-Time Metrics:

yaml
🔲 CPU Usage:
  %Cpu(s):  2.5 us,  1.2 sy,  0.0 ni, 96.0 id,  0.3 wa

💾 Memory Usage:
              total        used        free
  Mem:           15G        4.2G         10G
  Swap:         8.0G        1.2G        6.8G

💽 Disk Usage:
  Filesystem      Size  Used Avail Use% Mounted on
  /dev/nvme0n1p2  200G  120G   80G  60% /
  /dev/nvme0n1p4  300G  200G  100G  67% /home

⚙️ Total processes: 287

👤 Logged-in users:
  johndoe  tty1         2024-03-20 09:15
  johndoe  pts/0        2024-03-20 14:30

🌐 Network connections (sample):
  Netid  State      Recv-Q Send-Q Local Address:Port  Peer Address:Port
  tcp    ESTAB      0      0      192.168.1.10:22     192.168.1.100:54321
  tcp    LISTEN     0      128    0.0.0.0:80          0.0.0.0:*

📦 Total installed packages: 1847
🏗️ Architecture
Component Diagram
text
┌─────────────────────────────────────────────────────────────┐
│                    Graphical Interface (Tkinter)             │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐  │
│  │  System  │  Users   │ Services │   Apps   │  Files   │  │
│  ├──────────┼──────────┼──────────┼──────────┼──────────┤  │
│  │   Logs   │ Timeline │   Stats  │  Export  │  Config  │  │
│  └──────────┴──────────┴──────────┴──────────┴──────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Control Layer                             │
│  ┌─────────────────┬─────────────────┬──────────────────┐  │
│  │ Thread Manager  │  Event Handler  │  Queue Manager   │  │
│  └─────────────────┴─────────────────┴──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Data Layer                                │
│  ┌─────────────────┬─────────────────┬──────────────────┐  │
│  │  Data Collection│  Log Parsing    │  Structures      │  │
│  │  (subprocess)   │  (regex)        │  (defaultdict)   │  │
│  └─────────────────┴─────────────────┴──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Operating System                          │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐  │
│  │ /proc    │ /var/log │  pacman  │ systemctl│ journalctl│ │
│  └──────────┴──────────┴──────────┴──────────┴──────────┘  │
└─────────────────────────────────────────────────────────────┘
Code Structure
text
ArchForensicAnalyzer/
│
├── __init__(self, root)
│   ├── Root privilege verification
│   ├── Variable initialization
│   └── GUI creation call
│
├── restart_with_sudo()
│   └── Restart with elevated privileges
│
├── compile_patterns()
│   └── Regular expression compilation
│
├── create_widgets()
│   ├── create_system_tab()
│   ├── create_users_tab()
│   ├── create_services_tab()
│   ├── create_applications_tab()
│   ├── create_files_tab()
│   ├── create_logs_tab()
│   ├── create_timeline_tab()
│   └── create_statistics_tab()
│
├── load_initial_data()
│   ├── load_system_info()
│   ├── load_current_services()
│   ├── load_installed_applications()
│   ├── load_user_activity()
│   ├── update_timeline()
│   └── update_statistics()
│
├── monitor_system()
│   ├── Execute journalctl -f
│   └── Log queueing
│
├── update_display()
│   ├── Log queue consumption
│   └── Interface update
│
├── process_log_line()
│   └── Regex pattern analysis
│
├── scan_recent_files()
│   ├── Directory walk
│   ├── Metadata collection
│   └── Treeview update
│
└── export_full_report()
    ├── Consolidated data collection
    └── JSON file generation
Design Patterns Used
MVC (Model-View-Controller) Adapted

Model: Data structures (self.users, self.file_activities)

View: Tkinter interface

Controller: Callback methods and threading

Observer Pattern

UI update via Tkinter's after()

Data change notification

Producer-Consumer

Monitoring thread produces logs

UI thread consumes and displays

Thread Pool Pattern

Multiple threads for parallel loading

join() for synchronization

Lazy Loading

On-demand data loading

Cache for frequently accessed information

Detailed Data Structures
python
# Users (nested)
self.users = defaultdict(lambda: {
    'last_event': None,           # Last recorded event
    'timestamp': None,            # Last event timestamp
    'services': [],               # Services started by user
    'files_accessed': [],         # Files accessed
    'files_created': [],          # Files created
    'files_deleted': [],          # Files deleted
    'commands': [],               # Commands executed
    'logins': [],                 # Login sessions
    'applications': set(),        # Applications used
    'last_activity': None         # Last activity timestamp
})

# Applications
self.applications = {
    'firefox': {
        'version': '123.0.1-1',
        'type': 'Application',
        'size': '250 MB',
        'install_date': '2024-01-15'
    }
}

# File Activities
self.file_activities = [
    {
        'time': '2024-03-20 14:30:00',
        'user': 'johndoe',
        'action': 'Modified',
        'file': '/home/johndoe/document.txt',
        'size': '1.5 MB',
        'perms': '-rw-r--r--',
        'inode': 12345678,
        'device': '259,2'
    }
]

# Services
self.services = {
    'sshd.service': {
        'status': 'running',
        'pid': 1234,
        'memory': '10.5M',
        'enabled': True
    }
}
🔒 Security
Privileges and Permissions
Requirement: The tool requires root privileges for complete access

Automatic Detection: Identifies if running as root

Privilege Elevation: Offers automatic restart with sudo

Limited Mode: Without root, functionalities are restricted (only public data read)

Usage Best Practices
Controlled Environment

bash
# Run in a VM or container for testing
docker run -it --privileged archlinux /bin/bash
Data Backup

bash
# Backup before deep analysis
sudo tar -czf system_backup_$(date +%Y%m%d).tar.gz /etc /home
Activity Logging

bash
# Keep log of all actions
script -a forensic_session_$(date +%Y%m%d_%H%M%S).log
sudo forense
exit  # To end script
Integrity Verification

bash
# Calculate hash of generated report
sha256sum forensic_report_*.json > report.sha256
Network Isolation

bash
# For sensitive analysis, disconnect from network
sudo ip link set dev eth0 down
Security Considerations
DO NOT run on production systems without authorization

DO NOT share reports without sanitizing sensitive data

ALWAYS verify script integrity before execution

KEEP system updated to avoid false positives

DOCUMENT all actions performed during analysis

Report Sanitization
Before sharing reports, remove sensitive data:

python
# Helper script to sanitize JSON
import json
import re

def sanitize_report(input_file, output_file):
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Remove IPs, passwords, tokens
    sensitive_patterns = [
        (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP_REMOVED]'),
        (r'password[=:]\S+', 'password=[REMOVED]'),
        (r'token[=:]\S+', 'token=[REMOVED]')
    ]
    
    data_str = json.dumps(data)
    for pattern, replacement in sensitive_patterns:
        data_str = re.sub(pattern, replacement, data_str)
    
    with open(output_file, 'w') as f:
        f.write(data_str)

sanitize_report('original.json', 'sanitized.json')
💾 Data Export
JSON Format
The exported report follows this structure:

json
{
  "system_info": {
    "hostname": "archlinux-workstation",
    "kernel": "6.8.1-arch1-1",
    "architecture": "x86_64",
    "uptime": "3 days, 14:23:45",
    "memory": {
      "total": "15Gi",
      "used": "4.2Gi",
      "free": "10Gi"
    },
    "cpu": "Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz"
  },
  "users": {
    "johndoe": {
      "last_event": "login",
      "timestamp": "2024-03-20T14:30:15",
      "commands": ["sudo pacman -Syu", "git clone..."],
      "logins": ["2024-03-20 09:15 from tty1"],
      "applications": ["firefox", "code", "bash"]
    }
  },
  "file_activities": [
    {
      "time": "2024-03-20T14:30:00",
      "user": "johndoe",
      "action": "Modified",
      "file": "/home/johndoe/document.txt",
      "size": "1.5 MB",
      "perms": "-rw-r--r--"
    }
  ],
  "applications": {
    "firefox": {
      "version": "123.0.1-1",
      "type": "Application"
    }
  },
  "timestamp": "2024-03-20T14:45:30.123456"
}
JSON Usage Example
python
# Programmatic report analysis
import json
from datetime import datetime

with open('forensic_report_20240320_144530.json', 'r') as f:
    report = json.load(f)

# List active users
active_users = [
    user for user, data in report['users'].items()
    if data.get('logins')
]

# Find suspicious files
suspicious_files = [
    activity for activity in report['file_activities']
    if activity['file'].startswith('/etc/') 
    and activity['action'] == 'Modified'
]

# Generate executive report
print(f"Report generated at: {report['timestamp']}")
print(f"Active users: {len(active_users)}")
print(f"Modified system files: {len(suspicious_files)}")
🔧 Troubleshooting
Common Errors and Solutions
Error	Cause	Solution
cannot access free variable 'e'	Lambda bug in Python 3.14	Fixed in current version
name 'stat' is not defined	Module not imported	Fixed in current version
Permission denied	Running without sudo	Run with sudo
tkinter not found	Python without Tk support	Install python-tk or tk
journalctl: command not found	systemd not installed	sudo pacman -S systemd
pacman: command not found	Not Arch Linux	This tool is Arch-specific
No module named 'pwd'	Trying to run on Windows	Use Linux only
Interface frozen	File scan too slow	Wait or reduce scan depth
Debug Logs
To run in debug mode:

bash
# Enable detailed logging
export FORENSE_DEBUG=1
sudo -E python3 FORENSEultra.py

# Or redirect stderr
sudo python3 FORENSEultra.py 2> debug.log
Performance Issues
If file scanning is too slow:

Reduce scan depth

Edit line: if root.count(os.sep) - scan_dir.count(os.sep) > 3:

Change 3 to 2 or 1

Limit scanned directories

Comment directories in scan_dirs = ['/home', '/etc', '/var/log']

Increase time cutoff

Change cutoff = time.time() - (24 * 3600) to 12 * 3600

Run with lower nice value

bash
sudo nice -n 19 python3 FORENSEultra.py
🤝 Contributing
How to Contribute
Fork the Repository

bash
git clone https://github.com/OtavioTavaresDev/arch-forensic-analyzer.git
cd arch-forensic-analyzer
git checkout -b feature/new-functionality
Make Your Modifications

Follow PEP 8 code style

Add explanatory comments

Maintain compatibility with Python 3.8+

Test Locally

bash
sudo python3 FORENSEultra.py
Commit and Push

bash
git add .
git commit -m "feat: add new functionality X"
git push origin feature/new-functionality
Open a Pull Request

Describe changes in detail

Include screenshots if applicable

Reference related issues

Style Guide
Commits: Use Conventional Commits

feat: new feature

fix: bug fix

docs: documentation

style: formatting

refactor: refactoring

perf: performance

Code:

Indentation: 4 spaces

Maximum 79 characters per line

Docstrings for public functions

Type hints when possible

Reporting Bugs
Use GitHub Issues with:

Descriptive title

Steps to reproduce

Expected vs actual behavior

Screenshots

Error logs

System version (uname -a)

📄 License
MIT License

Copyright (c) 2024 Arch Linux Forensic Analyzer Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

MIT License Summary
✅ Commercial use: Allowed

✅ Modification: Allowed

✅ Distribution: Allowed

✅ Private use: Allowed

✅ Sublicensing: Allowed

❌ Warranty: Not provided

❌ Liability: Not assumed

👨‍💻 Author
Otávio (and Arch Linux community)

GitHub: @OtavioTavaresDev

Email: otaviotavaresdev@gmail.com

🙏 Acknowledgments
Arch Linux Community - For excellent documentation and support

Python Software Foundation - For the amazing language

Tkinter Team - For the graphical toolkit

Systemd Team - For the init system and journal

Inspirations
The Sleuth Kit - Forensic tools

Autopsy - Forensic interface

Volatility - Memory analysis

<div align="center">
⭐ If this project was useful, consider giving it a star on GitHub! ⭐
</div> ```

