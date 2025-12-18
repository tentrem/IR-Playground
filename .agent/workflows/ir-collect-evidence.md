---
description: Evidence Collection Scripts untuk IR (Remote-Safe)
---

# IR Evidence Collection

Semua script dibawah ini didesain untuk dijalankan dari **LOCAL WORKSTATION** via SSH. Tidak perlu install tools di target server.

## Quick Setup

```bash
# Buat folder evidence dengan timestamp
CASE_ID="IR-$(date +%Y%m%d-%H%M)"
TARGET="user@server-ip"
mkdir -p evidence/$CASE_ID/{system,users,network,processes,files,logs,memory}
cd evidence/$CASE_ID
```

## Linux Evidence Collection

### One-liner Quick Collection

```bash
# Collect semua basic info dalam satu command
ssh $TARGET "
tar czf - \
  /etc/passwd /etc/shadow /etc/group /etc/sudoers \
  /etc/crontab /etc/cron.* \
  /var/log/auth.log /var/log/syslog /var/log/secure \
  /home/*/.bash_history \
  2>/dev/null
" > linux_evidence.tar.gz
```

### Detailed Collection Script

```bash
#!/bin/bash
# Save as: collect_linux.sh
# Usage: ./collect_linux.sh user@target

TARGET=$1
OUTDIR="evidence/$(date +%Y%m%d)_linux"
mkdir -p $OUTDIR/{system,users,network,processes,files,logs}

echo "[*] Collecting system info..."
ssh $TARGET "uname -a; hostname; uptime; date" > $OUTDIR/system/info.txt

echo "[*] Collecting user data..."
ssh $TARGET "cat /etc/passwd; echo '---'; last -100" > $OUTDIR/users/users.txt

echo "[*] Collecting network data..."
ssh $TARGET "netstat -tulpn; echo '---'; ss -tulpn" > $OUTDIR/network/connections.txt

echo "[*] Collecting processes..."
ssh $TARGET "ps auxf" > $OUTDIR/processes/ps.txt

echo "[*] Collecting recent files..."
ssh $TARGET "find /tmp /var/tmp /dev/shm -type f -mtime -7 2>/dev/null" > $OUTDIR/files/recent.txt

echo "[*] Collecting logs..."
ssh $TARGET "cat /var/log/auth.log 2>/dev/null || cat /var/log/secure" > $OUTDIR/logs/auth.log

echo "[+] Collection complete: $OUTDIR"
```

## Windows Evidence Collection

### PowerShell Remote Collection

```powershell
# Save as: Collect-WindowsEvidence.ps1
# Usage: .\Collect-WindowsEvidence.ps1 -Target "servername"

param(
    [Parameter(Mandatory=$true)]
    [string]$Target
)

$OutDir = "evidence\$(Get-Date -Format 'yyyyMMdd')_windows"
New-Item -ItemType Directory -Force -Path "$OutDir\system","$OutDir\users","$OutDir\network","$OutDir\processes","$OutDir\logs"

Write-Host "[*] Collecting system info..."
Invoke-Command -ComputerName $Target -ScriptBlock {
    Get-ComputerInfo | Select-Object CsName, WindowsVersion, OsUptime
} | Out-File "$OutDir\system\info.txt"

Write-Host "[*] Collecting user data..."
Invoke-Command -ComputerName $Target -ScriptBlock {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon
    Get-WinEvent -LogName Security -MaxEvents 100 | Where-Object Id -eq 4624
} | Out-File "$OutDir\users\users.txt"

Write-Host "[*] Collecting network data..."
Invoke-Command -ComputerName $Target -ScriptBlock {
    Get-NetTCPConnection | Where-Object State -eq 'Established'
} | Out-File "$OutDir\network\connections.txt"

Write-Host "[*] Collecting processes..."
Invoke-Command -ComputerName $Target -ScriptBlock {
    Get-Process | Select-Object Name, Id, Path, StartTime
} | Out-File "$OutDir\processes\processes.txt"

Write-Host "[*] Collecting event logs..."
Invoke-Command -ComputerName $Target -ScriptBlock {
    Get-WinEvent -LogName Security -MaxEvents 1000
    Get-WinEvent -LogName System -MaxEvents 1000
} | Out-File "$OutDir\logs\events.txt"

Write-Host "[+] Collection complete: $OutDir"
```

### WMI Collection (alternative)

```powershell
# Jika PowerShell remoting tidak available
Get-WmiObject -ComputerName $Target -Class Win32_Process | 
    Select-Object Name, ProcessId, CommandLine | 
    Export-Csv "$OutDir\processes\wmi_processes.csv"
```

## Hash Verification

Selalu hash evidence untuk integrity:

```bash
# Linux
find evidence/ -type f -exec sha256sum {} \; > evidence/hashes.sha256

# Verify later
sha256sum -c evidence/hashes.sha256
```

```powershell
# Windows
Get-ChildItem -Recurse evidence\ | Get-FileHash -Algorithm SHA256 | 
    Export-Csv evidence\hashes.csv
```

## Chain of Custody Log

Buat file log untuk setiap evidence:

```bash
cat << EOF > evidence/$CASE_ID/chain_of_custody.txt
Case ID: $CASE_ID
Date/Time Collected: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Collected By: [YOUR NAME]
Source System: $TARGET
Collection Method: Remote SSH/PowerShell
Evidence Hash: [SEE hashes.sha256]

Notes:
- [Add any relevant notes]
EOF
```

## Post-Collection: AI Analysis

Setelah collection, gunakan AI untuk analisis:

```
Saya sudah collect evidence IR dari server Linux. Tolong analisis:

1. File: users.txt
[PASTE CONTENT]

2. File: connections.txt  
[PASTE CONTENT]

3. File: ps.txt
[PASTE CONTENT]

Identifikasi:
- IOCs (IP, hash, domain)
- Suspicious activities
- Timeline of events
- Recommended next steps
```
