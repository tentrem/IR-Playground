---
description: Windows Server Incident Response Playbook
---

# Windows IR Playbook

Workflow untuk incident response pada Windows server. Commands dijalankan via PowerShell Remoting dari workstation Anda.

## Prerequisites

- [ ] PowerShell Remoting enabled di target
- [ ] Admin credentials ke target server
- [ ] Evidence folder sudah disiapkan

```powershell
# Setup evidence folder
$CaseID = "IR-$(Get-Date -Format 'yyyyMMdd-HHmm')"
$Target = "TARGET_HOSTNAME"
$EvidenceDir = "C:\Evidence\$CaseID"
New-Item -ItemType Directory -Force -Path "$EvidenceDir\system","$EvidenceDir\users","$EvidenceDir\network","$EvidenceDir\processes","$EvidenceDir\files","$EvidenceDir\logs","$EvidenceDir\registry"
```

---

## 1. System Information

```powershell
Invoke-Command -ComputerName $Target -ScriptBlock {
    Write-Output "=== SYSTEM INFO ==="
    Get-ComputerInfo | Select-Object CsName, WindowsVersion, WindowsBuildLabEx, OsUptime, TimeZone
    
    Write-Output "=== INSTALLED UPDATES ==="
    Get-HotFix | Select-Object HotFixID, InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 20
    
    Write-Output "=== INSTALLED SOFTWARE ==="
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Select-Object DisplayName, DisplayVersion, InstallDate | Sort-Object InstallDate -Descending
} | Out-File "$EvidenceDir\system\info.txt"
```

---

## 2. User & Authentication

```powershell
Invoke-Command -ComputerName $Target -ScriptBlock {
    Write-Output "=== LOCAL USERS ==="
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet
    
    Write-Output "=== LOCAL ADMINS ==="
    Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource
    
    Write-Output "=== RECENT LOGONS (Event 4624) ==="
    Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 100 | 
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            [PSCustomObject]@{
                Time = $_.TimeCreated
                User = $xml.Event.EventData.Data[5].'#text'
                LogonType = $xml.Event.EventData.Data[8].'#text'
                SourceIP = $xml.Event.EventData.Data[18].'#text'
            }
        } | Format-Table
    
    Write-Output "=== FAILED LOGONS (Event 4625) ==="
    Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 50 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            [PSCustomObject]@{
                Time = $_.TimeCreated
                User = $xml.Event.EventData.Data[5].'#text'
                SourceIP = $xml.Event.EventData.Data[19].'#text'
            }
        } | Format-Table
} | Out-File "$EvidenceDir\users\auth.txt"
```

---

## 3. Processes & Services

```powershell
Invoke-Command -ComputerName $Target -ScriptBlock {
    Write-Output "=== RUNNING PROCESSES ==="
    Get-Process | Select-Object Name, Id, Path, StartTime, CPU | Sort-Object StartTime -Descending | Format-Table -AutoSize
    
    Write-Output "=== PROCESSES WITH COMMAND LINE ==="
    Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine | Format-List
    
    Write-Output "=== SUSPICIOUS PROCESS PATHS ==="
    Get-Process | Where-Object {
        $_.Path -like "*\Temp\*" -or 
        $_.Path -like "*\AppData\*" -or 
        $_.Path -like "*\Downloads\*" -or
        $_.Path -like "*\ProgramData\*"
    } | Select-Object Name, Id, Path
    
    Write-Output "=== SERVICES ==="
    Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, StartType
    
    Write-Output "=== NON-MICROSOFT SERVICES ==="
    Get-CimInstance Win32_Service | Where-Object {$_.PathName -notlike "*\Windows\*"} | 
        Select-Object Name, State, PathName
} | Out-File "$EvidenceDir\processes\processes.txt"
```

---

## 4. Network Connections

```powershell
Invoke-Command -ComputerName $Target -ScriptBlock {
    Write-Output "=== ESTABLISHED CONNECTIONS ==="
    Get-NetTCPConnection | Where-Object State -eq 'Established' | 
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
            @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
        Format-Table -AutoSize
    
    Write-Output "=== LISTENING PORTS ==="
    Get-NetTCPConnection | Where-Object State -eq 'Listen' |
        Select-Object LocalAddress, LocalPort, OwningProcess,
            @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
        Format-Table -AutoSize
    
    Write-Output "=== DNS CACHE ==="
    Get-DnsClientCache | Select-Object Entry, Data
    
    Write-Output "=== ARP TABLE ==="
    Get-NetNeighbor | Where-Object State -ne 'Permanent' | Select-Object IPAddress, LinkLayerAddress, State
    
    Write-Output "=== HOSTS FILE ==="
    Get-Content C:\Windows\System32\drivers\etc\hosts | Where-Object {$_ -notmatch "^#" -and $_ -ne ""}
    
    Write-Output "=== FIREWALL RULES ==="
    Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound'} |
        Select-Object Name, Action, Profile | Format-Table -AutoSize
} | Out-File "$EvidenceDir\network\network.txt"
```

---

## 5. Persistence Mechanisms

```powershell
Invoke-Command -ComputerName $Target -ScriptBlock {
    Write-Output "=== SCHEDULED TASKS ==="
    Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} |
        Select-Object TaskName, TaskPath, State | Format-Table -AutoSize
    
    Write-Output "=== SCHEDULED TASKS DETAILS ==="
    Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | ForEach-Object {
        $task = $_
        $actions = $task | Get-ScheduledTaskInfo
        [PSCustomObject]@{
            Name = $task.TaskName
            Path = $task.TaskPath
            Action = ($task.Actions | Select-Object -First 1).Execute
            Arguments = ($task.Actions | Select-Object -First 1).Arguments
            LastRun = $actions.LastRunTime
        }
    } | Format-List
    
    Write-Output "=== STARTUP PROGRAMS (Registry) ==="
    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue
    Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
    Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue
    
    Write-Output "=== STARTUP FOLDER ==="
    Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -ErrorAction SilentlyContinue
    Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue
    
    Write-Output "=== WMI SUBSCRIPTIONS ==="
    Get-WMIObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue
    Get-WMIObject -Namespace root\Subscription -Class __EventConsumer -ErrorAction SilentlyContinue
    Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
} | Out-File "$EvidenceDir\files\persistence.txt"
```

---

## 6. File System Analysis

```powershell
Invoke-Command -ComputerName $Target -ScriptBlock {
    Write-Output "=== RECENT FILES (24h) ==="
    Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | 
        Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-24)} |
        Select-Object FullName, LastWriteTime, Length | 
        Sort-Object LastWriteTime -Descending | Select-Object -First 100
    
    Write-Output "=== TEMP FILES ==="
    Get-ChildItem -Path "C:\Windows\Temp", "C:\Users\*\AppData\Local\Temp" -Recurse -ErrorAction SilentlyContinue |
        Select-Object FullName, LastWriteTime, Length | Sort-Object LastWriteTime -Descending
    
    Write-Output "=== EXECUTABLE IN TEMP ==="
    Get-ChildItem -Path "C:\Windows\Temp", "C:\Users\*\AppData\Local\Temp" -Recurse -Include *.exe,*.dll,*.ps1,*.bat,*.cmd,*.vbs -ErrorAction SilentlyContinue |
        Select-Object FullName, LastWriteTime
    
    Write-Output "=== ALTERNATE DATA STREAMS ==="
    Get-ChildItem -Path C:\Users -Recurse -ErrorAction SilentlyContinue | 
        Get-Item -Stream * -ErrorAction SilentlyContinue | 
        Where-Object Stream -ne ':$DATA' | Select-Object FileName, Stream
    
    Write-Output "=== PREFETCH ==="
    Get-ChildItem C:\Windows\Prefetch -ErrorAction SilentlyContinue | 
        Select-Object Name, LastWriteTime | Sort-Object LastWriteTime -Descending | Select-Object -First 50
} | Out-File "$EvidenceDir\files\filesystem.txt"
```

---

## 7. Event Log Collection

```powershell
# Security Log
Invoke-Command -ComputerName $Target -ScriptBlock {
    Get-WinEvent -LogName Security -MaxEvents 5000
} | Export-Clixml "$EvidenceDir\logs\Security.xml"

# System Log
Invoke-Command -ComputerName $Target -ScriptBlock {
    Get-WinEvent -LogName System -MaxEvents 5000
} | Export-Clixml "$EvidenceDir\logs\System.xml"

# PowerShell Log
Invoke-Command -ComputerName $Target -ScriptBlock {
    Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 2000 -ErrorAction SilentlyContinue
} | Export-Clixml "$EvidenceDir\logs\PowerShell.xml"

# Sysmon (if installed)
Invoke-Command -ComputerName $Target -ScriptBlock {
    Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5000 -ErrorAction SilentlyContinue
} | Export-Clixml "$EvidenceDir\logs\Sysmon.xml"
```

---

## 8. Registry Analysis

```powershell
Invoke-Command -ComputerName $Target -ScriptBlock {
    Write-Output "=== USERASSIST (User Activity) ==="
    Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count" -ErrorAction SilentlyContinue
    
    Write-Output "=== RECENT DOCS ==="
    Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -ErrorAction SilentlyContinue
    
    Write-Output "=== TYPED PATHS ==="
    Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -ErrorAction SilentlyContinue
    
    Write-Output "=== RUN MRU ==="
    Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue
    
    Write-Output "=== SHELL BAGS ==="
    Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\Shell\BagMRU" -ErrorAction SilentlyContinue
} | Out-File "$EvidenceDir\registry\registry.txt"

# Export full registry hives (for offline analysis)
Invoke-Command -ComputerName $Target -ScriptBlock {
    reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM.hiv /y
    reg save HKLM\SAM C:\Windows\Temp\SAM.hiv /y
    reg save HKLM\SOFTWARE C:\Windows\Temp\SOFTWARE.hiv /y
}
# Copy to evidence
Copy-Item -Path "\\$Target\C$\Windows\Temp\*.hiv" -Destination "$EvidenceDir\registry\" -Force
```

---

## 9. Memory Dump (Optional)

```powershell
# Menggunakan built-in Windows tools
Invoke-Command -ComputerName $Target -ScriptBlock {
    # Task Manager can create dump, or use procdump
    # For full memory, need third-party tools like WinPMEM
    
    # Dump specific suspicious process
    $proc = Get-Process -Name "suspicious_process" -ErrorAction SilentlyContinue
    if ($proc) {
        $dumpPath = "C:\Windows\Temp\$($proc.Name)_$($proc.Id).dmp"
        # Requires procdump.exe pre-staged
        # & C:\Tools\procdump.exe -ma $proc.Id $dumpPath
    }
}
```

---

## 10. Isolation Commands

```powershell
# ISOLATE - Block all except analyst IP
Invoke-Command -ComputerName $Target -ScriptBlock {
    param($AnalystIP)
    
    # Block all inbound
    New-NetFirewallRule -DisplayName "IR-BlockAll-In" -Direction Inbound -Action Block -Enabled True
    # Block all outbound  
    New-NetFirewallRule -DisplayName "IR-BlockAll-Out" -Direction Outbound -Action Block -Enabled True
    # Allow analyst
    New-NetFirewallRule -DisplayName "IR-AllowAnalyst-In" -Direction Inbound -RemoteAddress $AnalystIP -Action Allow -Enabled True
    New-NetFirewallRule -DisplayName "IR-AllowAnalyst-Out" -Direction Outbound -RemoteAddress $AnalystIP -Action Allow -Enabled True
} -ArgumentList "YOUR_ANALYST_IP"

# REMOVE ISOLATION
Invoke-Command -ComputerName $Target -ScriptBlock {
    Remove-NetFirewallRule -DisplayName "IR-BlockAll-In" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "IR-BlockAll-Out" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "IR-AllowAnalyst-In" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "IR-AllowAnalyst-Out" -ErrorAction SilentlyContinue
}
```

---

## 11. AI Analysis

Setelah collection selesai, minta AI untuk analisis:

```
Analisis evidence Windows IR berikut:

1. auth.txt - cari login anomaly, brute force
2. processes.txt - cari proses suspicious
3. network.txt - cari koneksi C2
4. persistence.txt - cari backdoor

[PASTE CONTENT FILE DISINI]

Identifikasi:
- IOCs
- Timeline
- MITRE ATT&CK mapping
- Recommended actions
```

---

## 12. Checklist Summary

- [ ] System info collected
- [ ] User/auth data documented
- [ ] Processes captured
- [ ] Network connections recorded
- [ ] Persistence mechanisms checked
- [ ] File system analyzed
- [ ] Event logs exported
- [ ] Registry analyzed
- [ ] Memory dump (if needed)
- [ ] AI analysis completed
- [ ] Report generated → `/ir-report-template`
