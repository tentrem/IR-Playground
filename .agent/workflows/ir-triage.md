---
description: Fast Triage for Isolation Decision - target < 5 menit
---

# Quick IR Triage

**Target waktu: < 5 menit untuk keputusan isolasi**

## Step 1: Quick System Check

Ganti `TARGET` dengan IP/hostname server yang akan di-triage.

### Linux

```bash
ssh TARGET "
  echo '=== SYSTEM INFO ==='
  uname -a; hostname; uptime
  
  echo '=== SUSPICIOUS PROCESSES ==='
  ps aux | grep -E 'nc |ncat|wget|curl|python.*-c|bash.*-i|/tmp/|/dev/shm/'
  
  echo '=== ACTIVE CONNECTIONS ==='
  netstat -tulpn 2>/dev/null || ss -tulpn
  
  echo '=== RECENT LOGINS ==='
  last -20
  
  echo '=== CRON JOBS ==='
  crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null
  
  echo '=== SUSPICIOUS FILES (last 24h) ==='
  find /tmp /var/tmp /dev/shm -type f -mtime -1 2>/dev/null | head -20
"
```

### Windows (via PowerShell remoting)

```powershell
Invoke-Command -ComputerName TARGET -ScriptBlock {
    Write-Host "=== SYSTEM INFO ==="
    Get-ComputerInfo | Select-Object CsName, WindowsVersion, OsUptime
    
    Write-Host "=== SUSPICIOUS PROCESSES ==="
    Get-Process | Where-Object {$_.Path -like "*temp*" -or $_.Path -like "*appdata*"} | Select-Object Name, Path, Id
    
    Write-Host "=== NETWORK CONNECTIONS ==="
    Get-NetTCPConnection | Where-Object State -eq 'Established' | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
    
    Write-Host "=== RECENT LOGINS ==="
    Get-WinEvent -LogName Security -MaxEvents 50 | Where-Object Id -eq 4624 | Select-Object TimeCreated, Message
}
```

## Step 2: AI Quick Analysis

Copy output dari Step 1, lalu tanyakan ke AI:

```
Analisis output triage berikut dan jawab:
1. Ada proses suspicious? (reverse shell, miners, downloaders)
2. Ada koneksi ke IP external unknown?
3. Ada login anomaly?
4. Rekomendasi: ISOLATE atau MONITOR?

Output:
[PASTE OUTPUT DISINI]
```

## Step 3: Isolation Decision

| Indikator | Action |
|-----------|--------|
| Reverse shell detected | 🔴 ISOLATE SEGERA |
| Unknown outbound connection | 🔴 ISOLATE SEGERA |
| Crypto miner process | 🟡 ISOLATE, bisa scheduled |
| Suspicious files in /tmp | 🟡 Investigate further |
| No anomaly found | 🟢 Continue monitoring |

## Step 4: Execute Isolation (if needed)

### Linux Isolation

```bash
# Block semua traffic kecuali dari IP Anda
ssh TARGET "
  iptables -I INPUT -j DROP
  iptables -I OUTPUT -j DROP
  iptables -I INPUT -s YOUR_ANALYST_IP -j ACCEPT
  iptables -I OUTPUT -d YOUR_ANALYST_IP -j ACCEPT
"
```

### Windows Isolation

```powershell
# Via Windows Firewall
Invoke-Command -ComputerName TARGET -ScriptBlock {
    New-NetFirewallRule -DisplayName "IR-BlockAll-In" -Direction Inbound -Action Block
    New-NetFirewallRule -DisplayName "IR-BlockAll-Out" -Direction Outbound -Action Block
    New-NetFirewallRule -DisplayName "IR-AllowAnalyst" -Direction Inbound -RemoteAddress YOUR_ANALYST_IP -Action Allow
    New-NetFirewallRule -DisplayName "IR-AllowAnalyst-Out" -Direction Outbound -RemoteAddress YOUR_ANALYST_IP -Action Allow
}
```

## Step 5: Next Steps

Setelah isolasi:

- [ ] Notifikasi ke team/management
- [ ] Lanjut ke deep analysis → `/ir-linux` atau `/ir-windows`
- [ ] Start evidence collection → `/ir-collect-evidence`
