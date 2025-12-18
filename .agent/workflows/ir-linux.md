---
description: Linux Server Incident Response Playbook
---

# Linux IR Playbook

Workflow untuk incident response pada Linux server. Semua command dijalankan via SSH dari workstation Anda.

## Prerequisites

- [ ] SSH access ke target server
- [ ] Evidence folder sudah disiapkan di local
- [ ] Server sudah di-isolate (jika diperlukan)

```bash
# Setup evidence folder
mkdir -p evidence/$(date +%Y%m%d)_TARGET_HOSTNAME
cd evidence/$(date +%Y%m%d)_TARGET_HOSTNAME
```

## 1. System Information

```bash
ssh TARGET "
  echo '### HOSTNAME ###' && hostname
  echo '### UNAME ###' && uname -a
  echo '### UPTIME ###' && uptime
  echo '### DATE ###' && date
  echo '### TIMEZONE ###' && cat /etc/timezone 2>/dev/null || timedatectl
" > 01_system_info.txt
```

## 2. User & Authentication

```bash
ssh TARGET "
  echo '### PASSWD ###' && cat /etc/passwd
  echo '### SHADOW ###' && sudo cat /etc/shadow 2>/dev/null
  echo '### GROUP ###' && cat /etc/group
  echo '### SUDOERS ###' && sudo cat /etc/sudoers 2>/dev/null
  echo '### LAST LOGINS ###' && last -100
  echo '### FAILED LOGINS ###' && lastb -100 2>/dev/null
  echo '### WHO ###' && who
  echo '### W ###' && w
" > 02_users_auth.txt
```

## 3. Process & Services

```bash
ssh TARGET "
  echo '### PS AUX ###' && ps auxf
  echo '### PSTREE ###' && pstree -p
  echo '### TOP SNAPSHOT ###' && top -bn1
  echo '### SERVICES ###' && systemctl list-units --type=service --all 2>/dev/null || service --status-all
" > 03_processes.txt
```

## 4. Network

```bash
ssh TARGET "
  echo '### NETSTAT ###' && netstat -tulpn 2>/dev/null || ss -tulpn
  echo '### ESTABLISHED ###' && netstat -an | grep ESTABLISHED
  echo '### ROUTING ###' && route -n 2>/dev/null || ip route
  echo '### ARP ###' && arp -a 2>/dev/null || ip neigh
  echo '### IPTABLES ###' && sudo iptables -L -n -v 2>/dev/null
  echo '### HOSTS ###' && cat /etc/hosts
  echo '### RESOLV ###' && cat /etc/resolv.conf
" > 04_network.txt
```

## 5. Persistence Mechanisms

```bash
ssh TARGET "
  echo '### CRONTAB ROOT ###' && sudo crontab -l 2>/dev/null
  echo '### CRONTAB ALL USERS ###' && for user in \$(cut -f1 -d: /etc/passwd); do echo \"--- \$user ---\"; sudo crontab -u \$user -l 2>/dev/null; done
  echo '### CRON DIRS ###' && ls -la /etc/cron.* 2>/dev/null
  echo '### SYSTEMD SERVICES ###' && ls -la /etc/systemd/system/
  echo '### RC.LOCAL ###' && cat /etc/rc.local 2>/dev/null
  echo '### INIT.D ###' && ls -la /etc/init.d/
  echo '### BASHRC ###' && cat /etc/bash.bashrc 2>/dev/null
  echo '### PROFILE ###' && cat /etc/profile
" > 05_persistence.txt
```

## 6. File System

```bash
ssh TARGET "
  echo '### RECENT FILES (24h) ###' && find / -type f -mtime -1 2>/dev/null | head -500
  echo '### SUID FILES ###' && find / -perm -4000 -type f 2>/dev/null
  echo '### SGID FILES ###' && find / -perm -2000 -type f 2>/dev/null
  echo '### WORLD WRITABLE ###' && find / -perm -0002 -type f 2>/dev/null | head -100
  echo '### TMP FILES ###' && ls -la /tmp /var/tmp /dev/shm 2>/dev/null
  echo '### HIDDEN FILES ###' && find / -name '.*' -type f 2>/dev/null | head -200
" > 06_filesystem.txt
```

## 7. Logs Collection

```bash
# Auth logs
ssh TARGET "cat /var/log/auth.log 2>/dev/null || cat /var/log/secure" > logs/auth.log

# Syslog
ssh TARGET "cat /var/log/syslog 2>/dev/null || cat /var/log/messages" > logs/syslog.log

# Kernel
ssh TARGET "dmesg" > logs/dmesg.log

# Audit (if enabled)
ssh TARGET "cat /var/log/audit/audit.log 2>/dev/null" > logs/audit.log

# Web logs (if applicable)
ssh TARGET "cat /var/log/apache2/access.log 2>/dev/null" > logs/apache_access.log
ssh TARGET "cat /var/log/nginx/access.log 2>/dev/null" > logs/nginx_access.log
```

## 8. Memory Dump (Optional - requires tools)

```bash
# Jika LiME sudah terinstall di target (pre-staged)
ssh TARGET "sudo insmod /path/to/lime.ko 'path=/tmp/memdump.lime format=lime'"
scp TARGET:/tmp/memdump.lime ./memory/
```

## 9. AI Analysis

Setelah collection selesai, minta AI untuk analisis:

```
Analisis file-file evidence berikut dari Linux IR:
1. 02_users_auth.txt - cari user baru/suspicious
2. 03_processes.txt - cari proses mencurigakan
3. 04_network.txt - cari koneksi C2
4. 05_persistence.txt - cari backdoor

[PASTE CONTENT FILE DISINI]
```

## 10. Checklist Summary

- [ ] System info collected
- [ ] User accounts documented
- [ ] Processes captured
- [ ] Network connections recorded
- [ ] Persistence mechanisms checked
- [ ] Recent files listed
- [ ] Logs collected
- [ ] AI analysis completed
- [ ] Report generated → `/ir-report-template`
