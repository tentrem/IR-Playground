# Incident Response (IR) Knowledge Base

Dokumentasi lengkap tentang best practices Incident Response menggunakan AI dan Workflows.

---

## 📋 Daftar Isi

1. [Arsitektur IR dengan AI](#arsitektur-ir-dengan-ai)
2. [3 Layer Approach](#3-layer-approach)
3. [Hybrid Approach: Speed vs Integrity](#hybrid-approach)
4. [Workflow Execution Patterns](#workflow-execution-patterns)
5. [Prompt Templates untuk IR](#prompt-templates)
6. [Quick Triage Commands](#quick-triage-commands)

---

## Arsitektur IR dengan AI

```
┌─────────────────────────────────────────────────────────────┐
│                    IR WORKFLOW SYSTEM                        │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │  DETECTION   │───▶│   TRIAGE     │───▶│ CONTAINMENT  │   │
│  │  (Trellix)   │    │  (AI+Human)  │    │  (Playbook)  │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│         │                   │                   │           │
│         ▼                   ▼                   ▼           │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │  ERADICATION │◀───│  RECOVERY    │◀───│   LESSONS    │   │
│  │  (Playbook)  │    │  (Checklist) │    │   LEARNED    │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Kapan IDE Agent Cocok untuk IR

| Aspek | Cocok ✅ | Tidak Cocok ❌ |
|-------|----------|----------------|
| Jump Host / Bastion | ✅ | |
| Analisis Log (exported) | ✅ | |
| Dokumentasi & Playbook | ✅ | |
| Post-Incident Analysis | ✅ | |
| Detection Engineering | ✅ | |
| | | Live investigation di server compromised ❌ |
| | | Forensic preservation ❌ |
| | | Isolated environment ❌ |

---

## 3 Layer Approach

> **Prinsip Utama: Jangan install/copy tools ke server yang compromised!**

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: LOCAL WORKSTATION (Full Setup)                    │
│  ├── IDE + AI Agent                                         │
│  ├── .agent/workflows/ (semua IR playbooks)                 │
│  ├── Analysis tools                                         │
│  └── Evidence storage                                       │
│                          ▲                                  │
│                          │ Evidence transfer                │
└──────────────────────────│──────────────────────────────────┘
                           │
┌──────────────────────────│──────────────────────────────────┐
│  LAYER 2: JUMP HOST / ANALYSIS SERVER (Minimal Setup)       │
│  ├── SSH access ke target                                   │
│  ├── Collection scripts (pre-approved)                      │
│  └── Staging area untuk evidence                            │
│                          ▲                                  │
│                          │ Remote commands only             │
└──────────────────────────│──────────────────────────────────┘
                           │
┌──────────────────────────│──────────────────────────────────┐
│  LAYER 3: TARGET SERVER (ZERO INSTALLATION!)                │
│  └── Hanya jalankan read-only commands via SSH              │
└─────────────────────────────────────────────────────────────┘
```

| Layer | Boleh Install | Fungsi |
|-------|---------------|--------|
| Local Workstation | ✅ Full setup | Analisis, AI, workflows |
| Jump Host | ✅ Minimal | Staging, collection scripts |
| Target Server | ❌ TIDAK | Hanya SSH commands |

---

## Hybrid Approach

Trade-off antara **kecepatan** vs **forensic integrity**:

```
┌─────────────────────────────────────────────────────────────┐
│  FASE 1: TRIAGE CEPAT (Di Server - Read Only)               │
│  ├── Quick commands via SSH (1-5 menit)                     │
│  └── Keputusan: Isolate YES/NO?                             │
├─────────────────────────────────────────────────────────────┤
│  FASE 2: ISOLASI (Immediate Action)                         │
│  └── Blokir network / Quarantine                            │
├─────────────────────────────────────────────────────────────┤
│  FASE 3: DEEP ANALYSIS (Di Local - Take Your Time)          │
│  ├── Transfer full evidence                                 │
│  └── Analisis mendalam dengan AI                            │
└─────────────────────────────────────────────────────────────┘
```

### Perbandingan Waktu

| Approach | Waktu Triage | Waktu ke Isolasi | Risk |
|----------|--------------|------------------|------|
| **Full Local Analysis** | 30-60 min | Lambat ❌ | Attacker bisa exfiltrate |
| **Hybrid (Recommended)** | 2-5 min | Cepat ✅ | Minimal |
| **No Triage, Langsung Isolate** | 0 min | Instant | Bisa false positive |

---

## Workflow Execution Patterns

### Pattern A: Remote Command via SSH (Recommended)

```bash
# Dari LOCAL, execute command di TARGET via SSH
# Workflow tetap di local, hanya command yang dikirim

ssh user@target "cat /var/log/auth.log" > evidence/auth.log
ssh user@target "ps aux" > evidence/processes.txt
ssh user@target "netstat -tulpn" > evidence/network.txt
```

### Pattern B: Pipe Evidence ke Local

```bash
# Collect dan langsung analisis di local
ssh user@target "cat /var/log/syslog" | grep -E "failed|error|denied"

# Atau simpan dulu baru analisis dengan AI
ssh user@target "journalctl -u sshd --since '24 hours ago'" > evidence/ssh.log
```

### Pattern C: Jump Host dengan Pre-staged Tools

```bash
# Di JUMP HOST (bukan target!), siapkan tools
scp -r ~/.agent/workflows analysis-server:~/.agent/
scp collection-scripts/* analysis-server:~/tools/

# Dari jump host, execute ke target
ssh -J jump-host target-server "command"
```

---

## Prompt Templates

### IOC Extraction

```
Analisis log berikut dan extract:
1. IP addresses (internal & external)
2. Domain names
3. File hashes (MD5/SHA256)
4. User accounts involved
5. Timestamps (dalam format UTC)

Log:
[paste log disini]
```

### Timeline Reconstruction

```
Buat timeline kronologis dari incident berdasarkan log berikut.
Format: [Timestamp] - [Action] - [Actor] - [Target]

Log:
[paste log disini]
```

### Detection Rule Generation

```
Berdasarkan IOC dan TTP dari incident ini:
[list IOC/TTP]

Buatkan:
1. Trellix ESM correlation rule
2. YARA rule untuk file detection
3. Sigma rule untuk SIEM lain
```

---

## Quick Triage Commands

### Linux Quick Triage (< 5 menit)

```bash
ssh TARGET "
  echo '=== SUSPICIOUS PROCESSES ==='
  ps aux | grep -E 'nc |ncat|wget|curl|python.*-c|bash.*-i'
  
  echo '=== ACTIVE CONNECTIONS ==='
  netstat -tulpn | grep ESTABLISHED
  
  echo '=== RECENT LOGINS ==='
  last -20
  
  echo '=== CRON JOBS ==='
  crontab -l 2>/dev/null; cat /etc/crontab
  
  echo '=== SUSPICIOUS FILES (last 24h) ==='
  find /tmp /var/tmp /dev/shm -type f -mtime -1 2>/dev/null
"
```

### Isolation Commands

```bash
# Option A: Network isolation via firewall
ssh TARGET "iptables -I INPUT -j DROP; iptables -I OUTPUT -j DROP"
# Whitelist IP Anda
ssh TARGET "iptables -I INPUT -s YOUR_IP -j ACCEPT; iptables -I OUTPUT -d YOUR_IP -j ACCEPT"

# Option B: Disable network interface (lebih extreme)
ssh TARGET "ip link set eth0 down"
```

### Evidence Collection

```bash
# Transfer evidence
scp -r TARGET:/var/log/* evidence/logs/
scp TARGET:/etc/passwd evidence/

# Atau compress dulu untuk transfer lebih cepat
ssh TARGET "tar czf /tmp/evidence.tar.gz /var/log /etc/passwd /etc/crontab"
scp TARGET:/tmp/evidence.tar.gz evidence/
```

---

## Struktur Workflows yang Disarankan

```
.agent/workflows/
├── ir-main.md              # Main IR workflow entry point
├── ir-triage.md            # Triage & classification
├── ir-windows.md           # Windows-specific playbook
├── ir-linux.md             # Linux-specific playbook
├── ir-malware.md           # Malware analysis workflow
├── ir-phishing.md          # Phishing incident workflow
├── ir-ransomware.md        # Ransomware response
├── ir-collect-evidence.md  # Evidence collection guides
└── ir-report-template.md   # Incident report template
```

---

## Cara Sinkronisasi Workflows ke Server

| Skenario | Solusi |
|----------|--------|
| **Target server** | JANGAN install apapun, SSH commands only |
| **Jump host** | Boleh install tools/workflows |
| **Local workstation** | Full setup, analisis disini |
| **Evidence** | Transfer ke local, analisis dengan AI |

### Opsi Sinkronisasi untuk Jump Host

1. **Git Repository** - `git clone` di jump host
2. **Rsync/SCP** - `rsync -avz ~/.agent/workflows/ user@jump:~/.agent/workflows/`
3. **Dotfiles Manager** - chezmoi/yadm untuk setup konsisten

---

## Bantuan AI untuk Setiap Fase IR

| Fase IR | Bantuan AI |
|---------|------------|
| **Detection** | Korelasi alert, anomaly detection |
| **Triage** | Analisis log, IOC extraction, severity assessment |
| **Investigation** | Timeline reconstruction, root cause analysis |
| **Containment** | Suggest blocking rules, isolation steps |
| **Recovery** | Checklist validation, config review |
| **Lessons Learned** | Generate report, detection rule improvement |
