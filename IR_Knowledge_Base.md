# Incident Response (IR) Knowledge Base

Panduan lengkap untuk menangani insiden keamanan siber menggunakan AI dan Workflows.

---

## 🚀 Mulai Dari Sini (Getting Started)

### Apa itu Incident Response?

**Incident Response** adalah proses menangani "kebakaran" di sistem komputer. Bayangkan seperti pemadam kebakaran:

1. Ada alarm (Detection) → Ada yang lapor "ada asap!"
2. Cek lokasi (Triage) → Seberapa parah? Satu ruangan atau seluruh gedung?
3. Padamkan api (Containment) → Isolasi area agar api tidak menyebar
4. Bersihkan sisa (Eradication) → Pastikan tidak ada bara tersisa
5. Perbaiki gedung (Recovery) → Kembalikan seperti semula
6. Evaluasi (Lessons Learned) → Supaya tidak terulang

### Kapan Pakai Project Ini?

| Situasi | Ya/Tidak |
|---------|----------|
| Server kena hack → butuh investigasi | ✅ Ya |
| Karyawan kena phishing | ✅ Ya |
| Malware terdeteksi di endpoint | ✅ Ya |
| Ransomware mengenkripsi file | ✅ Ya |
| Butuh buat laporan insiden | ✅ Ya |
| Forensik bukti untuk pengadilan | ❌ Tidak (butuh tools khusus) |

### Quick Start: 5 Langkah Mudah

```
1. Ada insiden → Jalankan /ir-main
2. Cek tingkat keparahan → Jalankan /ir-triage  
3. Pilih playbook sesuai kasus:
   - Server Linux: /ir-linux
   - Server Windows: /ir-windows
   - Malware: /ir-malware
   - Phishing: /ir-phishing
   - Ransomware: /ir-ransomware
4. Kumpulkan bukti → /ir-collect-evidence
5. Buat laporan → /ir-report-template
```

---

## 📋 Daftar Isi

1. [Alur Kerja IR](#alur-kerja-ir)
2. [Prinsip 3 Layer](#prinsip-3-layer)
3. [Pendekatan Hybrid: Cepat vs Aman](#pendekatan-hybrid)
4. [Daftar Workflow Lengkap](#daftar-workflow-lengkap)
5. [Command Cepat untuk Triage](#command-cepat-triage)
6. [Tips Analisis dengan AI](#tips-analisis-dengan-ai)

---

## Alur Kerja IR

```
┌──────────────────────────────────────────────────────────────┐
│                    ALUR INCIDENT RESPONSE                     │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│   1. DETECTION      2. TRIAGE        3. CONTAINMENT          │
│   ┌──────────┐     ┌──────────┐     ┌──────────┐            │
│   │ Ada      │────▶│ Seberapa │────▶│ Isolasi  │            │
│   │ Alert!   │     │ Parah?   │     │ Sistem   │            │
│   └──────────┘     └──────────┘     └──────────┘            │
│        │                │                 │                  │
│        │                │                 │                  │
│        ▼                ▼                 ▼                  │
│   4. ERADICATION   5. RECOVERY      6. LESSONS LEARNED       │
│   ┌──────────┐     ┌──────────┐     ┌──────────┐            │
│   │ Bersihkan│◀────│ Pulihkan │◀────│ Evaluasi │            │
│   │ Threat   │     │ Sistem   │     │ Apa yang │            │
│   └──────────┘     └──────────┘     │ Terjadi  │            │
│                                      └──────────┘            │
└──────────────────────────────────────────────────────────────┘
```

**Penjelasan Sederhana:**

1. **Detection** - Sistem (SIEM, EDR) atau user melaporkan ada yang aneh
2. **Triage** - Cek apakah benar ada masalah, seberapa serius (< 5 menit!)
3. **Containment** - Isolasi agar tidak menyebar (seperti karantina)
4. **Eradication** - Hapus malware, tutup celah keamanan
5. **Recovery** - Kembalikan sistem ke kondisi normal
6. **Lessons Learned** - Buat laporan, perbaiki detection supaya tidak terulang

---

## Prinsip 3 Layer

> **⚠️ Aturan Emas: JANGAN install apapun ke server yang dicurigai kena hack!**

Kenapa? Karena bisa merusak bukti forensik.

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: KOMPUTER KAMU (Aman untuk install apa saja)       │
│  - IDE + AI Agent                                           │
│  - Semua workflows ada disini                               │
│  - Tools analisis                                           │
│  - Tempat simpan bukti                                      │
└───────────────────────────────│──────────────────────────────┘
                                │ Transfer bukti kesini
                                ▼
┌─────────────────────────────────────────────────────────────┐
│  LAYER 2: JUMP HOST / SERVER ANALISIS (Minimal setup)       │
│  - Server perantara untuk akses ke target                   │
│  - Boleh install tools collection                           │
└───────────────────────────────│──────────────────────────────┘
                                │ SSH / Remote Command saja
                                ▼
┌─────────────────────────────────────────────────────────────┐
│  LAYER 3: SERVER TARGET (JANGAN INSTALL APAPUN!)            │
│  - Hanya jalankan command via SSH                           │
│  - Read-only sebisa mungkin                                 │
└─────────────────────────────────────────────────────────────┘
```

| Layer | Boleh Install? | Fungsi |
|-------|----------------|--------|
| Komputer Kamu | ✅ Ya, bebas | Analisis, AI, simpan bukti |
| Jump Host | ✅ Ya, minimal | Perantara, tools collection |
| Server Target | ❌ TIDAK! | Hanya SSH command |

---

## Pendekatan Hybrid

Ada trade-off antara **kecepatan isolasi** vs **kelengkapan bukti**:

```
┌─────────────────────────────────────────────────────────────┐
│  FASE 1: TRIAGE CEPAT (1-5 menit)                           │
│  └─→ Jalankan command remote, ambil keputusan: Isolasi?     │
├─────────────────────────────────────────────────────────────┤
│  FASE 2: ISOLASI (Segera jika perlu)                        │
│  └─→ Blokir network agar attacker tidak bisa lanjut         │
├─────────────────────────────────────────────────────────────┤
│  FASE 3: DEEP ANALYSIS (Setelah aman)                       │
│  └─→ Transfer bukti ke lokal, analisis dengan AI            │
└─────────────────────────────────────────────────────────────┘
```

**Kenapa tidak langsung deep analysis?**

| Pendekatan | Waktu ke Isolasi | Risiko |
|------------|------------------|--------|
| Full Analysis dulu | 30-60 menit | ❌ Attacker bisa curi data |
| **Hybrid (Recommended)** | 2-5 menit | ✅ Minimal |
| Langsung isolasi tanpa cek | 0 menit | ⚠️ Bisa false positive |

---

## Daftar Workflow Lengkap

Semua workflow bisa dipanggil dengan perintah `/nama-workflow`:

### Workflow Utama

| Workflow | Kegunaan | Kapan Pakai |
|----------|----------|-------------|
| `/ir-main` | Entry point untuk semua incident | Pertama kali ada incident |
| `/ir-triage` | Triage cepat (<5 menit) | Menentukan perlu isolasi atau tidak |

### Workflow Berdasarkan Tipe Sistem

| Workflow | Kegunaan | Kapan Pakai |
|----------|----------|-------------|
| `/ir-linux` | Playbook untuk Linux server | Target adalah Linux |
| `/ir-windows` | Playbook untuk Windows server | Target adalah Windows |

### Workflow Berdasarkan Tipe Insiden

| Workflow | Kegunaan | Kapan Pakai |
|----------|----------|-------------|
| `/ir-malware` | Analisis dan respons malware | Malware terdeteksi |
| `/ir-phishing` | Respons insiden phishing | User kena phishing |
| `/ir-ransomware` | Respons ransomware | File terenkripsi ransomware |

### Workflow Pendukung

| Workflow | Kegunaan | Kapan Pakai |
|----------|----------|-------------|
| `/ir-collect-evidence` | Panduan kumpulkan bukti | Setelah containment |
| `/ir-report-template` | Template laporan insiden | Akhir insiden |

---

## Command Cepat Triage

### Linux (via SSH)

Copy-paste command ini untuk triage cepat (< 2 menit):

```bash
ssh user@TARGET "
  echo '=== PROSES MENCURIGAKAN ==='
  ps aux | grep -E 'nc |ncat|wget|curl|python.*-c|bash.*-i'
  
  echo '=== KONEKSI AKTIF ==='
  netstat -tulpn | grep ESTABLISHED
  
  echo '=== LOGIN TERAKHIR ==='
  last -20
  
  echo '=== CRON JOBS ==='
  crontab -l 2>/dev/null; cat /etc/crontab
  
  echo '=== FILE BARU DI /tmp (24 jam) ==='
  find /tmp /var/tmp /dev/shm -type f -mtime -1 2>/dev/null
"
```

### Windows (via PowerShell Remote)

```powershell
Invoke-Command -ComputerName TARGET -ScriptBlock {
    Write-Host "=== PROSES MENCURIGAKAN ==="
    Get-Process | Where-Object {$_.Path -like "*temp*" -or $_.Path -like "*appdata*"}
    
    Write-Host "=== KONEKSI AKTIF ==="
    Get-NetTCPConnection | Where-Object State -eq 'Established'
    
    Write-Host "=== LOGIN TERAKHIR ==="
    Get-WinEvent -LogName Security -MaxEvents 20 | Where-Object Id -eq 4624
}
```

### Kapan Harus Isolasi?

| Tanda | Aksi |
|-------|------|
| 🔴 Ada reverse shell (nc, bash -i) | **ISOLASI SEGERA** |
| 🔴 Koneksi ke IP tidak dikenal | **ISOLASI SEGERA** |
| 🟡 Crypto miner process | Isolasi, bisa dijadwalkan |
| 🟡 File mencurigakan di /tmp | Investigasi lebih lanjut |
| 🟢 Tidak ada anomali | Lanjut monitoring |

---

## Tips Analisis dengan AI

Gunakan AI untuk mempercepat analisis. Berikut template prompt yang bisa dipakai:

### Ekstrak IOC (Indicators of Compromise)

```
Analisis log berikut dan extract:
1. IP addresses (internal & external)
2. Domain names
3. File hashes (MD5/SHA256)
4. User accounts yang terlibat
5. Timestamps (format UTC)

Log:
[paste log disini]
```

### Buat Timeline

```
Buat timeline kronologis dari incident berdasarkan log.
Format: [Timestamp] - [Action] - [Actor] - [Target]

Log:
[paste log disini]
```

### Buat Detection Rule

```
Berdasarkan IOC dan teknik dari incident ini:
[list IOC/TTP]

Buatkan:
1. Trellix ESM correlation rule
2. YARA rule untuk file detection
3. Sigma rule untuk SIEM lain
```

---

## Cara Kerja di Setiap Fase IR

| Fase IR | Bantuan AI |
|---------|------------|
| **Detection** | Korelasi alert, deteksi anomali |
| **Triage** | Analisis log, ekstrak IOC, assessment severity |
| **Investigation** | Rekonstruksi timeline, root cause analysis |
| **Containment** | Suggest blocking rules, langkah isolasi |
| **Recovery** | Validasi checklist, review konfigurasi |
| **Lessons Learned** | Generate report, improve detection rule |

---

## Glossary (Istilah Penting)

| Istilah | Artinya |
|---------|---------|
| **IOC** | Indicator of Compromise - tanda-tanda serangan (IP, hash, domain) |
| **C2** | Command & Control - server yang dipakai attacker untuk kontrol malware |
| **Lateral Movement** | Attacker berpindah dari satu sistem ke sistem lain |
| **Persistence** | Cara attacker supaya tetap bisa akses walaupun sistem di-restart |
| **Triage** | Proses cepat untuk menentukan tingkat keparahan |
| **Containment** | Isolasi sistem agar threat tidak menyebar |
| **Eradication** | Menghapus threat dari sistem |
| **MITRE ATT&CK** | Framework yang menjelaskan teknik-teknik serangan |
