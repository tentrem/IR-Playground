---
description: Phishing Incident Response Playbook
---

# Phishing IR Playbook

Workflow untuk menangani incident phishing. Fokus pada **analisis email, identifikasi korban, dan containment**.

## Kapan Pakai Workflow Ini?

- User report email suspicious
- Email gateway mendeteksi phishing
- Credential theft terdeteksi dari phishing campaign

## Prerequisites

- [ ] Punya sample email (header + body)
- [ ] Tahu jumlah recipient
- [ ] Akses ke email logs/gateway

---

## 1. Analisis Email

### Collect Email Sample

Dapatkan email dalam format:

- `.eml` atau `.msg` file
- Full headers (penting!)
- Semua attachments

### Analisis Headers

```
Cek field-field penting:
1. From: (Siapa pengirim?)
2. Reply-To: (Berbeda dari From? → Suspicious!)
3. Return-Path: (Email bounce kemana?)
4. Received: (Trace path email)
5. X-Originating-IP: (IP asli pengirim)
6. SPF/DKIM/DMARC: (Lolos atau fail?)
```

### Analisis Content

```
Identifikasi:
1. URL dalam email (hover, jangan klik!)
2. Attachment files (nama, type, hash)
3. Urgency language ("segera", "akun diblokir")
4. Typo di domain (microsofft.com, g00gle.com)
```

---

## 2. URL & Attachment Analysis

### Analisis URL (Jangan Klik Langsung!)

```
Gunakan tools aman:
1. https://urlscan.io - Scan URL
2. https://www.virustotal.com - Check reputation
3. https://www.whois.com - Cek domain info
4. https://archive.org/web/ - Lihat historical

Catat:
- Final redirect URL
- Domain age
- SSL certificate info
- Page content screenshot
```

### Analisis Attachment

```bash
# Hitung hash
sha256sum attachment.pdf

# Scan di VirusTotal
# Upload ke Sandbox (Any.run, Hybrid Analysis)

# Jangan buka di production machine!
```

---

## 3. Identifikasi Korban

### Cek Email Logs

```
Di email gateway/M365/Google Workspace:
1. Berapa user yang terima email ini?
2. Siapa yang klik link? (URL tracking)
3. Siapa yang reply? 
4. Siapa yang download/open attachment?
```

### Query untuk M365

```powershell
# Message trace
Get-MessageTrace -SenderAddress "phisher@domain.com" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)

# Atau via Security Center
# Search email by subject/sender
```

---

## 4. Containment

### Block Indicators

```
Block di:
1. Email Gateway - Sender domain/IP
2. Firewall/Proxy - URL/Domain phishing
3. DNS - Sinkhole domain
4. EDR - File hash (jika ada attachment)
```

### Hapus Email dari Mailbox

```powershell
# M365 - Hard delete phishing email dari semua mailbox
New-ComplianceSearch -Name "Phishing_Cleanup" -ExchangeLocation All -ContentMatchQuery 'subject:"Invoice Payment Urgent"'
Start-ComplianceSearch -Identity "Phishing_Cleanup"

# Setelah search selesai, purge
New-ComplianceSearchAction -SearchName "Phishing_Cleanup" -Purge -PurgeType HardDelete
```

### Reset Credentials (Jika Ada Korban)

```
Untuk user yang klik/submit credentials:
1. Force password reset
2. Revoke active sessions
3. Enable MFA (jika belum)
4. Review recent activity
```

---

## 5. Analisis dengan AI

```
Analisis phishing email berikut:

Headers:
[PASTE HEADERS]

Body:
[PASTE BODY]

Tolong identifikasi:
1. Tipe phishing (credential harvest, malware delivery, BEC)
2. IOCs (sender, domains, URLs, IPs)
3. Campaign indicators
4. Target audience
5. Recommended blocks
```

---

## 6. User Communication

### Template Notifikasi ke User

```
Subject: [Security Alert] Phishing Email Detected

Tim Security mendeteksi email phishing yang dikirim ke beberapa karyawan.

Ciri-ciri email:
- Subject: "[SUBJECT EMAIL]"
- Sender: [SENDER ADDRESS]

Jika Anda menerima email ini:
✅ Jangan klik link apapun
✅ Jangan download attachment
✅ Hapus email tersebut

Jika sudah terlanjur klik link atau memasukkan password:
⚠️ Hubungi IT Security segera di [CONTACT]
⚠️ Ganti password Anda sekarang

Terima kasih atas kewaspadaannya.
Tim IT Security
```

---

## 7. Post-Incident

- [ ] Buat email rule untuk block sender/domain
- [ ] Update spam filter
- [ ] Dokumentasi campaign untuk threat intel
- [ ] Security awareness reminder ke user
- [ ] Report → `/ir-report-template`

---

## Quick Reference: Phishing Red Flags

| Indicator | Contoh |
|-----------|--------|
| Urgency | "Akun akan diblokir dalam 24 jam!" |
| Typosquatting | micr0soft.com, amaz0n.com |
| Suspicious sender | <support@company.suspicious.com> |
| Generic greeting | "Dear Customer" instead of name |
| Mismatched URL | Display: bank.com, Actual: evil.com/bank |
| Attachment | .exe, .js, .iso dalam email unexpected |

---

## Checklist Summary

- [ ] Email sample collected (with headers)
- [ ] Headers analyzed (sender, SPF/DKIM)
- [ ] URLs scanned (urlscan.io, VT)
- [ ] Attachments analyzed (hash, sandbox)
- [ ] Recipients identified
- [ ] Victims identified (who clicked)
- [ ] IOCs blocked (domain, IP, hash)
- [ ] Phishing emails purged from mailboxes
- [ ] Compromised credentials reset
- [ ] Users notified
- [ ] Report generated → `/ir-report-template`
