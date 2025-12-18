---
description: Ransomware Incident Response Playbook
---

# Ransomware IR Playbook

Workflow untuk menangani incident ransomware. **WAKTU KRITIS** - fokus pada containment cepat untuk mencegah penyebaran.

> ⚠️ **PENTING**: Ransomware menyebar cepat. Prioritaskan ISOLASI sebelum investigasi!

## Kapan Pakai Workflow Ini?

- File terenkripsi dengan extension aneh (.locked, .encrypted, .ryuk)
- Ransom note ditemukan (README.txt, HOW_TO_DECRYPT)
- Alert EDR: ransomware behavior detected
- Multiple file encryption dalam waktu singkat

## Prerequisites

- [ ] Wewenang untuk isolasi network segera
- [ ] Kontak ke management/legal siap
- [ ] Backup status diketahui

---

## 1. IMMEDIATE ISOLATION (Menit 0-5)

### Isolasi Network SEGERA

**JANGAN MENUNGGU** - Isolasi dulu, investigasi kemudian!

```bash
# Linux - Block semua traffic
ssh TARGET "iptables -I INPUT -j DROP; iptables -I OUTPUT -j DROP"

# Whitelist IP analyst
ssh TARGET "iptables -I INPUT -s YOUR_IP -j ACCEPT; iptables -I OUTPUT -d YOUR_IP -j ACCEPT"
```

```powershell
# Windows - Block semua traffic
Invoke-Command -ComputerName TARGET -ScriptBlock {
    New-NetFirewallRule -DisplayName "IR-RansomBlock-In" -Direction Inbound -Action Block
    New-NetFirewallRule -DisplayName "IR-RansomBlock-Out" -Direction Outbound -Action Block
    New-NetFirewallRule -DisplayName "IR-AllowAnalyst" -RemoteAddress $args[0] -Direction Inbound -Action Allow
    New-NetFirewallRule -DisplayName "IR-AllowAnalyst-Out" -RemoteAddress $args[0] -Direction Outbound -Action Allow
} -ArgumentList "YOUR_ANALYST_IP"
```

### Disconnect dari Network (Alternatif)

```
Opsi cepat:
1. Cabut kabel network
2. Disable Wi-Fi
3. Disable NIC via command
4. Block di switch port
```

### Jangan Matikan Komputer

```
⚠️ JANGAN SHUTDOWN:
- Encryption key mungkin masih di memory
- Memory forensic bisa recover key
- Shutdown = hilang evidence volatile
```

---

## 2. Identify Ransomware Type

### Cek Ransom Note

```
Cari file seperti:
- README.txt, !!!README!!!.txt
- HOW_TO_DECRYPT.html
- DECRYPT_INSTRUCTIONS.txt
- Wallpaper berubah jadi ransom message
```

### Identifikasi Variant

```
Gunakan:
1. https://id-ransomware.malwarehunterteam.com/
   - Upload ransom note atau sample encrypted file
   
2. https://www.nomoreransom.org/
   - Cek apakah ada decryptor gratis

3. Catat:
   - Extension file encrypted (.locked, .ryuk, .locky)
   - Email/contact di ransom note
   - Bitcoin address
```

---

## 3. Scope Assessment

### Identifikasi Sistem Terinfeksi

```
Cek:
1. Sistem mana yang punya file encrypted?
2. Shared drives/network shares terdampak?
3. Backup terinfeksi juga?
4. Cloud storage sync terdampak?
```

### Cek Lateral Movement

```bash
# Linux - cek login ke sistem lain
ssh TARGET "last -20; who; w"
ssh TARGET "cat ~/.ssh/known_hosts"

# Windows - cek connections
Invoke-Command -ComputerName TARGET -ScriptBlock {
    Get-WinEvent -LogName Security -MaxEvents 100 | Where-Object Id -eq 4624
}
```

---

## 4. Evidence Collection

### Collect Ransom Note

```bash
# Copy ransom note untuk identifikasi
scp TARGET:/path/to/README.txt evidence/ransom/

# Screenshot jika wallpaper berubah
```

### Sample Encrypted File

```bash
# Ambil sample file terenkripsi (kecil saja)
scp TARGET:/path/to/file.docx.encrypted evidence/ransom/

# Hash original dan encrypted
sha256sum evidence/ransom/*
```

### Memory Dump (PENTING untuk decrypt)

```bash
# Linux dengan LiME (jika pre-installed)
ssh TARGET "sudo insmod /path/to/lime.ko 'path=/tmp/memory.lime format=lime'"
scp TARGET:/tmp/memory.lime evidence/memory/

# Windows dengan WinPMEM (jika pre-installed)
# Memory dump buat recover encryption key
```

---

## 5. Check for Free Decryptors

### No More Ransom Project

```
1. Buka https://www.nomoreransom.org/
2. Upload sample encrypted file + ransom note
3. Jika ada decryptor → Download dan test
```

### Vendor Decryptors

```
Cek decryptor dari:
- Kaspersky: https://noransom.kaspersky.com/
- Avast: https://www.avast.com/ransomware-decryption-tools
- Emsisoft: https://www.emsisoft.com/ransomware-decryption/
```

---

## 6. DO NOT PAY (Recommendation)

```
⚠️ JANGAN BAYAR RANSOM:
1. Tidak ada jaminan dapat decryptor
2. Membiayai operasi kriminal
3. Bisa dijadikan target lagi
4. Mungkin ada decryptor gratis

Diskusikan dengan:
- Management
- Legal team
- Law enforcement (jika diperlukan)
```

---

## 7. Recovery Options

### Option A: Restore from Backup

```
1. Verifikasi backup TIDAK terinfeksi
2. Wipe/reimage sistem terinfeksi
3. Restore data dari backup
4. Jangan connect ke network sampai clean
```

### Option B: Decrypt dengan Free Tool

```
Jika decryptor tersedia:
1. Test di 1 file dulu
2. Jika berhasil, decrypt sisanya
3. Scan semua file setelah decrypt
```

### Option C: Accept Data Loss

```
Jika tidak ada backup dan tidak ada decryptor:
1. Wipe dan rebuild sistem
2. Document data yang hilang
3. Lessons learned untuk backup policy
```

---

## 8. Eradication

### Wipe & Reimage

```
1. Full wipe disk (bukan format biasa)
2. Install fresh OS dari trusted media
3. Install dari backup yang bersih
4. Hardening sebelum reconnect
```

### Patch Entry Point

```
Cari bagaimana ransomware masuk:
- Phishing email? → Improve email security
- RDP exposed? → Disable/VPN only
- Unpatched vuln? → Patch segera
```

---

## 9. Analisis dengan AI

```
Ransomware incident summary:

Ransomware type: [type dari id-ransomware]
Entry point: [RDP/Phishing/Vuln]
Systems affected: [list]
Ransom note: [paste content]

Tolong bantu:
1. MITRE ATT&CK techniques used
2. Known TTPs untuk ransomware ini
3. Recommended detection rules
4. Hardening recommendations
```

---

## 10. Post-Incident

- [ ] Report ke management
- [ ] Report ke law enforcement (optional)
- [ ] Review dan improve backup strategy
- [ ] Patch vulnerabilities
- [ ] Improve detection rules
- [ ] Security awareness training
- [ ] Full report → `/ir-report-template`

---

## Quick Reference: Ransomware Entry Points

| Entry Point | Mitigation |
|-------------|------------|
| **Exposed RDP** | VPN only, MFA, disable RDP |
| **Phishing** | Email security, user training |
| **Vuln Exploit** | Patch management |
| **Weak Credentials** | MFA, password policy |
| **Supply Chain** | Vendor security assessment |

---

## Checklist Summary

- [ ] 🔴 Sistem DIISOLASI segera
- [ ] Ransomware type identified
- [ ] Scope assessed (berapa sistem?)
- [ ] Evidence collected (note, sample, memory)
- [ ] Free decryptor checked
- [ ] Recovery option decided
- [ ] Sistem di-wipe dan rebuild
- [ ] Entry point patched
- [ ] Detection rules created
- [ ] Report generated → `/ir-report-template`
