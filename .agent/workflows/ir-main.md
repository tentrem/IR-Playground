---
description: Main Incident Response workflow - entry point untuk semua incident
---

# Incident Response Workflow

## 1. Initial Assessment

- [ ] Identify incident type (malware, phishing, unauthorized access, etc.)
- [ ] Determine scope dan affected systems
- [ ] Assign severity level (P1/P2/P3/P4)

## 2. Triage dengan AI

Minta AI untuk bantu analisis dengan prompt:
> "Analisis log berikut dan identifikasi IOC, timeline, dan affected assets"

## 3. Related Workflows

Berdasarkan incident type, gunakan workflow yang sesuai:

- **Linux Server**: `/ir-linux`
- **Windows Server**: `/ir-windows`
- **Malware**: `/ir-malware`
- **Phishing**: `/ir-phishing`
- **Ransomware**: `/ir-ransomware`

## 4. Containment Decision

Setelah triage, tentukan:

- [ ] Apakah perlu isolasi segera?
- [ ] Scope isolasi (single host / network segment)
- [ ] Notifikasi ke stakeholder

## 5. Evidence Collection

Jalankan collection sesuai OS target → `/ir-collect-evidence`

## 6. Documentation

Generate incident report menggunakan → `/ir-report-template`
