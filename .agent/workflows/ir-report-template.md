---
description: Template untuk membuat Incident Report
---

# IR Report Template

Gunakan template ini untuk mendokumentasikan incident. Copy dan isi sesuai findings.

---

# Incident Report

## Executive Summary

| Field | Value |
|-------|-------|
| **Case ID** | IR-YYYYMMDD-XXX |
| **Date Detected** | YYYY-MM-DD HH:MM UTC |
| **Date Reported** | YYYY-MM-DD HH:MM UTC |
| **Severity** | P1 / P2 / P3 / P4 |
| **Status** | Open / Contained / Resolved / Closed |
| **Analyst** | [Name] |

### Brief Description

[1-2 paragraf ringkasan incident]

### Impact Assessment

- **Systems Affected**: [jumlah dan nama sistem]
- **Data Impact**: [data apa yang terdampak]
- **Business Impact**: [dampak bisnis]

---

## Timeline of Events

| Timestamp (UTC) | Event | Source |
|-----------------|-------|--------|
| YYYY-MM-DD HH:MM | Initial compromise detected | [SIEM/Alert/User Report] |
| YYYY-MM-DD HH:MM | [Event description] | [Source] |
| YYYY-MM-DD HH:MM | Containment initiated | [Analyst action] |
| YYYY-MM-DD HH:MM | [Event description] | [Source] |

---

## Technical Details

### Attack Vector

[Bagaimana attacker masuk - phishing, vuln exploit, credential theft, etc.]

### Indicators of Compromise (IOCs)

#### IP Addresses

| IP | Context | Action Taken |
|----|---------|--------------|
| x.x.x.x | C2 Server | Blocked at firewall |

#### Domains

| Domain | Context | Action Taken |
|--------|---------|--------------|
| malicious.com | Phishing | Blocked at DNS |

#### File Hashes

| Hash (SHA256) | Filename | Context |
|---------------|----------|---------|
| abc123... | malware.exe | Dropper |

#### Other IOCs

- Registry keys modified: [list]
- Scheduled tasks created: [list]
- User accounts created: [list]

### Affected Systems

| Hostname | IP | OS | Role | Status |
|----------|----|----|------|--------|
| server01 | 10.0.0.1 | Ubuntu 22.04 | Web Server | Reimaged |

### MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observation |
|--------|-----------|-----|-------------|
| Initial Access | Phishing | T1566 | [detail] |
| Execution | PowerShell | T1059.001 | [detail] |
| Persistence | Scheduled Task | T1053 | [detail] |

---

## Response Actions

### Containment

- [ ] Network isolation implemented
- [ ] Malicious accounts disabled
- [ ] Firewall rules updated
- [ ] [Other actions]

### Eradication

- [ ] Malware removed
- [ ] Persistence mechanisms cleaned
- [ ] Credentials reset
- [ ] [Other actions]

### Recovery

- [ ] Systems restored from backup
- [ ] Patches applied
- [ ] Monitoring enhanced
- [ ] [Other actions]

---

## Root Cause Analysis

### Primary Cause

[Root cause dari incident]

### Contributing Factors

1. [Factor 1]
2. [Factor 2]
3. [Factor 3]

---

## Lessons Learned

### What Went Well

1. [Positive observation]
2. [Positive observation]

### What Could Be Improved

1. [Area for improvement]
2. [Area for improvement]

### Recommendations

| Priority | Recommendation | Owner | Due Date |
|----------|---------------|-------|----------|
| High | [Recommendation] | [Team] | [Date] |
| Medium | [Recommendation] | [Team] | [Date] |
| Low | [Recommendation] | [Team] | [Date] |

---

## Evidence Inventory

| Evidence ID | Description | Location | Hash |
|-------------|-------------|----------|------|
| E001 | Memory dump | /evidence/case/memory.lime | sha256:xxx |
| E002 | Auth logs | /evidence/case/auth.log | sha256:xxx |

---

## Appendices

### A. Detection Rules Created

```yaml
# Contoh Sigma rule
title: [Rule name]
status: experimental
logsource:
  product: [product]
detection:
  selection:
    [field]: [value]
  condition: selection
```

### B. Full IOC List

[Export dari threat intel platform]

### C. Communication Log

| Date | Stakeholder | Communication |
|------|-------------|---------------|
| [Date] | Management | Initial notification |
| [Date] | Legal | [If applicable] |

---

**Report Prepared By**: [Name]
**Date**: [Date]
**Classification**: [Internal/Confidential]
