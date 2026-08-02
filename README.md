# 🛡️ Incident Response Tabletop Simulator

> A modern, dark-themed Python GUI application for cybersecurity GRC training.
> Maps attacker behaviors to **MITRE ATT&CK Enterprise v14**. Follows the **NIST SP 800-61 r2** lifecycle. Exports formatted GRC compliance reports.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Scenarios](https://img.shields.io/badge/Scenarios-20-purple?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-red?style=flat-square)
![Framework](https://img.shields.io/badge/Framework-NIST%20SP%20800--61%20r2-orange?style=flat-square)

---

## ✨ Features

- **20 fully detailed scenarios** — randomly selected at each launch for high replayability
- **Shuffled answer choices** — option order randomized every inject; scoring always resolves to the correct quality regardless of display position
- **Dark cyber-dashboard GUI** — built on Python `tkinter` (no Electron, no web server, no internet)
- **MITRE ATT&CK mapped injects** — 51 unique technique IDs across 100 injects
- **NIST SP 800-61 r2 lifecycle** — all 5 phases: Preparation → Detection → Containment → Eradication → Post-Incident
- **Three-axis GRC scoring** — NIST IR Score, Regulatory Compliance Score, Legal Standing Score; all update live
- **Markdown report export** — full post-incident GRC compliance report with executive recommendations, regulatory checklist, and MITRE technique coverage
- **Data-code separation** — all scenario content in `scenarios.json`; zero Python changes needed to add scenarios
- **Validator script** — `validate_scenarios.py` confirms any new scenario meets the required schema

---

## 🚀 Quick Start

### Prerequisites
- Python **3.9+**
- `tkinter` — included in the Python standard library

```bash
# 1. Clone
git clone https://github.com/errmorra/IR_Sim.git
cd IR_Sim

# 2. Run — a random scenario is selected automatically (no pip installs needed)
python app.py
```

> On Debian/Ubuntu, install tkinter first if missing: `sudo apt install python3-tk`

No database, no API keys, no server, no Docker.

---

## 🎮 How to Play

| Step | Action |
|------|--------|
| 1 | Read the inject — a scenario event describing what your security team discovered |
| 2 | Review the MITRE ATT&CK badge showing the adversary technique in play |
| 3 | Select a response action — order is randomized each time |
| 4 | Click **COMMIT DECISION** |
| 5 | Read the GRC feedback with regulatory citations |
| 6 | Monitor live scores, the MITRE tracker, and the exercise timer |
| 7 | At the end, click **GENERATE GRC REPORT** to preview the report in-app and save it as Markdown |
| 8 | Click **↻ RANDOM** for a fresh random scenario, or **▤ CHOOSE…** to pick a specific one |

**Keyboard shortcuts:** press `1`–`3` (or `A`–`C`) to select a response, and `Enter` to commit your decision / advance to the next inject.

Each launch picks a different scenario at random — play through all 20 for full coverage.

---

## 📁 Project Structure

```
IR_Sim/
├── app.py                    # Main GUI — all UI, session state, report export
├── scenarios.json            # 20 scenarios, 100 injects, 300 choices, 51 MITRE IDs
├── validate_scenarios.py     # Headless schema + scoring validator (for contributors)
├── requirements.txt          # Optional dependencies
├── CONTRIBUTING.md           # Scenario schema, PR process, accuracy standards
├── CHANGELOG.md              # Version history
├── LICENSE                   # MIT
├── .gitignore
└── .github/
    └── workflows/
        └── ci.yml            # GitHub Actions — syntax, JSON validation, logic tests
```

---

## 🎯 Scenario Roster

| # | ID | Title | Theme | Industry | Severity |
|---|----|-------|-------|----------|----------|
| 01 | RANSOMWARE-2024-001 | Operation Midnight Cipher | Enterprise Ransomware & Data Exfiltration | Healthcare | CRITICAL |
| 02 | INSIDER-2024-002 | Operation Trusted Betrayal | Malicious Insider Data Theft | Financial Services | HIGH |
| 03 | SUPPLYCHAIN-2024-003 | Operation Poisoned Update | Software Supply Chain Compromise | Defense / Technology | CRITICAL |
| 04 | CLOUD-S3-2024-004 | Operation Open Bucket | AWS S3 Misconfiguration Breach | E-Commerce | HIGH |
| 05 | DDOS-2024-005 | Operation Flood Wall | Multi-Vector DDoS Extortion | Online Gaming | HIGH |
| 06 | WHALING-2024-006 | Operation Silver Tongue | CEO Whaling / BEC Wire Fraud | Manufacturing | HIGH |
| 07 | ZERODAY-2024-007 | Operation Silent Strike | Zero-Day VPN Appliance Exploitation | Critical Infrastructure | CRITICAL |
| 08 | PHYSICAL-2024-008 | Operation Trojan Badge | Physical Breach / Rogue Network Implant | Pharmaceutical | HIGH |
| 09 | CRYPTOJACK-2024-009 | Operation Silent Miner | Cloud Cryptojacking via Exposed Credentials | SaaS / Technology | MEDIUM |
| 10 | MOBILEPHISH-2024-010 | Operation Smishing Storm | SMS Phishing / AiTM Session Hijack | Retail | HIGH |
| 11 | WEBAPP-2024-011 | Operation Broken Gate | SQL Injection & Web App Data Breach | E-Commerce | HIGH |
| 12 | ATO-2024-012 | Operation Account Harvest | Large-Scale Credential Stuffing / ATO | Banking | HIGH |
| 13 | VENDOR-2024-013 | Operation Broken Chain | Third-Party Vendor Breach | Insurance | HIGH |
| 14 | DEEPFAKE-2024-014 | Operation Synthetic Voice | AI Deepfake Voice Social Engineering | Media | HIGH |
| 15 | MEDDEVICE-2024-015 | Operation Flatline | Medical Device & Healthcare IoT Compromise | Hospital System | CRITICAL |
| 16 | PAM-2024-016 | Operation Root Access | Privileged Account Abuse / MSP PAM Failure | MSP | CRITICAL |
| 17 | DR-2024-017 | Operation Cold Restart | Data Center Outage & DR Failure | Banking | HIGH |
| 18 | CONTAINER-2024-018 | Operation Broken Pod | Kubernetes Container Escape | SaaS / Technology | HIGH |
| 19 | OAUTH-2024-019 | Operation Consent Trap | Malicious OAuth App Consent Grant | SaaS / Technology | HIGH |
| 20 | DEFI-2024-020 | Operation Empty Vault | DeFi Smart Contract Exploit | Fintech / Crypto | CRITICAL |

---

## 🧠 Architecture

Four clean classes, fully separated by concern:

```
ScenarioManager       →  loads scenarios.json, randomly selects one at startup
SimulationSession     →  runtime state: scores, decision log, MITRE technique tracking
ReportGenerator       →  stateless Markdown report builder (reads from session)
IncidentSimulatorApp  →  all tkinter GUI: dashboard, sidebar, meters, buttons
```

### Randomization Design

**Scenario selection** — `random.randrange(len(all_scenarios))` is called once in `ScenarioManager.__init__`. The window title and header show `Scenario N/20: Title` so the player knows which one they got.

**Choice shuffling** — `_load_inject()` shuffles a *copy* of the choices list on each inject display. Each button is assigned a scoped token `f"{inject_index}_{display_letter}"` as its radio button value. `_choice_token_map` resolves the token back to the original choice dict in `_on_submit()` — so scoring is always tied to `quality` + `text`, never to the A/B/C display position.

### Adding New Scenarios

Edit `scenarios.json` only — no Python changes required. Then validate:

```bash
python validate_scenarios.py
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full inject schema and score delta guidelines.

---

## 📊 Scoring System

Three independent scores start at **50/100** and shift based on decision quality:

| Metric | What It Measures |
|--------|-----------------|
| **NIST IR Score** | Technical IR decision quality per NIST SP 800-61 r2 |
| **Compliance Score** | Adherence to HIPAA, GDPR, PCI DSS, GLBA, NIST CSF, and other applicable frameworks |
| **Legal Standing** | Decisions that protect or expose the organization to regulatory and legal liability |

**Grade scale:** A (≥85) · B (≥70) · C (≥55) · D (≥40) · F (<40)

---

## 📄 Generated Report Includes

- Executive summary with overall grade and composite score
- GRC metrics table with per-dimension ratings
- NIST phase efficiency breakdown
- Full decision timeline — every inject, your choice, quality rating, feedback, and MITRE context
- MITRE ATT&CK checklist — all techniques encountered, identified vs. missed
- 7 prioritized executive remediation recommendations mapped to NIST CSF 2.0, CIS Controls v8, HIPAA, DISA STIG
- Regulatory obligations checklist — HIPAA OCR, OFAC, CIRCIA, FBI IC3, GLBA, GDPR, state breach laws
- Report certification block suitable for portfolio and audit documentation

---

## ⚖️ Regulatory Frameworks Referenced

NIST SP 800-61 r2 · MITRE ATT&CK Enterprise v14 · HIPAA Security Rule · NIST CSF 2.0 · NIST SP 800-53 r5 · NIST SP 800-161r1 · GDPR · CCPA · PCI DSS v4 · GLBA Safeguards Rule · OFAC Sanctions · CIRCIA 2022 · DFARS 252.204-7012 · CMMC Level 2 · AWIA 2018 · FFIEC Authentication Guidance · NIST AI RMF 1.0 · SEC Cybersecurity Disclosure Rules (2023) · FinCEN SAR Requirements · CIS Controls v8 · ISO/IEC 27001:2022

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Scenario PRs especially welcome — see the roster above for themes still uncovered.

---

## 📜 License

MIT — see [LICENSE](LICENSE)

---

*Framework references: NIST SP 800-61 r2 · MITRE ATT&CK Enterprise v14 · NIST CSF 2.0*
