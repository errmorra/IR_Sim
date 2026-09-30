# 🛡️ Incident Response Tabletop Simulator

> A dark-themed Python GUI application for cybersecurity GRC training.
> Maps attacker behaviors to **MITRE ATT&CK Enterprise v14**. Follows the **NIST SP 800-61 r2** lifecycle. Exports run-specific GRC compliance reports.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Scenarios](https://img.shields.io/badge/Scenarios-20-purple?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-red?style=flat-square)
![Framework](https://img.shields.io/badge/Framework-NIST%20SP%20800--61%20r2-orange?style=flat-square)

---

## ✨ Features

- **20 fully detailed scenarios** — 100 injects, 300 scored choices, 49 distinct ATT&CK technique IDs
- **Briefing → injects → debrief flow** — every run opens with a briefing (role, objectives, threat profile) and ends with a structured debrief screen
- **Branching narrative** — injects can carry `story_variants` so the next inject reflects the quality of your last decision (authored for *Operation Midnight Cipher*; the schema is open for the rest)
- **Technique identification challenge** — after each decision you are asked to pick the ATT&CK technique in play from three candidates; identification is scored independently from the response
- **Relative scoring that never saturates** — each axis is normalised against the best and worst achievable path, so the fifth inject matters as much as the first
- **Post-commit reveal** — see the quality, score impact, and assessment of *all three* options, not just the one you chose
- **Trainer tools** — facilitator mode (scores and ratings hidden until debrief), per-inject discussion timer, role prompts (IR lead / legal / comms / executive), save & resume, scenario picker with industry and severity filters
- **Run-specific GRC report** — recommendations derived from the techniques you met and the decisions you missed; regulatory checklist scoped to the industry with an *exercise indication* per obligation; rendered in-app with copy and save
- **Keyboard driven** — `1`–`3` / `A`–`C` select, `Enter` commits and advances
- **Pure standard library** — tkinter only; no Electron, no web server, no internet
- **Data-code separation** — all scenario content in `scenarios.json`; `validate_scenarios.py` checks schema, scoring, and shuffle stability

---

## 🚀 Quick Start

### Prerequisites
- Python **3.9+**
- `tkinter` — included in the Python standard library (Debian/Ubuntu: `sudo apt install python3-tk`)

```bash
git clone https://github.com/errmorra/IR_Sim.git
cd IR_Sim
python app.py                      # random scenario, opens on the briefing screen
python app.py --scenarios my.json  # or point at another scenario file ($IR_SIM_SCENARIOS also works)
```

No database, no API keys, no server, no Docker.

---

## 🎮 How to Play

| Step | Action |
|------|--------|
| 1 | Read the **briefing** — role, objectives, threat actor, severity — and press **Begin Exercise** |
| 2 | Read the inject. Open **Discussion prompts by role** if you are running it as a group |
| 3 | Select a response (order is shuffled every time) and **Commit Decision** |
| 4 | Read the assessment, score impact, and what the other two options would have done |
| 5 | **Identify the adversary technique** from three ATT&CK candidates — then the MITRE mapping is revealed |
| 6 | Watch the live meters, the ATT&CK tracker, and the decision log in the sidebar |
| 7 | At the **debrief**, review grade, phase efficiency, and every decision, then **Generate GRC Report** |
| 8 | Replay, pick a random scenario, or **Choose…** a specific one (filter by industry or severity) |

**Trainer menu:** Facilitator Mode hides scores, ratings, and feedback until the debrief. Discussion Timer sets a per-inject countdown shown in the status bar. **File menu:** Save Progress / Resume Saved Progress (`.irsim.json`).

**Keyboard shortcuts:** `1`–`3` or `A`–`C` select · `Enter` begin / commit / advance / open report · `Ctrl+S` save · `Ctrl+O` resume · `Ctrl+N` random scenario · `Ctrl+L` choose scenario · `Ctrl+R` report · `Ctrl+Q` quit.

---

## 📁 Project Structure

```
IR_Sim/
├── app.py                    # GUI, session state, report generator
├── scoring.py                # Scoring model shared by the app, validator, and tests
├── scenarios.json            # 20 scenarios, 100 injects, 300 choices
├── validate_scenarios.py     # Headless schema + scoring validator (for contributors)
├── tests/                    # unittest suite: scoring, session/report, GUI smoke (Xvfb)
├── requirements.txt          # No third-party dependencies
├── CONTRIBUTING.md           # Scenario schema, PR process, accuracy standards
├── CHANGELOG.md              # Version history
├── LICENSE                   # MIT
└── .github/workflows/ci.yml  # Lint, validate, unit tests, headless GUI smoke test
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

```
scoring.py            →  pure scoring functions (bounds, normalisation, grades, phase efficiency)
ScenarioManager       →  loads scenarios.json, mounts a scenario, resolves branching story variants,
                         exposes the ATT&CK technique pool for identification distractors
SimulationSession     →  runtime state: raw deltas, decision log, technique identifications,
                         save/resume serialisation
ReportGenerator       →  Markdown report built from the session (technique-driven recommendations,
                         industry- and run-scoped obligations)
IncidentSimulatorApp  →  tkinter GUI: briefing / inject / debrief views, sidebar, menus, dialogs
```

### Randomization

**Scenario selection** — a random scenario is mounted at launch; `↻ Random` avoids an immediate repeat.

**Choice shuffling** — each inject shuffles a *copy* of its choices. Each row is assigned a scoped token `f"{inject_index}_{letter}"` that resolves back to the original choice dict at commit time, so scoring is tied to the choice's quality and deltas, never to its display position.

**Technique distractors** — the identification challenge draws two distractors from the technique pool of the whole scenario file, preferring one from the same tactic.

### Branching narrative

An inject may carry a `story_variants` object keyed by the quality of the *previous* decision:

```json
"story": "Base narrative shown when no variant applies…",
"story_variants": {
  "optimal":     "Your Sigma rule fires within minutes…",
  "neutral":     "The tightened filters quarantined 400 legitimate emails — and still let the lure through…",
  "detrimental": "Nobody was watching for it…"
}
```

The choices and their scores do not change, so scoring bounds stay stable while the story reacts to the player.

### Adding new scenarios

Edit `scenarios.json` only, then run:

```bash
python validate_scenarios.py          # schema, scoring model, shuffle stability
python -m unittest discover tests     # full test suite (GUI test skips without a display)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the schema and score guidelines.

---

## 📊 Scoring System

Each choice carries three deltas: **NIST IR**, **Compliance**, **Legal**. A run's raw axis score is the sum of committed deltas, normalised against the worst and best sums achievable over the injects played so far:

\[ \text{score} = \frac{\text{raw} - \text{worst}}{\text{best} - \text{worst}} \times 100 \]

So **100** means "the strongest option at every inject" and **0** means "the weakest at every inject". Because it is relative, no decision is ever wasted to a clamp: the last inject can still change the grade.

| Metric | What It Measures |
|--------|-----------------|
| **NIST IR Score** | Technical IR decision quality per NIST SP 800-61 r2 |
| **Compliance Score** | Adherence to HIPAA, GDPR, PCI DSS, GLBA, NIST CSF, and other applicable frameworks |
| **Legal Standing** | Decisions that protect or expose the organization to regulatory and legal liability |
| **Technique identification** | Reported separately: correct ATT&CK picks / techniques challenged |

**Grade scale:** A (≥85) · B (≥70) · C (≥55) · D (≥30) · F (<30). An all-optimal run is an A, an all-neutral ("partial") run is a D, an all-detrimental run is an F, in every scenario — the validator enforces this.

---

## 📄 Generated Report Includes

- Executive summary with grade, composite score, decision quality counts, and identification rate
- GRC metrics table and NIST phase efficiency breakdown
- Full decision timeline — action taken, assessment, the alternatives not taken, ATT&CK context, and whether the technique was identified
- MITRE ATT&CK checklist and framework references exercised
- Executive recommendations mapped to NIST CSF 2.0, NIST SP 800-53, CIS Controls v8 and sector guidance — chosen from the techniques encountered, escalated where the response or identification fell short, plus a "revisit playbook" item for every non-optimal decision
- Regulatory obligations checklist scoped to the scenario's industry and techniques, with an *exercise indication* (addressed / partially addressed / at risk / not exercised) inferred from the run
- Certification block suitable for portfolio and audit documentation

---

## ⚖️ Regulatory Frameworks Referenced

NIST SP 800-61 r2 · MITRE ATT&CK Enterprise v14 · HIPAA Security Rule · NIST CSF 2.0 · NIST SP 800-53 r5 · NIST SP 800-161r1 · NIST SP 800-190 · NIST SP 800-207 · GDPR · CCPA · PCI DSS v4 · GLBA Safeguards Rule · OFAC Sanctions · CIRCIA 2022 · DFARS 252.204-7012 · CMMC Level 2 · FFIEC Authentication Guidance · SEC Cybersecurity Disclosure Rules (2023) · FinCEN SAR Requirements · CIS Controls v8 · ISO/IEC 27001:2022

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Scenario PRs especially welcome — and `story_variants` for the existing 19 scenarios that do not yet branch.

---

## 📜 License

MIT — see [LICENSE](LICENSE)
