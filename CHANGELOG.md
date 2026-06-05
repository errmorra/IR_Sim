# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.1.0] — 2024

### Added
- **Keyboard navigation** — press `1`–`3` (or `A`–`C`) to select a response and `Enter`
  to commit / advance to the next inject without reaching for the mouse
- **In-app replay** — a new sidebar **↻ NEW SCENARIO** button loads a fresh random scenario
  without relaunching the app (avoids repeating the current scenario when possible)
- **Inject progress bar** — a thin cyan bar in the inject header shows how far through the
  scenario the player is
- **Choice hover highlighting** — response options highlight on mouse-over for clearer affordance

### Changed
- **Scenario-aware regulatory checklist** — the exported GRC report's *Regulatory & Legal
  Obligations* section is now tailored to the scenario's industry and the MITRE techniques
  encountered (e.g. GLBA/FinCEN/SEC for financial scenarios, DFARS/CMMC for defense), instead
  of always emitting healthcare/HIPAA obligations regardless of scenario
- **Responsive text reflow** — story, MITRE badge, choice, and feedback text now re-wrap to the
  current window width on resize instead of using fixed wrap widths
- **Header phase tracker** — compact phase labels (PREP / DETECT / CONTAIN / ERADICATE / POST)
  prevent the last phase name from being clipped at the window edge
- Executive recommendations in the report are now ordered so those mapping to techniques actually
  seen in the run appear first

### Fixed
- Removed unused `os` import and f-strings without placeholders (clean `pyflakes` run)
- Guarded the resize handler against widgets destroyed during scenario restart

---

## [2.0.0] — 2024

### Added
- **Random scenario selection at startup** — `ScenarioManager` uses `random.randrange()` to pick a
  different scenario every launch; window title and header display `Scenario N/20`
- **Shuffled answer choices** — display order of A/B/C options randomized per inject via
  `random.shuffle()`; scoring always resolves through `_choice_token_map` keyed to quality+text,
  never to display position
- **20 fully detailed scenarios** covering diverse threat themes:
  - Enterprise Ransomware & Data Exfiltration (Healthcare)
  - Malicious Insider Data Theft (Financial Services)
  - Software Supply Chain Compromise (Defense / Technology)
  - AWS S3 Cloud Misconfiguration (E-Commerce)
  - Multi-Vector DDoS Extortion (Online Gaming)
  - CEO Whaling / BEC Wire Fraud (Manufacturing)
  - Zero-Day VPN Exploitation (Critical Infrastructure)
  - Physical Security Breach / Rogue Network Implant (Pharmaceutical)
  - Cloud Cryptojacking via Exposed Credentials (SaaS)
  - SMS Phishing / AiTM Session Hijack (Retail)
  - SQL Injection & Web Application Breach (E-Commerce)
  - Large-Scale Account Takeover / Credential Stuffing (Banking)
  - Third-Party Vendor Breach (Insurance)
  - AI-Powered Deepfake Voice Social Engineering (Media)
  - Medical Device & Healthcare IoT Compromise (Hospital)
  - Privileged Account Abuse / MSP PAM Failure (MSP)
  - Data Center Outage & Disaster Recovery Failure (Banking)
  - Kubernetes Container Escape & Cluster Compromise (SaaS)
  - Malicious OAuth App Consent Grant Attack (SaaS)
  - DeFi Smart Contract Exploit & Cryptocurrency Theft (Fintech)
- **Multi-scenario JSON format** — `scenarios.json` top-level `"scenarios"` array; backward-compatible
  with the original single-scenario format (auto-detected and wrapped transparently)
- **51 unique MITRE ATT&CK technique IDs** across 100 injects and 300 scored choices
- **Full validation suite** — every scenario confirmed: Optimal → Grade A, Detrimental → Grade F,
  shuffle-stable scoring

### Changed
- `ScenarioManager` refactored to support multi-scenario files with `_mount(index)` pattern
- `_load_inject()` now builds `_choice_token_map` (scoped token → choice dict) instead of using
  static `choice["id"]` for radio button values
- `_on_submit()` resolves selected choice via `_choice_token_map[token]` instead of `id` lookup
- Window title, header subtitle, and status bar updated to show scenario number and total count
- Version string updated to `IR_Sim v3.0 // GRC Portfolio Edition // 20 Scenarios`

---

## [1.0.0] — 2024

### Added
- Full interactive GUI built on Python `tkinter` with dark cyber-dashboard aesthetic
- Single scenario: *Operation Midnight Cipher* — Enterprise Ransomware & Data Exfiltration
- 5 injects across all 5 NIST SP 800-61 r2 lifecycle phases
- MITRE ATT&CK Enterprise v14 mapping for all injects
- Three-axis GRC scoring: NIST IR Score, Compliance Score, Legal Standing
- Live score meters, grade calculation (A–F), phase progress indicator
- Real-time MITRE ATT&CK technique tracker sidebar
- Markdown GRC compliance report export
- `scenarios.json` data-code separation
- `customtkinter` optional enhancement with clean stdlib fallback
