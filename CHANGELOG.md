# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
