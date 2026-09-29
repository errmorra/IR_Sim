# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [4.0.0] — 2026

### Changed — scoring model (breaking)
- **Relative scoring replaces the 50-start / 0–100 clamp.** Each axis is now normalised against the
  best and worst achievable path over the injects played, so no inject is ever lost to saturation
  (previously an all-optimal run hit 100 before the last two or three injects). Logic lives in the new
  `scoring.py`, shared by the app, the validator, CI, and tests
- Grade bands are now A ≥85 · B ≥70 · C ≥55 · D ≥30 · F <30; the validator enforces optimal → A,
  neutral → C/D, detrimental → F for every scenario
- Technique identification is a **player action**, not a flag on the chosen option: after committing,
  the player picks the ATT&CK technique from three candidates. The ATT&CK tracker and the report's
  identification rate now reflect that answer. Post-incident injects that reference NIST controls
  rather than ATT&CK techniques are reported as *framework references* and skip the challenge

### Added — gameplay
- **Briefing screen** with role, objectives (`scenario_meta.objectives`, optional), threat profile and
  a how-it-works primer before the first inject
- **Branching narrative** via optional `story_variants` on an inject, keyed by the previous decision's
  quality; authored for all four follow-on injects of *Operation Midnight Cipher*
- **Post-commit reveal** of the two options not taken, with their quality, score impact and assessment
- **Structured debrief screen** (grade, meters, NIST phase efficiency, decision review, next actions)
  replacing the ASCII summary in the story box
- **Decision log** tab in the sidebar alongside the ATT&CK tracker

### Added — trainer tools
- Menu bar (File / Scenario / Trainer / Help) with keyboard accelerators
- **Facilitator mode**: quality ratings, score impact, feedback and meters are withheld until the debrief
- **Discussion timer** per inject (3/5/10/15 min) and an inject elapsed clock in the status bar
- **Discussion prompts by role** (IR lead / legal / comms / executive) per NIST phase; injects may
  override with `role_prompts`
- **Save / resume progress** to a `.irsim.json` file
- Scenario picker rebuilt as a sortable table with **industry and severity filters** and a detail line
- Restarting or switching scenarios keeps the current window size and position

### Changed — report
- Executive recommendations are selected from a technique → control library covering every ATT&CK
  technique in the scenario file, escalated to CRITICAL when the response or identification fell
  short, plus a *Revisit playbook* item for every non-optimal decision. Previously the same seven
  ransomware controls were emitted for every scenario
- Regulatory checklist gains an **Exercise Indication** column (addressed / partially addressed /
  at risk / not exercised) inferred from the committed decisions; industry matching is token-based
  (no more PCI rows for "Technology" or defence rows for "E-Commerce")
- Timeline entries include the alternatives not taken and the identification result
- Report preview renders headings, tables, bold and quotes; **Copy Markdown** button; raw toggle
- Fixed: detection-rate line printed the literal words "if applicable"; certification timestamp was
  local time labelled UTC; emoji headings replaced with plain headings for portability

### Changed — UI
- Inject column is a **scrollable region with a pinned action bar**, so long choices and feedback no
  longer collapse the story and the primary action never scrolls away
- Whole-row **selectable options** with a visible selected state (replaces radiobuttons whose
  indicator matched the background); hover no longer clears the selection highlight
- Header auto-sizes and wraps instead of clipping the scenario line at narrow widths
- Proportional font for prose (story, choices, feedback); monospace kept for IDs, scores and tags
- Score meters and grade colour by grade band; severity coloured in the briefing and sidebar
- Sidebar has a fixed width so the layout no longer shifts as content changes; sidebar text wraps
  to the actual width; ATT&CK tracker and decision log scroll
- Status bar is no longer squeezed out of the window by the main panel
- Emoji in buttons replaced with glyphs that render consistently in Tk

### Changed — packaging and CI
- `scenarios.json` lookup: `--scenarios PATH`, `$IR_SIM_SCENARIOS`, next to `app.py`, working
  directory, then `<prefix>/share/ir_sim` (installed by `setup.py`), so the `ir_sim` console script
  works after `pip install`
- CI now fails on pyflakes findings, runs the unit tests and a headless GUI smoke test under Xvfb
- New `tests/` suite (scoring, session/report, GUI smoke)
- Validator: `--strict`, optional-field validation (`story_variants`, `role_prompts`, `objectives`,
  `role`), ATT&CK ID format warnings, delta-ordering warnings, duplicate-ID checks
- Removed dead `4`/`D` key bindings (injects have exactly three choices)

---

## [3.2.0] — 2026

### Added
- **In-app GRC report preview** — *Generate GRC Report* now opens a dark-themed preview window
  with the full Markdown report and **Save As…** / **Close** actions, instead of only writing a file
- **Scenario chooser** — new **▤ CHOOSE…** sidebar button opens a picker listing all scenarios
  (severity, title, theme, industry) so trainers can run a specific scenario; double-click,
  `Enter`, or **Load Scenario** to start it
- **Decision score impact chips** — the feedback panel now shows the committed choice's
  per-axis deltas (`NIST +20 · COMPLIANCE -8 · LEGAL -10`), color-coded by direction
- **Feedback quality tinting** — the feedback card background and border now tint
  green/yellow/red to match decision quality (the `QUALITY_STYLES` tints existed but were unused)
- **Live exercise timer** in the status bar; freezes at completion and matches the duration
  recorded in the exported report
- **Exit confirmation** when closing the window mid-exercise

### Changed
- Sidebar replay control split into **↻ RANDOM** and **▤ CHOOSE…** buttons
- Status bar version/scenario count now derive from `APP_VERSION` and the loaded scenario file
  instead of hardcoded strings

### Removed
- Dead `customtkinter` import block — the app is pure stdlib tkinter and the optional dependency
  had no effect; `requirements.txt`, `setup.py`, and README updated accordingly

### Fixed
- MITRE tracker "◇ Missed" status label was clipped to "Misse" (label width too narrow)

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
