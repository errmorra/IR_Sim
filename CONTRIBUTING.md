# Contributing to IR_Sim

Thank you for your interest in contributing! This project welcomes improvements from the cybersecurity and GRC community.

---

## 🚀 Ways to Contribute

### 1. New Scenarios
The easiest contribution — add a new scenario to `scenarios.json`. No Python changes needed. See the schema below.

**Themes still wanted:**
- OT/ICS Incident (IEC 62443 / NERC CIP)
- Election Infrastructure Attack
- Satellite / Space Systems Compromise
- AI Model Poisoning / MLOps Attack
- Quantum-Resistant Cryptography Migration Incident
- Social Media Account Takeover (Brand)
- Mobile Banking Trojan
- Municipal Government Ransomware

### 2. Bug Fixes
Open an issue first, then submit a PR with the fix.

### 3. UI / UX Improvements
Improvements to the tkinter dashboard layout, accessibility, or score visualization are welcome.

### 4. Feature Ideas
- Timer / pressure mode per inject
- Facilitator mode (reveal all answers, export to PDF)
- Score history comparison across runs
- Multi-language scenario support
- CSV export of decision log

---

## 📐 Scenario JSON Schema

Add your scenario as a new object inside the top-level `"scenarios"` array in `scenarios.json`.

```json
{
  "scenario_meta": {
    "id": "YOURTHEME-2024-021",
    "title": "Operation Your Title",
    "subtitle": "Short descriptive subtitle",
    "threat_actor": "Actor Name (Motivation)",
    "industry": "Target Industry",
    "severity": "CRITICAL | HIGH | MEDIUM | LOW",
    "estimated_impact": "$X.XM"
  },
  "nist_phases": [
    "Preparation",
    "Detection & Analysis",
    "Containment",
    "Eradication & Recovery",
    "Post-Incident Activity"
  ],
  "injects": [
    {
      "id": "inject_01",
      "phase": "Preparation",
      "phase_index": 0,
      "title": "Inject Title",
      "story": "Narrative describing what the security team discovers...",
      "mitre": {
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Phishing: Spearphishing Link",
        "technique_id": "T1566.002",
        "description": "One sentence explaining how this technique applies in context."
      },
      "choices": [
        {
          "id": "A",
          "text": "The response action text...",
          "quality": "optimal",
          "nist_score_delta": 20,
          "compliance_score_delta": 18,
          "legal_score_delta": 15,
          "feedback": "Explanation with regulatory citations (NIST, HIPAA, GDPR, etc.)...",
          "technique_identified": true
        },
        {
          "id": "B",
          "text": "...",
          "quality": "neutral",
          "nist_score_delta": 6,
          "compliance_score_delta": 4,
          "legal_score_delta": 3,
          "feedback": "...",
          "technique_identified": false
        },
        {
          "id": "C",
          "text": "...",
          "quality": "detrimental",
          "nist_score_delta": -12,
          "compliance_score_delta": -15,
          "legal_score_delta": -10,
          "feedback": "...",
          "technique_identified": false
        }
      ]
    }
  ]
}
```

### Schema Rules
- Every inject must have **exactly 3 choices**: one `optimal`, one `neutral`, one `detrimental`
- `phase_index` must match the position of `phase` in the `nist_phases` array (0-based)
- `technique_identified: true` on the choice that correctly identifies or acts on the MITRE technique
- Score deltas can be negative; all scores are clamped to [0, 100]
- Feedback **must** cite specific regulations, standards, or framework controls where applicable
- `nist_phases` must be the standard 5-phase array shown above (do not modify)

### Score Delta Guidelines

| Quality | NIST delta range | Compliance delta range | Legal delta range |
|---|---|---|---|
| `optimal` | +18 to +30 | +15 to +35 | +15 to +30 |
| `neutral` | +3 to +12 | 0 to +10 | -5 to +10 |
| `detrimental` | -5 to -25 | -10 to -35 | -10 to -35 |

---

## 🔀 Pull Request Process

1. Fork the repo and create a branch: `git checkout -b scenario/ot-ics-incident  # fork from https://github.com/errmorra/IR_Sim`
2. Add your scenario to `scenarios.json`
3. Run the validation script to confirm your scenario passes:
   ```bash
   python validate_scenarios.py
   ```
4. Play through your scenario in the app: `python app.py`
5. Update the scenario roster table in `README.md`
6. Submit a PR with a clear description of the scenario theme and MITRE techniques covered

---

## ✅ Code Style

- Follow the four-class architecture in `app.py`: `ScenarioManager`, `SimulationSession`, `ReportGenerator`, `IncidentSimulatorApp`
- Keep GUI logic in `IncidentSimulatorApp`, data logic in `SimulationSession` / `ScenarioManager`
- All scenario content belongs in `scenarios.json` — never hardcode scenario data in Python

---

## 🛡️ Accuracy Standard

This is a GRC training tool. All regulatory citations, MITRE technique IDs, and framework references must be accurate. If uncertain, cite the source in your PR for review.

**Key references:**
- MITRE ATT&CK: https://attack.mitre.org/
- NIST SP 800-61 r2: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
- NIST CSF 2.0: https://www.nist.gov/cyberframework
- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- HHS OCR HIPAA: https://www.hhs.gov/hipaa/for-professionals/security/index.html
- GDPR Full Text: https://gdpr-info.eu/
