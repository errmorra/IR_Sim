"""
Incident Response Tabletop Simulator
=====================================
A modern GUI application for cybersecurity GRC training, mapping attacker
behaviors to the MITRE ATT&CK framework and NIST SP 800-61 r2 lifecycle.

Author: Portfolio Project — Cybersecurity GRC Professional
Dependencies: customtkinter, Pillow (optional)
"""

import json
import random
import sys
import tkinter as tk
from tkinter import messagebox, filedialog
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Dependency handling — graceful fallback to standard tkinter if needed
# ---------------------------------------------------------------------------
try:
    import customtkinter as ctk
    CTK_AVAILABLE = True
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
except ImportError:
    CTK_AVAILABLE = False

# ---------------------------------------------------------------------------
# Design System Constants
# ---------------------------------------------------------------------------
COLORS = {
    # Base palette
    "bg_primary":    "#0A0E1A",   # Deep navy-black
    "bg_secondary":  "#0F1626",   # Slightly lighter navy
    "bg_card":       "#141E2E",   # Card/panel background
    "bg_elevated":   "#1A2540",   # Elevated element background
    "bg_input":      "#0D1520",   # Input field background

    # Accent colors
    "accent_cyan":   "#00D4FF",   # Primary accent — cyber cyan
    "accent_green":  "#00FF94",   # Success / Optimal
    "accent_yellow": "#FFD700",   # Warning / Neutral
    "accent_red":    "#FF3B6B",   # Danger / Detrimental
    "accent_purple": "#A855F7",   # MITRE ATT&CK highlight
    "accent_blue":   "#3B82F6",   # Info / Phase indicator

    # Text
    "text_primary":  "#E8F4FD",   # Main text
    "text_secondary":"#7A9EC8",   # Muted text
    "text_dim":      "#3D5A80",   # Dimmed/disabled text

    # Borders
    "border":        "#1E3A5F",   # Subtle border
    "border_bright": "#00D4FF",   # Active/highlighted border

    # Phase colors
    "phase_prep":    "#3B82F6",
    "phase_detect":  "#A855F7",
    "phase_contain": "#F59E0B",
    "phase_eradicate":"#EF4444",
    "phase_post":    "#10B981",
}

FONTS = {
    "display":   ("Courier New", 20, "bold"),
    "header":    ("Courier New", 14, "bold"),
    "subheader": ("Courier New", 11, "bold"),
    "body":      ("Consolas", 11),
    "body_sm":   ("Consolas", 10),
    "mono":      ("Courier New", 10),
    "mono_sm":   ("Courier New", 9),
    "button":    ("Courier New", 10, "bold"),
    "tag":       ("Courier New", 9, "bold"),
}

PHASE_COLORS = [
    COLORS["phase_prep"],
    COLORS["phase_detect"],
    COLORS["phase_contain"],
    COLORS["phase_eradicate"],
    COLORS["phase_post"],
]

QUALITY_STYLES = {
    "optimal":     {"color": COLORS["accent_green"],  "icon": "◆ OPTIMAL",    "bg": "#0A2618"},
    "neutral":     {"color": COLORS["accent_yellow"], "icon": "◇ NEUTRAL",    "bg": "#1A1500"},
    "detrimental": {"color": COLORS["accent_red"],    "icon": "✕ DETRIMENTAL","bg": "#1A0010"},
}


# ---------------------------------------------------------------------------
# Data Layer
# ---------------------------------------------------------------------------
class ScenarioManager:
    """
    Loads scenarios.json and randomly selects one scenario at startup.

    scenarios.json top-level format:
        { "scenarios": [ { "scenario_meta": {...}, "nist_phases": [...], "injects": [...] }, ... ] }

    A randomly chosen scenario is "mounted" — all subsequent access
    (meta, phases, injects) reads only from that selected scenario.
    """

    def __init__(self, path: str = "scenarios.json"):
        self.path = path
        self._all_scenarios = self._load()          # list of scenario dicts
        self._scenario_index = random.randrange(len(self._all_scenarios))
        self._mount(self._scenario_index)           # set active scenario

    def _load(self) -> list:
        script_dir = Path(__file__).parent
        full_path = script_dir / self.path
        if not full_path.exists():
            messagebox.showerror("Error", f"scenarios.json not found at:\n{full_path}")
            sys.exit(1)
        with open(full_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        # Support both the new multi-scenario format and the legacy single-scenario format
        if "scenarios" in raw:
            return raw["scenarios"]
        else:
            return [raw]   # wrap legacy single-scenario file transparently

    def _mount(self, index: int):
        """Set the active scenario by index."""
        scenario = self._all_scenarios[index]
        self.injects = scenario["injects"]
        self.meta    = scenario["scenario_meta"]
        self.phases  = scenario["nist_phases"]

    def reselect(self):
        """Pick a new random scenario, avoiding an immediate repeat when possible."""
        if len(self._all_scenarios) > 1:
            choices = [i for i in range(len(self._all_scenarios)) if i != self._scenario_index]
            self._scenario_index = random.choice(choices)
        self._mount(self._scenario_index)

    @property
    def total_scenarios(self) -> int:
        return len(self._all_scenarios)

    def get_inject(self, index: int) -> dict:
        return self.injects[index]

    @property
    def total_injects(self) -> int:
        return len(self.injects)


# ---------------------------------------------------------------------------
# Session State
# ---------------------------------------------------------------------------
class SimulationSession:
    """Tracks all runtime state: scores, decisions, MITRE techniques."""

    MAX_SCORE = 100

    def __init__(self, meta: dict, phases: list):
        self.meta = meta
        self.phases = phases
        self.start_time = datetime.now()
        self.current_inject_index = 0

        # Score buckets per NIST phase
        self.phase_scores = {phase: 0 for phase in phases}
        self.phase_max    = {phase: 0 for phase in phases}

        # Compliance metrics
        self.compliance_score = 50   # starts at 50/100
        self.legal_score      = 50
        self.nist_score       = 50

        # History for report
        self.decision_log: list[dict] = []
        self.mitre_techniques: list[dict] = []
        self.mitre_identified: list[dict] = []  # correctly ID'd by user

    def apply_decision(self, inject: dict, choice: dict):
        phase = inject["phase"]
        delta_nist       = choice["nist_score_delta"]
        delta_compliance = choice["compliance_score_delta"]
        delta_legal      = choice["legal_score_delta"]

        # Clamp scores to [0, 100]
        self.nist_score       = max(0, min(100, self.nist_score       + delta_nist))
        self.compliance_score = max(0, min(100, self.compliance_score + delta_compliance))
        self.legal_score      = max(0, min(100, self.legal_score      + delta_legal))

        # Phase score accumulation (track positive deltas)
        if delta_nist > 0:
            self.phase_scores[phase] = self.phase_scores.get(phase, 0) + delta_nist
        self.phase_max[phase] = self.phase_max.get(phase, 0) + max(
            c["nist_score_delta"] for c in inject["choices"]
        )

        # Log the decision
        self.decision_log.append({
            "inject_id":    inject["id"],
            "inject_title": inject["title"],
            "phase":        phase,
            "choice_id":    choice["id"],
            "choice_text":  choice["text"],
            "quality":      choice["quality"],
            "feedback":     choice["feedback"],
            "nist_delta":   delta_nist,
            "mitre":        inject["mitre"],
            "technique_identified": choice.get("technique_identified", False),
        })

        # Track MITRE techniques encountered
        mitre = inject["mitre"]
        if not any(t["technique_id"] == mitre["technique_id"] for t in self.mitre_techniques):
            self.mitre_techniques.append({
                **mitre,
                "identified": choice.get("technique_identified", False),
            })
        elif choice.get("technique_identified", False):
            # Update to identified if previously missed
            for t in self.mitre_techniques:
                if t["technique_id"] == mitre["technique_id"]:
                    t["identified"] = True

    @property
    def overall_score(self) -> float:
        return round((self.nist_score + self.compliance_score + self.legal_score) / 3, 1)

    @property
    def techniques_identified(self) -> int:
        return sum(1 for t in self.mitre_techniques if t.get("identified", False))

    def grade(self) -> tuple[str, str]:
        score = self.overall_score
        if score >= 85:  return ("A",  COLORS["accent_green"])
        if score >= 70:  return ("B",  COLORS["accent_cyan"])
        if score >= 55:  return ("C",  COLORS["accent_yellow"])
        if score >= 40:  return ("D",  "#FF8C42")
        return                  ("F",  COLORS["accent_red"])


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------
class ReportGenerator:
    """Generates a formatted Markdown post-incident GRC report."""

    def __init__(self, session: SimulationSession):
        self.session = session
        self.generated_at = datetime.now()

    def generate(self) -> str:
        s = self.session
        grade, _ = s.grade()
        duration = self.generated_at - s.start_time
        duration_str = str(duration).split(".")[0]

        lines = []
        a = lines.append

        # Header
        a("# 🛡️ POST-INCIDENT & GRC COMPLIANCE REVIEW REPORT")
        a("")
        a(f"**Incident Scenario:** {s.meta['title']}  ")
        a(f"**Subtitle:** {s.meta['subtitle']}  ")
        a(f"**Threat Actor Profile:** {s.meta['threat_actor']}  ")
        a(f"**Industry Sector:** {s.meta['industry']}  ")
        a(f"**Severity Classification:** {s.meta['severity']}  ")
        a(f"**Estimated Impact:** {s.meta['estimated_impact']}  ")
        a(f"**Simulation Date:** {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}  ")
        a(f"**Exercise Duration:** {duration_str}  ")
        a(f"**Overall Performance Grade:** **{grade}** ({s.overall_score:.1f}/100)  ")
        a("")
        a("---")
        a("")

        # Executive Summary
        a("## 📋 Executive Summary")
        a("")
        a(f"This report documents the results of an interactive cybersecurity incident response "
          f"tabletop exercise simulating a {s.meta['subtitle'].lower()}. "
          f"The exercise followed the **NIST SP 800-61 Rev. 2** Incident Response Lifecycle "
          f"across {len(s.phases)} phases and {len(s.decision_log)} decision points.")
        a("")
        a(f"The participant demonstrated **{grade}-level** incident response capability with "
          f"an overall composite score of **{s.overall_score:.1f}/100**. "
          f"**{s.techniques_identified}/{len(s.mitre_techniques)}** MITRE ATT&CK techniques "
          f"were correctly identified during the exercise.")
        a("")
        a("---")
        a("")

        # Score Dashboard
        a("## 📊 GRC Performance Metrics")
        a("")
        a("| Metric | Score | Assessment |")
        a("|--------|-------|------------|")

        def rating(score):
            if score >= 80: return "✅ Strong"
            if score >= 60: return "⚠️ Adequate"
            if score >= 40: return "🔶 Needs Improvement"
            return "❌ Critical Gap"

        a(f"| NIST IR Framework Score | {s.nist_score}/100 | {rating(s.nist_score)} |")
        a(f"| Regulatory Compliance Score | {s.compliance_score}/100 | {rating(s.compliance_score)} |")
        a(f"| Legal & Liability Score | {s.legal_score}/100 | {rating(s.legal_score)} |")
        a(f"| **Overall Composite** | **{s.overall_score:.1f}/100** | **{rating(s.overall_score)}** |")
        a("")
        a("### NIST Phase Breakdown")
        a("")
        a("| NIST Phase | Score Earned | Max Available | Efficiency |")
        a("|------------|-------------|---------------|------------|")
        for phase in s.phases:
            earned = s.phase_scores.get(phase, 0)
            max_s  = s.phase_max.get(phase, 0)
            eff = f"{(earned/max_s*100):.0f}%" if max_s > 0 else "N/A"
            a(f"| {phase} | {earned} | {max_s} | {eff} |")
        a("")
        a("---")
        a("")

        # Decision Timeline
        a("## 🕐 Incident Response Decision Timeline")
        a("")
        for i, decision in enumerate(s.decision_log, 1):
            quality = decision["quality"]
            icon = {"optimal": "✅", "neutral": "⚠️", "detrimental": "❌"}.get(quality, "•")
            a(f"### {icon} Inject {i}: {decision['inject_title']}")
            a(f"**Phase:** {decision['phase']} | **Decision Quality:** {quality.upper()}")
            a("")
            a("**Action Taken:**  ")
            a(f"> {decision['choice_text']}")
            a("")
            a("**Assessment:**  ")
            a(f"> {decision['feedback']}")
            a("")
            mitre = decision["mitre"]
            a("**MITRE ATT&CK Context:**  ")
            a(f"- Tactic: `{mitre['tactic']}` ({mitre['tactic_id']})")
            a(f"- Technique: `{mitre['technique']}` ({mitre['technique_id']})")
            a(f"- Technique Correctly Identified: {'Yes ✅' if decision['technique_identified'] else 'No ❌'}")
            a(f"- NIST Score Impact: `{'+' if decision['nist_delta'] >= 0 else ''}{decision['nist_delta']}`")
            a("")

        a("---")
        a("")

        # MITRE ATT&CK Checklist
        a("## 🎯 MITRE ATT&CK Techniques Encountered")
        a("")
        a("The following adversary techniques were present in this scenario, mapped to the "
          "MITRE ATT&CK Enterprise framework v14:")
        a("")
        a("| Status | Tactic | Technique | ID | Identified |")
        a("|--------|--------|-----------|-----|------------|")
        for t in s.mitre_techniques:
            status = "✅" if t.get("identified") else "❌"
            a(f"| {status} | {t['tactic']} ({t['tactic_id']}) | {t['technique']} | `{t['technique_id']}` | {'Yes' if t.get('identified') else 'No'} |")
        a("")
        a(f"**Detection Rate:** {s.techniques_identified}/{len(s.mitre_techniques)} "
          f"({(s.techniques_identified/len(s.mitre_techniques)*100):.0f}% if applicable)")
        a("")
        a("---")
        a("")

        # Executive Recommendations
        a("## 💼 Executive Recommendations for Framework Compliance")
        a("")
        a("Based on the simulation outcomes and MITRE techniques encountered, "
          "the following control improvements are recommended:")
        a("")

        recommendations = self._build_recommendations()
        for i, rec in enumerate(recommendations, 1):
            a(f"### Recommendation {i}: {rec['title']}")
            a(f"**Priority:** {rec['priority']} | **Framework Mapping:** {rec['framework']}  ")
            a(f"{rec['detail']}  ")
            a("")

        a("---")
        a("")

        # Regulatory Framework Obligations (tailored to scenario industry + techniques)
        a("## ⚖️ Regulatory & Legal Obligations Checklist")
        a("")
        a(f"Obligations below are scoped to the **{s.meta['industry']}** sector and the adversary "
          f"techniques observed in this scenario. Confirm specifics with legal counsel.")
        a("")
        a("| Obligation | Regulatory Source | Status | Notes |")
        a("|------------|------------------|--------|-------|")
        for ob in self._build_regulatory_obligations():
            a(f"| {ob['obligation']} | {ob['source']} | {ob['status']} | {ob['notes']} |")
        a("")
        a("---")
        a("")

        # Signature block
        a("## 📄 Report Certification")
        a("")
        a("This report was generated by the **Incident Response Tabletop Simulator** as a "
          "training and portfolio documentation artifact. It reflects simulated scenario outcomes "
          "and should be used for educational and preparedness assessment purposes.")
        a("")
        a(f"*Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}*  ")
        a(f"*Scenario ID: {s.meta['id']}*  ")
        a("*Framework References: NIST SP 800-61 r2 | MITRE ATT&CK Enterprise v14 | NIST CSF 2.0*")
        a("")

        return "\n".join(lines)

    def _build_recommendations(self) -> list[dict]:
        s = self.session
        recs = []

        # Always include core recommendations
        recs.append({
            "title": "Implement Phishing-Resistant Multi-Factor Authentication",
            "priority": "🔴 CRITICAL",
            "framework": "NIST CSF PR.AC-7 | CIS Control 6 | HIPAA §164.312(d)",
            "detail": "Deploy FIDO2/WebAuthn hardware security keys for all privileged accounts "
                      "and remote access gateways. SMS and TOTP-based MFA are insufficient against "
                      "real-time phishing proxy attacks (AiTM). This directly mitigates T1566.002.",
        })
        recs.append({
            "title": "Deploy Privileged Access Workstations (PAWs) & Tiered Admin Model",
            "priority": "🔴 CRITICAL",
            "framework": "NIST SP 800-207 Zero Trust | Microsoft PAW Guidance | CIS Control 12",
            "detail": "Service accounts and Domain Admin credentials must never be exposed on "
                      "general-purpose workstations. PAWs with no internet access and tiered "
                      "Active Directory models prevent credential harvest pivot chains (T1003.001).",
        })
        recs.append({
            "title": "Enable LSASS Protection & Credential Guard",
            "priority": "🔴 CRITICAL",
            "framework": "NIST SP 800-53 SI-3 | CIS Control 10 | DISA STIG Windows Server",
            "detail": "Enable RunAsPPL for LSASS (Windows Credential Guard) to prevent memory "
                      "reads by unsigned processes. This renders Mimikatz-class tools ineffective "
                      "against T1003.001 in most configurations.",
        })
        recs.append({
            "title": "Deploy Cloud Access Security Broker (CASB) for Data Exfiltration Prevention",
            "priority": "🟠 HIGH",
            "framework": "NIST SP 800-53 SC-7 | CIS Control 13 | HIPAA §164.312(e)(2)(i)",
            "detail": "A CASB solution provides inline inspection of cloud storage uploads "
                      "(Mega.nz, Google Drive, Dropbox) and can enforce DLP policies on encrypted "
                      "archives. This directly addresses T1567.002 exfiltration via cloud services.",
        })
        recs.append({
            "title": "Immutable, Tested Offline Backup Architecture",
            "priority": "🟠 HIGH",
            "framework": "NIST SP 800-34 | CIS Control 11 | HIPAA §164.308(a)(7)",
            "detail": "The 3-2-1-1 backup rule (3 copies, 2 media types, 1 offsite, 1 offline/immutable) "
                      "is the primary defense against ransomware (T1486). Backups must be tested "
                      "quarterly with documented RTO/RPO validation.",
        })
        recs.append({
            "title": "Formalize Incident Response Plan with Legal & Breach Notification Runbooks",
            "priority": "🟡 MEDIUM",
            "framework": "NIST SP 800-61 r2 | HIPAA §164.308(a)(6) | CIRCIA 2022",
            "detail": "Create pre-approved notification templates for HHS OCR, state AGs, FBI Cyber, "
                      "and CISA. Pre-identify legal counsel with cyber breach specialization. Establish "
                      "a decision tree for breach classification within the first 24 hours of detection.",
        })
        recs.append({
            "title": "Conduct Quarterly MITRE ATT&CK-Based Tabletop Exercises",
            "priority": "🟡 MEDIUM",
            "framework": "NIST CSF RS.CO | SOC 2 CC7.3 | ISO 27001 A.16.1.5",
            "detail": "Map each tabletop scenario to specific ATT&CK techniques relevant to your "
                      "industry vertical. Track 'technique identification rate' as a KPI for SOC maturity. "
                      "Target: >80% technique identification rate within 12 months.",
        })

        # Surface recommendations that map to techniques actually seen in this run first.
        encountered = {t.get("technique_id", "") for t in s.mitre_techniques}
        encountered.discard("")

        def relevance(rec):
            return any(tid and tid in rec["detail"] for tid in encountered)

        recs.sort(key=relevance, reverse=True)
        return recs

    def _build_regulatory_obligations(self) -> list[dict]:
        """Return a regulatory checklist scoped to the scenario industry and techniques.

        Previously this section was hardcoded to healthcare/HIPAA for every scenario,
        which produced inaccurate reports (e.g. PHI/HIPAA rows on a DeFi or DDoS run).
        """
        s = self.session
        industry = (s.meta.get("industry", "") or "").lower()
        technique_ids = " ".join(t.get("technique_id", "") for t in s.mitre_techniques)
        obligations: list[dict] = []

        def add(obligation, source, status, notes):
            obligations.append({"obligation": obligation, "source": source,
                                "status": status, "notes": notes})

        # ---- Industry-specific notification obligations ----
        if any(k in industry for k in ("health", "hospital", "pharma", "medical")):
            add("PHI Breach Notification to HHS OCR", "HIPAA §164.408",
                "Required within 60 days", "File at ocrportal.hhs.gov")
            add("Individual Patient Notification", "HIPAA §164.404",
                "Required within 60 days", "Written notice required")
            add("Media Notification (if >500 affected in a state)", "HIPAA §164.406",
                "Likely Required", "Notify prominent in-state media outlets")
        if any(k in industry for k in ("bank", "financial", "insurance", "fintech", "crypto")):
            add("Customer Notification & Safeguards Review", "GLBA Safeguards Rule (16 CFR 314)",
                "Required", "Notify FTC for breaches affecting 500+ consumers")
            add("Suspicious Activity Report (if fraud/funds movement)", "FinCEN SAR (31 CFR 1020.320)",
                "Required if applicable", "File within 30 days of detection")
            add("Material Cybersecurity Incident Disclosure", "SEC Cyber Disclosure Rule (2023)",
                "Required if public company", "Form 8-K Item 1.05 within 4 business days")
        if any(k in industry for k in ("commerce", "retail", "gaming", "saas", "media", "technology")):
            add("Cardholder Data Breach Notification", "PCI DSS v4.0 / Card Brands",
                "Required if CHD involved", "Notify acquirer & card brands immediately")
            add("Customer / Data Subject Notification", "GDPR Art. 33-34 / CCPA-CPRA",
                "Required if PII exposed", "GDPR: 72h to supervisory authority")
        if any(k in industry for k in ("defense", "manufactur")):
            add("DoD Cyber Incident Report", "DFARS 252.204-7012",
                "Required if CDI/CUI involved", "Report to DIBNET within 72 hours")
            add("CMMC Control Assessment", "CMMC Level 2",
                "Review post-incident", "Update SSP/POA&M as needed")

        # ---- Technique / threat-driven obligations ----
        ransomware = ("T1486" in technique_ids or "T1490" in technique_ids
                      or "ransom" in (s.meta.get("subtitle", "").lower()))
        if ransomware:
            add("OFAC Sanctions Screening Before Any Payment", "OFAC Advisory (2020/2021)",
                "Required before payment", "Verify threat actor not on SDN list")
        if any(tid in technique_ids for tid in ("T1567", "T1048", "T1041", "T1530")):
            add("Data Exfiltration Breach Assessment", "State Breach Laws / GDPR",
                "Required if PII/PHI exfiltrated", "Document data categories exposed")

        # ---- Critical infrastructure ----
        if "infrastructure" in industry:
            add("CISA Cyber Incident Report", "CIRCIA 2022",
                "Required for covered entities", "Report within 72 hours of determination")

        # ---- Always-applicable baseline obligations ----
        add("Law Enforcement Notification", "18 U.S.C. § 1030",
            "Recommended", "File complaint at IC3.gov / contact FBI field office")
        add("State Attorney General Notification", "State Breach Notification Laws",
            "Varies by state", "Review all applicable U.S. state requirements")
        add("Cyber Insurance Carrier Notification", "Policy Terms",
            "Required", "Notify within the policy-defined window to preserve coverage")
        add("Preserve Forensic Evidence & Litigation Hold", "FRCP / Legal Counsel",
            "Required", "Maintain chain of custody for potential litigation")

        return obligations


# ---------------------------------------------------------------------------
# Main GUI Application
# ---------------------------------------------------------------------------
class IncidentSimulatorApp(tk.Tk):
    """
    Main application window.
    Uses tkinter with heavy manual styling to achieve a modern dark dashboard.
    """

    def __init__(self):
        super().__init__()
        self.scenario_mgr = ScenarioManager()
        self.session = SimulationSession(
            self.scenario_mgr.meta,
            self.scenario_mgr.phases,
        )
        self._selected_choice = tk.StringVar(value="")
        self._feedback_visible = False
        self._sim_complete = False
        self._content_wraplength = 700

        self._configure_window()
        self._build_ui()
        self._load_inject(0)

    # ------------------------------------------------------------------ setup

    def _configure_window(self):
        n = self.scenario_mgr._scenario_index + 1
        t = self.scenario_mgr.total_scenarios
        self.title(f"IR_Sim  //  Scenario {n}/{t}: {self.scenario_mgr.meta['title']}")
        self.geometry("1280x820")
        self.minsize(1100, 750)
        self.configure(bg=COLORS["bg_primary"])
        self.resizable(True, True)

        # Center on screen
        self.update_idletasks()
        w, h = 1280, 820
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ------------------------------------------------------------- UI builder

    def _build_ui(self):
        """Build the full dashboard layout."""
        self._build_header()
        main = tk.Frame(self, bg=COLORS["bg_primary"])
        main.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        main.columnconfigure(0, weight=3)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(0, weight=1)

        self._build_main_panel(main)
        self._build_sidebar(main)
        self._build_status_bar()
        self._bind_shortcuts()

    def _bind_shortcuts(self):
        """Keyboard navigation: 1-4 / A-D pick a response, Enter commits/advances."""
        for i, key in enumerate(("1", "2", "3", "4")):
            self.bind(key, lambda e, idx=i: self._select_choice_by_index(idx))
        for i, key in enumerate(("a", "b", "c", "d")):
            self.bind(key, lambda e, idx=i: self._select_choice_by_index(idx))
            self.bind(key.upper(), lambda e, idx=i: self._select_choice_by_index(idx))
        self.bind("<Return>", self._on_enter)
        self.bind("<KP_Enter>", self._on_enter)

    def _select_choice_by_index(self, idx: int):
        if self._sim_complete:
            return
        if self._feedback_visible:
            return
        if 0 <= idx < len(getattr(self, "_display_tokens", [])):
            self._selected_choice.set(self._display_tokens[idx])

    def _on_enter(self, _event=None):
        if self._sim_complete:
            return
        if self._feedback_visible:
            self._next_btn.invoke()
        elif str(self._submit_btn["state"]) != "disabled":
            self._on_submit()

    # Compact labels for the header phase tracker so long names never clip.
    PHASE_SHORT_LABELS = [
        "PREP",
        "DETECT",
        "CONTAIN",
        "ERADICATE",
        "POST",
    ]

    def _build_header(self):
        hdr = tk.Frame(self, bg=COLORS["bg_card"], height=72)
        hdr.pack(fill="x", padx=0, pady=0)
        hdr.pack_propagate(False)

        # Left — branding
        left = tk.Frame(hdr, bg=COLORS["bg_card"])
        left.pack(side="left", padx=20, pady=10)

        tk.Label(left, text="⬡ IR·SIM",
                 font=FONTS["display"],
                 fg=COLORS["accent_cyan"], bg=COLORS["bg_card"]).pack(anchor="w")
        n = self.scenario_mgr._scenario_index + 1
        t = self.scenario_mgr.total_scenarios
        self._header_subtitle = tk.Label(left,
                 text=f"SCENARIO {n}/{t} [RANDOM]: {self.scenario_mgr.meta['title'].upper()}  //  {self.scenario_mgr.meta['threat_actor']}",
                 font=FONTS["mono_sm"],
                 fg=COLORS["text_secondary"], bg=COLORS["bg_card"])
        self._header_subtitle.pack(anchor="w")

        # Right — phase tracker (compact labels prevent clipping at the edge)
        right = tk.Frame(hdr, bg=COLORS["bg_card"])
        right.pack(side="right", padx=20, pady=14)

        self._phase_dots = []
        for i, phase in enumerate(self.scenario_mgr.phases):
            dot_frame = tk.Frame(right, bg=COLORS["bg_card"])
            dot_frame.pack(side="left", padx=5)
            dot = tk.Label(dot_frame, text="●", font=("Courier New", 13),
                           fg=COLORS["text_dim"], bg=COLORS["bg_card"])
            dot.pack()
            short = self.PHASE_SHORT_LABELS[i] if i < len(self.PHASE_SHORT_LABELS) else phase
            name = tk.Label(dot_frame, text=short,
                            font=FONTS["tag"], justify="center",
                            fg=COLORS["text_dim"], bg=COLORS["bg_card"])
            name.pack()
            self._phase_dots.append((dot, name))
            if i < len(self.scenario_mgr.phases) - 1:
                tk.Label(right, text="─", font=FONTS["mono"],
                         fg=COLORS["text_dim"], bg=COLORS["bg_card"]).pack(side="left", padx=1)

    def _build_main_panel(self, parent):
        panel = tk.Frame(parent, bg=COLORS["bg_primary"])
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=8)
        self._main_panel = panel
        panel.bind("<Configure>", self._on_panel_resize)
        panel.rowconfigure(0, weight=0)  # inject header
        panel.rowconfigure(1, weight=1)  # story text
        panel.rowconfigure(2, weight=0)  # MITRE badge
        panel.rowconfigure(3, weight=0)  # choices
        panel.rowconfigure(4, weight=0)  # feedback
        panel.columnconfigure(0, weight=1)

        # ── Inject header card
        self._inject_header = self._make_card(panel)
        self._inject_header.grid(row=0, column=0, sticky="ew", pady=(0, 6))

        ih_inner = tk.Frame(self._inject_header, bg=COLORS["bg_card"])
        ih_inner.pack(fill="x", padx=16, pady=12)

        header_top = tk.Frame(ih_inner, bg=COLORS["bg_card"])
        header_top.pack(fill="x")

        self._inject_num_label = tk.Label(header_top,
            text="INJECT 01/07",
            font=FONTS["tag"],
            fg=COLORS["accent_cyan"], bg=COLORS["bg_card"])
        self._inject_num_label.pack(side="left")

        self._phase_badge = tk.Label(header_top,
            text="[ PREPARATION ]",
            font=FONTS["tag"],
            fg=COLORS["phase_prep"], bg=COLORS["bg_card"])
        self._phase_badge.pack(side="right")

        self._inject_title_label = tk.Label(ih_inner,
            text="",
            font=FONTS["header"],
            fg=COLORS["text_primary"], bg=COLORS["bg_card"],
            anchor="w")
        self._inject_title_label.pack(fill="x", pady=(4, 6))

        # Thin progress bar showing how far through the scenario the player is
        prog_bg = tk.Frame(ih_inner, bg=COLORS["bg_input"], height=4)
        prog_bg.pack(fill="x")
        prog_bg.pack_propagate(False)
        self._progress_fill = tk.Frame(prog_bg, bg=COLORS["accent_cyan"], height=4)
        self._progress_fill.place(x=0, y=0, relheight=1.0, relwidth=0.0)

        # ── Story text area
        story_outer = self._make_card(panel)
        story_outer.grid(row=1, column=0, sticky="nsew", pady=(0, 6))

        self._story_text = tk.Text(
            story_outer,
            wrap="word",
            font=FONTS["body"],
            fg=COLORS["text_primary"],
            bg=COLORS["bg_input"],
            insertbackground=COLORS["accent_cyan"],
            selectbackground=COLORS["bg_elevated"],
            relief="flat",
            bd=0,
            padx=16, pady=14,
            state="disabled",
            cursor="arrow",
        )
        story_scroll = tk.Scrollbar(story_outer, command=self._story_text.yview,
                                    bg=COLORS["bg_card"], troughcolor=COLORS["bg_input"])
        self._story_text.configure(yscrollcommand=story_scroll.set)
        story_scroll.pack(side="right", fill="y")
        self._story_text.pack(fill="both", expand=True, padx=2, pady=2)

        # ── MITRE ATT&CK badge
        self._mitre_badge_frame = self._make_card(panel)
        self._mitre_badge_frame.grid(row=2, column=0, sticky="ew", pady=(0, 6))
        self._mitre_inner = tk.Frame(self._mitre_badge_frame, bg=COLORS["bg_card"])
        self._mitre_inner.pack(fill="x", padx=16, pady=10)

        self._mitre_badge_label = tk.Label(self._mitre_inner, text="",
                                           font=FONTS["body_sm"],
                                           fg=COLORS["text_secondary"],
                                           bg=COLORS["bg_card"],
                                           justify="left", anchor="w", wraplength=700)
        self._mitre_badge_label.pack(fill="x")

        # ── Choice buttons area
        choice_outer = self._make_card(panel)
        choice_outer.grid(row=3, column=0, sticky="ew", pady=(0, 6))

        choice_label = tk.Label(choice_outer,
            text="SELECT RESPONSE ACTION:   [ keys 1-3 or A-C select  ·  Enter commits ]",
            font=FONTS["tag"],
            fg=COLORS["accent_cyan"], bg=COLORS["bg_card"])
        choice_label.pack(anchor="w", padx=16, pady=(10, 4))

        self._choice_buttons_frame = tk.Frame(choice_outer, bg=COLORS["bg_card"])
        self._choice_buttons_frame.pack(fill="x", padx=14, pady=(0, 10))

        self._choice_buttons: list[tk.Radiobutton] = []

        # Submit button
        self._submit_btn = self._make_button(choice_outer,
            text="⬡  COMMIT DECISION  ⬡",
            command=self._on_submit,
            fg=COLORS["bg_primary"],
            bg=COLORS["accent_cyan"],
            active_bg=COLORS["accent_blue"])
        self._submit_btn.pack(anchor="e", padx=16, pady=(0, 12))

        # ── Feedback area
        self._feedback_frame = self._make_card(panel)
        self._feedback_frame.grid(row=4, column=0, sticky="ew", pady=(0, 4))
        self._feedback_frame.grid_remove()  # hidden until needed

        self._feedback_inner = tk.Frame(self._feedback_frame, bg=COLORS["bg_card"])
        self._feedback_inner.pack(fill="x", padx=16, pady=10)

        self._feedback_quality_label = tk.Label(self._feedback_inner, text="",
                                                font=FONTS["subheader"],
                                                bg=COLORS["bg_card"])
        self._feedback_quality_label.pack(anchor="w")

        self._feedback_text = tk.Label(self._feedback_inner, text="",
                                       font=FONTS["body_sm"],
                                       fg=COLORS["text_primary"],
                                       bg=COLORS["bg_card"],
                                       justify="left", wraplength=760, anchor="w")
        self._feedback_text.pack(fill="x", pady=(4, 0))

        self._next_btn = self._make_button(self._feedback_inner,
            text="NEXT INJECT  ▶",
            command=self._on_next,
            fg=COLORS["bg_primary"],
            bg=COLORS["accent_green"],
            active_bg="#00CC77")
        self._next_btn.pack(anchor="e", pady=(8, 0))

    def _build_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=COLORS["bg_primary"])
        sidebar.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=8)

        # ── Scenario Meta
        meta_card = self._make_card(sidebar)
        meta_card.pack(fill="x", pady=(0, 6))

        tk.Label(meta_card, text="SCENARIO BRIEFING",
                 font=FONTS["tag"], fg=COLORS["accent_cyan"],
                 bg=COLORS["bg_card"]).pack(anchor="w", padx=12, pady=(10, 4))

        meta = self.scenario_mgr.meta
        meta_rows = [
            ("Actor",    meta["threat_actor"]),
            ("Severity", meta["severity"]),
            ("Impact",   meta["estimated_impact"]),
            ("Industry", meta["industry"]),
        ]
        for label, val in meta_rows:
            row = tk.Frame(meta_card, bg=COLORS["bg_card"])
            row.pack(fill="x", padx=12, pady=1)
            tk.Label(row, text=f"{label}:", font=FONTS["mono_sm"],
                     fg=COLORS["text_dim"], bg=COLORS["bg_card"],
                     width=9, anchor="w").pack(side="left")
            tk.Label(row, text=val, font=FONTS["mono_sm"],
                     fg=COLORS["text_secondary"], bg=COLORS["bg_card"],
                     anchor="w", wraplength=160, justify="left").pack(side="left", fill="x")
        tk.Frame(meta_card, bg=COLORS["bg_card"], height=8).pack()

        # ── Score meters
        scores_card = self._make_card(sidebar)
        scores_card.pack(fill="x", pady=(0, 6))

        tk.Label(scores_card, text="LIVE GRC METRICS",
                 font=FONTS["tag"], fg=COLORS["accent_cyan"],
                 bg=COLORS["bg_card"]).pack(anchor="w", padx=12, pady=(10, 6))

        self._score_meters: dict[str, tuple] = {}
        score_defs = [
            ("NIST IR Score",    "nist_score",       COLORS["accent_cyan"]),
            ("Compliance",       "compliance_score", COLORS["accent_green"]),
            ("Legal Standing",   "legal_score",      COLORS["accent_yellow"]),
        ]
        for label, attr, color in score_defs:
            self._build_score_meter(scores_card, label, attr, color)

        tk.Frame(scores_card, bg=COLORS["border"], height=1).pack(fill="x", padx=12, pady=6)

        self._overall_label = tk.Label(scores_card,
            text=f"OVERALL: {self.session.overall_score:.1f}/100",
            font=FONTS["subheader"],
            fg=COLORS["accent_cyan"], bg=COLORS["bg_card"])
        self._overall_label.pack(anchor="w", padx=12, pady=(0, 4))

        self._grade_label = tk.Label(scores_card,
            text="GRADE: —",
            font=("Courier New", 16, "bold"),
            fg=COLORS["text_secondary"], bg=COLORS["bg_card"])
        self._grade_label.pack(anchor="w", padx=12, pady=(0, 10))

        # ── MITRE ATT&CK tracker
        mitre_card = self._make_card(sidebar)
        mitre_card.pack(fill="both", expand=True, pady=(0, 6))

        tk.Label(mitre_card, text="MITRE ATT&CK TRACKER",
                 font=FONTS["tag"], fg=COLORS["accent_purple"],
                 bg=COLORS["bg_card"]).pack(anchor="w", padx=12, pady=(10, 4))

        self._mitre_tracker_frame = tk.Frame(mitre_card, bg=COLORS["bg_card"])
        self._mitre_tracker_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self._mitre_count_label = tk.Label(mitre_card,
            text="Techniques: 0 encountered  |  0 identified",
            font=FONTS["mono_sm"],
            fg=COLORS["text_secondary"], bg=COLORS["bg_card"])
        self._mitre_count_label.pack(anchor="w", padx=12, pady=(0, 8))

        # ── Report button
        self._report_btn = self._make_button(sidebar,
            text="📄  GENERATE GRC REPORT",
            command=self._on_generate_report,
            fg=COLORS["bg_primary"],
            bg="#A855F7",
            active_bg="#7C3AED")
        self._report_btn.pack(fill="x", pady=(6, 0))
        self._report_btn.configure(state="disabled")

        # ── New scenario button — replay without relaunching the app
        self._new_btn = self._make_button(sidebar,
            text="↻  NEW SCENARIO",
            command=self._on_new_scenario,
            fg=COLORS["text_primary"],
            bg=COLORS["bg_elevated"],
            active_bg=COLORS["border"])
        self._new_btn.pack(fill="x", pady=(6, 0))

    def _build_score_meter(self, parent, label: str, attr: str, color: str):
        """Build a labeled progress bar for a score metric."""
        frame = tk.Frame(parent, bg=COLORS["bg_card"])
        frame.pack(fill="x", padx=12, pady=3)

        top = tk.Frame(frame, bg=COLORS["bg_card"])
        top.pack(fill="x")
        tk.Label(top, text=label, font=FONTS["mono_sm"],
                 fg=COLORS["text_secondary"], bg=COLORS["bg_card"]).pack(side="left")
        val_label = tk.Label(top, text="50", font=FONTS["mono_sm"],
                             fg=color, bg=COLORS["bg_card"])
        val_label.pack(side="right")

        bar_bg = tk.Frame(frame, bg=COLORS["bg_input"], height=6)
        bar_bg.pack(fill="x", pady=(2, 0))
        bar_bg.pack_propagate(False)

        bar_fill = tk.Frame(bar_bg, bg=color, height=6)
        bar_fill.place(x=0, y=0, relheight=1.0, relwidth=0.5)

        self._score_meters[attr] = (val_label, bar_fill)

    def _build_status_bar(self):
        bar = tk.Frame(self, bg=COLORS["bg_secondary"], height=24)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self._status_label = tk.Label(bar,
            text=f"▶  INJECT 1 OF {self.scenario_mgr.total_injects}  ·  PHASE: PREPARATION  ·  "
                 f"Framework: NIST SP 800-61 r2 | MITRE ATT&CK Enterprise v14",
            font=FONTS["mono_sm"],
            fg=COLORS["text_dim"], bg=COLORS["bg_secondary"])
        self._status_label.pack(side="left", padx=10)

        tk.Label(bar, text="IR_Sim v3.0  //  GRC Portfolio Edition  //  20 Scenarios",
                 font=FONTS["mono_sm"],
                 fg=COLORS["text_dim"], bg=COLORS["bg_secondary"]).pack(side="right", padx=10)

    # ----------------------------------------------------------- widget helpers

    def _make_card(self, parent) -> tk.Frame:
        return tk.Frame(parent, bg=COLORS["bg_card"],
                        highlightbackground=COLORS["border"],
                        highlightthickness=1)

    def _make_button(self, parent, text, command, fg, bg, active_bg) -> tk.Button:
        return tk.Button(parent,
            text=text,
            command=command,
            font=FONTS["button"],
            fg=fg,
            bg=bg,
            activeforeground=fg,
            activebackground=active_bg,
            relief="flat",
            bd=0,
            padx=14, pady=7,
            cursor="hand2",
        )

    def _on_panel_resize(self, event):
        """Reflow wrapped text so it adapts to the current window width."""
        # Card inner padding is ~16px on each side; leave a small safety margin.
        wrap = max(320, event.width - 48)
        self._content_wraplength = wrap
        for widget in (getattr(self, "_mitre_badge_label", None),
                       getattr(self, "_feedback_text", None)):
            if widget is not None and widget.winfo_exists():
                widget.configure(wraplength=wrap)
        for rb in getattr(self, "_choice_buttons", []):
            if rb.winfo_exists():
                rb.configure(wraplength=wrap - 24)

    # ----------------------------------------------------------- inject loader

    def _load_inject(self, index: int):
        inject = self.scenario_mgr.get_inject(index)
        phase_idx = inject["phase_index"]
        phase_color = PHASE_COLORS[phase_idx]

        # ── Phase dots
        for i, (dot, name) in enumerate(self._phase_dots):
            if i < phase_idx:
                dot.configure(fg=COLORS["text_secondary"])
                name.configure(fg=COLORS["text_secondary"])
            elif i == phase_idx:
                dot.configure(fg=phase_color)
                name.configure(fg=phase_color)
            else:
                dot.configure(fg=COLORS["text_dim"])
                name.configure(fg=COLORS["text_dim"])

        # ── Inject header
        self._inject_num_label.configure(
            text=f"INJECT {index+1:02d}/{self.scenario_mgr.total_injects:02d}")
        self._inject_title_label.configure(text=inject["title"])
        total = self.scenario_mgr.total_injects
        self._progress_fill.place_configure(relwidth=(index + 1) / total if total else 0)
        self._phase_badge.configure(
            text=f"[ {inject['phase'].upper()} ]",
            fg=phase_color)

        # ── Story text
        self._story_text.configure(state="normal")
        self._story_text.delete("1.0", "end")
        self._story_text.insert("end", inject["story"])
        self._story_text.configure(state="disabled")

        # ── MITRE badge
        m = inject["mitre"]
        self._mitre_badge_label.configure(
            text=(f"⚡  ADVERSARY BEHAVIOR DETECTED   "
                  f"TACTIC: {m['tactic']} ({m['tactic_id']})  //  "
                  f"TECHNIQUE: {m['technique']} ({m['technique_id']})  //  "
                  f"{m['description']}"),
            fg=COLORS["accent_purple"])

        # ── Choice buttons  (shuffled display order each inject)
        for w in self._choice_buttons_frame.winfo_children():
            w.destroy()
        self._choice_buttons.clear()
        self._selected_choice.set("")

        # Shuffle a *copy* so the underlying inject data is never mutated.
        # The radiobutton value is a scoped token (inject_index + display_letter),
        # resolved via _choice_token_map in _on_submit — scoring is always
        # tied to the choice's quality/text, never to positional A/B/C.
        display_choices = list(inject["choices"])
        random.shuffle(display_choices)
        display_labels  = ["A", "B", "C", "D"]
        self._choice_token_map = {}          # token → original choice dict
        self._display_tokens = []            # display order → token (for shortcuts)

        for display_idx, choice in enumerate(display_choices):
            letter = display_labels[display_idx]
            token  = f"{index}_{letter}"     # unique per inject render
            self._choice_token_map[token] = choice
            self._display_tokens.append(token)

            btn_frame = tk.Frame(self._choice_buttons_frame, bg=COLORS["bg_card"])
            btn_frame.pack(fill="x", pady=3)

            rb = tk.Radiobutton(
                btn_frame,
                text=f"  [{letter}]  {choice['text']}",
                variable=self._selected_choice,
                value=token,
                font=FONTS["body_sm"],
                fg=COLORS["text_primary"],
                bg=COLORS["bg_elevated"],
                activebackground=COLORS["bg_elevated"],
                activeforeground=COLORS["accent_cyan"],
                selectcolor=COLORS["bg_elevated"],
                indicatoron=True,
                wraplength=self._content_wraplength - 24,
                justify="left",
                anchor="w",
                relief="flat",
                bd=0,
                padx=10, pady=8,
                cursor="hand2",
            )
            rb.pack(fill="x")
            rb.bind("<Enter>", lambda e, b=rb: b.configure(fg=COLORS["accent_cyan"]))
            rb.bind("<Leave>", lambda e, b=rb: b.configure(fg=COLORS["text_primary"]))
            self._choice_buttons.append(rb)

        # ── Hide feedback
        self._feedback_frame.grid_remove()
        self._feedback_visible = False
        self._submit_btn.configure(state="normal")

        # ── Status bar
        self._status_label.configure(
            text=f"▶  INJECT {index+1} OF {self.scenario_mgr.total_injects}  ·  "
                 f"PHASE: {inject['phase'].upper()}  ·  "
                 f"Framework: NIST SP 800-61 r2 | MITRE ATT&CK Enterprise v14")

    # -------------------------------------------------------- event handlers

    def _on_submit(self):
        if not self._selected_choice.get():
            messagebox.showwarning("No Selection",
                "Please select a response action before committing.")
            return

        inject_idx = self.session.current_inject_index
        inject = self.scenario_mgr.get_inject(inject_idx)
        # Resolve the shuffled display token → original choice dict
        token  = self._selected_choice.get()
        choice = self._choice_token_map[token]

        # Apply to session
        self.session.apply_decision(inject, choice)

        # Show feedback
        style = QUALITY_STYLES[choice["quality"]]
        self._feedback_frame.grid()
        self._feedback_visible = True
        self._feedback_quality_label.configure(
            text=style["icon"],
            fg=style["color"])
        self._feedback_text.configure(text=choice["feedback"])

        is_last = (inject_idx == self.scenario_mgr.total_injects - 1)
        if is_last:
            self._next_btn.configure(text="VIEW FINAL RESULTS  ▶",
                                     command=self._on_finish)
        else:
            self._next_btn.configure(text="NEXT INJECT  ▶",
                                     command=self._on_next)

        self._submit_btn.configure(state="disabled")
        self._update_scores()
        self._update_mitre_tracker()

    def _on_next(self):
        self.session.current_inject_index += 1
        self._load_inject(self.session.current_inject_index)

    def _on_finish(self):
        self._sim_complete = True
        self._show_final_screen()

    def _on_new_scenario(self):
        """Restart with a freshly selected random scenario, in-place."""
        if not self._sim_complete and len(self.session.decision_log) > 0:
            if not messagebox.askyesno(
                "Start New Scenario?",
                "This will abandon your current run and load a new random scenario. "
                "Continue?"):
                return
        self.scenario_mgr.reselect()
        self.session = SimulationSession(self.scenario_mgr.meta, self.scenario_mgr.phases)
        self._selected_choice = tk.StringVar(value="")
        self._feedback_visible = False
        self._sim_complete = False
        for w in self.winfo_children():
            w.destroy()
        self._configure_window()
        self._build_ui()
        self._load_inject(0)

    def _show_final_screen(self):
        grade, grade_color = self.session.grade()
        s = self.session

        # Replace story area with a final results overlay
        self._story_text.configure(state="normal")
        self._story_text.delete("1.0", "end")

        summary = (
            f"{'='*60}\n"
            f"    SIMULATION COMPLETE — INCIDENT RESPONSE EXERCISE\n"
            f"{'='*60}\n\n"
            f"  Scenario:    {s.meta['title']}\n"
            f"  Threat Actor: {s.meta['threat_actor']}\n\n"
            f"  ── FINAL PERFORMANCE SUMMARY ──────────────────────────\n\n"
            f"  NIST IR Score:          {s.nist_score:3d}/100\n"
            f"  Compliance Score:       {s.compliance_score:3d}/100\n"
            f"  Legal Standing Score:   {s.legal_score:3d}/100\n"
            f"  Overall Composite:      {s.overall_score:5.1f}/100\n"
            f"  Performance Grade:      {grade}\n\n"
            f"  MITRE ATT&CK Detection: "
            f"{s.techniques_identified}/{len(s.mitre_techniques)} techniques identified\n\n"
            f"  ── DECISION BREAKDOWN ─────────────────────────────────\n\n"
        )
        for i, d in enumerate(s.decision_log, 1):
            icon = {"optimal": "◆", "neutral": "◇", "detrimental": "✕"}.get(d["quality"], "•")
            summary += f"  {icon} Inject {i}: [{d['quality'].upper()[:3]}] {d['inject_title']}\n"

        summary += (
            f"\n  ── NEXT STEPS ──────────────────────────────────────────\n\n"
            f"  Click 'GENERATE GRC REPORT' in the sidebar to export\n"
            f"  a full Markdown compliance report with:\n"
            f"  • Complete decision timeline\n"
            f"  • MITRE ATT&CK technique checklist\n"
            f"  • Regulatory obligation checklist\n"
            f"  • Executive remediation recommendations\n\n"
            f"{'='*60}\n"
        )

        self._story_text.insert("end", summary)
        self._story_text.configure(state="disabled")

        self._inject_title_label.configure(text="EXERCISE COMPLETE — POST-INCIDENT DEBRIEF")
        self._phase_badge.configure(text="[ POST-INCIDENT ACTIVITY ]",
                                    fg=COLORS["phase_post"])
        self._choice_buttons_frame.destroy()
        self._submit_btn.configure(state="disabled", text="SIMULATION COMPLETE")
        self._feedback_frame.grid_remove()
        self._report_btn.configure(state="normal")

        # Light up all phase dots
        for i, (dot, name) in enumerate(self._phase_dots):
            dot.configure(fg=PHASE_COLORS[i])
            name.configure(fg=PHASE_COLORS[i])

    def _on_generate_report(self):
        gen = ReportGenerator(self.session)
        report_md = gen.generate()

        # Ask where to save
        default_name = f"IR_GRC_Report_{self.session.meta['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        save_path = filedialog.asksaveasfilename(
            defaultextension=".md",
            filetypes=[("Markdown files", "*.md"), ("All files", "*.*")],
            initialfile=default_name,
            title="Save GRC Compliance Report",
        )
        if not save_path:
            return

        with open(save_path, "w", encoding="utf-8") as f:
            f.write(report_md)

        messagebox.showinfo(
            "Report Generated",
            f"✅ GRC Compliance Report saved successfully!\n\n"
            f"Location: {save_path}\n\n"
            f"Open the .md file in VS Code, Typora, or any Markdown viewer\n"
            f"for the formatted post-incident compliance report."
        )

    # ------------------------------------------------------- score updaters

    def _update_scores(self):
        s = self.session
        for attr, (val_label, bar_fill) in self._score_meters.items():
            score = getattr(s, attr)
            val_label.configure(text=str(score))
            bar_fill.place_configure(relwidth=score / 100)

        grade, grade_color = s.grade()
        self._overall_label.configure(text=f"OVERALL: {s.overall_score:.1f}/100")
        self._grade_label.configure(text=f"GRADE: {grade}", fg=grade_color)

    def _update_mitre_tracker(self):
        # Clear and rebuild
        for w in self._mitre_tracker_frame.winfo_children():
            w.destroy()

        s = self.session
        for t in s.mitre_techniques:
            row = tk.Frame(self._mitre_tracker_frame, bg=COLORS["bg_card"])
            row.pack(fill="x", pady=2)

            status_color = COLORS["accent_green"] if t.get("identified") else COLORS["accent_red"]
            status_icon  = "◆ ID'd" if t.get("identified") else "◇ Missed"

            tk.Label(row, text=status_icon,
                     font=FONTS["mono_sm"], fg=status_color,
                     bg=COLORS["bg_card"], width=7, anchor="w").pack(side="left")

            details = tk.Frame(row, bg=COLORS["bg_card"])
            details.pack(side="left", fill="x", expand=True)
            tk.Label(details,
                     text=f"{t['technique_id']}",
                     font=FONTS["mono_sm"], fg=COLORS["accent_purple"],
                     bg=COLORS["bg_card"], anchor="w").pack(anchor="w")
            tk.Label(details,
                     text=t["technique"],
                     font=("Consolas", 8), fg=COLORS["text_secondary"],
                     bg=COLORS["bg_card"], anchor="w",
                     wraplength=165, justify="left").pack(anchor="w")

        total = len(s.mitre_techniques)
        identified = s.techniques_identified
        self._mitre_count_label.configure(
            text=f"Techniques: {total} encountered  |  {identified} identified")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    app = IncidentSimulatorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
