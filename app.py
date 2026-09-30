"""
Incident Response Tabletop Simulator
=====================================
A GUI application for cybersecurity GRC training, mapping attacker behaviors
to the MITRE ATT&CK framework and the NIST SP 800-61 r2 lifecycle.

Author: Portfolio Project — Cybersecurity GRC Professional
Dependencies: Python standard library only (tkinter)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont
from datetime import datetime, timedelta
from pathlib import Path

import scoring

APP_VERSION = "4.0.0"
SAVE_FORMAT_VERSION = 1
ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# ---------------------------------------------------------------------------
# Design System Constants
# ---------------------------------------------------------------------------
COLORS = {
    # Base palette
    "bg_primary":    "#0A0E1A",
    "bg_secondary":  "#0F1626",
    "bg_card":       "#141E2E",
    "bg_elevated":   "#1A2540",
    "bg_hover":      "#1F2D4D",
    "bg_input":      "#0D1520",

    # Accents
    "accent_cyan":   "#00D4FF",
    "accent_green":  "#00FF94",
    "accent_yellow": "#FFD700",
    "accent_orange": "#FF8C42",
    "accent_red":    "#FF3B6B",
    "accent_purple": "#A855F7",
    "accent_blue":   "#3B82F6",

    # Text
    "text_primary":  "#E8F4FD",
    "text_secondary":"#7A9EC8",
    "text_dim":      "#3D5A80",

    # Borders
    "border":        "#1E3A5F",
    "border_bright": "#00D4FF",

    # Phase colors
    "phase_prep":    "#3B82F6",
    "phase_detect":  "#A855F7",
    "phase_contain": "#F59E0B",
    "phase_eradicate":"#EF4444",
    "phase_post":    "#10B981",
}

# Filled in by init_fonts() once a Tk root exists; defaults keep imports safe.
FONTS: dict[str, tuple] = {
    "display":   ("Courier New", 20, "bold"),
    "title":     ("Helvetica", 16, "bold"),
    "header":    ("Helvetica", 14, "bold"),
    "subheader": ("Helvetica", 11, "bold"),
    "body":      ("Helvetica", 11),
    "body_sm":   ("Helvetica", 10),
    "mono":      ("Courier New", 10),
    "mono_bold": ("Courier New", 10, "bold"),
    "mono_sm":   ("Courier New", 9),
    "button":    ("Courier New", 10, "bold"),
    "tag":       ("Courier New", 9, "bold"),
    "grade":     ("Courier New", 44, "bold"),
}

UI_FONT_CANDIDATES = ["Segoe UI", "SF Pro Text", "Helvetica Neue", "Inter",
                      "Noto Sans", "DejaVu Sans", "Liberation Sans", "Arial"]
MONO_FONT_CANDIDATES = ["Cascadia Mono", "Consolas", "JetBrains Mono", "Menlo",
                        "SF Mono", "DejaVu Sans Mono", "Liberation Mono",
                        "Noto Sans Mono", "Courier New"]


def init_fonts(root: tk.Misc) -> None:
    """Pick a proportional face for prose and a monospace face for codes/IDs."""
    families = set(tkfont.families(root))

    def pick(candidates, fallback):
        return next((f for f in candidates if f in families), fallback)

    ui = pick(UI_FONT_CANDIDATES, "Helvetica")
    mono = pick(MONO_FONT_CANDIDATES, "Courier")
    FONTS.update({
        "display":   (mono, 20, "bold"),
        "title":     (ui, 16, "bold"),
        "header":    (ui, 14, "bold"),
        "subheader": (ui, 11, "bold"),
        "body":      (ui, 11),
        "body_sm":   (ui, 10),
        "mono":      (mono, 10),
        "mono_bold": (mono, 10, "bold"),
        "mono_sm":   (mono, 9),
        "button":    (mono, 10, "bold"),
        "tag":       (mono, 9, "bold"),
        "grade":     (mono, 44, "bold"),
    })


PHASE_COLORS = [
    COLORS["phase_prep"],
    COLORS["phase_detect"],
    COLORS["phase_contain"],
    COLORS["phase_eradicate"],
    COLORS["phase_post"],
]

PHASE_SHORT_LABELS = ["PREP", "DETECT", "CONTAIN", "ERADICATE", "POST"]

QUALITY_STYLES = {
    "optimal":     {"color": COLORS["accent_green"],  "glyph": "◆", "label": "OPTIMAL",     "bg": "#0A2618"},
    "neutral":     {"color": COLORS["accent_yellow"], "glyph": "◇", "label": "NEUTRAL",     "bg": "#1A1500"},
    "detrimental": {"color": COLORS["accent_red"],    "glyph": "✕", "label": "DETRIMENTAL", "bg": "#1A0010"},
}

SEVERITY_COLORS = {
    "CRITICAL": COLORS["accent_red"],
    "HIGH":     COLORS["accent_orange"],
    "MEDIUM":   COLORS["accent_yellow"],
    "LOW":      COLORS["accent_green"],
}

GRADE_COLORS = {
    "A": COLORS["accent_green"],
    "B": COLORS["accent_cyan"],
    "C": COLORS["accent_yellow"],
    "D": COLORS["accent_orange"],
    "F": COLORS["accent_red"],
}

# Generic discussion prompts per NIST phase; an inject may override with "role_prompts".
ROLE_PROMPTS = {
    "Preparation": {
        "IR Lead":   "Which playbook applies, and who is on call for it right now?",
        "Legal":     "Which regulators and contracts define notification clocks for this data?",
        "Comms":     "Who owns internal messaging if this escalates in the next hour?",
        "Executive": "What tolerance for business disruption has leadership set?",
    },
    "Detection & Analysis": {
        "IR Lead":   "What evidence confirms scope, and what is still assumption?",
        "Legal":     "Has a breach-determination clock started? Record the timestamp.",
        "Comms":     "What do employees need to know now, and what stays need-to-know?",
        "Executive": "Which business processes are at risk in the next 24 hours?",
    },
    "Containment": {
        "IR Lead":   "What is the blast radius, and what will isolation break?",
        "Legal":     "Are we preserving evidence and chain of custody while containing?",
        "Comms":     "Who speaks to customers, partners, and press, and when?",
        "Executive": "What does downtime cost versus a wider compromise?",
    },
    "Eradication & Recovery": {
        "IR Lead":   "How do we prove the adversary is gone before restoring trust?",
        "Legal":     "Which recovery actions must be documented for regulators or insurers?",
        "Comms":     "How do we report restoration status without over-promising?",
        "Executive": "Which systems return first, and who signs off?",
    },
    "Post-Incident Activity": {
        "IR Lead":   "Which detection or response gap would have changed the outcome?",
        "Legal":     "Which notifications, filings, and litigation holds remain open?",
        "Comms":     "What is the lessons-learned message to staff and stakeholders?",
        "Executive": "Which controls get funded, and how is progress measured?",
    },
}

DEFAULT_OBJECTIVES = [
    "Work the incident through all five NIST SP 800-61 r2 phases.",
    "Choose responses that contain the threat while preserving evidence.",
    "Keep the organization inside its regulatory and legal obligations.",
    "Identify the adversary technique in play at each step.",
]


def quality_color(q: str) -> str:
    return QUALITY_STYLES.get(q, {}).get("color", COLORS["text_secondary"])


def score_color(value: int | None) -> str:
    if value is None:
        return COLORS["text_dim"]
    return GRADE_COLORS[scoring.grade_for(value)]


def is_attack_id(technique_id: str) -> bool:
    return bool(ATTACK_ID_RE.match(technique_id or ""))


def format_duration(td: timedelta) -> str:
    total = int(td.total_seconds())
    hours, rem = divmod(max(total, 0), 3600)
    minutes, seconds = divmod(rem, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes:02d}:{seconds:02d}"


def industry_tokens(industry: str) -> set[str]:
    """'Defense / Technology' -> {'defense', 'technology'}; 'E-Commerce' -> {'e-commerce', 'commerce'}."""
    tokens = set()
    for part in re.split(r"[/,&]", industry or ""):
        for word in part.strip().lower().split():
            tokens.add(word)
            if "-" in word:
                tokens.update(word.split("-"))
    return tokens


def industry_segments(industry: str) -> list[str]:
    """'Defense / Technology' -> ['Defense', 'Technology'] (display casing preserved)."""
    return [p.strip() for p in re.split(r"[/,]", industry or "") if p.strip()]


# ---------------------------------------------------------------------------
# Data Layer
# ---------------------------------------------------------------------------
class ScenarioManager:
    """
    Loads scenarios.json and mounts one scenario at a time.

    scenarios.json top-level format:
        { "scenarios": [ { "scenario_meta": {...}, "nist_phases": [...], "injects": [...] }, ... ] }
    """

    def __init__(self, path: str | os.PathLike | None = None):
        self.path = self.resolve_path(path)
        self._all_scenarios = self._load()
        self._scenario_index = random.randrange(len(self._all_scenarios))
        self._mount(self._scenario_index)

    @staticmethod
    def resolve_path(explicit: str | os.PathLike | None) -> Path:
        """Find scenarios.json: explicit arg > env var > next to app.py > cwd > share dir."""
        if explicit:
            p = Path(explicit)
            if p.is_file():
                return p
            raise FileNotFoundError(f"Scenario file not found: {p}")
        candidates = []
        if os.environ.get("IR_SIM_SCENARIOS"):
            candidates.append(Path(os.environ["IR_SIM_SCENARIOS"]))
        candidates.append(Path(__file__).resolve().parent / "scenarios.json")
        candidates.append(Path.cwd() / "scenarios.json")
        candidates.append(Path(sys.prefix) / "share" / "ir_sim" / "scenarios.json")
        for c in candidates:
            if c.is_file():
                return c
        searched = "\n".join(f"  - {c}" for c in candidates)
        raise FileNotFoundError(
            f"scenarios.json not found. Searched:\n{searched}\n"
            f"Pass --scenarios PATH or set IR_SIM_SCENARIOS.")

    def _load(self) -> list:
        with open(self.path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        scenarios = raw["scenarios"] if "scenarios" in raw else [raw]
        if not scenarios:
            raise ValueError(f"{self.path} contains no scenarios")
        return scenarios

    def _mount(self, index: int):
        scenario = self._all_scenarios[index]
        self.injects = scenario["injects"]
        self.meta    = scenario["scenario_meta"]
        self.phases  = scenario["nist_phases"]
        self.scenario = scenario

    def reselect(self):
        """Pick a new random scenario, avoiding an immediate repeat when possible."""
        if len(self._all_scenarios) > 1:
            options = [i for i in range(len(self._all_scenarios)) if i != self._scenario_index]
            self._scenario_index = random.choice(options)
        self._mount(self._scenario_index)

    def select(self, index: int):
        self._scenario_index = index
        self._mount(index)

    def index_of(self, scenario_id: str) -> int | None:
        for i, s in enumerate(self._all_scenarios):
            if s["scenario_meta"]["id"] == scenario_id:
                return i
        return None

    def all_meta(self) -> list:
        return [s["scenario_meta"] for s in self._all_scenarios]

    def technique_pool(self) -> list[dict]:
        """Every distinct ATT&CK technique across the file (for identification distractors)."""
        seen: dict[str, dict] = {}
        for s in self._all_scenarios:
            for inj in s["injects"]:
                m = inj["mitre"]
                if is_attack_id(m["technique_id"]) and m["technique_id"] not in seen:
                    seen[m["technique_id"]] = m
        return list(seen.values())

    @property
    def scenario_index(self) -> int:
        return self._scenario_index

    @property
    def total_scenarios(self) -> int:
        return len(self._all_scenarios)

    def get_inject(self, index: int) -> dict:
        return self.injects[index]

    @property
    def total_injects(self) -> int:
        return len(self.injects)

    @staticmethod
    def story_for(inject: dict, prior_quality: str | None) -> str:
        """Branching narrative: an inject may carry `story_variants` keyed by the
        quality of the previous decision. Falls back to the base `story`."""
        variants = inject.get("story_variants") or {}
        if prior_quality and prior_quality in variants:
            return variants[prior_quality]
        return inject["story"]


# ---------------------------------------------------------------------------
# Session State
# ---------------------------------------------------------------------------
class SimulationSession:
    """Runtime state: raw score sums, decision log, technique identification."""

    def __init__(self, scenario: dict):
        self.scenario = scenario
        self.meta = scenario["scenario_meta"]
        self.phases = scenario["nist_phases"]
        self.injects = scenario["injects"]
        self.start_time = datetime.now()
        self.current_inject_index = 0
        self.facilitated = False

        self.raw = {a: 0 for a in scoring.AXES}
        self.decision_log: list[dict] = []
        self.mitre_techniques: list[dict] = []      # ATT&CK techniques encountered
        self.framework_refs: list[dict] = []        # non-ATT&CK "mitre" blocks (framework refs)
        self.identifications: list[dict] = []       # technique quiz results

    # ---------------------------------------------------------------- decisions

    def apply_decision(self, inject: dict, choice: dict):
        for axis, key in scoring.DELTA_KEYS.items():
            self.raw[axis] += choice[key]

        self.decision_log.append({
            "inject_id":    inject["id"],
            "inject_title": inject["title"],
            "phase":        inject["phase"],
            "choice_id":    choice["id"],
            "choice_text":  choice["text"],
            "quality":      choice["quality"],
            "feedback":     choice["feedback"],
            "nist_delta":   choice["nist_score_delta"],
            "compliance_delta": choice["compliance_score_delta"],
            "legal_delta":  choice["legal_score_delta"],
            "mitre":        inject["mitre"],
            "alternatives": [c for c in inject["choices"] if c is not choice],
        })

        mitre = inject["mitre"]
        if is_attack_id(mitre["technique_id"]):
            if not any(t["technique_id"] == mitre["technique_id"] for t in self.mitre_techniques):
                self.mitre_techniques.append({**mitre, "identified": False, "quizzed": False})
        elif not any(r["technique_id"] == mitre["technique_id"] and r["technique"] == mitre["technique"]
                     for r in self.framework_refs):
            self.framework_refs.append(dict(mitre))

    def record_identification(self, inject: dict, picked_id: str | None) -> bool:
        """Record the player's technique pick for an inject. Returns True if correct."""
        correct_id = inject["mitre"]["technique_id"]
        correct = picked_id == correct_id
        self.identifications.append({
            "inject_id": inject["id"],
            "correct_id": correct_id,
            "picked_id": picked_id,
            "correct": correct,
        })
        for t in self.mitre_techniques:
            if t["technique_id"] == correct_id:
                t["quizzed"] = True
                if correct:
                    t["identified"] = True
        return correct

    def identification_for(self, inject_id: str) -> dict | None:
        return next((i for i in self.identifications if i["inject_id"] == inject_id), None)

    @property
    def last_quality(self) -> str | None:
        return self.decision_log[-1]["quality"] if self.decision_log else None

    # ------------------------------------------------------------------- scores

    @property
    def played_injects(self) -> list[dict]:
        return self.injects[:len(self.decision_log)]

    def scores(self) -> dict[str, int] | None:
        """Normalised live scores against the injects played so far (None before any decision)."""
        if not self.decision_log:
            return None
        return scoring.normalised_scores(self.raw, self.played_injects)

    @property
    def nist_score(self) -> int:
        return (self.scores() or {}).get("nist", 0)

    @property
    def compliance_score(self) -> int:
        return (self.scores() or {}).get("compliance", 0)

    @property
    def legal_score(self) -> int:
        return (self.scores() or {}).get("legal", 0)

    @property
    def overall_score(self) -> float:
        s = self.scores()
        return scoring.overall(s) if s else 0.0

    @property
    def techniques_identified(self) -> int:
        return sum(1 for t in self.mitre_techniques if t.get("identified"))

    @property
    def techniques_quizzed(self) -> int:
        return sum(1 for t in self.mitre_techniques if t.get("quizzed"))

    def grade(self) -> tuple[str, str]:
        if not self.decision_log:
            return ("—", COLORS["text_secondary"])
        letter = scoring.grade_for(self.overall_score)
        return (letter, GRADE_COLORS[letter])

    def phase_rows(self) -> list[dict]:
        return scoring.phase_efficiency(self.injects, self.decision_log, self.phases)

    @property
    def complete(self) -> bool:
        return len(self.decision_log) >= len(self.injects)

    # ------------------------------------------------------------ save / resume

    def to_dict(self) -> dict:
        return {
            "format": SAVE_FORMAT_VERSION,
            "app_version": APP_VERSION,
            "scenario_id": self.meta["id"],
            "facilitated": self.facilitated,
            "elapsed_seconds": int((datetime.now() - self.start_time).total_seconds()),
            "saved_at": datetime.now().isoformat(timespec="seconds"),
            "decisions": [
                {
                    "inject_id": d["inject_id"],
                    "choice_id": d["choice_id"],
                    "picked_technique": (self.identification_for(d["inject_id"]) or {}).get("picked_id"),
                    "quizzed": self.identification_for(d["inject_id"]) is not None,
                }
                for d in self.decision_log
            ],
        }

    @classmethod
    def from_dict(cls, scenario: dict, data: dict) -> "SimulationSession":
        if data.get("format") != SAVE_FORMAT_VERSION:
            raise ValueError("Unsupported save file format")
        if scenario["scenario_meta"]["id"] != data.get("scenario_id"):
            raise ValueError("Save file does not match this scenario")
        session = cls(scenario)
        session.facilitated = bool(data.get("facilitated", False))
        by_id = {inj["id"]: inj for inj in scenario["injects"]}
        for rec in data.get("decisions", []):
            inject = by_id[rec["inject_id"]]
            choice = next(c for c in inject["choices"] if c["id"] == rec["choice_id"])
            session.apply_decision(inject, choice)
            if rec.get("quizzed"):
                session.record_identification(inject, rec.get("picked_technique"))
        session.current_inject_index = len(session.decision_log)
        session.start_time = datetime.now() - timedelta(seconds=int(data.get("elapsed_seconds", 0)))
        return session


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

# Control recommendations keyed by ATT&CK technique prefix. A technique matches the
# longest prefix that is a prefix of its ID (so T1566.002 matches "T1566").
RECOMMENDATION_LIBRARY: list[tuple[tuple[str, ...], dict]] = [
    (("T1566.004", "T1656", "T1657", "T1587.001"), {
        "title": "Out-of-Band Verification for Payment & Executive Requests",
        "framework": "NIST CSF PR.AT-01 | FFIEC Authentication Guidance | CIS Control 14",
        "detail": "Require callback verification on a known number and dual approval for any payment "
                  "instruction, vendor banking change, or urgent executive request, regardless of how "
                  "convincing the voice or video is. Brief finance and executive assistants on "
                  "deepfake and BEC pretexts.",
    }),
    (("T1566", "T1557", "T1111", "T1621"), {
        "title": "Phishing-Resistant Multi-Factor Authentication",
        "framework": "NIST CSF PR.AA-03 | NIST SP 800-63B AAL3 | CIS Control 6",
        "detail": "Deploy FIDO2/WebAuthn authenticators for all privileged accounts and remote access "
                  "gateways. SMS and TOTP codes are relayed in real time by adversary-in-the-middle "
                  "phishing kits; only origin-bound authenticators defeat them.",
    }),
    (("T1003", "T1558"), {
        "title": "Credential Guard, LSASS Protection & Tiered Administration",
        "framework": "NIST SP 800-53 IA-5 | Microsoft Enterprise Access Model | CIS Control 5",
        "detail": "Enable RunAsPPL/Credential Guard, keep Domain Admin credentials off general-purpose "
                  "workstations, and administer Tier 0 assets only from Privileged Access Workstations.",
    }),
    (("T1078", "T1098", "T1136"), {
        "title": "Identity Threat Detection & Account Lifecycle Controls",
        "framework": "NIST CSF PR.AA-05 | NIST SP 800-53 AC-2 | CIS Control 5",
        "detail": "Alert on impossible travel, new-device sign-ins, privilege grants, and dormant-account "
                  "reactivation. Enforce joiner/mover/leaver reviews and just-in-time elevation so a "
                  "valid credential is not a persistent foothold.",
    }),
    (("T1486", "T1489", "T1490", "T1485"), {
        "title": "Immutable, Tested Offline Backup Architecture",
        "framework": "NIST SP 800-34 | NIST CSF RC.RP | CIS Control 11",
        "detail": "Apply the 3-2-1-1 rule (three copies, two media, one offsite, one offline/immutable), "
                  "protect backup consoles with separate credentials, and test restores quarterly with "
                  "documented RTO/RPO evidence.",
    }),
    (("T1567", "T1041", "T1048", "T1537", "T1052", "T1005", "T1114", "T1213", "T1530"), {
        "title": "Data Loss Prevention, Egress Filtering & Cloud Storage Posture",
        "framework": "NIST SP 800-53 SC-7 / SI-4 | NIST CSF PR.DS-01 | CIS Control 3 & 13",
        "detail": "Inspect uploads to personal cloud storage, alert on mailbox forwarding rules and bulk "
                  "downloads, block removable media by default, and continuously audit bucket and share "
                  "permissions with a CSPM tool.",
    }),
    (("T1498", "T1499"), {
        "title": "DDoS Mitigation Capacity & Provider Runbooks",
        "framework": "NIST SP 800-53 SC-5 | NIST CSF PR.IR-04 | CIS Control 12",
        "detail": "Contract always-on scrubbing or anycast CDN protection for public services, pre-authorize "
                  "upstream provider mitigations, and rehearse the extortion decision (no payment; law "
                  "enforcement engagement) with executives.",
    }),
    (("T1190", "T1203", "T1068", "T1595", "T1587.004", "T1133"), {
        "title": "External Attack Surface Management & KEV Patch SLAs",
        "framework": "NIST SP 800-40 r4 | CISA BOD 22-01 | CIS Control 7",
        "detail": "Inventory every internet-facing asset, place a WAF in front of web applications, and "
                  "patch CISA KEV-listed vulnerabilities on edge devices within 48 hours, with "
                  "compensating isolation when a fix is not yet available.",
    }),
    (("T1195", "T1584", "T1554"), {
        "title": "Software Supply Chain Integrity",
        "framework": "NIST SP 800-161 r1 | SSDF (SP 800-218) | EO 14028",
        "detail": "Require SBOMs and signed artifacts from vendors, pin and verify dependencies in the build "
                  "pipeline, and stage vendor updates in a canary ring before enterprise deployment.",
    }),
    (("T1110",), {
        "title": "Credential Stuffing Defenses",
        "framework": "NIST SP 800-63B §5.1.1.2 | OWASP ASVS V2 | FFIEC Guidance",
        "detail": "Screen passwords against breach corpora, rate-limit and fingerprint login traffic, deploy "
                  "bot management, and step up to MFA on risk signals rather than after a takeover.",
    }),
    (("T1528", "T1550"), {
        "title": "OAuth Application Governance",
        "framework": "NIST CSF PR.AA-05 | Microsoft App Consent Policies | CIS Control 6",
        "detail": "Disable end-user consent for unverified publishers, require admin approval workflows, "
                  "review granted permissions monthly, and alert on new high-privilege grants.",
    }),
    (("T1609", "T1610", "T1611", "T1613"), {
        "title": "Container & Kubernetes Hardening",
        "framework": "NIST SP 800-190 | CIS Kubernetes Benchmark | NSA/CISA K8s Hardening Guide",
        "detail": "Enforce Pod Security Standards (no privileged pods, no hostPath), sign and scan images, "
                  "deploy runtime detection, and scope RBAC so a compromised workload cannot reach the API server.",
    }),
    (("T0860", "T1200", "T1091"), {
        "title": "Physical Security & Network Access Control",
        "framework": "NIST SP 800-53 PE-3 / AC-19 | IEEE 802.1X | CIS Control 1",
        "detail": "Require 802.1X on every wired port, alert on unknown MAC addresses, audit badge access "
                  "against HR records, and sweep sensitive areas for rogue devices.",
    }),
    (("T1496", "T1580", "T1578"), {
        "title": "Cloud Account Guardrails & Cost Anomaly Detection",
        "framework": "NIST SP 800-53 CM-7 | CSA CCM | CIS Control 4",
        "detail": "Apply service control policies that block unused regions and instance families, alert on "
                  "spend anomalies within the hour, and rotate long-lived access keys in favor of short-lived roles.",
    }),
    (("T1552", "T1555"), {
        "title": "Secrets Management & Repository Scanning",
        "framework": "NIST SP 800-53 IA-5(7) | OWASP Secrets Management Cheat Sheet | CIS Control 3",
        "detail": "Move credentials out of files and repositories into a vault with short-lived tokens, "
                  "scan every commit for secrets, and rotate anything ever exposed.",
    }),
    (("T1053", "T1036", "T1059", "T1547"), {
        "title": "Endpoint Detection Engineering for Persistence & Scripting",
        "framework": "NIST SP 800-53 SI-4 | MITRE D3FEND | CIS Control 8",
        "detail": "Enable PowerShell script-block logging, alert on new scheduled tasks and services with "
                  "encoded commands, and hunt fleet-wide for any persistence artifact found on one host.",
    }),
    (("T1021",), {
        "title": "Network Segmentation & Lateral Movement Detection",
        "framework": "NIST SP 800-207 | NIST SP 800-53 SC-7 | CIS Control 12",
        "detail": "Restrict RDP and SMB to jump hosts, segment clinical/OT and payment systems from user "
                  "networks, and alert on workstation-to-workstation administrative traffic.",
    }),
    (("T1562",), {
        "title": "Log Integrity & Defense-Evasion Alerting",
        "framework": "NIST SP 800-53 AU-9 | NIST CSF DE.CM | CIS Control 8",
        "detail": "Forward logs to immutable central storage and raise a high-severity alert whenever "
                  "audit logging, EDR, or cloud trail services are disabled or reconfigured.",
    }),
    (("T1491",), {
        "title": "Web Integrity Monitoring",
        "framework": "PCI DSS 11.6.1 | NIST CSF DE.CM-09 | CIS Control 16",
        "detail": "Monitor public pages and payment scripts for unauthorized changes and serve them "
                  "through a CDN/WAF with content integrity controls.",
    }),
    (("T1204",), {
        "title": "Application Control & Attachment Sandboxing",
        "framework": "NIST SP 800-167 | CIS Control 2 & 9",
        "detail": "Block unsigned executables and macros from user-writable paths and detonate attachments "
                  "in a sandbox before delivery.",
    }),
    (("T1583", "T1585", "T1587"), {
        "title": "Brand, Domain & Threat Intelligence Monitoring",
        "framework": "NIST CSF ID.RA-02 | CIS Control 17",
        "detail": "Subscribe to lookalike-domain and impersonation monitoring, pre-arrange takedown "
                  "channels, and route sector ISAC bulletins straight into detection engineering.",
    }),
]

BASELINE_RECOMMENDATIONS = [
    {
        "title": "Formalize Incident Response Plan with Legal & Breach Notification Runbooks",
        "framework": "NIST SP 800-61 r2 | NIST CSF RS.MA | CIRCIA 2022",
        "detail": "Pre-approve notification templates for regulators, law enforcement, and insurers, "
                  "retain breach counsel in advance, and set a 24-hour breach-classification decision tree.",
    },
    {
        "title": "Conduct Quarterly ATT&CK-Based Tabletop Exercises",
        "framework": "NIST CSF RS.CO | SOC 2 CC7.3 | ISO/IEC 27001:2022 A.5.24",
        "detail": "Map each exercise to the techniques most relevant to your sector and track technique "
                  "identification rate as a SOC maturity KPI (target >80% within 12 months).",
    },
]


class ReportGenerator:
    """Generates a formatted Markdown post-incident GRC report from a session."""

    def __init__(self, session: SimulationSession):
        self.session = session
        self.generated_at = datetime.now().astimezone()

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def _rating(score: float) -> str:
        if score >= 80: return "Strong"
        if score >= 60: return "Adequate"
        if score >= 40: return "Needs Improvement"
        return "Critical Gap"

    @staticmethod
    def _glyph(quality: str) -> str:
        return QUALITY_STYLES.get(quality, {}).get("glyph", "•")

    # ---------------------------------------------------------------- generate

    def generate(self) -> str:
        s = self.session
        scores = s.scores() or {a: 0 for a in scoring.AXES}
        grade = scoring.grade_for(scoring.overall(scores)) if s.decision_log else "—"
        duration_str = format_duration(self.generated_at.replace(tzinfo=None) - s.start_time)
        stamp = self.generated_at.strftime("%Y-%m-%d %H:%M:%S %Z").strip()

        lines: list[str] = []
        a = lines.append

        a("# Post-Incident & GRC Compliance Review Report")
        a("")
        a(f"**Incident Scenario:** {s.meta['title']}  ")
        a(f"**Subtitle:** {s.meta['subtitle']}  ")
        a(f"**Threat Actor Profile:** {s.meta['threat_actor']}  ")
        a(f"**Industry Sector:** {s.meta['industry']}  ")
        a(f"**Severity Classification:** {s.meta['severity']}  ")
        a(f"**Estimated Impact:** {s.meta['estimated_impact']}  ")
        a(f"**Exercise Mode:** {'Facilitated (scores hidden during play)' if s.facilitated else 'Self-guided'}  ")
        a(f"**Simulation Date:** {stamp}  ")
        a(f"**Exercise Duration:** {duration_str}  ")
        a(f"**Overall Performance Grade:** **{grade}** ({s.overall_score:.1f}/100)  ")
        a("")
        a("---")
        a("")

        # Executive summary
        a("## Executive Summary")
        a("")
        subtitle = s.meta["subtitle"].lower()
        article = "an" if subtitle[:1] in "aeiou" else "a"
        a(f"This report documents an interactive incident response tabletop exercise simulating "
          f"{article} {subtitle}. The exercise followed the **NIST SP 800-61 Rev. 2** "
          f"lifecycle across {len(s.phases)} phases and {len(s.decision_log)} decision points.")
        a("")
        quizzed = s.techniques_quizzed
        a(f"The participant demonstrated **{grade}-level** incident response capability with an "
          f"overall composite score of **{s.overall_score:.1f}/100**. "
          f"**{s.techniques_identified}/{quizzed}** MITRE ATT&CK techniques were correctly "
          f"identified when challenged.")
        counts = {q: sum(1 for d in s.decision_log if d["quality"] == q) for q in scoring.QUALITIES}
        a("")
        a(f"Decisions: **{counts['optimal']} optimal**, **{counts['neutral']} neutral**, "
          f"**{counts['detrimental']} detrimental**.")
        a("")
        a("---")
        a("")

        # Scores
        a("## GRC Performance Metrics")
        a("")
        a("Scores are normalised against the best and worst achievable paths through this "
          "scenario: 100 means the strongest available option was chosen at every inject.")
        a("")
        a("| Metric | Score | Assessment |")
        a("|--------|-------|------------|")
        a(f"| NIST IR Framework Score | {scores['nist']}/100 | {self._rating(scores['nist'])} |")
        a(f"| Regulatory Compliance Score | {scores['compliance']}/100 | {self._rating(scores['compliance'])} |")
        a(f"| Legal & Liability Score | {scores['legal']}/100 | {self._rating(scores['legal'])} |")
        a(f"| **Overall Composite** | **{s.overall_score:.1f}/100** | **{self._rating(s.overall_score)}** |")
        a("")
        a("### NIST Phase Breakdown")
        a("")
        a("| NIST Phase | Earned | Available | Efficiency |")
        a("|------------|--------|-----------|------------|")
        for row in s.phase_rows():
            eff = f"{row['efficiency']}%" if row["efficiency"] is not None else "Not played"
            a(f"| {row['phase']} | {row['earned']} | {row['available']} | {eff} |")
        a("")
        a("---")
        a("")

        # Timeline
        a("## Incident Response Decision Timeline")
        a("")
        for i, d in enumerate(s.decision_log, 1):
            a(f"### {self._glyph(d['quality'])} Inject {i}: {d['inject_title']}")
            a(f"**Phase:** {d['phase']} | **Decision Quality:** {d['quality'].upper()} | "
              f"**Impact:** NIST {d['nist_delta']:+d} · Compliance {d['compliance_delta']:+d} · "
              f"Legal {d['legal_delta']:+d}")
            a("")
            a("**Action Taken:**  ")
            a(f"> {d['choice_text']}")
            a("")
            a("**Assessment:**  ")
            a(f"> {d['feedback']}")
            a("")
            a("**Alternatives Not Taken:**  ")
            for alt in d["alternatives"]:
                a(f"- {self._glyph(alt['quality'])} *{alt['quality'].upper()}* — {alt['text']}")
            a("")
            m = d["mitre"]
            ident = s.identification_for(d["inject_id"])
            if is_attack_id(m["technique_id"]):
                a("**MITRE ATT&CK Context:**  ")
                a(f"- Tactic: `{m['tactic']}` ({m['tactic_id']})")
                a(f"- Technique: `{m['technique']}` ({m['technique_id']})")
                if ident is None:
                    a("- Technique Identification: Not attempted")
                elif ident["correct"]:
                    a(f"- Technique Identification: Correct (`{ident['picked_id']}`)")
                else:
                    a(f"- Technique Identification: Missed (picked `{ident['picked_id'] or 'none'}`)")
            else:
                a("**Framework Reference:**  ")
                a(f"- {m['technique']} ({m['technique_id']}) — {m['description']}")
            a("")

        a("---")
        a("")

        # ATT&CK table
        a("## MITRE ATT&CK Techniques Encountered")
        a("")
        a("Adversary techniques present in this scenario, mapped to MITRE ATT&CK Enterprise v14. "
          "'Identified' reflects the participant's answer to the technique identification challenge.")
        a("")
        a("| Status | Tactic | Technique | ID | Identified |")
        a("|--------|--------|-----------|----|------------|")
        for t in s.mitre_techniques:
            if not t.get("quizzed"):
                status, ident_txt = "—", "Not attempted"
            elif t.get("identified"):
                status, ident_txt = "◆", "Yes"
            else:
                status, ident_txt = "✕", "No"
            a(f"| {status} | {t['tactic']} ({t['tactic_id']}) | {t['technique']} | `{t['technique_id']}` | {ident_txt} |")
        a("")
        if quizzed:
            a(f"**Technique Identification Rate:** {s.techniques_identified}/{quizzed} "
              f"({s.techniques_identified / quizzed * 100:.0f}%)")
        else:
            a("**Technique Identification Rate:** no techniques were challenged in this run.")
        if s.framework_refs:
            a("")
            a("**Framework references exercised (non-ATT&CK injects):**")
            for r in s.framework_refs:
                a(f"- {r['technique']} ({r['technique_id']})")
        a("")
        a("---")
        a("")

        # Recommendations
        a("## Executive Recommendations")
        a("")
        a("Control improvements below are derived from the adversary techniques encountered and "
          "from decisions in this run that fell short of the optimal response.")
        a("")
        for i, rec in enumerate(self._build_recommendations(), 1):
            a(f"### Recommendation {i}: {rec['title']}")
            a(f"**Priority:** {rec['priority']} | **Framework Mapping:** {rec['framework']}  ")
            a(f"{rec['detail']}  ")
            if rec.get("why"):
                a(f"*Why it appears here:* {rec['why']}  ")
            a("")

        a("---")
        a("")

        # Obligations
        a("## Regulatory & Legal Obligations Checklist")
        a("")
        a(f"Obligations are scoped to the **{s.meta['industry']}** sector and the techniques observed. "
          f"The *Exercise Indication* column is inferred from the decisions committed in this run and "
          f"should be confirmed with legal counsel.")
        a("")
        a("| Obligation | Regulatory Source | Deadline / Requirement | Exercise Indication | Notes |")
        a("|------------|------------------|------------------------|---------------------|-------|")
        for ob in self._build_regulatory_obligations():
            a(f"| {ob['obligation']} | {ob['source']} | {ob['deadline']} | {ob['indication']} | {ob['notes']} |")
        a("")
        a("---")
        a("")

        a("## Report Certification")
        a("")
        a("This report was generated by the **Incident Response Tabletop Simulator** as a training and "
          "portfolio documentation artifact. It reflects simulated scenario outcomes and should be used "
          "for educational and preparedness-assessment purposes.")
        a("")
        a(f"*Generated: {stamp}*  ")
        a(f"*Scenario ID: {s.meta['id']}*  ")
        a(f"*IR_Sim v{APP_VERSION} · Framework References: NIST SP 800-61 r2 | MITRE ATT&CK Enterprise v14 | NIST CSF 2.0*")
        a("")
        return "\n".join(lines)

    # ---------------------------------------------------------- recommendations

    def _build_recommendations(self) -> list[dict]:
        s = self.session
        recs: list[dict] = []
        seen_titles: set[str] = set()

        # Which techniques were met with a weak decision or a missed identification?
        weak_by_tid: dict[str, list[str]] = {}
        for i, d in enumerate(s.decision_log, 1):
            tid = d["mitre"]["technique_id"]
            reasons = []
            if d["quality"] != "optimal":
                reasons.append(f"Inject {i} response was {d['quality']}")
            ident = s.identification_for(d["inject_id"])
            if ident is not None and not ident["correct"]:
                reasons.append(f"technique not identified at Inject {i}")
            if reasons:
                weak_by_tid.setdefault(tid, []).extend(reasons)

        encountered = [t["technique_id"] for t in s.mitre_techniques]
        for tid in encountered:
            best = None
            best_len = -1
            for prefixes, rec in RECOMMENDATION_LIBRARY:
                for p in prefixes:
                    if tid.startswith(p) and len(p) > best_len:
                        best, best_len = rec, len(p)
            if best is None or best["title"] in seen_titles:
                continue
            seen_titles.add(best["title"])
            weak = weak_by_tid.get(tid, [])
            recs.append({
                **best,
                "priority": "CRITICAL" if weak else "HIGH",
                "why": (f"Technique {tid} was observed; " + "; ".join(weak) + ".") if weak
                       else f"Technique {tid} was observed in this scenario.",
                "_weak": len(weak),
            })

        # Decision-derived remediation: the optimal action for each non-optimal inject.
        for i, d in enumerate(s.decision_log, 1):
            if d["quality"] == "optimal":
                continue
            optimal = next((c for c in d["alternatives"] if c["quality"] == "optimal"), None)
            if optimal is None:
                continue
            recs.append({
                "title": f"Revisit {d['phase']} Playbook — {d['inject_title']}",
                "priority": "HIGH" if d["quality"] == "detrimental" else "MEDIUM",
                "framework": f"NIST SP 800-61 r2 ({d['phase']})",
                "detail": f"The recommended response at this decision point was: {optimal['text']}",
                "why": f"Inject {i} was answered with a {d['quality']} option.",
                "_weak": 2 if d["quality"] == "detrimental" else 1,
            })

        for rec in BASELINE_RECOMMENDATIONS:
            recs.append({**rec, "priority": "MEDIUM", "why": "", "_weak": 0})

        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        recs.sort(key=lambda r: (order[r["priority"]], -r["_weak"]))
        for r in recs:
            r.pop("_weak", None)
        return recs

    # -------------------------------------------------------------- obligations

    def _indication(self, keywords: tuple[str, ...], phases: tuple[str, ...] = ()) -> str:
        """Infer whether an obligation was addressed, from committed choices.

        Looks for the keywords in the *chosen* option text and, failing that, at the
        quality of decisions in the relevant phases.
        """
        s = self.session
        pattern = re.compile("|".join(keywords), re.IGNORECASE) if keywords else None
        for i, d in enumerate(s.decision_log, 1):
            if pattern and pattern.search(d["choice_text"]):
                if d["quality"] == "optimal":
                    return f"Addressed (Inject {i})"
                if d["quality"] == "detrimental":
                    return f"At risk (Inject {i})"
                return f"Partially addressed (Inject {i})"
        relevant = [ (i, d) for i, d in enumerate(s.decision_log, 1) if d["phase"] in phases ]
        if relevant:
            worst = min(relevant, key=lambda x: ("detrimental", "neutral", "optimal").index(x[1]["quality"]))
            if worst[1]["quality"] == "detrimental":
                return f"At risk (Inject {worst[0]})"
            if all(d["quality"] == "optimal" for _, d in relevant):
                return "Addressed"
            return "Partially addressed"
        return "Not exercised"

    def _build_regulatory_obligations(self) -> list[dict]:
        s = self.session
        tokens = industry_tokens(s.meta.get("industry", ""))
        technique_ids = {t["technique_id"] for t in s.mitre_techniques}
        chosen_text = " ".join(d["choice_text"] for d in s.decision_log)
        obligations: list[dict] = []

        NOTIFY = ("Post-Incident Activity", "Detection & Analysis")
        CONTAIN = ("Containment", "Eradication & Recovery")

        def add(obligation, source, deadline, indication, notes):
            obligations.append({"obligation": obligation, "source": source, "deadline": deadline,
                                "indication": indication, "notes": notes})

        notify_kw = ("notif", "disclos", "report to", "regulator", "OCR", "HHS", "attorney general", "72", "8-K")

        # ---- Industry-specific
        if tokens & {"health", "healthcare", "hospital", "pharma", "pharmaceutical", "medical"}:
            add("PHI Breach Notification to HHS OCR", "HIPAA §164.408", "Within 60 days of discovery",
                self._indication(notify_kw, NOTIFY), "File at ocrportal.hhs.gov")
            add("Individual Patient Notification", "HIPAA §164.404", "Within 60 days of discovery",
                self._indication(notify_kw, NOTIFY), "Written notice required")
            add("Media Notification (>500 residents of a state)", "HIPAA §164.406", "Within 60 days",
                self._indication(notify_kw, NOTIFY), "Notify prominent in-state media")
        if tokens & {"bank", "banking", "financial", "finance", "insurance", "fintech", "crypto", "msp"}:
            add("Customer Notification & Safeguards Review", "GLBA Safeguards Rule (16 CFR 314)",
                "FTC notice within 30 days for 500+ consumers",
                self._indication(notify_kw, NOTIFY), "Document safeguards program review")
            add("Suspicious Activity Report", "FinCEN SAR (31 CFR 1020.320)", "Within 30 days of detection",
                self._indication(("SAR", "FinCEN", "suspicious activity"), NOTIFY), "Required if funds moved or fraud suspected")
            add("Material Cybersecurity Incident Disclosure", "SEC Cyber Disclosure Rule (2023)",
                "Form 8-K Item 1.05 within 4 business days of materiality determination",
                self._indication(("8-K", "SEC", "material", "disclos"), NOTIFY), "Public companies only")
        if tokens & {"commerce", "e-commerce", "retail", "gaming", "fintech"}:
            add("Cardholder Data Breach Notification", "PCI DSS v4.0 / card brand rules", "Immediately upon confirmation",
                self._indication(("acquirer", "card brand", "PCI", "PFI"), NOTIFY), "Engage a PFI; notify acquirer and brands")
        if tokens & {"commerce", "e-commerce", "retail", "gaming", "saas", "media", "technology", "software"}:
            add("Data Subject / Consumer Notification", "GDPR Art. 33-34 / CCPA-CPRA",
                "GDPR: 72h to supervisory authority", self._indication(notify_kw, NOTIFY),
                "Required where EU or California residents' PII exposed")
        if tokens & {"defense", "manufacturing", "manufacturer"}:
            add("DoD Cyber Incident Report", "DFARS 252.204-7012", "Within 72 hours to DIBNET",
                self._indication(("DIBNET", "DoD", "DC3", "DFARS"), NOTIFY), "Required if CDI/CUI involved")
            add("CMMC Control Assessment", "CMMC Level 2", "Post-incident review",
                self._indication(("SSP", "POA&M", "CMMC"), ("Post-Incident Activity",)), "Update SSP / POA&M")
        if tokens & {"infrastructure", "critical", "utility", "energy", "water"}:
            add("CISA Cyber Incident Report", "CIRCIA 2022", "Within 72 hours of determination",
                self._indication(("CISA",), NOTIFY), "Covered entities; ransom payments within 24h")

        # ---- Technique / threat-driven
        ransomware = bool(technique_ids & {"T1486", "T1490"}) or "ransom" in s.meta.get("subtitle", "").lower()
        if ransomware:
            paid = re.search(r"\bpay\b.*ransom|ransom.*\bpay\b|pay the", chosen_text, re.IGNORECASE)
            add("OFAC Sanctions Screening Before Any Payment", "OFAC Ransomware Advisory (2021)",
                "Before any payment", "At risk (payment chosen)" if paid else self._indication(("OFAC", "sanction", "against payment"), CONTAIN),
                "Verify actor is not on the SDN list; consult counsel")
        if any(tid.startswith(p) for tid in technique_ids for p in ("T1567", "T1048", "T1041", "T1530", "T1537", "T1052", "T1005")):
            add("Data Exfiltration Breach Assessment", "State breach laws / GDPR Art. 33",
                "Determine within statutory window", self._indication(("assess", "scope", "exfil", "data categories"), NOTIFY),
                "Document data categories and record counts exposed")

        # ---- Always-applicable
        add("Law Enforcement Notification", "18 U.S.C. § 1030 / FBI IC3", "Recommended promptly",
            self._indication(("FBI", "CISA", "law enforcement", "IC3", "Secret Service"), CONTAIN),
            "File at IC3.gov or contact the FBI field office")
        add("State Attorney General Notification", "State breach notification laws", "Varies (30-60 days typical)",
            self._indication(notify_kw, NOTIFY), "Review every applicable U.S. state statute")
        add("Cyber Insurance Carrier Notification", "Policy terms", "Within policy-defined window",
            self._indication(("insur", "carrier", "broker"), NOTIFY), "Late notice can void coverage")
        add("Preserve Forensic Evidence & Litigation Hold", "FRCP 37(e) / counsel guidance", "Immediately",
            self._indication(("preserve", "forensic", "chain of custody", "evidence", "image"), CONTAIN),
            "Maintain chain of custody for litigation and regulators")
        return obligations


# ---------------------------------------------------------------------------
# Widget helpers
# ---------------------------------------------------------------------------
class ScrollableFrame(tk.Frame):
    """A vertically scrollable container. Children go in `.inner`."""

    def __init__(self, parent, bg: str, on_width=None):
        super().__init__(parent, bg=bg)
        self.on_width = on_width
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.vbar = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview,
                                 bg=COLORS["bg_card"], troughcolor=COLORS["bg_input"],
                                 activebackground=COLORS["bg_elevated"], bd=0, width=10)
        self.canvas.configure(yscrollcommand=self.vbar.set)
        self.vbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        self.canvas.bind("<Enter>", self._bind_wheel)
        self.canvas.bind("<Leave>", self._unbind_wheel)

    def _on_inner_configure(self, _event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self.canvas.itemconfigure(self._win, width=event.width)
        if self.on_width:
            self.on_width(event.width)

    def _bind_wheel(self, _event=None):
        self.canvas.bind_all("<MouseWheel>", self._on_wheel)
        self.canvas.bind_all("<Button-4>", self._on_wheel)
        self.canvas.bind_all("<Button-5>", self._on_wheel)

    def _unbind_wheel(self, _event=None):
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")

    def _on_wheel(self, event):
        if event.num == 4:
            step = -1
        elif event.num == 5:
            step = 1
        else:
            step = -1 if event.delta > 0 else 1
        self.canvas.yview_scroll(step, "units")

    def scroll_to(self, fraction: float):
        self.update_idletasks()
        self.canvas.yview_moveto(fraction)

    def scroll_to_widget(self, widget: tk.Widget):
        """Scroll so that `widget` (a descendant of inner) is near the top of the view."""
        self.update_idletasks()
        total = self.inner.winfo_height()
        if total <= 0:
            return
        y = widget.winfo_rooty() - self.inner.winfo_rooty()
        self.canvas.yview_moveto(max(0.0, min(1.0, (y - 8) / total)))


class ChoiceRow(tk.Frame):
    """A whole-row selectable option: letter tag + wrapped text, styled by state."""

    def __init__(self, parent, letter: str, text: str, on_select, wrap: int):
        super().__init__(parent, bg=COLORS["bg_elevated"], highlightthickness=1,
                         highlightbackground=COLORS["border"], cursor="hand2")
        self._on_select = on_select
        self._selected = False
        self._locked = False
        self._tag = tk.Label(self, text=letter, font=FONTS["mono_bold"], width=3,
                             fg=COLORS["text_secondary"], bg=COLORS["bg_elevated"])
        self._tag.pack(side="left", anchor="n", padx=(10, 2), pady=10)
        self._text = tk.Label(self, text=text, font=FONTS["body"], fg=COLORS["text_primary"],
                              bg=COLORS["bg_elevated"], justify="left", anchor="w", wraplength=wrap)
        self._text.pack(side="left", fill="x", expand=True, padx=(0, 12), pady=10)
        self._note = None
        for w in (self, self._tag, self._text):
            w.bind("<Button-1>", self._click)
            w.bind("<Enter>", lambda e: self._hover(True))
            w.bind("<Leave>", lambda e: self._hover(False))

    def _click(self, _event=None):
        if not self._locked:
            self._on_select()

    def _hover(self, on: bool):
        if self._locked or self._selected:
            return
        bg = COLORS["bg_hover"] if on else COLORS["bg_elevated"]
        self._set_bg(bg)
        self.configure(highlightbackground=COLORS["text_dim"] if on else COLORS["border"])

    def _set_bg(self, bg: str):
        self.configure(bg=bg)
        self._tag.configure(bg=bg)
        self._text.configure(bg=bg)
        if self._note is not None:
            self._note.configure(bg=bg)

    def set_selected(self, selected: bool):
        self._selected = selected
        if selected:
            self._set_bg(COLORS["bg_hover"])
            self.configure(highlightbackground=COLORS["border_bright"], highlightthickness=2)
            self._tag.configure(fg=COLORS["accent_cyan"])
        else:
            self._set_bg(COLORS["bg_elevated"])
            self.configure(highlightbackground=COLORS["border"], highlightthickness=1)
            self._tag.configure(fg=COLORS["text_secondary"])

    def set_wrap(self, wrap: int):
        self._text.configure(wraplength=wrap)

    def lock(self):
        self._locked = True
        self.configure(cursor="arrow")
        for w in (self._tag, self._text):
            w.configure(cursor="arrow")

    def reveal(self, quality: str | None, chosen: bool, note: str = ""):
        """Post-commit styling: colour by quality; dim unchosen rows."""
        self.lock()
        color = quality_color(quality) if quality else COLORS["text_secondary"]
        if chosen:
            self.configure(highlightbackground=color, highlightthickness=2)
            self._tag.configure(fg=color)
            self._text.configure(fg=COLORS["text_primary"])
        else:
            self._set_bg(COLORS["bg_card"])
            self.configure(highlightbackground=COLORS["border"], highlightthickness=1)
            self._tag.configure(fg=color)
            self._text.configure(fg=COLORS["text_secondary"])
        if note:
            self._note = tk.Label(self, text=note, font=FONTS["tag"], fg=color, bg=self["bg"])
            self._note.pack(side="right", anchor="n", padx=(0, 12), pady=10)


def render_markdown(text: tk.Text, md: str) -> None:
    """Light Markdown rendering into a Text widget: headings, bold, code, quotes, bullets, tables, rules."""
    ui = FONTS["body"][0]
    mono = FONTS["mono"][0]
    text.configure(state="normal")
    text.delete("1.0", "end")
    # "body" is configured first so the inline tags configured after it take priority.
    text.tag_configure("body", font=(ui, 10))
    text.tag_configure("h1", font=(ui, 18, "bold"), foreground=COLORS["accent_cyan"], spacing1=10, spacing3=6)
    text.tag_configure("h2", font=(ui, 14, "bold"), foreground=COLORS["accent_purple"], spacing1=14, spacing3=4)
    text.tag_configure("h3", font=(ui, 12, "bold"), foreground=COLORS["text_primary"], spacing1=8, spacing3=2)
    text.tag_configure("bold", font=(ui, 10, "bold"))
    text.tag_configure("italic", font=(ui, 10, "italic"), foreground=COLORS["text_secondary"])
    text.tag_configure("code", font=(mono, 9), foreground=COLORS["accent_cyan"], background=COLORS["bg_elevated"])
    text.tag_configure("quote", lmargin1=24, lmargin2=24, foreground=COLORS["text_secondary"])
    text.tag_configure("bullet", lmargin1=16, lmargin2=32)
    text.tag_configure("table", font=(mono, 9), foreground=COLORS["text_primary"])
    text.tag_configure("table_head", font=(mono, 9, "bold"), foreground=COLORS["accent_cyan"])
    text.tag_configure("rule", foreground=COLORS["border"])

    inline_re = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)")

    def emit_inline(line: str, base_tags=("body",)):
        pos = 0
        for m in inline_re.finditer(line):
            if m.start() > pos:
                text.insert("end", line[pos:m.start()], base_tags)
            tok = m.group(0)
            if tok.startswith("**"):
                text.insert("end", tok[2:-2], base_tags + ("bold",))
            elif tok.startswith("`"):
                text.insert("end", tok[1:-1], base_tags + ("code",))
            else:
                text.insert("end", tok[1:-1], base_tags + ("italic",))
            pos = m.end()
        if pos < len(line):
            text.insert("end", line[pos:], base_tags)
        text.insert("end", "\n")

    def strip_inline(cell: str) -> str:
        return re.sub(r"\*\*|`", "", cell).strip()

    lines = md.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        if stripped.startswith("|"):
            table: list[list[str]] = []
            while i < len(lines) and lines[i].rstrip().startswith("|"):
                row = lines[i].strip().strip("|").split("|")
                if not all(re.fullmatch(r"\s*:?-+:?\s*", c) for c in row):
                    table.append([strip_inline(c) for c in row])
                i += 1
            if table:
                ncols = max(len(r) for r in table)
                widths = [max(len(r[c]) if c < len(r) else 0 for r in table) for c in range(ncols)]
                widths = [min(w, 48) for w in widths]
                for ri, row in enumerate(table):
                    cells = []
                    for c in range(ncols):
                        cell = row[c] if c < len(row) else ""
                        if len(cell) > widths[c]:
                            cell = cell[:widths[c] - 1] + "…"
                        cells.append(cell.ljust(widths[c]))
                    text.insert("end", "  ".join(cells) + "\n", ("table_head" if ri == 0 else "table",))
                text.insert("end", "\n")
            continue
        if stripped.startswith("# "):
            text.insert("end", stripped[2:] + "\n", ("h1",))
        elif stripped.startswith("## "):
            text.insert("end", stripped[3:] + "\n", ("h2",))
        elif stripped.startswith("### "):
            text.insert("end", stripped[4:] + "\n", ("h3",))
        elif stripped == "---":
            text.insert("end", "─" * 72 + "\n", ("rule",))
        elif stripped.startswith("> "):
            emit_inline(stripped[2:], ("body", "quote"))
        elif stripped.startswith("- "):
            emit_inline("• " + stripped[2:], ("body", "bullet"))
        elif stripped == "":
            text.insert("end", "\n")
        else:
            emit_inline(stripped)
        i += 1
    text.configure(state="disabled")


# ---------------------------------------------------------------------------
# Main GUI Application
# ---------------------------------------------------------------------------
class IncidentSimulatorApp(tk.Tk):
    """Main application window."""

    def __init__(self, scenarios_path: str | None = None):
        super().__init__()
        self.withdraw()
        init_fonts(self)
        try:
            self.scenario_mgr = ScenarioManager(scenarios_path)
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror("IR_Sim — cannot start", str(exc))
            self.destroy()
            raise SystemExit(1) from exc

        self.session = SimulationSession(self.scenario_mgr.scenario)
        self._facilitated = tk.BooleanVar(value=False)
        self._prompts_open = tk.BooleanVar(value=False)
        self._discussion_limit = tk.IntVar(value=0)    # minutes; 0 = off
        self._timer_job = None
        self._inject_started_at: datetime | None = None
        self._inject_frozen: timedelta | None = None
        self._content_width = 760
        self._sidebar_width = 300
        self._wrap_widgets: list[tuple[tk.Widget, int]] = []
        self._view = "briefing"
        self._selected_token: str | None = None
        self._committed = False
        self._quiz_pending = False

        self._configure_window(first=True)
        self._build_menu()
        self._build_ui()
        self._render_briefing()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.deiconify()

    # ------------------------------------------------------------------ setup

    def _configure_window(self, first: bool = False):
        n = self.scenario_mgr.scenario_index + 1
        t = self.scenario_mgr.total_scenarios
        self.title(f"IR_Sim  //  Scenario {n}/{t}: {self.scenario_mgr.meta['title']}")
        if first:
            self.configure(bg=COLORS["bg_primary"])
            self.minsize(1000, 680)
            w, h = 1280, 820
            self.update_idletasks()
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            w, h = min(w, sw - 40), min(h, sh - 80)
            x, y = (sw - w) // 2, max(0, (sh - h) // 2 - 20)
            self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_menu(self):
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Progress…", accelerator="Ctrl+S", command=self._save_progress)
        file_menu.add_command(label="Resume Saved Progress…", accelerator="Ctrl+O", command=self._resume_progress)
        file_menu.add_separator()
        file_menu.add_command(label="Generate GRC Report…", accelerator="Ctrl+R", command=self._on_generate_report)
        file_menu.add_separator()
        file_menu.add_command(label="Quit", accelerator="Ctrl+Q", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        scen_menu = tk.Menu(menubar, tearoff=0)
        scen_menu.add_command(label="Random Scenario", accelerator="Ctrl+N", command=self._on_new_scenario)
        scen_menu.add_command(label="Choose Scenario…", accelerator="Ctrl+L", command=self._on_choose_scenario)
        scen_menu.add_command(label="Restart This Scenario", command=self._on_restart_same)
        scen_menu.add_separator()
        scen_menu.add_command(label="Show Briefing", command=self._show_briefing_dialog)
        menubar.add_cascade(label="Scenario", menu=scen_menu)

        trainer_menu = tk.Menu(menubar, tearoff=0)
        trainer_menu.add_checkbutton(label="Facilitator Mode (hide scores until debrief)",
                                     variable=self._facilitated, command=self._on_toggle_facilitator)
        trainer_menu.add_checkbutton(label="Show Discussion Prompts",
                                     variable=self._prompts_open, command=self._refresh_prompts)
        timer_menu = tk.Menu(trainer_menu, tearoff=0)
        for minutes in (0, 3, 5, 10, 15):
            timer_menu.add_radiobutton(label="Off" if minutes == 0 else f"{minutes} minutes per inject",
                                       variable=self._discussion_limit, value=minutes)
        trainer_menu.add_cascade(label="Discussion Timer", menu=timer_menu)
        menubar.add_cascade(label="Trainer", menu=trainer_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Keyboard Shortcuts", command=self._show_shortcuts)
        help_menu.add_command(label="About IR_Sim", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)

        self.bind("<Control-s>", lambda e: self._save_progress())
        self.bind("<Control-o>", lambda e: self._resume_progress())
        self.bind("<Control-r>", lambda e: self._on_generate_report())
        self.bind("<Control-q>", lambda e: self._on_close())
        self.bind("<Control-n>", lambda e: self._on_new_scenario())
        self.bind("<Control-l>", lambda e: self._on_choose_scenario())

    SIDEBAR_WIDTH = 320

    def _build_ui(self):
        self._build_header()
        # Status bar is packed before the expanding main panel so it is never squeezed out.
        self._build_status_bar()
        main = tk.Frame(self, bg=COLORS["bg_primary"])
        main.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        main.columnconfigure(0, weight=1, minsize=560)
        main.columnconfigure(1, weight=0, minsize=self.SIDEBAR_WIDTH)
        main.rowconfigure(0, weight=1)
        self._build_main_panel(main)
        self._build_sidebar(main)
        self._bind_shortcuts()

    def _bind_shortcuts(self):
        for i, key in enumerate(("1", "2", "3")):
            self.bind(key, lambda e, idx=i: self._select_by_index(idx))
        for i, key in enumerate(("a", "b", "c")):
            self.bind(key, lambda e, idx=i: self._select_by_index(idx))
            self.bind(key.upper(), lambda e, idx=i: self._select_by_index(idx))
        self.bind("<Return>", self._on_enter)
        self.bind("<KP_Enter>", self._on_enter)

    # ------------------------------------------------------------------ header

    def _build_header(self):
        hdr = tk.Frame(self, bg=COLORS["bg_card"])
        hdr.pack(fill="x")
        self._header = hdr

        left = tk.Frame(hdr, bg=COLORS["bg_card"])
        left.pack(side="left", fill="x", expand=True, padx=20, pady=10)
        tk.Label(left, text="⬡ IR·SIM", font=FONTS["display"],
                 fg=COLORS["accent_cyan"], bg=COLORS["bg_card"]).pack(anchor="w")
        self._header_subtitle = tk.Label(left, text="", font=FONTS["mono_sm"], justify="left",
                                         fg=COLORS["text_secondary"], bg=COLORS["bg_card"], anchor="w")
        self._header_subtitle.pack(anchor="w", fill="x")
        left.bind("<Configure>", lambda e: self._header_subtitle.configure(wraplength=max(200, e.width - 10)))
        self._refresh_header_subtitle()

        right = tk.Frame(hdr, bg=COLORS["bg_card"])
        right.pack(side="right", padx=20, pady=12)
        self._phase_dots = []
        for i, phase in enumerate(self.scenario_mgr.phases):
            cell = tk.Frame(right, bg=COLORS["bg_card"])
            cell.pack(side="left", padx=5)
            dot = tk.Label(cell, text="●", font=(FONTS["mono"][0], 13), fg=COLORS["text_dim"], bg=COLORS["bg_card"])
            dot.pack()
            short = PHASE_SHORT_LABELS[i] if i < len(PHASE_SHORT_LABELS) else phase
            name = tk.Label(cell, text=short, font=FONTS["tag"], fg=COLORS["text_dim"], bg=COLORS["bg_card"])
            name.pack()
            self._phase_dots.append((dot, name))
            if i < len(self.scenario_mgr.phases) - 1:
                tk.Label(right, text="─", font=FONTS["mono"], fg=COLORS["text_dim"], bg=COLORS["bg_card"]).pack(side="left")

    def _refresh_header_subtitle(self):
        n = self.scenario_mgr.scenario_index + 1
        t = self.scenario_mgr.total_scenarios
        mode = "  //  FACILITATED" if self._facilitated.get() else ""
        self._header_subtitle.configure(
            text=f"SCENARIO {n:02d}/{t}  //  {self.scenario_mgr.meta['title'].upper()}{mode}")

    def _set_phase_dots(self, active_idx: int | None, all_done: bool = False):
        for i, (dot, name) in enumerate(self._phase_dots):
            if all_done:
                color = PHASE_COLORS[i]
            elif active_idx is None or i > active_idx:
                color = COLORS["text_dim"]
            elif i == active_idx:
                color = PHASE_COLORS[i]
            else:
                color = COLORS["text_secondary"]
            dot.configure(fg=color)
            name.configure(fg=color)

    # -------------------------------------------------------------- main panel

    def _build_main_panel(self, parent):
        column = tk.Frame(parent, bg=COLORS["bg_primary"])
        column.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=8)
        column.rowconfigure(0, weight=1)
        column.columnconfigure(0, weight=1)

        self._scroll = ScrollableFrame(column, bg=COLORS["bg_primary"], on_width=self._on_content_width)
        self._scroll.grid(row=0, column=0, sticky="nsew")
        self._content = self._scroll.inner

        # Pinned action bar — the primary action never scrolls away.
        bar = self._make_card(column)
        bar.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self._action_hint = tk.Label(bar, text="", font=FONTS["tag"], fg=COLORS["text_dim"],
                                     bg=COLORS["bg_card"], anchor="w", justify="left")
        self._action_hint.pack(side="left", padx=14, pady=10, fill="x", expand=True)
        self._action_secondary = self._make_button(bar, text="", command=lambda: None,
                                                   fg=COLORS["text_primary"], bg=COLORS["bg_elevated"],
                                                   active_bg=COLORS["border"])
        self._action_primary = self._make_button(bar, text="", command=lambda: None,
                                                 fg=COLORS["bg_primary"], bg=COLORS["accent_cyan"],
                                                 active_bg=COLORS["accent_blue"])
        self._action_primary.pack(side="right", padx=(6, 12), pady=8)

    def _set_actions(self, primary: tuple[str, callable, str] | None, secondary: tuple[str, callable] | None,
                     hint: str = "", primary_enabled: bool = True):
        if primary:
            text, cmd, color = primary
            self._action_primary.configure(text=text, command=cmd, bg=color,
                                           activebackground=color,
                                           state="normal" if primary_enabled else "disabled",
                                           disabledforeground=COLORS["text_dim"])
            self._action_primary.pack(side="right", padx=(6, 12), pady=8)
        else:
            self._action_primary.pack_forget()
        if secondary:
            text, cmd = secondary
            self._action_secondary.configure(text=text, command=cmd)
            self._action_secondary.pack(side="right", padx=0, pady=8)
        else:
            self._action_secondary.pack_forget()
        self._action_hint.configure(text=hint)

    def _on_content_width(self, width: int):
        self._content_width = width
        wrap = max(320, width - 64)
        for widget, offset in list(self._wrap_widgets):
            if widget.winfo_exists():
                if isinstance(widget, ChoiceRow):
                    widget.set_wrap(max(240, wrap - offset))
                else:
                    widget.configure(wraplength=max(240, wrap - offset))
        if hasattr(self, "_action_hint"):
            self._action_hint.configure(wraplength=max(200, width - 320))

    def _clear_content(self):
        for w in self._content.winfo_children():
            w.destroy()
        self._wrap_widgets.clear()
        self._scroll.scroll_to(0.0)

    def _wrap_for(self, offset: int = 0) -> int:
        return max(240, self._content_width - 64 - offset)

    def _track_wrap(self, widget, offset: int = 0):
        self._wrap_widgets.append((widget, offset))
        return widget

    def _card(self, parent=None, pady=(0, 8)) -> tk.Frame:
        card = self._make_card(parent or self._content)
        card.pack(fill="x", pady=pady, padx=(0, 4))
        return card

    def _card_title(self, card, text, color=COLORS["accent_cyan"], pady=(10, 4)):
        return tk.Label(card, text=text, font=FONTS["tag"], fg=color, bg=card["bg"], anchor="w").pack(
            anchor="w", padx=16, pady=pady)

    def _prose(self, card, text, font_key="body", fg=COLORS["text_primary"], offset=0, pady=(0, 12), bg=None):
        lbl = tk.Label(card, text=text, font=FONTS[font_key], fg=fg, bg=bg or card["bg"],
                       justify="left", anchor="w", wraplength=self._wrap_for(offset))
        lbl.pack(fill="x", padx=16, pady=pady)
        return self._track_wrap(lbl, offset)

    # ------------------------------------------------------------- briefing

    def _render_briefing(self):
        self._view = "briefing"
        self._committed = False
        self._quiz_pending = False
        self._selected_token = None
        self._clear_content()
        meta = self.scenario_mgr.meta
        self._set_phase_dots(None)
        self._refresh_header_subtitle()

        card = self._card()
        self._card_title(card, "SCENARIO BRIEFING")
        tk.Label(card, text=meta["title"], font=FONTS["title"], fg=COLORS["text_primary"],
                 bg=card["bg"], anchor="w").pack(fill="x", padx=16)
        self._prose(card, meta["subtitle"], "subheader", COLORS["text_secondary"], pady=(2, 10))

        grid = tk.Frame(card, bg=card["bg"])
        grid.pack(fill="x", padx=16, pady=(0, 12))
        rows = [
            ("THREAT ACTOR", meta["threat_actor"], COLORS["text_primary"]),
            ("INDUSTRY",     meta["industry"], COLORS["text_primary"]),
            ("SEVERITY",     meta["severity"], SEVERITY_COLORS.get(meta["severity"].upper(), COLORS["text_primary"])),
            ("EST. IMPACT",  meta["estimated_impact"], COLORS["text_primary"]),
            ("INJECTS",      f"{self.scenario_mgr.total_injects} decision points across {len(self.scenario_mgr.phases)} NIST phases",
                             COLORS["text_primary"]),
        ]
        for r, (k, v, color) in enumerate(rows):
            tk.Label(grid, text=k, font=FONTS["tag"], fg=COLORS["text_dim"], bg=card["bg"], anchor="w", width=14).grid(
                row=r, column=0, sticky="nw", pady=2)
            lbl = tk.Label(grid, text=v, font=FONTS["body"], fg=color, bg=card["bg"], anchor="w",
                           justify="left", wraplength=self._wrap_for(140))
            lbl.grid(row=r, column=1, sticky="w", pady=2)
            self._track_wrap(lbl, 140)

        role_card = self._card()
        self._card_title(role_card, "YOUR ROLE")
        self._prose(role_card, meta.get("role", "Incident Response Team Lead. You coordinate technical "
                    "response, legal, communications, and executive stakeholders across the incident lifecycle."))

        obj_card = self._card()
        self._card_title(obj_card, "OBJECTIVES")
        for obj in meta.get("objectives", DEFAULT_OBJECTIVES):
            self._prose(obj_card, f"•  {obj}", pady=(0, 4))
        tk.Frame(obj_card, bg=obj_card["bg"], height=8).pack()

        how_card = self._card()
        self._card_title(how_card, "HOW IT WORKS", COLORS["accent_purple"])
        steps = [
            "Read each inject, then pick the response action. Option order is shuffled every time.",
            "After committing, you will be challenged to identify the ATT&CK technique in play.",
            "Scores are relative to the best and worst possible path, so every decision counts.",
            "Keys 1-3 or A-C select an option; Enter commits or advances.",
        ]
        if self._facilitated.get():
            steps.append("Facilitator mode is on: scores, quality ratings, and feedback are withheld until the debrief.")
        for st in steps:
            self._prose(how_card, f"•  {st}", "body_sm", COLORS["text_secondary"], pady=(0, 4))
        tk.Frame(how_card, bg=how_card["bg"], height=8).pack()

        self._set_actions(("BEGIN EXERCISE  ▶", self._begin_exercise, COLORS["accent_cyan"]),
                          ("▤  CHOOSE SCENARIO", self._on_choose_scenario),
                          hint="Press Enter to begin")
        self._refresh_sidebar_meta()
        self._update_scores()
        self._update_tracker()
        self._refresh_log()
        self._update_status("BRIEFING  ·  review the scenario and begin when ready")

    def _begin_exercise(self):
        self.session.facilitated = self._facilitated.get()
        self.session.start_time = datetime.now()
        self._render_inject(0)

    # --------------------------------------------------------------- inject

    def _render_inject(self, index: int):
        self._view = "inject"
        self._committed = False
        self._quiz_pending = False
        self._selected_token = None
        self._clear_content()
        inject = self.scenario_mgr.get_inject(index)
        phase_idx = inject["phase_index"]
        phase_color = PHASE_COLORS[phase_idx]
        total = self.scenario_mgr.total_injects
        self._set_phase_dots(phase_idx)

        # Inject header
        head = self._card()
        top = tk.Frame(head, bg=head["bg"])
        top.pack(fill="x", padx=16, pady=(12, 0))
        tk.Label(top, text=f"INJECT {index + 1:02d}/{total:02d}", font=FONTS["tag"],
                 fg=COLORS["accent_cyan"], bg=head["bg"]).pack(side="left")
        tk.Label(top, text=f"[ {inject['phase'].upper()} ]", font=FONTS["tag"],
                 fg=phase_color, bg=head["bg"]).pack(side="right")
        self._prose(head, inject["title"], "header", pady=(4, 8))
        prog_bg = tk.Frame(head, bg=COLORS["bg_input"], height=4)
        prog_bg.pack(fill="x")
        prog_bg.pack_propagate(False)
        fill = tk.Frame(prog_bg, bg=COLORS["accent_cyan"], height=4)
        fill.place(x=0, y=0, relheight=1.0, relwidth=(index + 1) / total)

        # Story (branching variant if the previous decision unlocked one)
        story_card = self._card()
        prior = self.session.last_quality
        story = ScenarioManager.story_for(inject, prior)
        if prior and story != inject["story"]:
            tk.Label(story_card, text="◈  CONSEQUENCE OF YOUR LAST DECISION", font=FONTS["tag"],
                     fg=quality_color(prior), bg=story_card["bg"]).pack(anchor="w", padx=16, pady=(10, 0))
        self._prose(story_card, story, pady=(12, 14))

        # Discussion prompts (collapsible)
        self._prompts_card = self._card()
        self._build_prompts(inject)

        # Choices
        choice_card = self._card()
        self._choice_card = choice_card
        self._card_title(choice_card, "SELECT RESPONSE ACTION")
        display = list(inject["choices"])
        random.shuffle(display)
        self._choice_token_map: dict[str, dict] = {}
        self._display_tokens: list[str] = []
        self._choice_rows: dict[str, ChoiceRow] = {}
        for i, choice in enumerate(display):
            letter = "ABC"[i] if i < 3 else str(i + 1)
            token = f"{index}_{letter}"
            self._choice_token_map[token] = choice
            self._display_tokens.append(token)
            row = ChoiceRow(choice_card, letter, choice["text"],
                            on_select=lambda t=token: self._select_token(t), wrap=self._wrap_for(90))
            row.pack(fill="x", padx=14, pady=3)
            self._track_wrap(row, 90)
            self._choice_rows[token] = row
        tk.Frame(choice_card, bg=choice_card["bg"], height=10).pack()

        self._set_actions(("⬡  COMMIT DECISION", self._on_submit, COLORS["accent_cyan"]), None,
                          hint="Keys 1-3 / A-C select  ·  Enter commits", primary_enabled=False)
        self._inject_started_at = datetime.now()
        self._inject_frozen = None
        self._update_status(f"INJECT {index + 1} OF {total}  ·  PHASE: {inject['phase'].upper()}")
        self._update_scores()
        self._tick_timer()

    def _build_prompts(self, inject: dict):
        card = self._prompts_card
        for w in card.winfo_children():
            w.destroy()
        is_open = self._prompts_open.get()
        arrow = "▾" if is_open else "▸"
        hdr = tk.Label(card, text=f"{arrow}  DISCUSSION PROMPTS BY ROLE", font=FONTS["tag"],
                       fg=COLORS["accent_purple"], bg=card["bg"], anchor="w", cursor="hand2")
        hdr.pack(fill="x", padx=16, pady=(8, 8 if not is_open else 2))
        hdr.bind("<Button-1>", lambda e: self._toggle_prompts())
        if not is_open:
            return
        prompts = inject.get("role_prompts") or ROLE_PROMPTS.get(inject["phase"], {})
        for role, prompt in prompts.items():
            row = tk.Frame(card, bg=card["bg"])
            row.pack(fill="x", padx=16, pady=1)
            tk.Label(row, text=role.upper(), font=FONTS["tag"], fg=COLORS["text_dim"], bg=card["bg"],
                     width=10, anchor="nw").pack(side="left")
            lbl = tk.Label(row, text=prompt, font=FONTS["body_sm"], fg=COLORS["text_secondary"], bg=card["bg"],
                           justify="left", anchor="w", wraplength=self._wrap_for(110))
            lbl.pack(side="left", fill="x", expand=True)
            self._track_wrap(lbl, 110)
        tk.Frame(card, bg=card["bg"], height=8).pack()

    def _toggle_prompts(self):
        self._prompts_open.set(not self._prompts_open.get())
        self._refresh_prompts()

    def _refresh_prompts(self):
        if self._view == "inject" and getattr(self, "_prompts_card", None) and self._prompts_card.winfo_exists():
            self._build_prompts(self.scenario_mgr.get_inject(self.session.current_inject_index))

    # ------------------------------------------------------------- selection

    def _select_token(self, token: str):
        if self._committed:
            return
        self._selected_token = token
        for t, row in self._choice_rows.items():
            row.set_selected(t == token)
        self._action_primary.configure(state="normal")

    def _select_by_index(self, idx: int):
        if self._view != "inject":
            return
        if self._quiz_pending:
            tokens = getattr(self, "_quiz_tokens", [])
            if 0 <= idx < len(tokens):
                self._answer_quiz(tokens[idx])
            return
        if self._committed:
            return
        if 0 <= idx < len(self._display_tokens):
            self._select_token(self._display_tokens[idx])

    def _on_enter(self, _event=None):
        if self._view == "briefing":
            self._begin_exercise()
        elif self._view == "inject":
            if str(self._action_primary["state"]) == "disabled":
                return
            self._action_primary.invoke()
        elif self._view == "debrief":
            self._on_generate_report()

    # ---------------------------------------------------------------- commit

    def _on_submit(self):
        if self._committed or not self._selected_token:
            return
        inject_idx = self.session.current_inject_index
        inject = self.scenario_mgr.get_inject(inject_idx)
        choice = self._choice_token_map[self._selected_token]
        self.session.apply_decision(inject, choice)
        self._committed = True
        self._inject_frozen = datetime.now() - (self._inject_started_at or datetime.now())
        facilitated = self.session.facilitated

        # Reveal on the option rows
        for token, row in self._choice_rows.items():
            c = self._choice_token_map[token]
            chosen = token == self._selected_token
            if facilitated:
                row.reveal(None, chosen, "SELECTED" if chosen else "")
            else:
                style = QUALITY_STYLES[c["quality"]]
                row.reveal(c["quality"], chosen, f"{style['glyph']} {style['label']}")

        # Feedback card
        fb = self._card()
        self._feedback_card = fb
        if facilitated:
            fb.configure(highlightbackground=COLORS["border"])
            self._card_title(fb, "DECISION RECORDED", COLORS["text_secondary"])
            self._prose(fb, "Facilitator mode: the quality rating, score impact, and assessment for this "
                            "decision are withheld until the debrief. Discuss the reasoning as a group before "
                            "moving on.", "body_sm", COLORS["text_secondary"])
        else:
            style = QUALITY_STYLES[choice["quality"]]
            tint = style["bg"]
            fb.configure(bg=tint, highlightbackground=style["color"])
            row = tk.Frame(fb, bg=tint)
            row.pack(fill="x", padx=16, pady=(10, 2))
            tk.Label(row, text=f"{style['glyph']} {style['label']}", font=FONTS["subheader"],
                     fg=style["color"], bg=tint).pack(side="left")
            for name, d in (("LEGAL", choice["legal_score_delta"]),
                            ("COMPLIANCE", choice["compliance_score_delta"]),
                            ("NIST", choice["nist_score_delta"])):
                color = (COLORS["accent_green"] if d > 0 else COLORS["accent_red"] if d < 0 else COLORS["text_secondary"])
                tk.Label(row, text=f"{name} {d:+d}", font=FONTS["tag"], fg=color, bg=tint).pack(side="right", padx=(10, 0))
            self._prose(fb, choice["feedback"], "body", pady=(4, 10), bg=tint)

            tk.Label(fb, text="WHAT THE OTHER OPTIONS WOULD HAVE DONE", font=FONTS["tag"],
                     fg=COLORS["text_secondary"], bg=tint).pack(anchor="w", padx=16, pady=(2, 4))
            for alt in inject["choices"]:
                if alt is choice:
                    continue
                a_style = QUALITY_STYLES[alt["quality"]]
                head = tk.Frame(fb, bg=tint)
                head.pack(fill="x", padx=16)
                tk.Label(head, text=f"{a_style['glyph']} {a_style['label']}", font=FONTS["tag"],
                         fg=a_style["color"], bg=tint).pack(side="left")
                tk.Label(head, text=f"NIST {alt['nist_score_delta']:+d} · COMP {alt['compliance_score_delta']:+d} · "
                                    f"LEGAL {alt['legal_score_delta']:+d}",
                         font=FONTS["tag"], fg=COLORS["text_dim"], bg=tint).pack(side="right")
                self._prose(fb, alt["text"], "body_sm", COLORS["text_primary"], pady=(2, 0), bg=tint)
                self._prose(fb, alt["feedback"], "body_sm", COLORS["text_secondary"], pady=(2, 8), bg=tint)

        # Technique identification challenge (ATT&CK injects only)
        if is_attack_id(inject["mitre"]["technique_id"]):
            self._build_quiz(inject)
            self._set_actions(("NEXT INJECT  ▶", self._on_next, COLORS["accent_green"]), None,
                              hint="Identify the adversary technique to continue  ·  keys 1-3 select",
                              primary_enabled=False)
        else:
            self._show_mitre_card(inject, verdict=None)
            self._finish_inject_actions(inject_idx)

        self._update_scores()
        self._update_tracker()
        self._refresh_log()
        self._scroll.scroll_to_widget(fb)

    def _finish_inject_actions(self, inject_idx: int):
        is_last = inject_idx == self.scenario_mgr.total_injects - 1
        if is_last:
            self._set_actions(("VIEW DEBRIEF  ▶", self._on_finish, COLORS["accent_green"]), None,
                              hint="Enter advances")
        else:
            self._set_actions(("NEXT INJECT  ▶", self._on_next, COLORS["accent_green"]), None,
                              hint="Enter advances")

    # ------------------------------------------------------------------ quiz

    def _build_quiz(self, inject: dict):
        self._quiz_pending = True
        correct = inject["mitre"]
        pool = [t for t in self.scenario_mgr.technique_pool() if t["technique_id"] != correct["technique_id"]]
        same_tactic = [t for t in pool if t["tactic"] == correct["tactic"]]
        random.shuffle(pool)
        random.shuffle(same_tactic)
        distractors: list[dict] = []
        for t in same_tactic[:1] + pool:
            if len(distractors) == 2:
                break
            if all(d["technique_id"] != t["technique_id"] for d in distractors):
                distractors.append(t)
        options = [correct] + distractors
        random.shuffle(options)

        card = self._card()
        self._quiz_card = card
        card.configure(highlightbackground=COLORS["accent_purple"])
        self._card_title(card, "IDENTIFY THE ADVERSARY TECHNIQUE", COLORS["accent_purple"])
        self._prose(card, "Which MITRE ATT&CK technique best describes the adversary behavior in this inject?",
                    "body_sm", COLORS["text_secondary"], pady=(0, 6))
        self._quiz_tokens: list[str] = []
        self._quiz_rows: dict[str, ChoiceRow] = {}
        self._quiz_options: dict[str, dict] = {}
        for i, opt in enumerate(options):
            token = f"quiz_{i}"
            self._quiz_tokens.append(token)
            self._quiz_options[token] = opt
            row = ChoiceRow(card, "ABC"[i], f"{opt['technique_id']}  —  {opt['technique']}",
                            on_select=lambda t=token: self._answer_quiz(t), wrap=self._wrap_for(90))
            row.pack(fill="x", padx=14, pady=3)
            self._track_wrap(row, 90)
            self._quiz_rows[token] = row
        tk.Frame(card, bg=card["bg"], height=10).pack()

    def _answer_quiz(self, token: str):
        if not self._quiz_pending:
            return
        self._quiz_pending = False
        inject = self.scenario_mgr.get_inject(self.session.current_inject_index)
        picked = self._quiz_options[token]
        correct = self.session.record_identification(inject, picked["technique_id"])
        facilitated = self.session.facilitated
        for t, row in self._quiz_rows.items():
            is_correct = self._quiz_options[t]["technique_id"] == inject["mitre"]["technique_id"]
            chosen = t == token
            if facilitated:
                row.reveal(None, chosen, "SELECTED" if chosen else "")
            elif is_correct:
                row.reveal("optimal", chosen, "◆ CORRECT")
            elif chosen:
                row.reveal("detrimental", True, "✕ YOUR PICK")
            else:
                row.reveal(None, False)
        if not facilitated:
            self._show_mitre_card(inject, verdict=correct)
        else:
            note = self._card()
            self._prose(note, "Technique pick recorded. The correct mapping is revealed in the debrief.",
                        "body_sm", COLORS["text_secondary"], pady=(10, 10))
        self._finish_inject_actions(self.session.current_inject_index)
        self._update_tracker()
        self._scroll.scroll_to(1.0)

    def _show_mitre_card(self, inject: dict, verdict: bool | None):
        m = inject["mitre"]
        card = self._card()
        card.configure(highlightbackground=COLORS["accent_purple"])
        if is_attack_id(m["technique_id"]):
            title = "⚡  ADVERSARY BEHAVIOR — MITRE ATT&CK"
            if verdict is True:
                title += "   ·   IDENTIFIED"
            elif verdict is False:
                title += "   ·   MISSED"
        else:
            title = "▤  FRAMEWORK REFERENCE"
        self._card_title(card, title, COLORS["accent_purple"])
        grid = tk.Frame(card, bg=card["bg"])
        grid.pack(fill="x", padx=16, pady=(0, 4))
        for r, (k, v) in enumerate((("TACTIC", f"{m['tactic']}  ({m['tactic_id']})"),
                                    ("TECHNIQUE", f"{m['technique']}  ({m['technique_id']})"))):
            tk.Label(grid, text=k, font=FONTS["tag"], fg=COLORS["text_dim"], bg=card["bg"], width=11, anchor="w").grid(
                row=r, column=0, sticky="nw", pady=1)
            lbl = tk.Label(grid, text=v, font=FONTS["mono"], fg=COLORS["accent_purple"], bg=card["bg"],
                           anchor="w", justify="left", wraplength=self._wrap_for(120))
            lbl.grid(row=r, column=1, sticky="w", pady=1)
            self._track_wrap(lbl, 120)
        self._prose(card, m["description"], "body_sm", COLORS["text_secondary"], pady=(4, 12))

    # ---------------------------------------------------------------- advance

    def _on_next(self):
        if self._quiz_pending:
            return
        self.session.current_inject_index += 1
        self._render_inject(self.session.current_inject_index)

    def _on_finish(self):
        self.session.current_inject_index = self.scenario_mgr.total_injects
        self._render_debrief()

    # ---------------------------------------------------------------- debrief

    def _render_debrief(self):
        self._view = "debrief"
        self._committed = True
        self._quiz_pending = False
        self._clear_content()
        s = self.session
        scores = s.scores() or {a: 0 for a in scoring.AXES}
        grade, grade_color = s.grade()
        self._set_phase_dots(None, all_done=True)
        self._inject_frozen = None
        self._inject_started_at = None

        # Headline card
        card = self._card()
        self._card_title(card, "EXERCISE COMPLETE — POST-INCIDENT DEBRIEF", COLORS["phase_post"])
        head = tk.Frame(card, bg=card["bg"])
        head.pack(fill="x", padx=16, pady=(0, 12))
        tk.Label(head, text=grade, font=FONTS["grade"], fg=grade_color, bg=card["bg"], width=2).pack(side="left", padx=(0, 18))
        right = tk.Frame(head, bg=card["bg"])
        right.pack(side="left", fill="x", expand=True)
        tk.Label(right, text=s.meta["title"], font=FONTS["title"], fg=COLORS["text_primary"], bg=card["bg"], anchor="w").pack(anchor="w")
        tk.Label(right, text=f"OVERALL {s.overall_score:.1f}/100  ·  {format_duration(datetime.now() - s.start_time)} elapsed"
                             f"  ·  {'FACILITATED' if s.facilitated else 'SELF-GUIDED'}",
                 font=FONTS["mono_sm"], fg=COLORS["text_secondary"], bg=card["bg"], anchor="w").pack(anchor="w", pady=(4, 8))
        for label, key in (("NIST IR", "nist"), ("COMPLIANCE", "compliance"), ("LEGAL", "legal")):
            self._debrief_meter(right, label, scores[key])
        ident = f"{s.techniques_identified}/{s.techniques_quizzed}" if s.techniques_quizzed else "n/a"
        tk.Label(right, text=f"ATT&CK techniques identified: {ident}", font=FONTS["mono_sm"],
                 fg=COLORS["accent_purple"], bg=card["bg"], anchor="w").pack(anchor="w", pady=(6, 0))

        # Phase efficiency
        ph = self._card()
        self._card_title(ph, "NIST PHASE EFFICIENCY")
        for i, row in enumerate(s.phase_rows()):
            eff = row["efficiency"]
            line = tk.Frame(ph, bg=ph["bg"])
            line.pack(fill="x", padx=16, pady=2)
            tk.Label(line, text=row["phase"], font=FONTS["body_sm"], fg=COLORS["text_secondary"], bg=ph["bg"],
                     width=24, anchor="w").pack(side="left")
            bar_bg = tk.Frame(line, bg=COLORS["bg_input"], height=8)
            bar_bg.pack(side="left", fill="x", expand=True, padx=8)
            bar_bg.pack_propagate(False)
            tk.Frame(bar_bg, bg=PHASE_COLORS[i], height=8).place(x=0, y=0, relheight=1.0, relwidth=(eff or 0) / 100)
            tk.Label(line, text=f"{eff}%" if eff is not None else "—", font=FONTS["mono_sm"],
                     fg=score_color(eff), bg=ph["bg"], width=5, anchor="e").pack(side="left")
        tk.Frame(ph, bg=ph["bg"], height=10).pack()

        # Decision review
        dr = self._card()
        self._card_title(dr, "DECISION REVIEW")
        for i, d in enumerate(s.decision_log, 1):
            style = QUALITY_STYLES[d["quality"]]
            block = tk.Frame(dr, bg=dr["bg"])
            block.pack(fill="x", padx=16, pady=(0, 8))
            top = tk.Frame(block, bg=dr["bg"])
            top.pack(fill="x")
            tk.Label(top, text=f"{style['glyph']} {i:02d}  {d['inject_title']}", font=FONTS["subheader"],
                     fg=style["color"], bg=dr["bg"], anchor="w").pack(side="left")
            tk.Label(top, text=f"NIST {d['nist_delta']:+d} · COMP {d['compliance_delta']:+d} · LEGAL {d['legal_delta']:+d}",
                     font=FONTS["tag"], fg=COLORS["text_dim"], bg=dr["bg"]).pack(side="right")
            ident_rec = s.identification_for(d["inject_id"])
            if ident_rec is not None:
                txt = (f"Technique identified: {ident_rec['correct_id']}" if ident_rec["correct"]
                       else f"Technique missed: picked {ident_rec['picked_id'] or 'none'}, was {ident_rec['correct_id']}")
                tk.Label(block, text=txt, font=FONTS["mono_sm"],
                         fg=COLORS["accent_green"] if ident_rec["correct"] else COLORS["accent_red"],
                         bg=dr["bg"], anchor="w").pack(anchor="w", pady=(2, 0))
            lbl = tk.Label(block, text=d["choice_text"], font=FONTS["body_sm"], fg=COLORS["text_primary"],
                           bg=dr["bg"], justify="left", anchor="w", wraplength=self._wrap_for(20))
            lbl.pack(fill="x", pady=(2, 0))
            self._track_wrap(lbl, 20)
            lbl2 = tk.Label(block, text=d["feedback"], font=FONTS["body_sm"], fg=COLORS["text_secondary"],
                            bg=dr["bg"], justify="left", anchor="w", wraplength=self._wrap_for(20))
            lbl2.pack(fill="x", pady=(2, 0))
            self._track_wrap(lbl2, 20)
        tk.Frame(dr, bg=dr["bg"], height=6).pack()

        # Next steps
        nx = self._card()
        self._card_title(nx, "NEXT STEPS", COLORS["accent_purple"])
        self._prose(nx, "Generate the GRC report for the full decision timeline, technique checklist, tailored "
                        "recommendations, and the regulatory obligations checklist. Then replay this scenario "
                        "or pick another.", "body_sm", COLORS["text_secondary"])
        btns = tk.Frame(nx, bg=nx["bg"])
        btns.pack(fill="x", padx=16, pady=(0, 12))
        self._make_button(btns, text="↺  REPLAY THIS SCENARIO", command=self._on_restart_same,
                          fg=COLORS["text_primary"], bg=COLORS["bg_elevated"], active_bg=COLORS["border"]).pack(side="left", padx=(0, 6))
        self._make_button(btns, text="↻  RANDOM SCENARIO", command=self._on_new_scenario,
                          fg=COLORS["text_primary"], bg=COLORS["bg_elevated"], active_bg=COLORS["border"]).pack(side="left", padx=(0, 6))
        self._make_button(btns, text="▤  CHOOSE…", command=self._on_choose_scenario,
                          fg=COLORS["text_primary"], bg=COLORS["bg_elevated"], active_bg=COLORS["border"]).pack(side="left")

        self._set_actions(("▤  GENERATE GRC REPORT", self._on_generate_report, COLORS["accent_purple"]),
                          ("↻  NEW SCENARIO", self._on_new_scenario), hint="Enter opens the report")
        self._report_btn.configure(state="normal")
        self._update_scores(force_visible=True)
        self._update_tracker(force_visible=True)
        self._refresh_log(force_visible=True)
        self._update_status("EXERCISE COMPLETE  ·  generate the GRC report or start another scenario")
        self._tick_timer()

    def _debrief_meter(self, parent, label: str, value: int):
        row = tk.Frame(parent, bg=parent["bg"])
        row.pack(fill="x", pady=1)
        tk.Label(row, text=label, font=FONTS["tag"], fg=COLORS["text_secondary"], bg=parent["bg"], width=11, anchor="w").pack(side="left")
        bar_bg = tk.Frame(row, bg=COLORS["bg_input"], height=8)
        bar_bg.pack(side="left", fill="x", expand=True, padx=8)
        bar_bg.pack_propagate(False)
        tk.Frame(bar_bg, bg=score_color(value), height=8).place(x=0, y=0, relheight=1.0, relwidth=value / 100)
        tk.Label(row, text=f"{value:3d}", font=FONTS["mono_sm"], fg=score_color(value), bg=parent["bg"], width=4, anchor="e").pack(side="left")

    # ----------------------------------------------------------------- sidebar

    def _build_sidebar(self, parent):
        # Fixed width so the layout does not shift as sidebar content changes.
        sidebar = tk.Frame(parent, bg=COLORS["bg_primary"], width=self.SIDEBAR_WIDTH)
        sidebar.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=8)
        sidebar.pack_propagate(False)
        sidebar.bind("<Configure>", self._on_sidebar_resize)
        self._sidebar = sidebar
        self._sidebar_width = self.SIDEBAR_WIDTH

        # Scenario meta
        meta_card = self._make_card(sidebar)
        meta_card.pack(fill="x", pady=(0, 6))
        tk.Label(meta_card, text="SCENARIO", font=FONTS["tag"], fg=COLORS["accent_cyan"],
                 bg=COLORS["bg_card"]).pack(anchor="w", padx=12, pady=(10, 4))
        self._meta_rows: list[tk.Label] = []
        self._meta_values: dict[str, tk.Label] = {}
        for key in ("Title", "Actor", "Industry", "Severity", "Impact"):
            row = tk.Frame(meta_card, bg=COLORS["bg_card"])
            row.pack(fill="x", padx=12, pady=1)
            tk.Label(row, text=f"{key}:", font=FONTS["mono_sm"], fg=COLORS["text_dim"], bg=COLORS["bg_card"],
                     width=9, anchor="nw").pack(side="left")
            val = tk.Label(row, text="", font=FONTS["body_sm"], fg=COLORS["text_secondary"], bg=COLORS["bg_card"],
                           anchor="w", justify="left", wraplength=160)
            val.pack(side="left", fill="x", expand=True)
            self._meta_values[key] = val
        tk.Frame(meta_card, bg=COLORS["bg_card"], height=8).pack()

        # Live metrics
        scores_card = self._make_card(sidebar)
        scores_card.pack(fill="x", pady=(0, 6))
        self._metrics_title = tk.Label(scores_card, text="LIVE GRC METRICS", font=FONTS["tag"],
                                       fg=COLORS["accent_cyan"], bg=COLORS["bg_card"])
        self._metrics_title.pack(anchor="w", padx=12, pady=(10, 6))
        self._score_meters: dict[str, tuple] = {}
        for label, key in (("NIST IR Score", "nist"), ("Compliance", "compliance"), ("Legal Standing", "legal")):
            self._build_score_meter(scores_card, label, key)
        tk.Frame(scores_card, bg=COLORS["border"], height=1).pack(fill="x", padx=12, pady=6)
        self._overall_label = tk.Label(scores_card, text="OVERALL: —", font=FONTS["subheader"],
                                       fg=COLORS["accent_cyan"], bg=COLORS["bg_card"])
        self._overall_label.pack(anchor="w", padx=12, pady=(0, 2))
        self._grade_label = tk.Label(scores_card, text="GRADE: —", font=(FONTS["mono"][0], 16, "bold"),
                                     fg=COLORS["text_secondary"], bg=COLORS["bg_card"])
        self._grade_label.pack(anchor="w", padx=12, pady=(0, 6))
        self._metrics_note = tk.Label(scores_card, text="", font=FONTS["mono_sm"], fg=COLORS["text_dim"],
                                      bg=COLORS["bg_card"], anchor="w", justify="left", wraplength=240)
        self._metrics_note.pack(anchor="w", padx=12, pady=(0, 8))

        # Tabbed tracker: ATT&CK | DECISION LOG
        tab_card = self._make_card(sidebar)
        tab_card.pack(fill="both", expand=True, pady=(0, 6))
        tabs = tk.Frame(tab_card, bg=COLORS["bg_card"])
        tabs.pack(fill="x", padx=8, pady=(8, 4))
        self._tab_buttons: dict[str, tk.Label] = {}
        for key, label in (("attack", "ATT&CK TRACKER"), ("log", "DECISION LOG")):
            b = tk.Label(tabs, text=label, font=FONTS["tag"], fg=COLORS["text_dim"], bg=COLORS["bg_card"],
                         cursor="hand2", padx=6, pady=3)
            b.pack(side="left", padx=(4, 0))
            b.bind("<Button-1>", lambda e, k=key: self._show_tab(k))
            self._tab_buttons[key] = b
        self._tab_scroll = ScrollableFrame(tab_card, bg=COLORS["bg_card"])
        self._tab_scroll.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        self._tab_frames = {
            "attack": tk.Frame(self._tab_scroll.inner, bg=COLORS["bg_card"]),
            "log":    tk.Frame(self._tab_scroll.inner, bg=COLORS["bg_card"]),
        }
        self._tab_footer = tk.Label(tab_card, text="", font=FONTS["mono_sm"], fg=COLORS["text_secondary"],
                                    bg=COLORS["bg_card"], anchor="w", justify="left", wraplength=240)
        self._tab_footer.pack(anchor="w", padx=12, pady=(0, 8), fill="x")
        self._active_tab = "attack"
        self._show_tab("attack")

        # Buttons
        self._report_btn = self._make_button(sidebar, text="▤  GENERATE GRC REPORT", command=self._on_generate_report,
                                             fg=COLORS["bg_primary"], bg=COLORS["accent_purple"], active_bg="#7C3AED")
        self._report_btn.pack(fill="x", pady=(6, 0))
        self._report_btn.configure(state="disabled", disabledforeground=COLORS["text_dim"])
        replay_row = tk.Frame(sidebar, bg=COLORS["bg_primary"])
        replay_row.pack(fill="x", pady=(6, 0))
        replay_row.columnconfigure(0, weight=1)
        replay_row.columnconfigure(1, weight=1)
        self._make_button(replay_row, text="↻  RANDOM", command=self._on_new_scenario,
                          fg=COLORS["text_primary"], bg=COLORS["bg_elevated"], active_bg=COLORS["border"]).grid(
            row=0, column=0, sticky="ew", padx=(0, 3))
        self._make_button(replay_row, text="▤  CHOOSE…", command=self._on_choose_scenario,
                          fg=COLORS["text_primary"], bg=COLORS["bg_elevated"], active_bg=COLORS["border"]).grid(
            row=0, column=1, sticky="ew", padx=(3, 0))

    def _on_sidebar_resize(self, event):
        self._sidebar_width = event.width
        wrap = max(120, event.width - 110)
        for lbl in self._meta_values.values():
            lbl.configure(wraplength=wrap)
        self._metrics_note.configure(wraplength=max(120, event.width - 30))
        self._tab_footer.configure(wraplength=max(120, event.width - 30))
        for lbl in getattr(self, "_tracker_wrap_labels", []) + getattr(self, "_log_wrap_labels", []):
            if lbl.winfo_exists():
                lbl.configure(wraplength=max(100, event.width - 120))

    def _refresh_sidebar_meta(self):
        meta = self.scenario_mgr.meta
        self._meta_values["Title"].configure(text=meta["title"], fg=COLORS["text_primary"])
        self._meta_values["Actor"].configure(text=meta["threat_actor"])
        self._meta_values["Industry"].configure(text=meta["industry"])
        self._meta_values["Severity"].configure(text=meta["severity"],
                                                fg=SEVERITY_COLORS.get(meta["severity"].upper(), COLORS["text_secondary"]))
        self._meta_values["Impact"].configure(text=meta["estimated_impact"])

    def _build_score_meter(self, parent, label: str, key: str):
        frame = tk.Frame(parent, bg=COLORS["bg_card"])
        frame.pack(fill="x", padx=12, pady=3)
        top = tk.Frame(frame, bg=COLORS["bg_card"])
        top.pack(fill="x")
        tk.Label(top, text=label, font=FONTS["mono_sm"], fg=COLORS["text_secondary"], bg=COLORS["bg_card"]).pack(side="left")
        val_label = tk.Label(top, text="—", font=FONTS["mono_sm"], fg=COLORS["text_dim"], bg=COLORS["bg_card"])
        val_label.pack(side="right")
        bar_bg = tk.Frame(frame, bg=COLORS["bg_input"], height=6)
        bar_bg.pack(fill="x", pady=(2, 0))
        bar_bg.pack_propagate(False)
        bar_fill = tk.Frame(bar_bg, bg=COLORS["text_dim"], height=6)
        bar_fill.place(x=0, y=0, relheight=1.0, relwidth=0.0)
        self._score_meters[key] = (val_label, bar_fill)

    def _show_tab(self, key: str):
        self._active_tab = key
        for k, frame in self._tab_frames.items():
            frame.pack_forget()
        self._tab_frames[key].pack(fill="both", expand=True)
        for k, b in self._tab_buttons.items():
            active = k == key
            b.configure(fg=COLORS["accent_purple"] if active else COLORS["text_dim"],
                        bg=COLORS["bg_elevated"] if active else COLORS["bg_card"])
        self._update_tab_footer()

    def _update_tab_footer(self):
        s = self.session
        if self._active_tab == "attack":
            hidden = s.facilitated and self._view != "debrief"
            ident = "hidden" if hidden else str(s.techniques_identified)
            self._tab_footer.configure(text=f"Techniques: {len(s.mitre_techniques)} encountered  |  {ident} identified")
        else:
            self._tab_footer.configure(text=f"Decisions: {len(s.decision_log)}/{self.scenario_mgr.total_injects}")

    # --------------------------------------------------------- sidebar updates

    def _scores_hidden(self, force_visible=False) -> bool:
        return self.session.facilitated and self._view != "debrief" and not force_visible

    def _update_scores(self, force_visible: bool = False):
        s = self.session
        hidden = self._scores_hidden(force_visible)
        scores = None if hidden else s.scores()
        for key, (val_label, bar_fill) in self._score_meters.items():
            if scores is None:
                val_label.configure(text="—", fg=COLORS["text_dim"])
                bar_fill.place_configure(relwidth=0.0)
                bar_fill.configure(bg=COLORS["text_dim"])
            else:
                v = scores[key]
                val_label.configure(text=str(v), fg=score_color(v))
                bar_fill.place_configure(relwidth=v / 100)
                bar_fill.configure(bg=score_color(v))
        if scores is None:
            self._overall_label.configure(text="OVERALL: —", fg=COLORS["text_secondary"])
            self._grade_label.configure(text="GRADE: —", fg=COLORS["text_secondary"])
            note = ("Facilitator mode: scores are hidden until the debrief." if hidden
                    else "Scores appear after your first decision. 100 = best available path.")
        else:
            grade, color = s.grade()
            self._overall_label.configure(text=f"OVERALL: {s.overall_score:.1f}/100", fg=color)
            self._grade_label.configure(text=f"GRADE: {grade}", fg=color)
            note = f"Relative to best/worst path over {len(s.decision_log)} decision(s)."
        self._metrics_note.configure(text=note)
        self._metrics_title.configure(text="LIVE GRC METRICS" + ("  ·  HIDDEN" if hidden else ""))

    def _update_tracker(self, force_visible: bool = False):
        frame = self._tab_frames["attack"]
        for w in frame.winfo_children():
            w.destroy()
        self._tracker_wrap_labels: list[tk.Label] = []
        s = self.session
        hidden = self._scores_hidden(force_visible)
        wrap = max(100, self._sidebar_width - 120)
        if not s.mitre_techniques:
            tk.Label(frame, text="Techniques appear here as you encounter them.", font=FONTS["mono_sm"],
                     fg=COLORS["text_dim"], bg=COLORS["bg_card"], anchor="w", justify="left", wraplength=wrap + 40).pack(
                anchor="w", padx=8, pady=6)
        for t in s.mitre_techniques:
            row = tk.Frame(frame, bg=COLORS["bg_card"])
            row.pack(fill="x", pady=2, padx=4)
            if hidden or not t.get("quizzed"):
                icon, color = "○ Seen", COLORS["text_secondary"]
            elif t.get("identified"):
                icon, color = "◆ ID'd", COLORS["accent_green"]
            else:
                icon, color = "◇ Missed", COLORS["accent_red"]
            tk.Label(row, text=icon, font=FONTS["mono_sm"], fg=color, bg=COLORS["bg_card"], width=9, anchor="nw").pack(side="left")
            details = tk.Frame(row, bg=COLORS["bg_card"])
            details.pack(side="left", fill="x", expand=True)
            tk.Label(details, text=t["technique_id"], font=FONTS["mono_sm"], fg=COLORS["accent_purple"],
                     bg=COLORS["bg_card"], anchor="w").pack(anchor="w")
            lbl = tk.Label(details, text=t["technique"], font=(FONTS["body_sm"][0], 9), fg=COLORS["text_secondary"],
                           bg=COLORS["bg_card"], anchor="w", wraplength=wrap, justify="left")
            lbl.pack(anchor="w")
            self._tracker_wrap_labels.append(lbl)
        self._update_tab_footer()

    def _refresh_log(self, force_visible: bool = False):
        frame = self._tab_frames["log"]
        for w in frame.winfo_children():
            w.destroy()
        self._log_wrap_labels: list[tk.Label] = []
        s = self.session
        hidden = self._scores_hidden(force_visible)
        wrap = max(100, self._sidebar_width - 120)
        if not s.decision_log:
            tk.Label(frame, text="Committed decisions appear here.", font=FONTS["mono_sm"],
                     fg=COLORS["text_dim"], bg=COLORS["bg_card"], anchor="w").pack(anchor="w", padx=8, pady=6)
        for i, d in enumerate(s.decision_log, 1):
            row = tk.Frame(frame, bg=COLORS["bg_card"])
            row.pack(fill="x", pady=2, padx=4)
            if hidden:
                glyph, color = "•", COLORS["text_secondary"]
            else:
                st = QUALITY_STYLES[d["quality"]]
                glyph, color = st["glyph"], st["color"]
            tk.Label(row, text=f"{glyph} {i:02d}", font=FONTS["mono_sm"], fg=color, bg=COLORS["bg_card"],
                     width=5, anchor="nw").pack(side="left")
            details = tk.Frame(row, bg=COLORS["bg_card"])
            details.pack(side="left", fill="x", expand=True)
            lbl = tk.Label(details, text=d["inject_title"], font=(FONTS["body_sm"][0], 9), fg=COLORS["text_primary"],
                           bg=COLORS["bg_card"], anchor="w", wraplength=wrap + 30, justify="left")
            lbl.pack(anchor="w")
            self._log_wrap_labels.append(lbl)
            sub = PHASE_SHORT_LABELS[self.scenario_mgr.phases.index(d["phase"])] if d["phase"] in self.scenario_mgr.phases else d["phase"]
            if not hidden:
                sub += f"  ·  N{d['nist_delta']:+d} C{d['compliance_delta']:+d} L{d['legal_delta']:+d}"
            tk.Label(details, text=sub, font=FONTS["mono_sm"], fg=COLORS["text_dim"], bg=COLORS["bg_card"], anchor="w").pack(anchor="w")
        self._update_tab_footer()

    # -------------------------------------------------------------- status bar

    def _build_status_bar(self):
        bar = tk.Frame(self, bg=COLORS["bg_secondary"])
        bar.pack(fill="x", side="bottom")
        self._status_label = tk.Label(bar, text="", font=FONTS["mono_sm"], fg=COLORS["text_dim"],
                                      bg=COLORS["bg_secondary"], anchor="w")
        self._status_label.pack(side="left", padx=10, pady=3)
        tk.Label(bar, text=f"IR_Sim v{APP_VERSION}  //  {self.scenario_mgr.total_scenarios} scenarios",
                 font=FONTS["mono_sm"], fg=COLORS["text_dim"], bg=COLORS["bg_secondary"]).pack(side="right", padx=10)
        self._timer_label = tk.Label(bar, text="", font=FONTS["mono_sm"], fg=COLORS["text_secondary"], bg=COLORS["bg_secondary"])
        self._timer_label.pack(side="right", padx=10)
        self._inject_timer_label = tk.Label(bar, text="", font=FONTS["mono_sm"], fg=COLORS["text_secondary"], bg=COLORS["bg_secondary"])
        self._inject_timer_label.pack(side="right", padx=10)
        self._tick_timer()

    def _update_status(self, text: str):
        self._status_label.configure(text=f"▶  {text}")

    def _tick_timer(self):
        if self._timer_job is not None:
            self.after_cancel(self._timer_job)
            self._timer_job = None
        if not self._timer_label.winfo_exists():
            return
        now = datetime.now()
        if self._view == "briefing":
            self._timer_label.configure(text="EXERCISE 00:00")
            self._inject_timer_label.configure(text="")
        else:
            self._timer_label.configure(text=f"EXERCISE {format_duration(now - self.session.start_time)}")
            if self._view == "inject" and self._inject_started_at is not None:
                elapsed = self._inject_frozen if self._inject_frozen is not None else now - self._inject_started_at
                limit = self._discussion_limit.get()
                if limit:
                    remaining = timedelta(minutes=limit) - elapsed
                    if remaining.total_seconds() >= 0:
                        self._inject_timer_label.configure(text=f"DISCUSSION {format_duration(remaining)} left",
                                                           fg=COLORS["text_secondary"])
                    else:
                        self._inject_timer_label.configure(text=f"DISCUSSION OVER +{format_duration(-remaining)}",
                                                           fg=COLORS["accent_red"])
                else:
                    self._inject_timer_label.configure(text=f"INJECT {format_duration(elapsed)}", fg=COLORS["text_secondary"])
            else:
                self._inject_timer_label.configure(text="")
        if self._view != "debrief":
            self._timer_job = self.after(1000, self._tick_timer)

    # ----------------------------------------------------------- widget helpers

    def _make_card(self, parent) -> tk.Frame:
        return tk.Frame(parent, bg=COLORS["bg_card"], highlightbackground=COLORS["border"], highlightthickness=1)

    def _make_button(self, parent, text, command, fg, bg, active_bg) -> tk.Button:
        return tk.Button(parent, text=text, command=command, font=FONTS["button"], fg=fg, bg=bg,
                         activeforeground=fg, activebackground=active_bg, relief="flat", bd=0,
                         padx=14, pady=7, cursor="hand2", highlightthickness=0)

    # ------------------------------------------------------- scenario control

    def _run_in_progress(self) -> bool:
        return self._view != "debrief" and bool(self.session.decision_log)

    def _confirm_abandon_run(self) -> bool:
        if not self._run_in_progress():
            return True
        return messagebox.askyesno("Start New Scenario?",
                                   "This will abandon your current run. Save progress first from the File menu "
                                   "if you want to resume later.\n\nContinue?", parent=self)

    def _restart_simulation(self, session: SimulationSession | None = None):
        """Reset session state and re-render for the currently mounted scenario, keeping window geometry."""
        self.session = session or SimulationSession(self.scenario_mgr.scenario)
        self.session.facilitated = self._facilitated.get() if session is None else self.session.facilitated
        self._facilitated.set(self.session.facilitated)
        self._configure_window()
        self._refresh_sidebar_meta()
        self._report_btn.configure(state="disabled")
        self._show_tab("attack")
        if session is not None and session.decision_log:
            self._update_scores()
            self._update_tracker()
            self._refresh_log()
            if session.complete:
                self._render_debrief()
            else:
                self._render_inject(session.current_inject_index)
        else:
            self._update_tracker()
            self._refresh_log()
            self._render_briefing()
        self._tick_timer()

    def _on_new_scenario(self):
        if not self._confirm_abandon_run():
            return
        self.scenario_mgr.reselect()
        self._restart_simulation()

    def _on_restart_same(self):
        if not self._confirm_abandon_run():
            return
        self._restart_simulation()

    def _on_toggle_facilitator(self):
        self.session.facilitated = self._facilitated.get()
        self._refresh_header_subtitle()
        self._update_scores()
        self._update_tracker()
        self._refresh_log()
        if self._view == "inject" and not self._committed:
            self._render_inject(self.session.current_inject_index)
        elif self._view == "briefing":
            self._render_briefing()

    def _show_briefing_dialog(self):
        meta = self.scenario_mgr.meta
        objectives = "\n".join(f"  • {o}" for o in meta.get("objectives", DEFAULT_OBJECTIVES))
        messagebox.showinfo(
            "Scenario Briefing",
            f"{meta['title']}\n{meta['subtitle']}\n\n"
            f"Threat actor: {meta['threat_actor']}\nIndustry: {meta['industry']}\n"
            f"Severity: {meta['severity']}    Est. impact: {meta['estimated_impact']}\n\n"
            f"Objectives:\n{objectives}", parent=self)

    def _show_shortcuts(self):
        messagebox.showinfo(
            "Keyboard Shortcuts",
            "1-3 / A-C     Select a response (or a technique in the identification step)\n"
            "Enter         Begin / commit / advance / open report\n"
            "Ctrl+S        Save progress\n"
            "Ctrl+O        Resume saved progress\n"
            "Ctrl+R        Generate GRC report (after the debrief)\n"
            "Ctrl+N        Random scenario\n"
            "Ctrl+L        Choose scenario\n"
            "Ctrl+Q        Quit", parent=self)

    def _show_about(self):
        messagebox.showinfo(
            "About IR_Sim",
            f"Incident Response Tabletop Simulator v{APP_VERSION}\n\n"
            f"{self.scenario_mgr.total_scenarios} scenarios · NIST SP 800-61 r2 · MITRE ATT&CK Enterprise v14\n"
            f"Scenario file: {self.scenario_mgr.path}\n\nMIT License", parent=self)

    # ------------------------------------------------------------- save / load

    def _save_progress(self):
        if self._view == "briefing" or not self.session.decision_log:
            messagebox.showinfo("Nothing to save", "Commit at least one decision before saving progress.", parent=self)
            return
        default = f"IR_Sim_progress_{self.session.meta['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.irsim.json"
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".json",
                                            filetypes=[("IR_Sim progress", "*.irsim.json"), ("JSON", "*.json"), ("All files", "*.*")],
                                            initialfile=default, title="Save Exercise Progress")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.session.to_dict(), f, indent=2)
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc), parent=self)
            return
        self._update_status(f"PROGRESS SAVED  ·  {Path(path).name}")

    def _resume_progress(self):
        path = filedialog.askopenfilename(parent=self, filetypes=[("IR_Sim progress", "*.irsim.json"),
                                                                  ("JSON", "*.json"), ("All files", "*.*")],
                                          title="Resume Exercise Progress")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            idx = self.scenario_mgr.index_of(data.get("scenario_id", ""))
            if idx is None:
                raise ValueError(f"Scenario '{data.get('scenario_id')}' is not in the loaded scenario file.")
            if not self._confirm_abandon_run():
                return
            self.scenario_mgr.select(idx)
            session = SimulationSession.from_dict(self.scenario_mgr.scenario, data)
        except (OSError, ValueError, KeyError, StopIteration, json.JSONDecodeError) as exc:
            messagebox.showerror("Resume failed", f"Could not load progress file:\n{exc}", parent=self)
            return
        self._restart_simulation(session)
        self._update_status(f"RESUMED  ·  {len(session.decision_log)} decision(s) restored")

    # ------------------------------------------------------------- chooser

    def _on_choose_scenario(self):
        dialog = tk.Toplevel(self)
        dialog.title("Choose Scenario")
        dialog.geometry("900x560")
        dialog.configure(bg=COLORS["bg_primary"])
        dialog.transient(self)
        dialog.grab_set()
        dialog.bind("<Escape>", lambda e: dialog.destroy())

        tk.Label(dialog, text="SELECT A TRAINING SCENARIO", font=FONTS["subheader"], fg=COLORS["accent_cyan"],
                 bg=COLORS["bg_primary"]).pack(anchor="w", padx=16, pady=(14, 6))

        # Filters
        metas = self.scenario_mgr.all_meta()
        industries = sorted({seg for m in metas for seg in industry_segments(m["industry"])})
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        filt = tk.Frame(dialog, bg=COLORS["bg_primary"])
        filt.pack(fill="x", padx=16, pady=(0, 6))
        ind_var = tk.StringVar(value="All industries")
        sev_var = tk.StringVar(value="All severities")
        style = ttk.Style(dialog)
        style.theme_use("clam")
        style.configure("Dark.TCombobox", fieldbackground=COLORS["bg_input"], background=COLORS["bg_elevated"],
                        foreground=COLORS["text_primary"], arrowcolor=COLORS["accent_cyan"], bordercolor=COLORS["border"],
                        lightcolor=COLORS["bg_input"], darkcolor=COLORS["bg_input"])
        style.map("Dark.TCombobox", fieldbackground=[("readonly", COLORS["bg_input"])],
                  foreground=[("readonly", COLORS["text_primary"])])
        dialog.option_add("*TCombobox*Listbox.background", COLORS["bg_input"])
        dialog.option_add("*TCombobox*Listbox.foreground", COLORS["text_primary"])
        dialog.option_add("*TCombobox*Listbox.selectBackground", COLORS["bg_elevated"])
        dialog.option_add("*TCombobox*Listbox.selectForeground", COLORS["accent_cyan"])
        tk.Label(filt, text="INDUSTRY", font=FONTS["tag"], fg=COLORS["text_dim"], bg=COLORS["bg_primary"]).pack(side="left")
        ind_box = ttk.Combobox(filt, textvariable=ind_var, values=["All industries"] + industries, state="readonly",
                               width=22, style="Dark.TCombobox", font=FONTS["body_sm"])
        ind_box.pack(side="left", padx=(6, 18))
        tk.Label(filt, text="SEVERITY", font=FONTS["tag"], fg=COLORS["text_dim"], bg=COLORS["bg_primary"]).pack(side="left")
        sev_box = ttk.Combobox(filt, textvariable=sev_var, values=["All severities"] + severities, state="readonly",
                               width=16, style="Dark.TCombobox", font=FONTS["body_sm"])
        sev_box.pack(side="left", padx=(6, 0))
        count_lbl = tk.Label(filt, text="", font=FONTS["mono_sm"], fg=COLORS["text_dim"], bg=COLORS["bg_primary"])
        count_lbl.pack(side="right")

        # Table
        style.configure("Dark.Treeview", background=COLORS["bg_input"], fieldbackground=COLORS["bg_input"],
                        foreground=COLORS["text_primary"], rowheight=26, borderwidth=0, font=FONTS["body_sm"])
        style.configure("Dark.Treeview.Heading", background=COLORS["bg_card"], foreground=COLORS["accent_cyan"],
                        font=FONTS["tag"], relief="flat")
        style.map("Dark.Treeview", background=[("selected", COLORS["bg_elevated"])],
                  foreground=[("selected", COLORS["accent_cyan"])])
        style.map("Dark.Treeview.Heading", background=[("active", COLORS["bg_elevated"])])
        body = tk.Frame(dialog, bg=COLORS["bg_primary"])
        body.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        cols = ("num", "severity", "title", "theme", "industry")
        tree = ttk.Treeview(body, columns=cols, show="headings", style="Dark.Treeview", selectmode="browse")
        for col, text, width, anchor in (("num", "#", 40, "center"), ("severity", "SEVERITY", 90, "center"),
                                         ("title", "TITLE", 210, "w"), ("theme", "THEME", 330, "w"),
                                         ("industry", "INDUSTRY", 170, "w")):
            tree.heading(col, text=text, anchor=anchor)
            tree.column(col, width=width, anchor=anchor, stretch=(col in ("theme", "title")))
        tree.tag_configure("CRITICAL", foreground=COLORS["accent_red"])
        vsb = ttk.Scrollbar(body, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)

        detail = tk.Label(dialog, text="", font=FONTS["body_sm"], fg=COLORS["text_secondary"], bg=COLORS["bg_primary"],
                          anchor="w", justify="left", wraplength=860)
        detail.pack(fill="x", padx=16, pady=(0, 8))

        def populate(*_):
            tree.delete(*tree.get_children())
            ind = ind_var.get()
            sev = sev_var.get()
            shown = 0
            for i, m in enumerate(metas):
                if ind != "All industries" and ind not in industry_segments(m["industry"]):
                    continue
                if sev != "All severities" and m["severity"].upper() != sev:
                    continue
                sev_glyph = {"CRITICAL": "▲", "HIGH": "●", "MEDIUM": "○", "LOW": "·"}.get(m["severity"].upper(), "")
                tree.insert("", "end", iid=str(i),
                            values=(f"{i + 1:02d}", f"{sev_glyph} {m['severity']}", m["title"], m["subtitle"], m["industry"]),
                            tags=(m["severity"].upper(),))
                shown += 1
            count_lbl.configure(text=f"{shown}/{len(metas)} scenarios")
            current = str(self.scenario_mgr.scenario_index)
            if tree.exists(current):
                tree.selection_set(current)
                tree.see(current)
            elif tree.get_children():
                tree.selection_set(tree.get_children()[0])
            on_select()

        def on_select(*_):
            sel = tree.selection()
            if not sel:
                detail.configure(text="")
                return
            m = metas[int(sel[0])]
            detail.configure(text=f"{m['title']} — {m['subtitle']}\nThreat actor: {m['threat_actor']}   ·   "
                                  f"Estimated impact: {m['estimated_impact']}   ·   {len(self.scenario_mgr._all_scenarios[int(sel[0])]['injects'])} injects")

        def load_selected(_event=None):
            sel = tree.selection()
            if not sel:
                return
            idx = int(sel[0])
            dialog.destroy()
            if not self._confirm_abandon_run():
                return
            self.scenario_mgr.select(idx)
            self._restart_simulation()

        tree.bind("<<TreeviewSelect>>", on_select)
        tree.bind("<Double-Button-1>", load_selected)
        tree.bind("<Return>", load_selected)
        ind_box.bind("<<ComboboxSelected>>", populate)
        sev_box.bind("<<ComboboxSelected>>", populate)
        populate()

        btn_row = tk.Frame(dialog, bg=COLORS["bg_primary"])
        btn_row.pack(fill="x", padx=16, pady=(0, 14))
        self._make_button(btn_row, text="CANCEL", command=dialog.destroy, fg=COLORS["text_primary"],
                          bg=COLORS["bg_elevated"], active_bg=COLORS["border"]).pack(side="right", padx=(6, 0))
        self._make_button(btn_row, text="▶  LOAD SCENARIO", command=load_selected, fg=COLORS["bg_primary"],
                          bg=COLORS["accent_cyan"], active_bg=COLORS["accent_blue"]).pack(side="right")
        tree.focus_set()

    # ------------------------------------------------------------- report

    def _on_generate_report(self):
        if self._view != "debrief":
            messagebox.showinfo("Report not ready", "Finish the exercise to generate the GRC report.", parent=self)
            return
        report_md = ReportGenerator(self.session).generate()

        preview = tk.Toplevel(self)
        preview.title(f"GRC Report — {self.session.meta['title']}")
        preview.geometry("960x720")
        preview.configure(bg=COLORS["bg_primary"])
        preview.transient(self)
        preview.bind("<Escape>", lambda e: preview.destroy())

        toolbar = tk.Frame(preview, bg=COLORS["bg_card"])
        toolbar.pack(fill="x")
        tk.Label(toolbar, text="▤  POST-INCIDENT GRC COMPLIANCE REPORT", font=FONTS["subheader"],
                 fg=COLORS["accent_purple"], bg=COLORS["bg_card"]).pack(side="left", padx=14, pady=8)
        status = tk.Label(toolbar, text="", font=FONTS["mono_sm"], fg=COLORS["text_secondary"], bg=COLORS["bg_card"])
        status.pack(side="left", padx=6)
        self._make_button(toolbar, text="CLOSE", command=preview.destroy, fg=COLORS["text_primary"],
                          bg=COLORS["bg_elevated"], active_bg=COLORS["border"]).pack(side="right", padx=(4, 14), pady=6)
        self._make_button(toolbar, text="SAVE AS…", command=lambda: self._save_report(report_md, preview),
                          fg=COLORS["bg_primary"], bg=COLORS["accent_cyan"], active_bg=COLORS["accent_blue"]).pack(side="right", padx=4, pady=6)

        def copy_md():
            preview.clipboard_clear()
            preview.clipboard_append(report_md)
            status.configure(text="Markdown copied to clipboard")
            preview.after(2500, lambda: status.configure(text="") if status.winfo_exists() else None)

        self._make_button(toolbar, text="COPY MARKDOWN", command=copy_md, fg=COLORS["text_primary"],
                          bg=COLORS["bg_elevated"], active_bg=COLORS["border"]).pack(side="right", padx=4, pady=6)

        view_var = tk.StringVar(value="rendered")
        toggle = tk.Frame(toolbar, bg=COLORS["bg_card"])
        toggle.pack(side="right", padx=8)

        body = tk.Frame(preview, bg=COLORS["bg_primary"])
        body.pack(fill="both", expand=True, padx=10, pady=10)
        text = tk.Text(body, wrap="word", font=FONTS["body_sm"], fg=COLORS["text_primary"], bg=COLORS["bg_input"],
                       insertbackground=COLORS["accent_cyan"], selectbackground=COLORS["bg_elevated"],
                       relief="flat", bd=0, padx=18, pady=14)
        scroll = tk.Scrollbar(body, command=text.yview, bg=COLORS["bg_card"], troughcolor=COLORS["bg_input"], width=10)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(fill="both", expand=True)

        def show():
            if view_var.get() == "rendered":
                render_markdown(text, report_md)
            else:
                text.configure(state="normal")
                text.delete("1.0", "end")
                text.insert("1.0", report_md, ("raw",))
                text.tag_configure("raw", font=FONTS["mono_sm"])
                text.configure(state="disabled")
            for k, b in toggle_btns.items():
                b.configure(fg=COLORS["accent_cyan"] if k == view_var.get() else COLORS["text_dim"])

        toggle_btns = {}
        for key, label in (("rendered", "RENDERED"), ("raw", "MARKDOWN")):
            b = tk.Label(toggle, text=label, font=FONTS["tag"], fg=COLORS["text_dim"], bg=COLORS["bg_card"], cursor="hand2", padx=6)
            b.pack(side="left")
            b.bind("<Button-1>", lambda e, k=key: (view_var.set(k), show()))
            toggle_btns[key] = b
        show()

    def _save_report(self, report_md: str, parent=None):
        default_name = f"IR_GRC_Report_{self.session.meta['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        save_path = filedialog.asksaveasfilename(parent=parent or self, defaultextension=".md",
                                                 filetypes=[("Markdown files", "*.md"), ("All files", "*.*")],
                                                 initialfile=default_name, title="Save GRC Compliance Report")
        if not save_path:
            return
        try:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(report_md)
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc), parent=parent or self)
            return
        messagebox.showinfo("Report Saved", f"GRC Compliance Report saved to:\n{save_path}\n\n"
                            "Open the .md file in any Markdown viewer for the formatted report.", parent=parent or self)

    # ------------------------------------------------------------------ close

    def _on_close(self):
        if self._run_in_progress():
            if not messagebox.askyesno("Exit IR_Sim?",
                                       "An exercise is in progress. Quit and lose this run's progress?\n"
                                       "(Use File > Save Progress to resume later.)", parent=self):
                return
        if self._timer_job is not None:
            self.after_cancel(self._timer_job)
        self.destroy()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    parser = argparse.ArgumentParser(prog="ir_sim", description="Incident Response Tabletop Simulator")
    parser.add_argument("--scenarios", metavar="PATH", default=None,
                        help="path to scenarios.json (default: next to app.py, or $IR_SIM_SCENARIOS)")
    parser.add_argument("--version", action="version", version=f"IR_Sim {APP_VERSION}")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    app = IncidentSimulatorApp(scenarios_path=args.scenarios)
    app.mainloop()


if __name__ == "__main__":
    main()
