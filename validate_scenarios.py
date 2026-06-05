#!/usr/bin/env python3
"""
validate_scenarios.py
=====================
Standalone headless validator for scenarios.json.
Run before submitting a PR to confirm your scenario meets the required schema.

Usage:
    python validate_scenarios.py
    python validate_scenarios.py --file path/to/scenarios.json
"""

import json
import sys
import argparse
import random
from pathlib import Path


REQUIRED_META_KEYS = {"id", "title", "subtitle", "threat_actor", "industry", "severity", "estimated_impact"}
REQUIRED_INJECT_KEYS = {"id", "phase", "phase_index", "title", "story", "mitre", "choices"}
REQUIRED_MITRE_KEYS = {"tactic", "tactic_id", "technique", "technique_id", "description"}
REQUIRED_CHOICE_KEYS = {"id", "text", "quality", "nist_score_delta", "compliance_score_delta",
                         "legal_score_delta", "feedback", "technique_identified"}
VALID_QUALITIES = {"optimal", "neutral", "detrimental"}
STANDARD_PHASES = [
    "Preparation",
    "Detection & Analysis",
    "Containment",
    "Eradication & Recovery",
    "Post-Incident Activity",
]


def load_scenarios(path: str) -> list:
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    if "scenarios" in raw:
        return raw["scenarios"]
    return [raw]   # legacy single-scenario format


def validate_scenario(s: dict, idx: int) -> list[str]:
    errors = []
    sid = s.get("scenario_meta", {}).get("id", f"scenario[{idx}]")

    # Meta
    meta = s.get("scenario_meta", {})
    for k in REQUIRED_META_KEYS:
        if k not in meta:
            errors.append(f"{sid}: scenario_meta missing key '{k}'")

    # Phases
    phases = s.get("nist_phases", [])
    if phases != STANDARD_PHASES:
        errors.append(f"{sid}: nist_phases must match the standard 5-phase array exactly")

    # Injects
    injects = s.get("injects", [])
    if not injects:
        errors.append(f"{sid}: no injects found")

    for j, inj in enumerate(injects):
        iid = inj.get("id", f"inject[{j}]")
        loc = f"{sid} / {iid}"

        for k in REQUIRED_INJECT_KEYS:
            if k not in inj:
                errors.append(f"{loc}: missing key '{k}'")

        # MITRE block
        mitre = inj.get("mitre", {})
        for k in REQUIRED_MITRE_KEYS:
            if k not in mitre:
                errors.append(f"{loc}: mitre missing key '{k}'")

        # phase_index in range
        pi = inj.get("phase_index", -1)
        if not (0 <= pi < len(STANDARD_PHASES)):
            errors.append(f"{loc}: phase_index {pi} out of range [0, {len(STANDARD_PHASES)-1}]")
        elif STANDARD_PHASES[pi] != inj.get("phase", ""):
            errors.append(f"{loc}: phase_index {pi} → '{STANDARD_PHASES[pi]}' "
                          f"but phase is '{inj.get('phase')}'")

        # Choices
        choices = inj.get("choices", [])
        if len(choices) != 3:
            errors.append(f"{loc}: must have exactly 3 choices, got {len(choices)}")

        qualities = []
        for c in choices:
            for k in REQUIRED_CHOICE_KEYS:
                if k not in c:
                    errors.append(f"{loc} / choice[{c.get('id','?')}]: missing key '{k}'")
            q = c.get("quality", "")
            if q not in VALID_QUALITIES:
                errors.append(f"{loc} / choice[{c.get('id','?')}]: invalid quality '{q}'")
            qualities.append(q)

        if sorted(qualities) != sorted(VALID_QUALITIES):
            errors.append(f"{loc}: choices must include one each of optimal/neutral/detrimental, "
                          f"got {qualities}")

    return errors


def simulate_path(s: dict, quality: str) -> dict:
    """Run a full scenario with all choices of a given quality. Returns final scores."""
    nist, comp, legal = 50, 50, 50
    for inj in s["injects"]:
        choice = next(c for c in inj["choices"] if c["quality"] == quality)
        nist  = max(0, min(100, nist  + choice["nist_score_delta"]))
        comp  = max(0, min(100, comp  + choice["compliance_score_delta"]))
        legal = max(0, min(100, legal + choice["legal_score_delta"]))
    overall = round((nist + comp + legal) / 3, 1)
    grade = "A" if overall>=85 else "B" if overall>=70 else "C" if overall>=55 else "D" if overall>=40 else "F"
    return {"nist": nist, "comp": comp, "legal": legal, "overall": overall, "grade": grade}


def simulate_shuffle_stability(s: dict) -> bool:
    """Confirm shuffled choice order produces identical scores to non-shuffled."""
    # non-shuffled optimal
    r1 = simulate_path(s, "optimal")
    # shuffled optimal
    nist, comp, legal = 50, 50, 50
    for inj in s["injects"]:
        shuffled = list(inj["choices"])
        random.shuffle(shuffled)
        choice = next(c for c in shuffled if c["quality"] == "optimal")
        nist  = max(0, min(100, nist  + choice["nist_score_delta"]))
        comp  = max(0, min(100, comp  + choice["compliance_score_delta"]))
        legal = max(0, min(100, legal + choice["legal_score_delta"]))
    return (nist, comp, legal) == (r1["nist"], r1["comp"], r1["legal"])


def main():
    parser = argparse.ArgumentParser(description="Validate scenarios.json for IR_Sim")
    parser.add_argument("--file", default="scenarios.json",
                        help="Path to scenarios.json (default: ./scenarios.json)")
    parser.add_argument("--quiet", action="store_true", help="Only print failures and summary")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"ERROR: File not found: {path}")
        sys.exit(1)

    try:
        scenarios = load_scenarios(str(path))
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {path}: {e}")
        sys.exit(1)

    print(f"\n{'='*62}")
    print(f"  IR_Sim — Scenario Validator")
    print(f"  File : {path}  ({path.stat().st_size // 1024} KB)")
    print(f"  Count: {len(scenarios)} scenario(s)")
    print(f"{'='*62}\n")

    all_errors = []
    results = []

    for i, s in enumerate(scenarios):
        sid = s.get("scenario_meta", {}).get("id", f"scenario[{i}]")
        title = s.get("scenario_meta", {}).get("title", "Unknown")

        # Schema validation
        errors = validate_scenario(s, i)
        all_errors.extend(errors)

        if errors:
            status = "❌ SCHEMA FAIL"
            opt_result = det_result = shuffle_ok = None
        else:
            # Scoring simulations
            opt_result = simulate_path(s, "optimal")
            det_result = simulate_path(s, "detrimental")
            shuffle_ok = simulate_shuffle_stability(s)

            score_ok   = opt_result["grade"] in ("A", "B") and det_result["grade"] in ("D", "F")
            if not score_ok:
                all_errors.append(f"{sid}: unexpected grade — optimal={opt_result['grade']}, "
                                  f"detrimental={det_result['grade']}")
            if not shuffle_ok:
                all_errors.append(f"{sid}: shuffle instability detected")

            status = "✅ PASS" if (score_ok and shuffle_ok and not errors) else "❌ LOGIC FAIL"

        if not args.quiet or "FAIL" in status:
            injects = len(s.get("injects", []))
            mitre_ids = {inj["mitre"]["technique_id"] for inj in s.get("injects", []) if "mitre" in inj}
            print(f"  {status}  [{i+1:02d}] {sid}")
            print(f"           {title}")
            if opt_result:
                print(f"           Optimal  → {opt_result['grade']}  ({opt_result['overall']}/100)")
                print(f"           Detriment→ {det_result['grade']}  ({det_result['overall']}/100)")
                print(f"           Shuffle  → {'stable' if shuffle_ok else 'UNSTABLE'}")
                print(f"           Injects  → {injects}  |  MITRE IDs: {', '.join(sorted(mitre_ids))}")
            if errors:
                for e in errors:
                    print(f"           ⚠  {e}")
            print()

        results.append({"id": sid, "passed": "FAIL" not in status})

    # Summary
    passed = sum(1 for r in results if r["passed"])
    failed = len(results) - passed
    total_injects = sum(len(s.get("injects",[])) for s in scenarios)
    mitre_all = set()
    for s in scenarios:
        for inj in s.get("injects", []):
            if "mitre" in inj:
                mitre_all.add(inj["mitre"]["technique_id"])

    print(f"{'='*62}")
    print(f"  Results   : {passed}/{len(results)} passed")
    print(f"  Injects   : {total_injects}")
    print(f"  Choices   : {total_injects * 3}")
    print(f"  MITRE IDs : {len(mitre_all)} unique technique IDs")

    if all_errors:
        print(f"\n  ERRORS ({len(all_errors)}):")
        for e in all_errors:
            print(f"    • {e}")
        print(f"{'='*62}\n")
        sys.exit(1)
    else:
        print(f"\n  ✅ All scenarios valid and ready for use.")
        print(f"{'='*62}\n")


if __name__ == "__main__":
    main()
