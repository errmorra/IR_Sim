#!/usr/bin/env python3
"""
validate_scenarios.py
=====================
Standalone headless validator for scenarios.json.
Run before submitting a PR to confirm your scenario meets the required schema.

Usage:
    python validate_scenarios.py
    python validate_scenarios.py --file path/to/scenarios.json
    python validate_scenarios.py --quiet          # failures + summary only
    python validate_scenarios.py --strict         # treat warnings as errors
"""

import argparse
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scoring  # noqa: E402  (shared with app.py)


REQUIRED_META_KEYS = {"id", "title", "subtitle", "threat_actor", "industry", "severity", "estimated_impact"}
OPTIONAL_META_KEYS = {"objectives", "role"}
REQUIRED_INJECT_KEYS = {"id", "phase", "phase_index", "title", "story", "mitre", "choices"}
OPTIONAL_INJECT_KEYS = {"story_variants", "role_prompts"}
REQUIRED_MITRE_KEYS = {"tactic", "tactic_id", "technique", "technique_id", "description"}
REQUIRED_CHOICE_KEYS = {"id", "text", "quality", "nist_score_delta", "compliance_score_delta",
                        "legal_score_delta", "feedback", "technique_identified"}
VALID_QUALITIES = set(scoring.QUALITIES)
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
STANDARD_PHASES = [
    "Preparation",
    "Detection & Analysis",
    "Containment",
    "Eradication & Recovery",
    "Post-Incident Activity",
]
ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
TACTIC_ID_RE = re.compile(r"^TA\d{4}$")


def load_scenarios(path: str) -> list:
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    if "scenarios" in raw:
        return raw["scenarios"]
    return [raw]   # legacy single-scenario format


def validate_scenario(s: dict, idx: int) -> tuple[list[str], list[str]]:
    """Return (errors, warnings) for one scenario."""
    errors: list[str] = []
    warnings: list[str] = []
    meta = s.get("scenario_meta", {})
    sid = meta.get("id", f"scenario[{idx}]")

    # Meta
    for k in REQUIRED_META_KEYS:
        if k not in meta:
            errors.append(f"{sid}: scenario_meta missing key '{k}'")
    if "severity" in meta and str(meta["severity"]).upper() not in VALID_SEVERITIES:
        errors.append(f"{sid}: severity '{meta['severity']}' must be one of {sorted(VALID_SEVERITIES)}")
    if "objectives" in meta and not (isinstance(meta["objectives"], list)
                                     and all(isinstance(o, str) and o.strip() for o in meta["objectives"])):
        errors.append(f"{sid}: scenario_meta.objectives must be a list of non-empty strings")
    if "role" in meta and not isinstance(meta["role"], str):
        errors.append(f"{sid}: scenario_meta.role must be a string")
    for k in meta:
        if k not in REQUIRED_META_KEYS | OPTIONAL_META_KEYS:
            warnings.append(f"{sid}: unknown scenario_meta key '{k}'")

    # Phases
    phases = s.get("nist_phases", [])
    if phases != STANDARD_PHASES:
        errors.append(f"{sid}: nist_phases must match the standard 5-phase array exactly")

    # Injects
    injects = s.get("injects", [])
    if not injects:
        errors.append(f"{sid}: no injects found")
    seen_inject_ids = set()

    for j, inj in enumerate(injects):
        iid = inj.get("id", f"inject[{j}]")
        loc = f"{sid} / {iid}"
        if iid in seen_inject_ids:
            errors.append(f"{loc}: duplicate inject id")
        seen_inject_ids.add(iid)

        for k in REQUIRED_INJECT_KEYS:
            if k not in inj:
                errors.append(f"{loc}: missing key '{k}'")
        for k in inj:
            if k not in REQUIRED_INJECT_KEYS | OPTIONAL_INJECT_KEYS:
                warnings.append(f"{loc}: unknown inject key '{k}'")

        # Branching narrative variants
        variants = inj.get("story_variants")
        if variants is not None:
            if not isinstance(variants, dict):
                errors.append(f"{loc}: story_variants must be an object keyed by prior decision quality")
            else:
                for k, v in variants.items():
                    if k not in VALID_QUALITIES:
                        errors.append(f"{loc}: story_variants key '{k}' is not a quality "
                                      f"({', '.join(sorted(VALID_QUALITIES))})")
                    if not isinstance(v, str) or not v.strip():
                        errors.append(f"{loc}: story_variants['{k}'] must be a non-empty string")
                if j == 0:
                    warnings.append(f"{loc}: story_variants on the first inject can never be shown")

        prompts = inj.get("role_prompts")
        if prompts is not None and not (isinstance(prompts, dict)
                                        and all(isinstance(k, str) and isinstance(v, str) for k, v in prompts.items())):
            errors.append(f"{loc}: role_prompts must be an object of role -> prompt strings")

        # MITRE block
        mitre = inj.get("mitre", {})
        for k in REQUIRED_MITRE_KEYS:
            if k not in mitre:
                errors.append(f"{loc}: mitre missing key '{k}'")
        tid = mitre.get("technique_id", "")
        if tid and not ATTACK_ID_RE.match(tid):
            warnings.append(f"{loc}: technique_id '{tid}' is not an ATT&CK ID — treated as a framework "
                            f"reference (no identification challenge)")
        if tid and ATTACK_ID_RE.match(tid) and not TACTIC_ID_RE.match(mitre.get("tactic_id", "")):
            warnings.append(f"{loc}: tactic_id '{mitre.get('tactic_id')}' does not look like TAxxxx")

        # phase_index in range
        pi = inj.get("phase_index", -1)
        if not (isinstance(pi, int) and 0 <= pi < len(STANDARD_PHASES)):
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
            cid = c.get("id", "?")
            for k in REQUIRED_CHOICE_KEYS:
                if k not in c:
                    errors.append(f"{loc} / choice[{cid}]: missing key '{k}'")
            q = c.get("quality", "")
            if q not in VALID_QUALITIES:
                errors.append(f"{loc} / choice[{cid}]: invalid quality '{q}'")
            qualities.append(q)
            for k in scoring.DELTA_KEYS.values():
                if k in c and not isinstance(c[k], int):
                    errors.append(f"{loc} / choice[{cid}]: {k} must be an integer")

        if sorted(qualities) != sorted(VALID_QUALITIES):
            errors.append(f"{loc}: choices must include one each of optimal/neutral/detrimental, "
                          f"got {qualities}")
        elif all(isinstance(c.get(k), int) for c in choices for k in scoring.DELTA_KEYS.values()):
            # The optimal choice should be the best on every axis, detrimental the worst.
            by_q = {c["quality"]: c for c in choices}
            for k in scoring.DELTA_KEYS.values():
                if by_q["optimal"][k] < max(c[k] for c in choices):
                    warnings.append(f"{loc}: optimal choice does not have the highest {k}")
                if by_q["detrimental"][k] > min(c[k] for c in choices):
                    warnings.append(f"{loc}: detrimental choice does not have the lowest {k}")

    return errors, warnings


def simulate_shuffle_stability(s: dict) -> bool:
    """Confirm shuffled choice order produces identical scores to non-shuffled."""
    baseline = scoring.score_path(s, "optimal")
    picked = []
    for inj in s["injects"]:
        shuffled = list(inj["choices"])
        random.shuffle(shuffled)
        picked.append(next(c for c in shuffled if c["quality"] == "optimal"))
    shuffled_result = scoring.score_choices(s, picked)
    return all(shuffled_result[a] == baseline[a] for a in scoring.AXES)


def main():
    parser = argparse.ArgumentParser(description="Validate scenarios.json for IR_Sim")
    parser.add_argument("--file", default=str(Path(__file__).resolve().parent / "scenarios.json"),
                        help="Path to scenarios.json (default: ./scenarios.json)")
    parser.add_argument("--quiet", action="store_true", help="Only print failures and summary")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as errors")
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
    print("  IR_Sim — Scenario Validator")
    print(f"  File : {path}  ({path.stat().st_size // 1024} KB)")
    print(f"  Count: {len(scenarios)} scenario(s)")
    print(f"{'='*62}\n")

    all_errors: list[str] = []
    all_warnings: list[str] = []
    results = []
    seen_ids = set()

    for i, s in enumerate(scenarios):
        sid = s.get("scenario_meta", {}).get("id", f"scenario[{i}]")
        title = s.get("scenario_meta", {}).get("title", "Unknown")
        if sid in seen_ids:
            all_errors.append(f"{sid}: duplicate scenario id")
        seen_ids.add(sid)

        errors, warnings = validate_scenario(s, i)
        all_errors.extend(errors)
        all_warnings.extend(warnings)

        if errors:
            status = "FAIL  schema"
            opt_result = det_result = neu_result = shuffle_ok = None
        else:
            opt_result = scoring.score_path(s, "optimal")
            neu_result = scoring.score_path(s, "neutral")
            det_result = scoring.score_path(s, "detrimental")
            shuffle_ok = simulate_shuffle_stability(s)

            score_ok = opt_result["grade"] == "A" and det_result["grade"] == "F" and neu_result["grade"] in ("C", "D")
            if not score_ok:
                all_errors.append(f"{sid}: unexpected grades — optimal={opt_result['grade']}, "
                                  f"neutral={neu_result['grade']}, detrimental={det_result['grade']} "
                                  f"(expected A / C-D / F)")
            if not shuffle_ok:
                all_errors.append(f"{sid}: shuffle instability detected")
            status = "PASS" if (score_ok and shuffle_ok) else "FAIL  logic"

        if not args.quiet or "FAIL" in status:
            injects = len(s.get("injects", []))
            mitre_ids = {inj["mitre"]["technique_id"] for inj in s.get("injects", []) if "mitre" in inj}
            branching = sum(1 for inj in s.get("injects", []) if inj.get("story_variants"))
            print(f"  {status:<12} [{i+1:02d}] {sid}")
            print(f"               {title}")
            if opt_result:
                print(f"               Optimal     → {opt_result['grade']}  ({opt_result['overall']}/100)")
                print(f"               Neutral     → {neu_result['grade']}  ({neu_result['overall']}/100)")
                print(f"               Detrimental → {det_result['grade']}  ({det_result['overall']}/100)")
                print(f"               Shuffle     → {'stable' if shuffle_ok else 'UNSTABLE'}")
                print(f"               Injects     → {injects}  |  branching: {branching}  |  "
                      f"MITRE IDs: {', '.join(sorted(mitre_ids))}")
            for e in errors:
                print(f"               ERROR  {e}")
            for w in warnings:
                print(f"               warn   {w}")
            print()

        results.append({"id": sid, "passed": "FAIL" not in status})

    passed = sum(1 for r in results if r["passed"])
    total_injects = sum(len(s.get("injects", [])) for s in scenarios)
    mitre_all = {inj["mitre"]["technique_id"] for s in scenarios for inj in s.get("injects", [])
                 if "mitre" in inj and ATTACK_ID_RE.match(inj["mitre"].get("technique_id", ""))}
    branching_total = sum(1 for s in scenarios for inj in s.get("injects", []) if inj.get("story_variants"))

    print(f"{'='*62}")
    print(f"  Results   : {passed}/{len(results)} passed")
    print(f"  Injects   : {total_injects}  ({branching_total} with branching narrative)")
    print(f"  Choices   : {total_injects * 3}")
    print(f"  MITRE IDs : {len(mitre_all)} unique ATT&CK technique IDs")
    print(f"  Warnings  : {len(all_warnings)}")

    failed = bool(all_errors) or (args.strict and all_warnings)
    if all_errors:
        print(f"\n  ERRORS ({len(all_errors)}):")
        for e in all_errors:
            print(f"    • {e}")
    if args.strict and all_warnings:
        print(f"\n  WARNINGS treated as errors ({len(all_warnings)}):")
        for w in all_warnings:
            print(f"    • {w}")
    if failed:
        print(f"{'='*62}\n")
        sys.exit(1)
    print("\n  All scenarios valid and ready for use.")
    print(f"{'='*62}\n")


if __name__ == "__main__":
    main()
