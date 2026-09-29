"""
scoring.py
==========
Pure scoring logic shared by the GUI (app.py), the validator
(validate_scenarios.py) and CI. No tkinter dependency.

Scoring model
-------------
Each choice carries three deltas (NIST, compliance, legal). A player's raw
axis score is the sum of the deltas of the choices they committed. That raw
sum is normalised against the *worst* and *best* sums achievable across the
injects played so far:

    score = (raw - worst) / (best - worst) * 100

so 100 means "you took the best available option every time", 0 means "you
took the worst every time", and every inject moves the number. (The previous
model started at 50 and clamped to [0, 100], which saturated after two or
three injects and made the last half of every scenario irrelevant.)
"""

from __future__ import annotations

AXES = ("nist", "compliance", "legal")
DELTA_KEYS = {
    "nist":       "nist_score_delta",
    "compliance": "compliance_score_delta",
    "legal":      "legal_score_delta",
}
QUALITIES = ("optimal", "neutral", "detrimental")

# (minimum overall score, letter). Scenario content calibrates "neutral" choices as
# partial credit (roughly +5 against +25 / -15), so an all-neutral run lands in the
# 30-50 range: a D. Anything below 30 means mostly detrimental decisions.
GRADE_BANDS = ((85, "A"), (70, "B"), (55, "C"), (30, "D"), (0, "F"))


def grade_for(overall: float) -> str:
    for floor, letter in GRADE_BANDS:
        if overall >= floor:
            return letter
    return "F"


def axis_bounds(injects: list[dict]) -> dict[str, tuple[int, int]]:
    """Worst and best achievable raw sums per axis across the given injects."""
    bounds = {}
    for axis, key in DELTA_KEYS.items():
        lo = hi = 0
        for inj in injects:
            deltas = [c[key] for c in inj["choices"]]
            lo += min(deltas)
            hi += max(deltas)
        bounds[axis] = (lo, hi)
    return bounds


def normalise(raw: int, lo: int, hi: int) -> int:
    if hi <= lo:
        return 100
    return int(round((raw - lo) / (hi - lo) * 100))


def normalised_scores(raw: dict[str, int], injects: list[dict]) -> dict[str, int]:
    """Normalise raw axis sums against the bounds of the injects played."""
    bounds = axis_bounds(injects)
    return {axis: normalise(raw[axis], *bounds[axis]) for axis in AXES}


def overall(scores: dict[str, int]) -> float:
    return round(sum(scores[a] for a in AXES) / len(AXES), 1)


def phase_efficiency(injects: list[dict], decisions: list[dict], phases: list[str]) -> list[dict]:
    """Per-phase NIST efficiency: how much of the available NIST delta range was earned.

    `decisions` items need `inject_id` and `nist_delta`.
    """
    by_id = {inj["id"]: inj for inj in injects}
    rows = []
    for phase in phases:
        earned = lo = hi = 0
        played = 0
        for d in decisions:
            inj = by_id.get(d["inject_id"])
            if inj is None or inj["phase"] != phase:
                continue
            deltas = [c["nist_score_delta"] for c in inj["choices"]]
            lo += min(deltas)
            hi += max(deltas)
            earned += d["nist_delta"]
            played += 1
        eff = normalise(earned, lo, hi) if played else None
        rows.append({"phase": phase, "earned": earned - lo if played else 0,
                     "available": hi - lo, "efficiency": eff, "played": played})
    return rows


def score_path(scenario: dict, quality: str) -> dict:
    """Play a whole scenario choosing the given quality every time."""
    raw = {a: 0 for a in AXES}
    for inj in scenario["injects"]:
        choice = next(c for c in inj["choices"] if c["quality"] == quality)
        for axis, key in DELTA_KEYS.items():
            raw[axis] += choice[key]
    scores = normalised_scores(raw, scenario["injects"])
    ov = overall(scores)
    return {**scores, "overall": ov, "grade": grade_for(ov)}


def score_choices(scenario: dict, choices: list[dict]) -> dict:
    """Score an explicit list of committed choices (one per inject, in order)."""
    raw = {a: 0 for a in AXES}
    for choice in choices:
        for axis, key in DELTA_KEYS.items():
            raw[axis] += choice[key]
    scores = normalised_scores(raw, scenario["injects"][:len(choices)])
    ov = overall(scores)
    return {**scores, "overall": ov, "grade": grade_for(ov)}
