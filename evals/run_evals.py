#!/usr/bin/env python3
"""
run_evals.py
------------
Eval harness for ics_alert_pipeline.py's Claude enrichment step.

Runs each frozen input in evals/inputs/ through enrich_alert(), grades the
result against evals/expected/<case>.expected.json, and prints a pass/fail
summary. Exits non-zero if any case fails, so it's safe to wire into a
pre-commit hook or CI.

Run this after any change to SYSTEM_PROMPT, ALERT_ANALYSIS_TOOL, MODEL,
temperature/max_tokens, or the JSON extraction/repair logic.

USAGE
  export ANTHROPIC_API_KEY="sk-ant-..."
  python3 evals/run_evals.py
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ics_alert_pipeline as pipeline

EVALS_DIR = Path(__file__).resolve().parent
INPUTS_DIR = EVALS_DIR / "inputs"
EXPECTED_DIR = EVALS_DIR / "expected"

# sid -> category. This is a property of the Suricata rule, not a judgment
# call Claude has to make, so it lives here rather than in the tool schema.
CATEGORY_MAP = {
    1000001: "command-injection",
    1000002: "command-injection",
    1000003: "program-tampering",
    1000004: "command-injection",
    1000006: "reconnaissance",
    1000010: "unclassified",
}

HUMAN_REVIEW_SEVERITIES = {"high", "critical"}


def derive_category(sid: int) -> str:
    return CATEGORY_MAP.get(sid, "unknown")


def derive_requires_human_review(severity: str) -> bool:
    return severity in HUMAN_REVIEW_SEVERITIES


def extract_mitre_id(mitre_technique: str) -> str | None:
    match = re.match(r"T0\d{3}", mitre_technique or "")
    return match.group(0) if match else None


def check_severity_min(actual: str, minimum: str, failures: list[str]) -> None:
    rank = pipeline._SEVERITY_RANK
    if actual not in rank:
        failures.append(f"severity: {actual!r} is not a recognized severity")
        return
    if rank[actual] < rank[minimum]:
        failures.append(f"severity: expected at least {minimum!r}, got {actual!r}")


def check_exact(actual, expected, label: str, failures: list[str]) -> None:
    if actual != expected:
        failures.append(f"{label}: expected {expected!r}, got {actual!r}")


def check_mitre(actual_full: str, exp: dict, failures: list[str]) -> None:
    actual_id = extract_mitre_id(actual_full)
    if "mitre_technique_id" in exp:
        check_exact(actual_id, exp["mitre_technique_id"], "mitre_technique_id", failures)
    elif "mitre_technique_id_any_of" in exp:
        options = exp["mitre_technique_id_any_of"]
        if actual_id not in options:
            failures.append(f"mitre_technique_id: expected one of {options!r}, got {actual_id!r}")


def check_text_bounds(actual: str, spec: dict, label: str, failures: list[str]) -> None:
    text = actual or ""
    length = len(text)
    if length < spec.get("min_len", 0):
        failures.append(f"{label}: length {length} below min_len {spec['min_len']}")
    if "max_len" in spec and length > spec["max_len"]:
        failures.append(f"{label}: length {length} above max_len {spec['max_len']}")
    for kw in spec.get("required_keywords", []):
        if kw.lower() not in text.lower():
            failures.append(f"{label}: missing required keyword {kw!r}")
    any_of = spec.get("required_keywords_any_of")
    if any_of and not any(kw.lower() in text.lower() for kw in any_of):
        failures.append(f"{label}: none of the alternative keywords {any_of!r} present (need at least one)")


def check_array_bounds(actual, spec: dict, label: str, failures: list[str]) -> None:
    items = actual if isinstance(actual, list) else []
    n = len(items)
    if n < spec.get("min_items", 0):
        failures.append(f"{label}: {n} items below min_items {spec['min_items']}")
    if "max_items" in spec and n > spec["max_items"]:
        failures.append(f"{label}: {n} items above max_items {spec['max_items']}")
    for kw in spec.get("must_contain", []):
        if kw not in items:
            failures.append(f"{label}: missing required item {kw!r}")


def grade(enriched: dict, expected: dict) -> list[str]:
    failures: list[str] = []
    analysis = enriched.get("analysis", {})
    sid = enriched.get("sid")
    severity = analysis.get("severity")

    exp = expected.get("expect", {})

    if "severity" in exp:
        check_exact(severity, exp["severity"], "severity", failures)
    if "severity_min" in exp:
        check_severity_min(severity, exp["severity_min"], failures)
    if "mitre_technique_id" in exp or "mitre_technique_id_any_of" in exp:
        check_mitre(analysis.get("mitre_technique"), exp, failures)
    if "category" in exp:
        check_exact(derive_category(sid), exp["category"], "category", failures)
    if "requires_human_review" in exp:
        check_exact(derive_requires_human_review(severity), exp["requires_human_review"], "requires_human_review", failures)

    for field, spec in expected.get("text_checks", {}).items():
        check_text_bounds(analysis.get(field), spec, field, failures)

    for field, spec in expected.get("array_checks", {}).items():
        check_array_bounds(analysis.get(field), spec, field, failures)

    return failures


def run_case(input_path: Path) -> tuple[str, bool, list[str]]:
    case_id = input_path.stem
    expected_path = EXPECTED_DIR / f"{case_id}.expected.json"
    if not expected_path.exists():
        return case_id, False, [f"no expected file at {expected_path}"]

    raw = json.loads(input_path.read_text())
    expected = json.loads(expected_path.read_text())

    # each case should be judged independently of real-world rate limiting
    pipeline.last_call.pop(raw.get("alert", {}).get("signature_id"), None)

    enriched = pipeline.enrich_alert(raw)
    if enriched is None:
        return case_id, False, ["enrich_alert returned None (no API key set, or client not connected)"]

    failures = grade(enriched, expected)
    return case_id, len(failures) == 0, failures


def main() -> None:
    if not INPUTS_DIR.exists() or not any(INPUTS_DIR.glob("*.json")):
        print(f"[!] No frozen inputs found in {INPUTS_DIR}")
        sys.exit(1)

    results = [run_case(p) for p in sorted(INPUTS_DIR.glob("*.json"))]

    print()
    passed = 0
    for case_id, ok, failures in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {case_id}")
        for f in failures:
            print(f"    - {f}")
        passed += ok

    print(f"\n{passed}/{len(results)} cases passed")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
