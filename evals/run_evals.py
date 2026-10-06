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

import argparse
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


# Phrases that assert a confirmed physical effect. Paired with a process noun,
# these should never appear in the narrative text when physical_effect_assessment
# itself says the effect was not observed or could not be confirmed, since that
# would be the model contradicting its own grounded verdict in free text.
_OVERCLAIM_PHRASES = [
    "confirmed", "confirms", "successfully changed", "caused a change",
    "resulted in", "actually moved", "physically changed", "took effect on the process",
]
_PROCESS_NOUNS = ["pressure", "valve", "reactor", "process", "chemical a", "feed"]


def check_physical_claim_consistency(enriched: dict, failures: list[str]) -> None:
    analysis = enriched.get("analysis", {})
    assessment = analysis.get("physical_effect_assessment")
    if assessment not in ("not_observed", "inconclusive"):
        return  # nothing to check when a physical effect genuinely was observed
    combined = f"{analysis.get('what_happened', '')} {analysis.get('likely_attack', '')}".lower()
    for phrase in _OVERCLAIM_PHRASES:
        if phrase in combined and any(noun in combined for noun in _PROCESS_NOUNS):
            failures.append(
                f"physical claim consistency: assessment is {assessment!r} but narrative text "
                f"contains overclaiming language ({phrase!r})"
            )
            return


def grade(enriched: dict, expected: dict) -> list[str]:
    failures: list[str] = []
    analysis = enriched.get("analysis", {})
    tags = analysis.get("tags", [])

    # If the real Claude call never happened (API outage, billing, schema
    # violation), enrich_alert() substitutes a hardcoded fallback analysis.
    # Grading that fallback against content expectations (a specific MITRE
    # ID, specific keywords) always fails and always looks like a content
    # defect in the report, when it's actually an availability problem.
    # Surface that distinction explicitly instead of letting it masquerade as
    # "the model got this wrong."
    if "api-error" in tags:
        return ["enrichment degraded to the API-error fallback (Claude call failed, check API key/billing/connectivity), not a content defect"]
    if "schema-error" in tags:
        return ["enrichment degraded to the schema-error fallback (Claude's tool call didn't match the schema), not a content defect"]

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

    check_physical_claim_consistency(enriched, failures)

    return failures


def run_case_once(raw: dict, expected: dict) -> list[str]:
    # each run should be judged independently of real-world rate limiting,
    # and independently of any previous run in the same --repeat loop
    pipeline.last_call.pop(raw.get("alert", {}).get("signature_id"), None)

    enriched = pipeline.enrich_alert(raw)
    if enriched is None:
        return ["enrich_alert returned None (no API key set, or client not connected)"]

    return grade(enriched, expected)


def run_case(input_path: Path, repeat: int = 1) -> tuple[str, int, int, list[str]]:
    """Runs one frozen case `repeat` times and reports how many passed, not
    just a single pass/fail, since Claude's output is not perfectly
    deterministic even at low temperature."""
    case_id = input_path.stem
    expected_path = EXPECTED_DIR / f"{case_id}.expected.json"
    if not expected_path.exists():
        return case_id, 0, repeat, [f"no expected file at {expected_path}"]

    raw = json.loads(input_path.read_text())
    expected = json.loads(expected_path.read_text())

    passed = 0
    all_failures: list[str] = []
    for i in range(repeat):
        failures = run_case_once(raw, expected)
        if failures:
            all_failures.extend(f"run {i + 1}/{repeat}: {f}" for f in failures)
        else:
            passed += 1
    return case_id, passed, repeat, all_failures


def run_api_failure_case() -> tuple[str, int, int, list[str]]:
    """Not a frozen input: directly exercises enrich_alert()'s exception path
    by forcing the Claude call itself to raise. This path has only ever been
    seen firing by accident before (a real invalid API key produced a 401
    mid-session), never verified on purpose, so there was no guarantee it
    would keep behaving correctly after a future change."""
    case_id = "API_FAILURE_FALLBACK"
    sid = 1000001
    raw = {
        "timestamp": "2026-01-01T00:00:00-0700",
        "alert": {"signature_id": sid, "signature": "Unauthorized Coil Write!"},
        "src_ip": "192.168.90.6", "src_port": 12345,
        "dest_ip": "192.168.95.2", "dest_port": 502,
        "proto": "TCP",
    }
    pipeline.last_call.pop(sid, None)

    original_create = pipeline.client.messages.create
    pipeline.client.messages.create = lambda *a, **kw: (_ for _ in ()).throw(
        RuntimeError("simulated API failure for eval coverage")
    )
    try:
        enriched = pipeline.enrich_alert(raw)
    finally:
        pipeline.client.messages.create = original_create

    failures: list[str] = []
    if enriched is None:
        failures.append("enrich_alert returned None instead of a fallback analysis")
        return case_id, 0, 1, failures

    analysis = enriched.get("analysis", {})
    check_severity_min(analysis.get("severity"), pipeline.MIN_SEVERITY[sid], failures)
    if analysis.get("physical_effect_assessment") != "inconclusive":
        failures.append(
            f"physical_effect_assessment: expected 'inconclusive' on API failure, "
            f"got {analysis.get('physical_effect_assessment')!r}"
        )
    if "api-error" not in analysis.get("tags", []):
        failures.append("tags: expected an 'api-error' tag on the API-failure fallback")

    return case_id, (0 if failures else 1), 1, failures


def main() -> None:
    parser = argparse.ArgumentParser(description="Eval harness for ics_alert_pipeline.py")
    parser.add_argument(
        "--repeat", type=int, default=1,
        help="Run each frozen case this many times and report consistency (default: 1, fast single pass)",
    )
    args = parser.parse_args()

    if not INPUTS_DIR.exists() or not any(INPUTS_DIR.glob("*.json")):
        print(f"[!] No frozen inputs found in {INPUTS_DIR}")
        sys.exit(1)

    results = [run_case(p, args.repeat) for p in sorted(INPUTS_DIR.glob("*.json"))]
    results.append(run_api_failure_case())  # deterministic mock, repeat adds no information

    print()
    for case_id, passed, total, failures in results:
        ok = passed == total
        suffix = f" ({passed}/{total})" if total > 1 else ""
        print(f"[{'PASS' if ok else 'FAIL'}] {case_id}{suffix}")
        for f in failures:
            print(f"    - {f}")

    fully_passed = sum(1 for _, passed, total, _ in results if passed == total)
    repeat_note = f" (repeat={args.repeat})" if args.repeat > 1 else ""
    print(f"\n{fully_passed}/{len(results)} cases passed{repeat_note}")
    sys.exit(0 if fully_passed == len(results) else 1)


if __name__ == "__main__":
    main()
