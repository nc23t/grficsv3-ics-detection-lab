#!/usr/bin/env python3
"""
ics_alert_pipeline.py
---------------------
GRFICSv3 AI Alert Pipeline

Watches Suricata's eve.json for new alerts, sends each one to the Claude API
for enriched ICS-specific analysis, and serves the results via a local Flask
API that the dashboard polls every few seconds.

SETUP
  pip install flask anthropic --break-system-packages

USAGE
  export ANTHROPIC_API_KEY="sk-ant-..."
  python3 ics_alert_pipeline.py

  Then open dashboard.html in a browser.
  Make sure Suricata is running live: sudo suricata -c /etc/suricata/suricata.yaml -i eno1
"""

import json
import os
import subprocess
import time
import threading
from datetime import datetime, timezone
from collections import deque

import anthropic
from flask import Flask, jsonify, request
from flask_cors import CORS

# ─── CONFIG ──────────────────────────────────────────────────────────────────

EVE_LOG_PATH   = "/var/log/suricata/eve.json"
FAST_LOG_PATH  = "/var/log/suricata/fast.log"
API_KEY        = os.environ.get("ANTHROPIC_API_KEY", "")
MODEL          = "claude-sonnet-4-6"
MAX_ALERTS     = 50          # keep the last N enriched alerts in memory
RATE_LIMIT_SEC = 30          # minimum seconds between API calls for the same sid
POLL_INTERVAL  = 0.5         # how often (seconds) to check eve.json for new lines

# Durable, append-only record of every enrichment call (success or failure),
# separate from the in-memory `alerts` deque, which caps at MAX_ALERTS and is
# gone on restart. AI_ACTOR_ID is logged distinctly from the "human" actor tag
# used on disposition updates below, so the two are never confused in review.
AI_AUDIT_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai_audit.jsonl")
AI_ACTOR_ID       = f"ai:ics_alert_pipeline:{MODEL}"

# This pipeline runs on the host, which sits on a different subnet than the
# macvlan ICS network and cannot reach the PLC directly (confirmed by testing:
# a raw connect to 192.168.95.2:502 from the host times out). To read the PLC's
# current state, we run a short-lived read-only Modbus query inside a
# container that is on the ICS network, via `docker exec`.
#
# Default is "kali": EWS/HMI's image (workstation/Dockerfile, upstream) has no
# pymodbus installed, while kali's image (attacker/Dockerfile) already bundles
# it, so this works with no image changes. This is a real design tradeoff, not
# an ideal one: kali is documented elsewhere in this file as "never authorized"
# to talk to the PLC, yet it's the pipeline's own read vantage here. It is
# still strictly read-only and does not affect detection (Suricata already
# flags kali as unauthorized regardless of what this pipeline reads from it).
# Override via env var once EWS/HMI's image carries pymodbus.
PLC_IP                = "192.168.95.2"
MODBUS_READ_VANTAGE   = os.environ.get("MODBUS_READ_VANTAGE_CONTAINER", "kali")
MODBUS_READ_TIMEOUT   = 4     # seconds to wait for a single docker exec read
PRESSURE_INPUT_REG    = 108   # reactor pressure, a real sensor value (see SYSTEM_PROMPT)

# ─── RULE CATALOG ────────────────────────────────────────────────────────────
# Descriptions used in the system prompt so Claude knows what each rule means.

RULE_CATALOG = {
    1000001: "Unauthorized Modbus FC5/FC15 Write Single/Multiple Coil from non-HMI/EWS source. Coil 40 controls Chemical A feed enable.",
    1000002: "Unauthorized Modbus FC6/FC16 Write Single/Multiple Holding Register from non-HMI/EWS source. Holding registers control valve positions and setpoints.",
    1000003: "Unauthorized HTTP POST to OpenPLC /upload-program-action from non-EWS source. This endpoint accepts compiled Structured Text programs and replaces PLC control logic.",
    1000004: "Unauthorized Modbus write (any function code) from non-HMI/EWS source. Broad write detection — may include replay attacks.",
    1000006: "Multiple TCP SYN packets to PLC port 502 from non-authorized source. Signature of Modbus port scanning or register/coil enumeration.",
    1000010: "Any Modbus traffic from non-authorized source to PLC. Broad catch-all for unauthorized ICS network access.",
}

# ─── MITRE ATT&CK FOR ICS HINTS ──────────────────────────────────────────────
# Pre-vetted technique candidates per SID, given to Claude as grounding so it
# picks from known-correct IDs instead of inventing or misremembering one.

MITRE_HINTS = {
    1000001: "T0855 (Unauthorized Command Message) — a direct coil write forcing a physical process change.",
    1000002: "T0855 (Unauthorized Command Message) — a direct register write altering a setpoint or valve position.",
    1000003: "T0821 (Modify Controller Tasking) — uploading new control logic to the PLC, replacing its program.",
    1000004: "T0855 (Unauthorized Command Message) — broad write detection; if the payload is a program upload this may instead be T0821 (Modify Controller Tasking).",
    1000006: "T0846 (Remote System Discovery) — scanning or enumerating the Modbus service on port 502 ahead of an attack.",
    1000010: "No single best fit — this is a catch-all for unclassified unauthorized Modbus traffic. Prefer T0855 (Unauthorized Command Message) unless the alert context suggests reconnaissance (T0846) or something else.",
}

# ─── ALERT ANALYSIS TOOL SCHEMA ──────────────────────────────────────────────
# Forces Claude to return a schema-validated tool call instead of free-text
# JSON, so the output format is guaranteed by the API rather than by prompt.

ALERT_ANALYSIS_TOOL = {
    "name": "submit_alert_analysis",
    "description": "Submit structured security analysis of an ICS/OT Suricata alert.",
    "input_schema": {
        "type": "object",
        "properties": {
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "headline": {
                "type": "string",
                "description": (
                    "One plain-language line, roughly 100 characters at most, saying who did what "
                    "to what (e.g. 'Kali turned off Chemical A feed (coil 40)'). This is the first "
                    "thing an operator reads."
                ),
            },
            "severity_reason": {"type": "string"},
            "what_happened": {"type": "string"},
            "likely_attack": {"type": "string"},
            "mitre_technique": {
                "type": "string",
                "description": "MITRE ATT&CK for ICS technique ID and name, e.g. 'T0855 - Unauthorized Command Message'.",
            },
            "physical_effect_assessment": {
                "type": "string",
                "enum": ["observed", "not_observed", "inconclusive", "not_applicable"],
                "description": (
                    "Base this ONLY on the command_attempted / register_observed / physical_indicator "
                    "facts given below, never on assumption. 'not_applicable' if this alert carried no "
                    "write payload at all (e.g. recon)."
                ),
            },
            "physical_effect_reason": {"type": "string"},
            "immediate_actions": {
                "type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 4,
                "description": (
                    "Steps to neutralize THIS threat right now. Each one references a concrete "
                    "fact already given above (the actual attacker IP, the actual register/coil "
                    "address, the actual observed value), never generic advice. One short sentence "
                    "each, no more than 4 items."
                ),
            },
            "after_neutralized_actions": {
                "type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 4,
                "description": (
                    "Follow-up hardening or process changes for AFTER the threat above is handled "
                    "(audits, firewall rule changes, patching). Not urgent, not for right now. "
                    "One short sentence each, no more than 4 items."
                ),
            },
            "tags": {"type": "array", "items": {"type": "string"}},
        },
        "required": [
            "severity", "headline", "severity_reason", "what_happened", "likely_attack", "mitre_technique",
            "physical_effect_assessment", "physical_effect_reason",
            "immediate_actions", "after_neutralized_actions", "tags",
        ],
    },
}

# ─── SYSTEM PROMPT ───────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an ICS/OT cybersecurity analyst for a GRFICSv3 chemical reactor simulation lab.
Your job is to analyze Suricata IDS alerts and produce clear, actionable incident analysis tailored to this specific environment.

NETWORK TOPOLOGY:
- ICS Network (192.168.95.0/24): the control network
  - 192.168.95.2  : Chemical Reactor PLC (OpenPLC runtime, Modbus TCP port 502, web interface port 8080)
  - 192.168.95.5  : Engineering Workstation (EWS) — the ONLY authorized source for program uploads and register writes
  - 192.168.95.200: Router (ICS-side interface)
- DMZ Network (192.168.90.0/24): the operator network
  - 192.168.90.107: HMI — authorized to read process data and issue coil writes during operator actions
  - 192.168.90.6  : Kali Linux attacker machine — NEVER authorized to communicate with the PLC
  - 192.168.90.200: Router (DMZ-side interface)
  - 192.168.90.250: Caldera (adversary simulation framework)
- Admin Network (172.19.0.0/16): management plane, not for process traffic

AUTHORIZED WRITERS TO PLC:
- Coil writes: HMI (192.168.90.107) and EWS (192.168.95.5) only
- Register writes: EWS (192.168.95.5) only
- Program uploads: EWS (192.168.95.5) only
- Any other source issuing writes is unauthorized and should be treated as an active attack

ICS PROCESS OVERVIEW:
The simulation models a chemical reactor with the following key devices:
- Chemical A feed valve: binary on/off, controlled by coil 40 (coil write attack target)
- Purge valve: modulating (holding register 102), controls pressure venting, high-gain (k=-20) causes fast oscillation
- Product valve: modulating (holding register 103), controls product draw-off
- Reactor pressure: monitored via input register 108 (raw value ~55000 at normal ~2700 kPa)
- Process danger: sustained high pressure can cause reactor overpressure failure

SURICATA RULE CATALOG:
- sid 1000001: Unauthorized coil write (FC5/FC15) — direct process manipulation, can disable Chemical A feed
- sid 1000002: Unauthorized register write (FC6/FC16) — setpoint/valve manipulation
- sid 1000003: Unauthorized program upload to OpenPLC — highest impact, replaces control logic entirely
- sid 1000004: Unauthorized Modbus write (any type) — broad write detection, may be replay attack
- sid 1000006: Modbus reconnaissance — port scanning/enumeration before an attack
- sid 1000010: Any unauthorized Modbus traffic — catch-all, novel or unclassified technique

KNOWN ATTACK SEQUENCE FROM THIS LAB:
Stage 2: Register mapping (FC4 read enumeration)
Stage 3: Coil manipulation (FC5 write to coil 40 from Kali)
Stage 4: MITM concealment (ARP spoof + Modbus response falsification)
Stage 4: Structured Text injection (HTTP POST to /upload-program-action from Kali)
Stage 4: Replay attack (re-sent captured FC5 bytes over fresh TCP connection)

MITRE ATT&CK FOR ICS:
Every alert must be tagged with exactly one MITRE ATT&CK for ICS technique, formatted as "T0XXX - Technique Name".
Each alert's user message includes a "MITRE hint" naming the technique(s) already vetted as correct for that Suricata rule.
Use that hint as your primary source. Do not invent a technique ID or pull one from memory outside the hint.
If the hint offers more than one candidate, pick the one that best matches the specific alert context; if none fit well, fall back to the hint's suggested default.

THREE SEPARATE FACTS, NOT ONE STORY:
Each alert's user message gives you up to three distinct, independently-sourced facts:
- "Command attempted": parsed directly from Suricata's own Modbus payload decode. This is what the attacker sent, not what happened as a result.
- "Register/coil observed": a live read-only Modbus read of the same address, taken right after the alert. This is what the PLC's memory holds right now, which may or may not match the command.
- "Physical indicator": a live read of reactor pressure (input register 108), a real sensor value, not a control mirror.
Any of the last two may read "unavailable" if the live read failed, in which case treat that fact as unknown, not as evidence of anything.

Fill physical_effect_assessment using ONLY these facts:
- "observed": the register/coil read or the pressure reading shows a change consistent with the attempted command.
- "not_observed": a live read succeeded and shows no such change (example: register 102 is a Modbus-exposed mirror, not the real valve actuator, so a write there commonly succeeds at the protocol level with no physical effect).
- "inconclusive": a live read failed or the data doesn't clearly support either conclusion.
- "not_applicable": this alert had no write payload at all (recon, catch-all).
Never claim a physical effect the given facts don't actually support. This assessment is the one place you are graded on restraint, not inference.

TWO KINDS OF ACTIONS, NOT ONE LIST:
- immediate_actions: only steps that neutralize THIS specific threat right now (block this IP, restore this coil/register to this value). Each one must reference a concrete fact already given above (the actual attacker IP, the actual address, the actual observed value), never generic advice like "monitor the network." Maximum 4 items.
- after_neutralized_actions: only for follow-up hardening or process changes to do later (firewall rule changes, audits, patching). Nothing time-critical belongs here. Maximum 4 items.
If an action doesn't clearly belong in one or the other, put it in immediate_actions only if it stops or contains the attack right now.

BE TERSE, THIS IS READ UNDER TIME PRESSURE:
- headline: one line, plain language, roughly 100 characters, e.g. "Kali turned off Chemical A feed (coil 40)."
- severity_reason, what_happened, likely_attack, physical_effect_reason: 1-2 sentences each, not 2-3. Each field covers different ground; do not restate the same fact (attacker IP, target address) in more than one of them.
- Every action item and tag is a few words, not a sentence with sub-clauses.

The tool call must always include all required fields: severity, headline, severity_reason, what_happened, likely_attack, mitre_technique, physical_effect_assessment, physical_effect_reason, immediate_actions, after_neutralized_actions, tags.

Call the submit_alert_analysis tool with your analysis of this alert."""

# ─── STATE ───────────────────────────────────────────────────────────────────

alerts        = deque(maxlen=MAX_ALERTS)   # enriched alert objects, newest first
last_call     = {}                          # sid -> timestamp of last API call
alerts_lock   = threading.Lock()
client        = anthropic.Anthropic(api_key=API_KEY) if API_KEY else None

# Rolling window of the last N enrichment outcomes ("success" | "schema-error"
# | "api-error"), so a failure *rate* is visible system-wide instead of only
# as a tag buried on individual cards. This is the concrete version of CISA's
# "thresholds for defaulting back to non-AI systems" (Principles 3.4/4.2).
recent_outcomes     = deque(maxlen=20)
AI_DEGRADED_THRESHOLD = 0.3

# ─── FLASK APP ────────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app)   # allow the dashboard HTML (file://) to call this API

@app.route("/alerts")
def get_alerts():
    with alerts_lock:
        return jsonify(list(alerts))

@app.route("/status")
def status():
    error_rate = (
        sum(1 for o in recent_outcomes if o != "success") / len(recent_outcomes)
        if recent_outcomes else 0.0
    )
    return jsonify({
        "suricata_log": EVE_LOG_PATH,
        "model": MODEL,
        "alerts_in_memory": len(alerts),
        "api_connected": client is not None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ai_degraded": error_rate > AI_DEGRADED_THRESHOLD,
        "recent_error_rate": error_rate,
    })

# Analyst triage states for the human-in-the-loop disposition workflow. CISA's
# own AI-in-OT guidance (Principle 4.1, Human-in-the-Loop Decision-Making)
# calls for operators to be involved in decision-making on AI-assisted alerts,
# not just shown the AI's output; this is what records that a human actually
# looked, not just that one could have.
_VALID_DISPOSITIONS = {
    "new", "acknowledged", "investigating",
    "resolved_true_positive", "resolved_false_positive",
}


@app.route("/alerts/<alert_id>/disposition", methods=["POST"])
def set_disposition(alert_id):
    """Update (or resolve) the disposition of the whole correlated group that
    alert_id belongs to, not just that one alert. One attack packet commonly
    trips several rules at once (see group_key()); triaging each one
    separately, with the same packet showing a true positive under one SID
    and a false positive under another, isn't how real correlated-alert
    triage works, so a single disposition decision here applies to every
    member sharing the same group_id.

    Resolving (either outcome) deletes the whole group outright rather than
    just marking it, this is a working lab, not a system of record, and
    keeping closed alerts around only to let them quietly age out of the
    MAX_ALERTS ring buffer later serves no one."""
    body = request.get_json(silent=True) or {}
    disposition = body.get("disposition")
    note = body.get("note", "")
    if disposition not in _VALID_DISPOSITIONS:
        return jsonify({"error": f"disposition must be one of {sorted(_VALID_DISPOSITIONS)}"}), 400

    with alerts_lock:
        target = next((a for a in alerts if a["id"] == alert_id), None)
        if target is None:
            return jsonify({"error": "alert not found"}), 404

        group_id = target["group_id"]
        group_members = [a for a in alerts if a["group_id"] == group_id]

        if disposition.startswith("resolved_"):
            remaining = [a for a in alerts if a["group_id"] != group_id]
            alerts.clear()
            alerts.extend(remaining)
            return jsonify({
                "group_id": group_id,
                "removed": True,
                "ids": [a["id"] for a in group_members],
            })

        history_entry = {
            "state": disposition,
            "actor": "human",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": note,
        }
        for a in group_members:
            a["disposition"] = disposition
            a["disposition_history"].append(history_entry)

        return jsonify({"group_id": group_id, "removed": False, "alerts": group_members})

# ─── ALERT ENRICHMENT ────────────────────────────────────────────────────────

_REQUIRED_ANALYSIS_FIELDS = (
    "severity", "headline", "severity_reason", "what_happened", "likely_attack", "mitre_technique",
    "physical_effect_assessment", "physical_effect_reason",
    "immediate_actions", "after_neutralized_actions", "tags",
)
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_VALID_PHYSICAL_EFFECTS = {"observed", "not_observed", "inconclusive", "not_applicable"}
_STRING_LIST_FIELDS = ("immediate_actions", "after_neutralized_actions", "tags")


def _valid_analysis(analysis: dict) -> bool:
    """Defense-in-depth check that a tool call actually matches the expected schema."""
    if not isinstance(analysis, dict):
        return False
    if any(field not in analysis for field in _REQUIRED_ANALYSIS_FIELDS):
        return False
    if analysis["severity"] not in _VALID_SEVERITIES:
        return False
    if analysis["physical_effect_assessment"] not in _VALID_PHYSICAL_EFFECTS:
        return False
    for field in _STRING_LIST_FIELDS:
        if not isinstance(analysis[field], list) or not all(isinstance(item, str) for item in analysis[field]):
            return False
    return True


_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Rules whose real-world impact means the assigned severity should never be
# trusted below this floor, regardless of how the model reasoned about it.
# This is deliberate defense-in-depth: the model can rate a rule higher than
# its floor if the specific alert context warrants it, but never lower.
MIN_SEVERITY = {
    1000001: "high",      # coil write — direct actuator manipulation
    1000002: "high",      # register write — direct setpoint manipulation
    1000003: "critical",  # program upload — full control logic replacement
    1000004: "high",      # broad write detection — direct process manipulation risk
    1000006: "medium",    # recon/scanning — precursor, not direct manipulation
    1000010: "medium",    # catch-all — unclassified traffic, uncertain impact
}


def _apply_severity_floor(sid: int, analysis: dict) -> dict:
    """Clamp severity up to the hardcoded per-SID minimum so the model can
    never downgrade a rule that is known to be serious for this environment."""
    floor = MIN_SEVERITY.get(sid)
    if floor and _SEVERITY_RANK[analysis["severity"]] < _SEVERITY_RANK[floor]:
        original = analysis["severity"]
        analysis["severity"] = floor
        analysis["severity_reason"] = (
            f"[Severity floor applied: sid {sid} is never rated below '{floor}'; "
            f"the model assigned '{original}'.] " + analysis["severity_reason"]
        )
        analysis["tags"] = list(analysis.get("tags", [])) + ["severity-floor-applied"]
    return analysis


def _parse_modbus_write(raw: dict) -> tuple[str, int, int] | None:
    """Pull (kind, address, value) out of Suricata's own Modbus payload decode,
    if this alert's packet carried a write. Returns None for alerts with no
    write payload (recon, catch-all traffic with no parsed Modbus write)."""
    request = raw.get("modbus", {}).get("request", {})
    write = request.get("write")
    if not write or "address" not in write:
        return None
    access_type = request.get("access_type", "")
    if "COILS" in access_type:
        kind = "coil"
    elif "HOLDING" in access_type:
        kind = "holding"
    else:
        return None
    return kind, write["address"], write.get("data")


def _describe_command(kind: str, address: int, value: int) -> str:
    if kind == "coil":
        state = "ON" if value == 65280 else "OFF" if value == 0 else str(value)
        return f"Write coil {address} to {state}"
    return f"Write holding register {address} to {value}"


def _modbus_read(kind: str, address: int, count: int = 1) -> str:
    """Read-only Modbus query run from inside MODBUS_READ_VANTAGE (a real ICS
    asset, not the pipeline host, which cannot reach this network directly).
    Returns a short human-readable string, or an explicit 'unavailable' note
    on any failure. Never writes anything."""
    read_fn = {"coil": "read_coils", "holding": "read_holding_registers", "input": "read_input_registers"}[kind]
    # pymodbus 3.x response objects all carry a .bits attribute regardless of
    # type (empty for register reads), so hasattr(r, 'bits') cannot be used to
    # tell a coil response from a register response. Branch on kind instead,
    # which we already know here.
    value_expr = f"r.bits[:{count}]" if kind == "coil" else "r.registers"
    code = (
        "from pymodbus.client import ModbusTcpClient\n"
        f"c = ModbusTcpClient('{PLC_IP}', port=502)\n"
        "c.connect()\n"
        f"r = c.{read_fn}({address}, count={count})\n"
        f"print({value_expr} if not r.isError() else 'ERROR')\n"
        "c.close()\n"
    )
    try:
        result = subprocess.run(
            ["docker", "exec", MODBUS_READ_VANTAGE, "python3", "-c", code],
            capture_output=True, text=True, timeout=MODBUS_READ_TIMEOUT,
        )
        out = result.stdout.strip()
        if result.returncode != 0 or not out or out == "ERROR":
            return f"unavailable (could not read {kind} {address} from {MODBUS_READ_VANTAGE})"
        return out
    except Exception as e:
        return f"unavailable (read error: {e})"


def gather_physical_facts(raw: dict) -> tuple[str, str, str]:
    """Compute the three shared facts (command_attempted, register_observed,
    physical_indicator) for one raw Suricata alert. Call this ONCE per group
    of same-packet alerts (see group_key()) and pass the result to every
    enrich_alert() call for that group, so multiple rules matching the same
    packet describe the same physical reality instead of each taking its own
    live read seconds apart, during which the PLC's real state can change."""
    write = _parse_modbus_write(raw)
    if write is not None:
        kind, address, value = write
        command_attempted = _describe_command(kind, address, value)
        register_observed = _modbus_read(kind, address)
    else:
        command_attempted = "No write payload parsed for this alert (not a write, e.g. recon or catch-all traffic)."
        register_observed = "not applicable, no write to check"

    physical_indicator = (
        f"reactor pressure (input register {PRESSURE_INPUT_REG}) reads {_modbus_read('input', PRESSURE_INPUT_REG)} "
        f"raw (documented baseline: ~55000 raw at normal ~2700 kPa)"
        if write is not None else "not applicable, no write to check"
    )
    return command_attempted, register_observed, physical_indicator


# How much of fast.log to read when looking for a matching line. fast.log is
# append-only and grows unbounded across a session, so seeking from the end
# keeps this cheap no matter how long the lab has been running.
FAST_LOG_TAIL_BYTES = 1_000_000


def _find_fast_log_line(raw: dict, tolerance_sec: float = 2.0) -> str | None:
    """Best-effort match of one eve.json alert to its corresponding
    human-readable fast.log line, by signature ID, source/destination IP, and
    timestamp proximity. fast.log carries no flow_id or other structured join
    key, so this is a heuristic, not a guaranteed join: returns None rather
    than a low-confidence guess when nothing matches within tolerance_sec,
    consistent with this project's rule against claiming more certainty than
    the facts support."""
    sid = raw.get("alert", {}).get("signature_id")
    src_ip = raw.get("src_ip")
    dest_ip = raw.get("dest_ip")
    if sid is None or src_ip is None or dest_ip is None:
        return None

    try:
        alert_naive = datetime.fromisoformat(raw.get("timestamp", "")).replace(tzinfo=None)
    except ValueError:
        return None

    sid_marker = f"[1:{sid}:"

    try:
        with open(FAST_LOG_PATH, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - FAST_LOG_TAIL_BYTES))
            chunk = f.read().decode("utf-8", errors="replace")
    except OSError:
        return None

    best_line, best_delta = None, None
    for line in chunk.splitlines():
        if sid_marker not in line or src_ip not in line or dest_ip not in line:
            continue
        # fast.log format: "<ts>  [**] [gid:sid:rev] <msg> [**] ..."
        line_ts = line.split("  ", 1)[0]
        try:
            line_dt = datetime.strptime(line_ts, "%m/%d/%Y-%H:%M:%S.%f")
        except ValueError:
            continue
        delta = abs((line_dt - alert_naive).total_seconds())
        if delta <= tolerance_sec and (best_delta is None or delta < best_delta):
            best_line, best_delta = line, delta

    return best_line


_UNAVAILABLE_MARKER = "unavailable"


def _evidence_completeness(command_attempted: str, register_observed: str, physical_indicator: str) -> str:
    """Code-computed signal for how much of physical_effect_assessment's own
    grounding actually resolved, never asked of the model, same philosophy as
    _apply_severity_floor: compute what can be computed in code rather than
    trust the model to self-report something it can get wrong. Answers CISA
    1.1's "Lack of Explainability" risk by making the AI's evidence basis
    visible instead of buried in a paragraph of prose."""
    if command_attempted.startswith("No write payload parsed"):
        return "not_applicable"   # recon/catch-all: nothing to read in the first place

    reads = (register_observed, physical_indicator)
    failed = sum(1 for r in reads if _UNAVAILABLE_MARKER in r)
    if failed == 0:
        return "full"
    if failed == len(reads):
        return "none"
    return "partial"


def _write_ai_audit_log(entry: dict) -> None:
    """Append one durable, forensic record of an enrichment call to
    AI_AUDIT_LOG_PATH. Plain append-only JSONL, same spirit as eve.json/
    fast.log already being plain-text and greppable, not a database. Called
    on every enrich_alert() outcome, success, schema-error, and api-error
    alike, since CISA's guidance asks for AI decisions to be trackable "for
    compliance and forensic analysis" and a failure is as auditable as a
    success."""
    try:
        with open(AI_AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        print(f"[!] Could not write AI audit log: {e}")


def group_key(raw: dict) -> str:
    """Key that identifies 'the same packet' across multiple matched rules.
    Suricata assigns one flow_id per TCP flow and fires all matching rules
    for it with the same flow_id, so that's the precise key. Fall back to
    source/destination/timestamp for any event missing it."""
    flow_id = raw.get("flow_id")
    if flow_id is not None:
        return f"flow-{flow_id}"
    return f"{raw.get('src_ip')}-{raw.get('dest_ip')}-{raw.get('dest_port')}-{raw.get('timestamp')}"


def enrich_alert(raw: dict, shared_facts: tuple[str, str, str] | None = None) -> dict | None:
    """Send a raw Suricata alert to Claude and return the enriched alert object.
    shared_facts, if given, is (command_attempted, register_observed,
    physical_indicator) already computed once for this alert's whole group
    (see group_key()); otherwise it is computed here for this alert alone."""
    if client is None:
        print("[!] No API key set. Set ANTHROPIC_API_KEY environment variable.")
        return None

    sid = raw.get("alert", {}).get("signature_id", 0)
    msg = raw.get("alert", {}).get("signature", "Unknown")
    src = raw.get("src_ip", "?")
    dst = raw.get("dest_ip", "?")
    sport = raw.get("src_port", "?")
    dport = raw.get("dest_port", "?")
    proto = raw.get("proto", "?")
    ts    = raw.get("timestamp", datetime.now(timezone.utc).isoformat())

    # rate limit: skip API call if same rule fired within RATE_LIMIT_SEC
    now = time.time()
    if sid in last_call and (now - last_call[sid]) < RATE_LIMIT_SEC:
        print(f"[~] Rate limiting sid {sid} — skipping API call")
        return None
    last_call[sid] = now

    rule_context = RULE_CATALOG.get(sid, "Unknown custom rule.")
    mitre_hint = MITRE_HINTS.get(sid, "No specific hint for this SID — infer the most fitting MITRE ATT&CK for ICS technique from the alert context.")

    command_attempted, register_observed, physical_indicator = (
        shared_facts if shared_facts is not None else gather_physical_facts(raw)
    )

    user_message = f"""New Suricata alert from the GRFICSv3 ICS lab:

Timestamp : {ts}
Rule SID  : {sid}
Message   : {msg}
Rule context: {rule_context}
MITRE hint: {mitre_hint}
Source    : {src}:{sport}
Destination: {dst}:{dport}
Protocol  : {proto}

Command attempted   : {command_attempted}
Register/coil observed (live read, just now): {register_observed}
Physical indicator   : {physical_indicator}

Analyze this alert for this specific ICS environment."""

    outcome = "success"   # success | schema-error | api-error, recorded in the audit log below

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=1500,
            # SYSTEM_PROMPT and the tool schema are identical on every call and
            # large (full topology, rule catalog, MITRE hints); cache_control
            # marks each as a cache breakpoint so Anthropic reuses them instead
            # of re-billing full input tokens every time. Cuts cost on both
            # live alerts and eval runs, since both call this same function.
            system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user_message}],
            tools=[{**ALERT_ANALYSIS_TOOL, "cache_control": {"type": "ephemeral"}}],
            tool_choice={"type": "tool", "name": "submit_alert_analysis"},
        )

        tool_use_block = next((b for b in response.content if b.type == "tool_use"), None)
        if tool_use_block is None:
            raise ValueError("Claude response contained no tool_use block")

        analysis = tool_use_block.input
        if not _valid_analysis(analysis):
            raise ValueError(f"Claude tool call did not match expected schema: {analysis}")

    except ValueError as e:
        # debug: print what Claude actually sent so you can see what went wrong
        print(f"[!] Schema error from Claude for sid {sid}: {e}")
        outcome = "schema-error"
        analysis = {
            "severity": "medium",
            "headline": f"AI analysis failed for sid {sid} (schema error).",
            "severity_reason": "AI analysis failed schema validation. See pipeline terminal for details.",
            "what_happened": f"Claude's tool call for sid {sid} did not match the expected analysis schema. Check the pipeline terminal output for details.",
            "likely_attack": "Unknown due to schema validation failure.",
            "mitre_technique": "Unclassified — AI enrichment failed for this alert.",
            "physical_effect_assessment": "inconclusive",
            "physical_effect_reason": "AI analysis failed schema validation, so no assessment was produced.",
            "immediate_actions": [
                "Check the pipeline terminal for Claude's raw tool call.",
                "Review fast.log manually for this alert.",
            ],
            "after_neutralized_actions": [
                "This is a formatting issue with the AI response, not a false alarm.",
            ],
            "tags": ["schema-error", f"sid-{sid}"],
        }
    except Exception as e:
        print(f"[!] API error for sid {sid}: {e}")
        outcome = "api-error"
        analysis = {
            "severity": "medium",
            "headline": f"AI analysis unavailable for sid {sid} (API error).",
            "severity_reason": "AI analysis unavailable due to an API error. See pipeline terminal for details.",
            "what_happened": f"The call to Claude for sid {sid} failed ({e}). No AI analysis was produced for this alert.",
            "likely_attack": "Unknown due to API error.",
            "mitre_technique": "Unclassified — AI enrichment failed for this alert.",
            "physical_effect_assessment": "inconclusive",
            "physical_effect_reason": "AI analysis was unavailable due to an API error, so no assessment was produced.",
            "immediate_actions": [
                "Check the pipeline terminal for the API error.",
                "Review fast.log manually for this alert.",
            ],
            "after_neutralized_actions": [
                "Verify ANTHROPIC_API_KEY and network connectivity if this repeats.",
            ],
            "tags": ["api-error", f"sid-{sid}"],
        }

    raw_tool_output = dict(analysis)   # before the floor mutates it in place, for the audit log below
    analysis = _apply_severity_floor(sid, analysis)

    enriched = {
        "id": f"{ts}-{sid}",
        "timestamp": ts,
        "sid": sid,
        "msg": msg,
        "src_ip": src,
        "src_port": sport,
        "dest_ip": dst,
        "dest_port": dport,
        "proto": proto,
        # same key used in _flush_group to take physical facts once per packet
        # (see group_key() above); exposing it lets the dashboard group by this
        # exact server-side key instead of guessing from a time window, and
        # lets /alerts/<id>/disposition cascade a status change across every
        # rule that fired on the same packet, rather than one at a time.
        "group_id": group_key(raw),
        # human-in-the-loop triage state (CISA 4.1): starts "new", updated via
        # POST /alerts/<id>/disposition as an operator actually reviews it.
        "disposition": "new",
        "disposition_history": [],
        # deterministic facts, gathered in code, not by the model, so they're
        # true regardless of whether the Claude call itself succeeded.
        "command_attempted": command_attempted,
        "register_observed": register_observed,
        "physical_indicator": physical_indicator,
        "evidence_completeness": _evidence_completeness(command_attempted, register_observed, physical_indicator),
        "analysis": analysis,
        # ground-truth evidence for manual verification, kept separate from
        # the model's own narrative above — see the Alert Evidence Trail plan.
        "raw_eve_json": raw,
        "fast_log_line": _find_fast_log_line(raw),
    }

    _write_ai_audit_log({
        "logged_at": datetime.now(timezone.utc).isoformat(),
        "alert_timestamp": ts,
        "alert_id": enriched["id"],
        "sid": sid,
        "actor": AI_ACTOR_ID,
        "outcome": outcome,
        "user_message": user_message,
        "raw_tool_output": raw_tool_output,
        "final_analysis": analysis,
        "severity_floor_applied": "severity-floor-applied" in analysis.get("tags", []),
    })
    recent_outcomes.append(outcome)

    print(f"[+] Enriched alert: sid={sid} | {msg} | severity={analysis.get('severity','?')}")
    return enriched

# ─── EVE.JSON WATCHER ────────────────────────────────────────────────────────

# How long to wait, after the last alert in a group, before treating that
# group as complete and processing it. Multiple rules matching one packet
# (e.g. sid 1000001 + 1000004 + 1000010 for one coil write) all log within
# microseconds of each other, so this only ever adds real waiting time when a
# group turns out to have just one member.
GROUP_FLUSH_SEC = 1.5


def _flush_group(members: list[dict]) -> None:
    """Process one group of same-packet alerts: take the shared physical
    facts ONCE (see gather_physical_facts's docstring for why), then enrich
    every member with those same facts so they describe the same reality."""
    write_member = next((m for m in members if _parse_modbus_write(m) is not None), members[0])
    facts = gather_physical_facts(write_member)
    for member in members:
        enriched = enrich_alert(member, shared_facts=facts)
        if enriched:
            with alerts_lock:
                alerts.appendleft(enriched)   # newest first


def watch_eve_log():
    """Tail eve.json, group same-packet alerts (shared flow_id), and enrich
    each completed group."""
    print(f"[*] Watching {EVE_LOG_PATH} for new Suricata alerts...")

    # wait for the file to exist (Suricata may not have started yet)
    while not os.path.exists(EVE_LOG_PATH):
        print(f"[~] Waiting for {EVE_LOG_PATH} to appear...")
        time.sleep(3)

    pending: dict[str, list[dict]] = {}
    pending_since: dict[str, float] = {}

    def flush_ready_groups():
        now = time.time()
        ready = [k for k, t in pending_since.items() if (now - t) >= GROUP_FLUSH_SEC]
        for key in ready:
            _flush_group(pending.pop(key))
            pending_since.pop(key)

    with open(EVE_LOG_PATH, "r") as f:
        f.seek(0, 2)   # seek to end — don't replay old alerts on startup
        print("[*] Tailing eve.json from current position. Run an attack to generate alerts.")

        while True:
            line = f.readline()
            if not line:
                flush_ready_groups()
                time.sleep(POLL_INTERVAL)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            # only process alert-type events
            if event.get("event_type") != "alert":
                continue

            key = group_key(event)
            pending.setdefault(key, []).append(event)
            pending_since[key] = time.time()

# ─── MAIN ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not API_KEY:
        print("[!] WARNING: ANTHROPIC_API_KEY not set. Alerts will be detected but not enriched.")
        print("    Export it: export ANTHROPIC_API_KEY='sk-ant-...'")
    else:
        print(f"[*] Claude API connected ({MODEL})")

    # start the eve.json watcher in a background thread
    watcher = threading.Thread(target=watch_eve_log, daemon=True)
    watcher.start()

    # start Flask on localhost only (dashboard opens in the same machine's browser)
    print("[*] Dashboard API running at http://localhost:5000")
    print("[*] Open dashboard.html in your browser to view alerts.")
    app.run(host="127.0.0.1", port=5000, debug=False)
