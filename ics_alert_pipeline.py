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
import time
import threading
from datetime import datetime, timezone
from collections import deque

import anthropic
from flask import Flask, jsonify
from flask_cors import CORS

# ─── CONFIG ──────────────────────────────────────────────────────────────────

EVE_LOG_PATH   = "/var/log/suricata/eve.json"
API_KEY        = os.environ.get("ANTHROPIC_API_KEY", "")
MODEL          = "claude-sonnet-4-6"
MAX_ALERTS     = 50          # keep the last N enriched alerts in memory
RATE_LIMIT_SEC = 30          # minimum seconds between API calls for the same sid
POLL_INTERVAL  = 0.5         # how often (seconds) to check eve.json for new lines

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
            "severity_reason": {"type": "string"},
            "what_happened": {"type": "string"},
            "likely_attack": {"type": "string"},
            "mitre_technique": {
                "type": "string",
                "description": "MITRE ATT&CK for ICS technique ID and name, e.g. 'T0855 - Unauthorized Command Message'.",
            },
            "actions": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "tags": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["severity", "severity_reason", "what_happened", "likely_attack", "mitre_technique", "actions", "tags"],
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

Keep severity_reason and what_happened to 2-3 sentences each — be precise, not exhaustive.
The tool call must always include all required fields, including mitre_technique, actions, and tags.

Call the submit_alert_analysis tool with your analysis of this alert."""

# ─── STATE ───────────────────────────────────────────────────────────────────

alerts        = deque(maxlen=MAX_ALERTS)   # enriched alert objects, newest first
last_call     = {}                          # sid -> timestamp of last API call
alerts_lock   = threading.Lock()
client        = anthropic.Anthropic(api_key=API_KEY) if API_KEY else None

# ─── FLASK APP ────────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app)   # allow the dashboard HTML (file://) to call this API

@app.route("/alerts")
def get_alerts():
    with alerts_lock:
        return jsonify(list(alerts))

@app.route("/status")
def status():
    return jsonify({
        "suricata_log": EVE_LOG_PATH,
        "model": MODEL,
        "alerts_in_memory": len(alerts),
        "api_connected": client is not None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

# ─── ALERT ENRICHMENT ────────────────────────────────────────────────────────

_REQUIRED_ANALYSIS_FIELDS = (
    "severity", "severity_reason", "what_happened", "likely_attack", "mitre_technique", "actions", "tags",
)
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _valid_analysis(analysis: dict) -> bool:
    """Defense-in-depth check that a tool call actually matches the expected schema."""
    if not isinstance(analysis, dict):
        return False
    if any(field not in analysis for field in _REQUIRED_ANALYSIS_FIELDS):
        return False
    if analysis["severity"] not in _VALID_SEVERITIES:
        return False
    if not isinstance(analysis["actions"], list) or not all(isinstance(a, str) for a in analysis["actions"]):
        return False
    if not isinstance(analysis["tags"], list) or not all(isinstance(t, str) for t in analysis["tags"]):
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


def enrich_alert(raw: dict) -> dict | None:
    """Send a raw Suricata alert to Claude and return the enriched alert object."""
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

    user_message = f"""New Suricata alert from the GRFICSv3 ICS lab:

Timestamp : {ts}
Rule SID  : {sid}
Message   : {msg}
Rule context: {rule_context}
MITRE hint: {mitre_hint}
Source    : {src}:{sport}
Destination: {dst}:{dport}
Protocol  : {proto}

Analyze this alert for this specific ICS environment."""

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=1500,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
            tools=[ALERT_ANALYSIS_TOOL],
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
        analysis = {
            "severity": "medium",
            "severity_reason": "AI analysis failed schema validation. See pipeline terminal for details.",
            "what_happened": f"Claude's tool call for sid {sid} did not match the expected analysis schema. Check the pipeline terminal output for details.",
            "likely_attack": "Unknown due to schema validation failure.",
            "mitre_technique": "Unclassified — AI enrichment failed for this alert.",
            "actions": [
                "Check the pipeline terminal for Claude's raw tool call.",
                "Review fast.log manually for this alert.",
                "This is a formatting issue with the AI response, not a false alarm."
            ],
            "tags": ["schema-error", f"sid-{sid}"],
        }
    except Exception as e:
        print(f"[!] API error for sid {sid}: {e}")
        analysis = {
            "severity": "medium",
            "severity_reason": "AI analysis unavailable due to an API error. See pipeline terminal for details.",
            "what_happened": f"The call to Claude for sid {sid} failed ({e}). No AI analysis was produced for this alert.",
            "likely_attack": "Unknown due to API error.",
            "mitre_technique": "Unclassified — AI enrichment failed for this alert.",
            "actions": [
                "Check the pipeline terminal for the API error.",
                "Review fast.log manually for this alert.",
                "Verify ANTHROPIC_API_KEY and network connectivity if this repeats."
            ],
            "tags": ["api-error", f"sid-{sid}"],
        }

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
        "analysis": analysis,
    }

    print(f"[+] Enriched alert: sid={sid} | {msg} | severity={analysis.get('severity','?')}")
    return enriched

# ─── EVE.JSON WATCHER ────────────────────────────────────────────────────────

def watch_eve_log():
    """Tail eve.json and enrich each new alert-type line."""
    print(f"[*] Watching {EVE_LOG_PATH} for new Suricata alerts...")

    # wait for the file to exist (Suricata may not have started yet)
    while not os.path.exists(EVE_LOG_PATH):
        print(f"[~] Waiting for {EVE_LOG_PATH} to appear...")
        time.sleep(3)

    with open(EVE_LOG_PATH, "r") as f:
        f.seek(0, 2)   # seek to end — don't replay old alerts on startup
        print("[*] Tailing eve.json from current position. Run an attack to generate alerts.")

        while True:
            line = f.readline()
            if not line:
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

            enriched = enrich_alert(event)
            if enriched:
                with alerts_lock:
                    alerts.appendleft(enriched)   # newest first

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
