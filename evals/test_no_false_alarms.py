#!/usr/bin/env python3
"""
test_no_false_alarms.py
------------------------
Live integration test, separate from run_evals.py's frozen-input harness.

run_evals.py can only grade alerts that already fired, so it has no way to
test the mirror case: legitimate, authorized traffic that should trigger
*zero* alerts. This script sends real, authorized Modbus reads from HMI
(192.168.90.107) and EWS (192.168.95.5), both allow-listed as legitimate
sources in local.rules and in ics_alert_pipeline.py's SYSTEM_PROMPT, and
confirms none of the 6 custom SIDs fire for them.

Requires the live lab up: containers running, Suricata capturing on the real
NIC (see the lab-startup skill). Reads only, no writes, so it doesn't change
process state.

USAGE
  python3 evals/test_no_false_alarms.py
"""

import json
import subprocess
import sys
import time
from datetime import datetime

EVE_LOG = "/var/log/suricata/eve.json"
PLC_IP = "192.168.95.2"
CUSTOM_SIDS = {1000001, 1000002, 1000003, 1000004, 1000006, 1000010}

# (container, the IP Suricata should see it from, read-only pymodbus call)
AUTHORIZED_ACTIONS = [
    ("HMI", "192.168.90.107", "c.read_coils(40, count=1)"),
    ("EWS", "192.168.95.5", "c.read_holding_registers(102, count=1)"),
]


def ensure_pymodbus(container: str) -> None:
    """HMI/EWS's image has no pymodbus (unlike kali's, which bundles it, see
    attacker/Dockerfile). Installs it into the running container's writable
    layer only, same way kali's image does it (apt, not pip: neither
    container has pip, and apt matches how the attacker image installs the
    same package). Not persisted, gone on the next container recreation."""
    check = subprocess.run(
        ["docker", "exec", container, "python3", "-c", "import pymodbus"],
        capture_output=True,
    )
    if check.returncode != 0:
        print(f"[*] Installing python3-pymodbus in {container} (test-only, not persisted in the image)...")
        subprocess.run(["docker", "exec", container, "apt-get", "update", "-qq"], check=True)
        subprocess.run(
            ["docker", "exec", container, "apt-get", "install", "-y", "-qq", "--no-install-recommends", "python3-pymodbus"],
            check=True,
        )


def send_authorized_action(container: str, call: str) -> None:
    # HMI/EWS's apt-installed pymodbus is an older 2.x release with a
    # different import path (pymodbus.client.sync) than kali's 3.x
    # (pymodbus.client). Try the modern path first, fall back to the old one,
    # so this keeps working regardless of which version apt happens to pull.
    code = (
        "try:\n"
        "    from pymodbus.client import ModbusTcpClient\n"
        "except ImportError:\n"
        "    from pymodbus.client.sync import ModbusTcpClient\n"
        f"c = ModbusTcpClient('{PLC_IP}', port=502)\n"
        "c.connect()\n"
        f"{call}\n"
        "c.close()\n"
    )
    subprocess.run(["docker", "exec", container, "python3", "-c", code], check=True, capture_output=True)


def parse_ts(ts: str) -> float:
    return datetime.fromisoformat(ts).timestamp()


def read_eve_events_since(cutoff: float) -> list[dict]:
    events = []
    with open(EVE_LOG) as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = event.get("timestamp")
            if not ts:
                continue
            try:
                if parse_ts(ts) >= cutoff:
                    events.append(event)
            except ValueError:
                continue
    return events


def main() -> None:
    cutoff = time.time()

    for container, src_ip, call in AUTHORIZED_ACTIONS:
        ensure_pymodbus(container)
        print(f"[*] Sending authorized read from {container} ({src_ip})...")
        send_authorized_action(container, call)

    print("[*] Waiting for eve.json to flush...")
    time.sleep(5)

    events = read_eve_events_since(cutoff)
    authorized_ips = {ip for _, ip, _ in AUTHORIZED_ACTIONS}
    seen_from_authorized = [e for e in events if e.get("src_ip") in authorized_ips]
    false_alarms = [
        e for e in seen_from_authorized
        if e.get("event_type") == "alert" and e.get("alert", {}).get("signature_id") in CUSTOM_SIDS
    ]

    print(f"\n{len(seen_from_authorized)} events observed from authorized sources in the test window.")

    if not seen_from_authorized:
        print(
            "[FAIL] No traffic observed at all from authorized sources in this window. "
            "This test proves nothing until Suricata is confirmed to actually be seeing this "
            "traffic, check the lab is up and Suricata is running on the physical NIC."
        )
        sys.exit(1)

    if false_alarms:
        print(f"[FAIL] {len(false_alarms)} custom-SID alert(s) fired on authorized traffic:")
        for e in false_alarms:
            print(f"    sid {e['alert']['signature_id']} from {e.get('src_ip')}: {e['alert'].get('signature')}")
        sys.exit(1)

    print("[PASS] No custom-SID alerts fired on authorized traffic from HMI or EWS.")
    sys.exit(0)


if __name__ == "__main__":
    main()
