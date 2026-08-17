---
name: suricata-rules
description: Work on the custom Suricata detection rules for the GRFICSv3 lab. Trigger when the user wants to view, edit, add, validate, or reload rules in local.rules, understand what a SID detects, or troubleshoot a rule that is not firing or not validating. Covers the rule catalog, authorized sources, and the mandatory validate-before-reload workflow.
---

# GRFICSv3 Suricata Rules

> **Privilege note for Claude Code:** the rules file and Suricata's binaries are root-owned, so editing, validating, and reloading all require sudo. Commands marked **[USER RUNS]** must be run by Nathaniel. Claude Code cannot run sudo. Claude Code CAN still help fully with rule authoring: it can read a copy of the rules, draft new rule text, explain syntax, and check logic. It just cannot write the file or restart Suricata itself. Workflow: Claude Code drafts the rule text, Nathaniel pastes it in and runs the sudo steps.

Custom detection rules live in `/var/lib/suricata/rules/local.rules`. This is Layer 2 (author-owned custom rules), separate from `/var/lib/suricata/rules/suricata.rules` (Layer 1, the community Emerging Threats set that `suricata-update` overwrites). Never put custom rules in the Layer 1 file, they get wiped on the next update.

## Current rule catalog

| SID | Detects | Match logic |
|------|---------|-------------|
| 1000001 | Unauthorized coil write | `modbus:access write coils` from non-HMI/EWS to PLC |
| 1000002 | Unauthorized holding register write | `modbus:access write holding` from non-HMI/EWS to PLC |
| 1000003 | Unauthorized program upload | HTTP POST to `/upload-program-action` on port 8080 from non-EWS |
| 1000004 | Broad Modbus write / replay | `modbus:access write` (any table) from unauthorized source |
| 1000006 | Recon / port scan | 10 SYN packets to port 502 in 10 seconds from one source |
| 1000010 | Broad catch-all | any Modbus from non-authorized source to PLC |

SID 1000005 (ARP spoofing) was designed but abandoned: Suricata 7.0.3 does not implement `alert arp` signatures despite the config toggle existing. Do not re-attempt an ARP rule without first confirming the installed Suricata version supports it.

Custom SIDs use the 1000000+ range by convention to avoid collision with community rules. The catch-all uses 1000010 (a gap above the surgical rules) to stay visually separate in the file.

## Authorized sources (baked into the rules)

- HMI: `192.168.90.107` (authorized for coil writes during operator actions)
- EWS: `192.168.95.5` (authorized for coil writes, register writes, and program uploads)
- PLC (destination): `192.168.95.2`
- Kali attacker: `192.168.90.6` (never authorized)

Rules use negated source lists like `![192.168.90.107,192.168.95.5]` to mean "anything that is not the HMI or EWS." Note there is no space inside the bracket list, Suricata rejects `[192.168.90.107, 192.168.95.5]` with a space.

## Rule anatomy

```
action protocol src_ip src_port direction dst_ip dst_port (options)
alert  modbus  ![192.168.90.107,192.168.95.5] any -> 192.168.95.2 502 (modbus:access write coils; msg:"Unauthorized Coil Write!"; sid:1000001; rev:1;)
```

- **action**: `alert` for IDS mode. `drop` would be IPS mode (not currently used).
- **protocol**: `modbus` for app-layer Modbus matching, or `tcp` for lower-level matching (used by the HTTP and recon rules).
- **src_port**: almost always `any`, since an attacker can source from any port. Using `502` here is a common mistake.
- **direction**: `->` one-way, toward the PLC.
- **options**: every option ends with a semicolon, including the last one before the closing paren (`rev:1;)` not `rev:1)`). Missing trailing semicolons and spaces in IP lists are the two most common syntax errors.

## Two ways to match Modbus operations

- **By access type** (preferred, more robust): `modbus:access write coils` matches any write to the coils table regardless of specific function code. Can narrow further: `modbus:access write holding, address 500, value >200`.
- **By function code** (more specific): `modbus:function 5` matches FC5 exactly. Use when a single function code is the target.

## Mandatory workflow: validate before reload

Never restart Suricata on an edited ruleset without validating first. A syntax error takes Suricata down live.

### 1. Edit the rules [USER RUNS]

```bash
sudo nano /var/lib/suricata/rules/local.rules
```

- `sudo` because the file is root-owned.
- `nano` is the editor in use here. Save with Ctrl+O then Ctrl+X.

Claude Code can draft the exact rule text to paste here, it just cannot write the file itself.

### 2. Validate (dry run) [USER RUNS]

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

- `-T` test mode: loads the full config and every rule, reports any error with its file and line, then exits without capturing. This is the safety gate.
- `-c /etc/suricata/suricata.yaml` the config to test.
- `-v` verbose, so a failure names exactly what and where.

Only proceed if this reports no errors. If it errors, Nathaniel can paste the error output back to Claude Code for diagnosis.

### 3. Reload live [USER RUNS]

If Suricata is running, stop it (`Ctrl+C` in its terminal) and restart:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eno1
```

Note the absence of `-T` here, this is live capture on the `eno1` macvlan parent interface.

### 4. Confirm the rule fires [USER RUNS for the tail; attack may be CLAUDE OK]

Trigger the matching attack (see the attack-testing skill) and watch:

```bash
sudo tail -f /var/log/suricata/fast.log
```

The alert line should name the SID you just edited.

## Config dependencies

- Modbus detection must be enabled in `/etc/suricata/suricata.yaml` (the Modbus app-layer parser block set to `enabled: yes`, and `detection-ports: dp: 502`). Without this, `modbus:` keyword rules will not match.
- `HOME_NET` in the config `vars` section is scoped to the two lab subnets `192.168.95.0/24` (ICS) and `192.168.90.0/24` (DMZ), so `$HOME_NET` and `$EXTERNAL_NET` resolve correctly for the lab rather than generic private ranges.
- A config backup exists at `/etc/suricata/suricata.yaml.bak`. Restore from it if an edit breaks the config beyond quick repair.
