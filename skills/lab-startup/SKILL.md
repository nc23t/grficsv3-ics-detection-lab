---
name: lab-startup
description: Start, stop, or restart the full GRFICSv3 lab stack (simulation, Suricata, AI pipeline, dashboard). Trigger when the user wants to bring the lab up or down, spin up the simulation, launch the dashboard, start Suricata for this lab, or troubleshoot why a layer is not seeing traffic or alerts. Covers the required startup ordering and the shutdown sequence.
---

# GRFICSv3 Lab Startup and Shutdown

The lab is a four-layer stack. Each layer depends on the one below it being live. Starting out of order fails silently in ways that look like bugs, so ordering is not optional.

> **Privilege note for Claude Code:** commands marked **[USER RUNS]** require sudo and must be run by Nathaniel in his own terminal. Claude Code cannot run sudo. When one of these steps is reached, hand the command to Nathaniel and wait, do not attempt it. Steps not marked can be run by either.

## Startup order

Bring these up in sequence, each in its own terminal.

### 1. Simulation layer (GRFICSv3 containers) [USER RUNS]

```bash
cd <repo-root> && sudo docker-compose up
```

- `cd <repo-root>` moves into the project directory because `docker-compose` reads `docker-compose.yml` from the current working directory.
- `sudo` is required because Docker needs root on this setup (the user is not in the `docker` group).
- `docker-compose up` starts every container in the compose file (PLC, HMI, EWS, router, ScadaLTS, workstation) and streams their logs to the terminal.

Wait 30 to 60 seconds for containers to reach a healthy state before starting the next layer. Add `-d` for detached (background) mode if the terminal is needed, at the cost of not seeing live logs.

### 2. Detection layer (Suricata) [USER RUNS]

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eno1
```

- `sudo` because raw packet capture needs root.
- `-c /etc/suricata/suricata.yaml` points at the config file.
- `-i eno1` binds to the physical NIC. This must be the parent physical interface, not a Docker bridge, because the ICS and DMZ networks are macvlan and are invisible to the host's normal stack. Suricata on a bridge interface sees nothing.

### 3. Enrichment layer (AI pipeline)

This one does not need sudo and can be run by Claude Code, provided the API key is already exported in the same shell session.

```bash
export ANTHROPIC_API_KEY="sk-ant-REPLACE-WITH-REAL-KEY" && python3 ics_alert_pipeline.py
```

- `export ANTHROPIC_API_KEY=...` sets the key for this shell session only. The pipeline reads it via `os.environ.get()` at startup. Nathaniel supplies the real key; Claude Code should never insert or request it, and should assume Nathaniel has exported it in the target terminal.
- `&&` chains so the pipeline launches only if the export succeeded.
- The script tails `/var/log/suricata/eve.json`, enriches each alert via Claude, and serves results on `http://localhost:5000`.

Note: because environment variables do not cross between separate shell sessions, the pipeline must be launched in the same terminal where the key was exported. If Claude Code launches it in a different subshell than the one Nathaniel exported into, the key will not carry over and the pipeline will warn that it is unset.

On success it prints a Claude-connected line and a Flask server line. If it prints `[!] WARNING: ANTHROPIC_API_KEY not set`, the export did not reach this session.

### 4. Presentation layer (dashboard)

```bash
xdg-open dashboard.html
```

- `xdg-open` opens the file in the system default application. For `.html`, that is the default browser.
- The dashboard polls `http://localhost:5000/alerts` every 3 seconds and renders enriched alerts.

### Optional: live alert tail [USER RUNS]

```bash
sudo tail -f /var/log/suricata/fast.log
```

- `tail` prints the end of a file; `-f` follows it, streaming new lines as they are written.
- `sudo` because Suricata's logs are root-owned.
- Useful for confirming alerts fire the instant an attack triggers, independent of the dashboard.

## Shutdown order (reverse of startup)

1. Close the browser tab.
2. `Ctrl+C` in the tail terminal (if running). **[USER RUNS]** the terminal that holds the sudo tail.
3. `Ctrl+C` in the pipeline terminal.
4. `Ctrl+C` in the Suricata terminal. **[USER RUNS]**
5. Stop the containers **[USER RUNS]**:

```bash
cd <repo-root> && sudo docker-compose down
```

- `docker-compose down` stops and removes the containers while keeping their volumes. Works from any terminal in the project directory, including when the stack was started with `-d`.

## Troubleshooting the "silent failure" symptoms

- **Suricata sees no traffic:** containers not up yet, or Suricata bound to the wrong interface (must be `eno1`, the macvlan parent).
- **Pipeline processes zero alerts:** API key not exported into the pipeline's own shell session, or Suricata not actually writing to `eve.json` (confirm Suricata started without `-T`, since `-T` is validate-and-exit, not live capture).
- **Dashboard timeline empty:** pipeline not running, or opened before the pipeline started. Refresh after the pipeline is up.
