#!/usr/bin/env bash
# lab.sh: one-command control for the GRFICSv3 detection lab.
#
# Usage:
#   scripts/lab.sh setup-key        store your Anthropic API key once (hidden prompt)
#   scripts/lab.sh up [--no-browser]  start every layer, skipping ones already running
#   scripts/lab.sh status           read-only health report (no sudo)
#   scripts/lab.sh logs             follow Suricata's human-readable alert log
#   scripts/lab.sh down [--keep-containers]   stop everything in reverse order
#
# Layers, in dependency order:
#   1. Simulation  (Docker containers)
#   2. Detection   (Suricata on the physical NIC)
#   3. Enrichment  (ics_alert_pipeline.py, Flask on localhost)
#   4. Presentation (dashboard.html, opened as a local file)
#
# Nothing here hardcodes a home or project path: the repo root comes from this
# script's own location, and every setting below can be overridden with an
# environment variable or the optional config file.

set -euo pipefail

# ─── CONFIG (override via env vars or ~/.config/grficsv3/lab.conf) ───────────

LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF_DIR="${LAB_CONF_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/grficsv3}"
STATE_DIR="${LAB_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/grficsv3}"

# Optional overrides file; sourced before defaults are applied.
if [[ -f "$CONF_DIR/lab.conf" ]]; then
    # shellcheck disable=SC1091
    . "$CONF_DIR/lab.conf"
fi

LAB_IFACE="${LAB_IFACE:-eno1}"                       # physical NIC (macvlan parent)
SURICATA_CONF="${SURICATA_CONF:-/etc/suricata/suricata.yaml}"
SURICATA_PIDFILE="${SURICATA_PIDFILE:-/run/suricata-lab.pid}"
EVE_LOG="${EVE_LOG:-/var/log/suricata/eve.json}"
FAST_LOG="${FAST_LOG:-/var/log/suricata/fast.log}"
PIPELINE_PORT="${PIPELINE_PORT:-5000}"
KEY_FILE="${LAB_KEY_FILE:-$CONF_DIR/env}"            # holds ANTHROPIC_API_KEY, mode 600
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-120}"              # seconds to wait for containers
REQUIRED_CONTAINERS=(simulation plc HMI EWS router)  # caldera is not required

PIPELINE_LOG="$STATE_DIR/pipeline.log"
PIPELINE_PID="$STATE_DIR/pipeline.pid"
STATUS_URL="http://127.0.0.1:${PIPELINE_PORT}/status"

# ─── HELPERS ─────────────────────────────────────────────────────────────────

RESULTS=()      # summary lines printed at the end of `up`
FAILED=0

say()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }
record() { RESULTS+=("$1"); }
fail()   { FAILED=1; record "$1"; warn "$1"; }

# docker compose v2 is a plugin ("docker compose"); v1 is a separate binary.
compose() {
    if docker compose version >/dev/null 2>&1; then
        docker compose -f "$LAB_ROOT/docker-compose.yml" "$@"
    else
        docker-compose -f "$LAB_ROOT/docker-compose.yml" "$@"
    fi
}

container_health() {
    # Prints the health status, or the run state for containers with no healthcheck.
    docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
        "$1" 2>/dev/null || echo "missing"
}

suricata_running() {
    # A process named Suricata-Main is not enough: the packaged systemd unit
    # also runs under this name, often bound to a placeholder interface like
    # eth0. Only count an instance that is actually capturing on LAB_IFACE.
    local pid
    for pid in $(pgrep -x Suricata-Main 2>/dev/null); do
        if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q -- "-i $LAB_IFACE"; then
            return 0
        fi
    done
    return 1
}

pipeline_running() {
    # -f (fail on HTTP errors) and -s (silent), -m 2 caps the wait at 2 seconds.
    curl -fsm 2 "$STATUS_URL" >/dev/null 2>&1
}

pid_alive() {
    [[ -n "${1:-}" && -d "/proc/$1" ]]
}

# ─── setup-key ───────────────────────────────────────────────────────────────

cmd_setup_key() {
    if [[ -f "$KEY_FILE" ]]; then
        read -rp "A key file already exists. Overwrite it? [y/N] " answer
        [[ "$answer" =~ ^[Yy]$ ]] || die "Left the existing key file untouched."
    fi

    # -r keeps backslashes literal, -s hides typing so the key never shows on screen
    # or in scrollback. The value is never passed as an argument, so it stays out of
    # shell history and the process list.
    read -rsp "Paste your Anthropic API key (input hidden): " key
    printf '\n'
    [[ -n "$key" ]] || die "No key entered."
    [[ "$key" == sk-ant-* ]] || die "That does not look like an Anthropic key (expected an sk-ant- prefix). Nothing saved."

    umask 077   # new files get mode 600, new directories mode 700
    mkdir -p "$CONF_DIR"
    printf "ANTHROPIC_API_KEY='%s'\n" "$key" > "$KEY_FILE"
    chmod 600 "$KEY_FILE"
    unset key
    say "Saved to the private config folder (mode 600). The key is never stored in the repo."
}

# ─── up ──────────────────────────────────────────────────────────────────────

preflight() {
    command -v docker >/dev/null || die "docker not found on PATH."
    docker info >/dev/null 2>&1 || die "Cannot talk to Docker (is the daemon up and your user in the docker group?)."
    python3 - <<'PY' 2>/dev/null || die "Missing Python packages. Run: pip install flask flask-cors anthropic --break-system-packages"
import flask, flask_cors, anthropic  # noqa: F401
PY
    ip link show "$LAB_IFACE" >/dev/null 2>&1 || die "Interface '$LAB_IFACE' not found. Set LAB_IFACE to your physical NIC."

    [[ -f "$KEY_FILE" ]] || die "No API key file. Run: scripts/lab.sh setup-key"
    local mode
    mode="$(stat -c '%a' "$KEY_FILE")"
    [[ "$mode" == "600" ]] || die "Key file permissions are $mode, expected 600. Run: chmod 600 on the key file."
    grep -q '^ANTHROPIC_API_KEY=' "$KEY_FILE" || die "Key file does not define ANTHROPIC_API_KEY."
}

start_sudo_keepalive() {
    say "Sudo is needed for Suricata. Enter your password once."
    sudo -v                       # -v refreshes the cached credentials (prompts if needed)
    # Refresh every 50s so the cache does not expire while containers boot.
    ( while true; do sudo -n true; sleep 50; kill -0 "$$" 2>/dev/null || exit; done ) &
    KEEPALIVE_PID=$!
    trap 'kill "$KEEPALIVE_PID" 2>/dev/null || true' EXIT
}

start_containers() {
    mkdir -p "$STATE_DIR"
    local compose_log="$STATE_DIR/compose.log" compose_ok=1
    say "Starting containers (detached, output in $compose_log)..."
    # Keep Docker's own output so a failure is diagnosable. A non-zero exit does not
    # stop us: an optional container (caldera) can fail or start slowly while the
    # required ones are fine, so the real test is the health check below.
    compose up -d >"$compose_log" 2>&1 || compose_ok=0
    if (( ! compose_ok )); then
        warn "docker compose reported an error; last lines:"
        tail -n 8 "$compose_log" >&2
    fi

    say "Waiting up to ${HEALTH_TIMEOUT}s for containers to report healthy..."
    local deadline=$((SECONDS + HEALTH_TIMEOUT)) pending c s
    while (( SECONDS < deadline )); do
        pending=()
        for c in "${REQUIRED_CONTAINERS[@]}"; do
            s="$(container_health "$c")"
            [[ "$s" == "healthy" ]] || pending+=("$c=$s")
        done
        if (( ${#pending[@]} == 0 )); then
            if (( compose_ok )); then
                record "containers : up and healthy (${REQUIRED_CONTAINERS[*]})"
            else
                record "containers : required ones healthy, but compose reported an error (see $compose_log; caldera is optional, now: $(container_health caldera))"
            fi
            return 0
        fi
        sleep 3
    done
    fail "containers : not healthy after ${HEALTH_TIMEOUT}s (${pending[*]}). Try: docker restart simulation"
    return 1
}

start_suricata() {
    if suricata_running; then
        record "suricata   : already running (skipped)"
        return 0
    fi

    # The packaged systemd unit captures on the interface named in suricata.yaml
    # (often a placeholder like eth0), so it can sit in a restart loop and compete
    # with our capture on the real NIC. Stop it for this session (runtime only).
    case "$(systemctl is-active suricata 2>/dev/null || true)" in
        active|activating)
            say "Stopping the system suricata service (it is not bound to $LAB_IFACE)..."
            sudo systemctl stop suricata || true
            ;;
    esac

    say "Starting Suricata on $LAB_IFACE..."
    # -D daemonizes so no terminal is held, -c is the config, -i binds the capture
    # interface, --pidfile lets `down` stop exactly this instance.
    if ! sudo suricata -D -c "$SURICATA_CONF" -i "$LAB_IFACE" --pidfile "$SURICATA_PIDFILE" >/dev/null 2>&1; then
        fail "suricata   : failed to start (validate with: sudo suricata -T -c $SURICATA_CONF -v)"
        return 1
    fi

    # Rule loading takes a few seconds; the daemon exits early on a bad config.
    local i
    for i in $(seq 1 15); do
        suricata_running && break
        sleep 1
    done
    sleep 2
    if suricata_running; then
        record "suricata   : running on $LAB_IFACE"
    else
        fail "suricata   : exited during startup (validate with: sudo suricata -T -c $SURICATA_CONF -v)"
        return 1
    fi
}

start_pipeline() {
    if pipeline_running; then
        record "pipeline   : already running (skipped)"
        return 0
    fi

    mkdir -p "$STATE_DIR"
    say "Starting the AI pipeline (log: $PIPELINE_LOG)..."
    # The key is loaded inside this subshell only, so it never enters this script's
    # environment, argv, or shell history. nohup keeps the pipeline alive if the
    # terminal is closed.
    (
        set -a                      # export everything the key file defines
        # shellcheck disable=SC1090
        . "$KEY_FILE"
        set +a
        cd "$LAB_ROOT"
        exec nohup python3 ics_alert_pipeline.py >>"$PIPELINE_LOG" 2>&1
    ) &
    echo $! > "$PIPELINE_PID"

    local i
    for i in $(seq 1 20); do
        if curl -fsm 2 "$STATUS_URL" 2>/dev/null | grep -q '"api_connected": *true'; then
            record "pipeline   : running, Claude connected (http://127.0.0.1:${PIPELINE_PORT}/status)"
            return 0
        fi
        sleep 1
    done
    fail "pipeline   : did not report a Claude connection (see $PIPELINE_LOG)"
    return 1
}

open_dashboard() {
    # The dashboard is a local file that polls the API; it is not served on the
    # pipeline port, so open the file itself.
    if command -v xdg-open >/dev/null; then
        xdg-open "$LAB_ROOT/dashboard.html" >/dev/null 2>&1 &
        record "dashboard  : opened dashboard.html in your browser"
    else
        record "dashboard  : xdg-open not found; open dashboard.html manually"
    fi
}

cmd_up() {
    local open_browser=1
    [[ "${1:-}" == "--no-browser" ]] && open_browser=0

    preflight
    start_sudo_keepalive

    start_containers || true
    start_suricata   || true
    start_pipeline   || true
    (( open_browser )) && open_dashboard

    printf '\n=== lab summary ===\n'
    printf '%s\n' "${RESULTS[@]}"
    printf '\nFollow alerts:  scripts/lab.sh logs\nHealth check:   scripts/lab.sh status\n'
    (( FAILED == 0 )) || { warn "One or more layers failed. See the messages above."; exit 1; }
}

# ─── status (read-only, no sudo) ─────────────────────────────────────────────

cmd_status() {
    local c s
    printf 'Containers:\n'
    for c in "${REQUIRED_CONTAINERS[@]}"; do
        printf '  %-11s %s\n' "$c" "$(container_health "$c")"
    done

    printf 'Suricata:\n'
    if suricata_running; then printf '  running\n'; else printf '  NOT running\n'; fi

    if [[ -r "$EVE_LOG" ]]; then
        s=$(( $(date +%s) - $(stat -c %Y "$EVE_LOG") ))
        printf '  eve.json last written %ss ago\n' "$s"
    else
        printf '  eve.json not readable without sudo (skipped)\n'
    fi

    printf 'Pipeline:\n'
    if pipeline_running; then
        curl -fsm 2 "$STATUS_URL"; printf '\n'
    else
        printf '  NOT running\n'
    fi
}

# ─── logs ────────────────────────────────────────────────────────────────────

cmd_logs() {
    # tail prints the end of a file, -f follows it as new lines arrive, sudo is
    # needed because Suricata's logs are root-owned.
    exec sudo tail -f "$FAST_LOG"
}

# ─── down ────────────────────────────────────────────────────────────────────

cmd_down() {
    local keep=0
    [[ "${1:-}" == "--keep-containers" ]] && keep=1

    # Reverse of startup: presentation is just a browser tab, so start at the pipeline.
    if [[ -f "$PIPELINE_PID" ]] && pid_alive "$(cat "$PIPELINE_PID")"; then
        say "Stopping pipeline..."
        kill "$(cat "$PIPELINE_PID")" 2>/dev/null || true
    elif pipeline_running; then
        say "Stopping pipeline (started outside this script)..."
        pkill -f ics_alert_pipeline.py || true
    fi
    rm -f "$PIPELINE_PID"

    if suricata_running; then
        say "Stopping Suricata (sudo)..."
        if [[ -r "$SURICATA_PIDFILE" ]]; then
            sudo kill "$(cat "$SURICATA_PIDFILE")" || true
        else
            # Fallback: match only our own invocation, so a broken systemd
            # instance on another interface is left alone.
            sudo pkill -f -- "-i $LAB_IFACE --pidfile $SURICATA_PIDFILE" || true
        fi
    fi

    if (( keep )); then
        say "Leaving containers running (--keep-containers)."
    else
        say "Stopping containers..."
        compose down
    fi
    say "Done."
}

# ─── dispatch ────────────────────────────────────────────────────────────────

case "${1:-}" in
    setup-key) cmd_setup_key ;;
    up)        shift; cmd_up "$@" ;;
    status)    cmd_status ;;
    logs)      cmd_logs ;;
    down)      shift; cmd_down "$@" ;;
    *)
        sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
        exit 1
        ;;
esac
