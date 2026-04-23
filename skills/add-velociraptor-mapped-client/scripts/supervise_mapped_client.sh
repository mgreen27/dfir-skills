#!/usr/bin/env bash

set -uo pipefail

WORKSPACE_DIR="${1:?workspace dir required}"
CLIENT_NAME="${2:?client name required}"
CLIENT_DIR="${3:?client dir required}"
CLIENT_CONFIG="${4:?client config required}"
REMAP_FILE="${5:?remap file required}"
API_CLIENT_CONFIG="${6:?api client config required}"
SUPERVISOR_LOOP_SECONDS="${7:-15}"
STALE_SECONDS="${8:-90}"

VELOCIRAPTOR_BIN="${WORKSPACE_DIR}/velociraptor"
CLIENT_PID_FILE="${CLIENT_DIR}/client.pid"
STATUS_FILE="${CLIENT_DIR}/client-status.env"
CLIENT_LOG="${CLIENT_DIR}/client.log"

info() { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*"; }

write_status() {
    local state="$1"
    local detail="${2-}"
    {
        printf 'STATE=%q\n' "$state"
        printf 'DETAIL=%q\n' "$detail"
        printf 'UPDATED_AT=%q\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    } >"$STATUS_FILE"
}

regex_escape() {
    printf '%s' "$1" | sed -e 's/[][(){}.^$*+?|\/\\]/\\&/g'
}

client_last_seen_us() {
    local escaped_hostname=""
    local output=""
    escaped_hostname="$(regex_escape "$CLIENT_NAME")"
    output="$("$VELOCIRAPTOR_BIN" -a "$API_CLIENT_CONFIG" --runas api \
        query --format json \
        "SELECT client_id, last_seen_at FROM clients() WHERE os_info.hostname =~ '^${escaped_hostname}$' OR os_info.fqdn =~ '^${escaped_hostname}$' ORDER BY last_seen_at DESC LIMIT 1" \
        2>/dev/null || true)"

    printf '%s\n' "$output" | sed -n 's/.*"last_seen_at"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1
}

client_last_seen_age_seconds() {
    local last_seen_us=""
    local now_us=""
    last_seen_us="$(client_last_seen_us)"
    if [ -z "$last_seen_us" ]; then
        return 1
    fi
    now_us="$(( $(date +%s) * 1000000 ))"
    printf '%s\n' "$(( (now_us - last_seen_us) / 1000000 ))"
}

current_client_pid() {
    cat "$CLIENT_PID_FILE" 2>/dev/null || true
}

client_running() {
    local pid=""
    pid="$(current_client_pid)"
    [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1
}

start_client() {
    info "Starting mapped client ${CLIENT_NAME}"
    (
        cd "$WORKSPACE_DIR"
        nohup ./velociraptor client -v --config "$CLIENT_CONFIG" --remap "$REMAP_FILE" >>"$CLIENT_LOG" 2>&1 &
        echo "$!" >"$CLIENT_PID_FILE"
    )
    write_status "starting" "spawned client pid $(current_client_pid)"
}

stop_client() {
    local pid=""
    pid="$(current_client_pid)"
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
        warn "Stopping stale mapped client ${CLIENT_NAME} pid ${pid}"
        kill "$pid" >/dev/null 2>&1 || true
        sleep 1
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill -9 "$pid" >/dev/null 2>&1 || true
        fi
    fi
    rm -f "$CLIENT_PID_FILE"
}

write_status "starting" "initializing supervisor"

while true; do
    if ! client_running; then
        start_client
        sleep 5
    fi

    if client_running; then
        if age="$(client_last_seen_age_seconds)"; then
            if [ "$age" -gt "$STALE_SECONDS" ]; then
                write_status "stale" "last seen ${age}s ago"
                stop_client
                sleep 2
                start_client
                sleep 5
            else
                write_status "online" "last seen ${age}s ago"
            fi
        else
            write_status "waiting" "client record not visible yet"
        fi
    fi

    sleep "$SUPERVISOR_LOOP_SECONDS"
done
