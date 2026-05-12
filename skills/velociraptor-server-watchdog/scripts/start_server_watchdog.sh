#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
WORKSPACE_DIR="${REPO_ROOT}/velociraptor"
VELOCIRAPTOR_BIN="${WORKSPACE_DIR}/velociraptor"
SERVER_CONFIG="${WORKSPACE_DIR}/server.config.yaml"
API_CLIENT_CONFIG="${WORKSPACE_DIR}/api_client.yaml"
SUPERVISOR_SCRIPT="${SCRIPT_DIR}/supervise_server.sh"
SUPERVISOR_PID_FILE="${WORKSPACE_DIR}/server-supervisor.pid"
SUPERVISOR_LOG="${WORKSPACE_DIR}/server-supervisor.log"
STATUS_FILE="${WORKSPACE_DIR}/server-status.env"
SESSION_FILE="${WORKSPACE_DIR}/server-session.env"
SERVER_PID_FILE="${WORKSPACE_DIR}/gui.pid"
SUPERVISOR_LOOP_SECONDS=15
START_WAIT_SECONDS=20
HEALTH_FAILURE_THRESHOLD=2

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
error()   { echo "[ERROR] $*" >&2; exit 1; }

write_env_line() {
    local key="$1"
    local value="${2-}"
    printf '%s=%q\n' "$key" "$value"
}

usage() {
    printf '%s\n' \
        "Usage:" \
        " ./skills/velociraptor-server-watchdog/scripts/start_server_watchdog.sh" \
        ""
    exit 0
}

require_cmd() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || error "Required command not found: $cmd"
    done
}

read_yaml_section_value() {
    local file="$1"
    local section="$2"
    local key="$3"

    awk -v section="$section" -v key="$key" '
        $0 ~ ("^" section ":") { in_section=1; next }
        in_section && $0 ~ /^[^[:space:]]/ { in_section=0 }
        in_section {
            gsub(/^[[:space:]]+/, "", $0)
            if ($0 ~ ("^" key ":")) {
                sub("^" key ":[[:space:]]*", "", $0)
                print $0
                exit
            }
        }
    ' "$file"
}

gui_host() {
    local host=""
    host="$(read_yaml_section_value "$SERVER_CONFIG" "GUI" "bind_address" || true)"
    case "$host" in
        ""|0.0.0.0|::) echo "127.0.0.1" ;;
        *) echo "$host" ;;
    esac
}

gui_port() {
    local port=""
    port="$(read_yaml_section_value "$SERVER_CONFIG" "GUI" "bind_port" || true)"
    echo "${port:-8889}"
}

api_port() {
    local port=""
    port="$(read_yaml_section_value "$SERVER_CONFIG" "API" "bind_port" || true)"
    echo "${port:-8001}"
}

frontend_port() {
    local port=""
    port="$(read_yaml_section_value "$SERVER_CONFIG" "Frontend" "bind_port" || true)"
    echo "${port:-8000}"
}

gui_url() {
    printf 'https://%s:%s/app/index.html' "$(gui_host)" "$(gui_port)"
}

listener_running() {
    local port="$1"

    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
        return $?
    fi

    if command -v nc >/dev/null 2>&1; then
        nc -z "$(gui_host)" "$port" >/dev/null 2>&1
        return $?
    fi

    return 1
}

server_query_ok() {
    "$VELOCIRAPTOR_BIN" -a "$API_CLIENT_CONFIG" --runas api \
        query --format json "SELECT 1 AS ok FROM scope()" >/dev/null 2>&1
}

server_ready() {
    listener_running "$(frontend_port)" &&
        listener_running "$(api_port)" &&
        listener_running "$(gui_port)" &&
        server_query_ok
}

current_supervisor_pid() {
    local pid=""
    pid="$(cat "$SUPERVISOR_PID_FILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
        printf '%s\n' "$pid"
        return 0
    fi

    if command -v pgrep >/dev/null 2>&1; then
        pid="$(pgrep -f "supervise_server.sh ${WORKSPACE_DIR} ${API_CLIENT_CONFIG}" | head -n 1 || true)"
        if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
            printf '%s\n' "$pid" >"$SUPERVISOR_PID_FILE"
            printf '%s\n' "$pid"
            return 0
        fi
    fi
}

current_server_pid() {
    local pid=""
    pid="$(cat "$SERVER_PID_FILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
        printf '%s\n' "$pid"
        return 0
    fi

    if command -v lsof >/dev/null 2>&1; then
        pid="$(lsof -t -iTCP:"$(api_port)" -sTCP:LISTEN 2>/dev/null | head -n 1 || true)"
        if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
            printf '%s\n' "$pid" >"$SERVER_PID_FILE"
            printf '%s\n' "$pid"
            return 0
        fi
    fi

    return 1
}

write_session_file() {
    local supervisor_pid="$1"
    local server_pid="$2"

    {
        write_env_line "GUI_URL" "$(gui_url)"
        write_env_line "GUI_HOST" "$(gui_host)"
        write_env_line "GUI_PORT" "$(gui_port)"
        write_env_line "API_PORT" "$(api_port)"
        write_env_line "FRONTEND_PORT" "$(frontend_port)"
        write_env_line "SERVER_PID" "$server_pid"
        write_env_line "SUPERVISOR_PID" "$supervisor_pid"
        write_env_line "SUPERVISOR_LOOP_SECONDS" "$SUPERVISOR_LOOP_SECONDS"
        write_env_line "START_WAIT_SECONDS" "$START_WAIT_SECONDS"
        write_env_line "HEALTH_FAILURE_THRESHOLD" "$HEALTH_FAILURE_THRESHOLD"
        write_env_line "STATUS_FILE" "$STATUS_FILE"
        write_env_line "STARTED_AT" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    } >"$SESSION_FILE"
}

wait_for_server_ready() {
    local tries=0

    while [ "$tries" -lt "$START_WAIT_SECONDS" ]; do
        if server_ready; then
            return 0
        fi
        sleep 1
        tries=$((tries + 1))
    done

    return 1
}

start_supervisor_if_needed() {
    local supervisor_pid=""

    supervisor_pid="$(current_supervisor_pid || true)"
    if [ -n "$supervisor_pid" ]; then
        info "Velociraptor server watchdog is already running with PID ${supervisor_pid}"
        return 0
    fi

    info "Starting Velociraptor server watchdog"
    (
        cd "$WORKSPACE_DIR"
        nohup bash "$SUPERVISOR_SCRIPT" \
            "$WORKSPACE_DIR" \
            "$API_CLIENT_CONFIG" \
            "$SUPERVISOR_LOOP_SECONDS" \
            "$START_WAIT_SECONDS" \
            "$HEALTH_FAILURE_THRESHOLD" >"$SUPERVISOR_LOG" 2>&1 &
        echo "$!" >"$SUPERVISOR_PID_FILE"
        disown "$!" 2>/dev/null || true
    )

    sleep 2
    supervisor_pid="$(current_supervisor_pid || true)"
    [ -n "$supervisor_pid" ] || error "Velociraptor server watchdog exited early. Check ${SUPERVISOR_LOG}"
}

if [ "${1-}" = "-h" ] || [ "${1-}" = "--help" ]; then
    usage
fi

require_cmd bash awk date grep nohup sed
[ -x "$VELOCIRAPTOR_BIN" ] || error "Velociraptor binary not found at ${VELOCIRAPTOR_BIN}. Run ./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t velociraptor first."
[ -f "$SERVER_CONFIG" ] || error "Velociraptor server config not found at ${SERVER_CONFIG}. Run ./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t velociraptor first."
[ -f "$API_CLIENT_CONFIG" ] || error "Velociraptor API config not found at ${API_CLIENT_CONFIG}. Run ./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t velociraptor first."
[ -x "$SUPERVISOR_SCRIPT" ] || error "Supervisor script is not executable: ${SUPERVISOR_SCRIPT}"

start_supervisor_if_needed

if ! wait_for_server_ready; then
    warn "Velociraptor server did not become healthy in ${START_WAIT_SECONDS}s"
    warn "Check watchdog log: ${SUPERVISOR_LOG}"
    exit 1
fi

write_session_file "$(current_supervisor_pid || true)" "$(current_server_pid || true)"
success "Velociraptor server is healthy at $(gui_url)"
info "Watchdog log: ${SUPERVISOR_LOG}"
info "Session file: ${SESSION_FILE}"
