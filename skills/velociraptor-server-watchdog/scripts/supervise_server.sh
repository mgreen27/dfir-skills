#!/usr/bin/env bash

set -uo pipefail

WORKSPACE_DIR="${1:?workspace dir required}"
API_CLIENT_CONFIG="${2:?api client config required}"
SUPERVISOR_LOOP_SECONDS="${3:-15}"
START_WAIT_SECONDS="${4:-20}"
HEALTH_FAILURE_THRESHOLD="${5:-2}"

VELOCIRAPTOR_BIN="${WORKSPACE_DIR}/velociraptor"
SERVER_CONFIG="${WORKSPACE_DIR}/server.config.yaml"
GUI_LOG="${WORKSPACE_DIR}/gui.log"
SERVER_PID_FILE="${WORKSPACE_DIR}/gui.pid"
SUPERVISOR_PID_FILE="${WORKSPACE_DIR}/server-supervisor.pid"
STATUS_FILE="${WORKSPACE_DIR}/server-status.env"
SESSION_FILE="${WORKSPACE_DIR}/server-session.env"

info() { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*"; }

write_env_line() {
    local key="$1"
    local value="${2-}"
    printf '%s=%q\n' "$key" "$value"
}

write_session_file() {
    {
        write_env_line "GUI_URL" "https://$(gui_host):$(gui_port)/app/index.html"
        write_env_line "GUI_HOST" "$(gui_host)"
        write_env_line "GUI_PORT" "$(gui_port)"
        write_env_line "API_PORT" "$(api_port)"
        write_env_line "FRONTEND_PORT" "$(frontend_port)"
        write_env_line "SERVER_PID" "$(current_server_pid 2>/dev/null || true)"
        write_env_line "SUPERVISOR_PID" "$$"
        write_env_line "SUPERVISOR_LOOP_SECONDS" "$SUPERVISOR_LOOP_SECONDS"
        write_env_line "START_WAIT_SECONDS" "$START_WAIT_SECONDS"
        write_env_line "HEALTH_FAILURE_THRESHOLD" "$HEALTH_FAILURE_THRESHOLD"
        write_env_line "STATUS_FILE" "$STATUS_FILE"
        write_env_line "STARTED_AT" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    } >"$SESSION_FILE"
}

write_status() {
    local state="$1"
    local detail="${2-}"
    {
        printf 'STATE=%q\n' "$state"
        printf 'DETAIL=%q\n' "$detail"
        printf 'UPDATED_AT=%q\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    } >"$STATUS_FILE"
    write_session_file
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

register_supervisor() {
    local existing_pid=""
    existing_pid="$(cat "$SUPERVISOR_PID_FILE" 2>/dev/null || true)"
    if [ -n "$existing_pid" ] && [ "$existing_pid" != "$$" ] && kill -0 "$existing_pid" >/dev/null 2>&1; then
        info "Velociraptor server watchdog already running with PID ${existing_pid}"
        exit 0
    fi

    printf '%s\n' "$$" >"$SUPERVISOR_PID_FILE"
}

cleanup_supervisor_pid_file() {
    local registered_pid=""
    registered_pid="$(cat "$SUPERVISOR_PID_FILE" 2>/dev/null || true)"
    if [ "$registered_pid" = "$$" ]; then
        rm -f "$SUPERVISOR_PID_FILE"
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

server_running() {
    local pid=""
    pid="$(current_server_pid 2>/dev/null || true)"
    [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1
}

server_query_ok() {
    "$VELOCIRAPTOR_BIN" -a "$API_CLIENT_CONFIG" --runas api \
        query --format json "SELECT 1 AS ok FROM scope()" >/dev/null 2>&1
}

server_healthy() {
    listener_running "$(frontend_port)" &&
        listener_running "$(api_port)" &&
        listener_running "$(gui_port)" &&
        server_query_ok
}

wait_for_server_ready() {
    local tries=0

    while [ "$tries" -lt "$START_WAIT_SECONDS" ]; do
        if server_healthy; then
            return 0
        fi
        sleep 1
        tries=$((tries + 1))
    done

    return 1
}

start_server() {
    info "Starting Velociraptor GUI server"
    (
        cd "$WORKSPACE_DIR"
        nohup ./velociraptor gui -v --datastore=. --nobrowser --noclient >>"$GUI_LOG" 2>&1 &
        echo "$!" >"$SERVER_PID_FILE"
    )
    write_status "starting" "spawned server pid $(cat "$SERVER_PID_FILE" 2>/dev/null || true)"
}

stop_server() {
    local pid=""
    pid="$(current_server_pid 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
        warn "Stopping unhealthy Velociraptor server pid ${pid}"
        kill "$pid" >/dev/null 2>&1 || true
        sleep 1
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill -9 "$pid" >/dev/null 2>&1 || true
        fi
    fi
    rm -f "$SERVER_PID_FILE"
}

write_status "starting" "initializing supervisor"
register_supervisor
trap cleanup_supervisor_pid_file EXIT INT TERM
consecutive_failures=0

while true; do
    if ! server_running; then
        start_server
        if wait_for_server_ready; then
            consecutive_failures=0
            write_status "online" "server pid $(current_server_pid 2>/dev/null || true) healthy"
        else
            consecutive_failures=$HEALTH_FAILURE_THRESHOLD
            write_status "degraded" "server start attempted but health checks did not pass"
        fi
    fi

    if server_healthy; then
        consecutive_failures=0
        write_status "online" "server pid $(current_server_pid 2>/dev/null || true) healthy"
    else
        consecutive_failures=$((consecutive_failures + 1))
        if [ "$consecutive_failures" -ge "$HEALTH_FAILURE_THRESHOLD" ]; then
            write_status "stale" "health failed ${consecutive_failures} times; restarting"
            stop_server
            sleep 2
            start_server
            if wait_for_server_ready; then
                consecutive_failures=0
                write_status "online" "server pid $(current_server_pid 2>/dev/null || true) healthy after restart"
            else
                write_status "degraded" "restart attempted but health checks still failed"
            fi
        else
            write_status "degraded" "health failed ${consecutive_failures}/${HEALTH_FAILURE_THRESHOLD}"
        fi
    fi

    sleep "$SUPERVISOR_LOOP_SECONDS"
done
