#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
WORKSPACE_DIR="${REPO_ROOT}/velociraptor"
VELOCIRAPTOR_BIN="${WORKSPACE_DIR}/velociraptor"
SERVER_CONFIG="${WORKSPACE_DIR}/server.config.yaml"
CLIENT_CONFIG="${WORKSPACE_DIR}/client.config.yaml"
API_CLIENT_CONFIG="${WORKSPACE_DIR}/api_client.yaml"
GUI_LOG="${WORKSPACE_DIR}/gui.log"
GUI_PID_FILE="${WORKSPACE_DIR}/gui.pid"
GUI_WAIT_SECONDS=20
CLIENT_INFO_WAIT_SECONDS=30

EVIDENCE_PATH=""
HOSTNAME_OVERRIDE=""

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
        " ./skills/add-velociraptor-mapped-client/scripts/add_mapped_client.sh [OPTIONS] <evidence-path>" \
        "" \
        "Options:" \
        " -n <name>  Override the mapped client hostname shown in Velociraptor" \
        " -h         Show this help message" \
        "" \
        "Examples:" \
        " ./skills/add-velociraptor-mapped-client/scripts/add_mapped_client.sh /cases/disk.E01" \
        " ./skills/add-velociraptor-mapped-client/scripts/add_mapped_client.sh -n dead-disk-lab01 /mnt/windows" \
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
    if [ -f "$SERVER_CONFIG" ]; then
        host="$(read_yaml_section_value "$SERVER_CONFIG" "GUI" "bind_address" || true)"
    fi

    case "$host" in
        ""|0.0.0.0|::) echo "127.0.0.1" ;;
        *) echo "$host" ;;
    esac
}

gui_port() {
    local port=""
    if [ -f "$SERVER_CONFIG" ]; then
        port="$(read_yaml_section_value "$SERVER_CONFIG" "GUI" "bind_port" || true)"
    fi

    if [ -n "$port" ]; then
        echo "$port"
    else
        echo "8889"
    fi
}

api_port() {
    local port=""
    if [ -f "$SERVER_CONFIG" ]; then
        port="$(read_yaml_section_value "$SERVER_CONFIG" "API" "bind_port" || true)"
    fi

    if [ -n "$port" ]; then
        echo "$port"
    else
        echo "8001"
    fi
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

gui_running() {
    if listener_running "$(gui_port)" && listener_running "$(api_port)"; then
        return 0
    fi

    curl -ksSf --max-time 2 "$(gui_url)" >/dev/null 2>&1
}

wait_for_gui() {
    local tries=0

    while [ "$tries" -lt "$GUI_WAIT_SECONDS" ]; do
        if gui_running; then
            return 0
        fi
        sleep 1
        tries=$((tries + 1))
    done

    return 1
}

ensure_workspace_ready() {
    [ -x "$VELOCIRAPTOR_BIN" ] || error "Velociraptor binary not found at ${VELOCIRAPTOR_BIN}. Run ./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t velociraptor first."
    [ -f "$SERVER_CONFIG" ] || error "Velociraptor server config not found at ${SERVER_CONFIG}. Run ./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t velociraptor first."
    [ -f "$CLIENT_CONFIG" ] || error "Velociraptor client config not found at ${CLIENT_CONFIG}. Run ./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t velociraptor first."
    [ -f "$API_CLIENT_CONFIG" ] || error "Velociraptor API config not found at ${API_CLIENT_CONFIG}. Run ./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh -t velociraptor first."
}

start_gui_if_needed() {
    if gui_running; then
        info "Velociraptor GUI is already reachable at $(gui_url)"
        return 0
    fi

    info "Starting Velociraptor GUI in the background"
    (
        cd "$WORKSPACE_DIR"
        nohup ./velociraptor gui -v --datastore=. --nobrowser --noclient >"$GUI_LOG" 2>&1 &
        echo "$!" >"$GUI_PID_FILE"
    )

    if ! wait_for_gui; then
        warn "Velociraptor GUI did not become reachable at $(gui_url)"
        warn "Check GUI log: ${GUI_LOG}"
        return 1
    fi

    success "Velociraptor GUI is reachable at $(gui_url)"
}

safe_name() {
    local input="$1"
    printf '%s' "$input" \
        | tr '[:upper:]' '[:lower:]' \
        | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+//; s/-+$//'
}

normalize_hostname_base() {
    local base="$1"

    printf '%s' "$base" | sed -E '
        s/([._-])(disk|image|img|mem|memory)$//;
        s/([._-])([a-z])drive$//;
        s/([._-])drive$//;
        s/[._-]+$//
    '
}

default_hostname() {
    local source="$1"
    local base=""

    base="$(basename "$source")"
    base="${base%%.*}"
    base="$(safe_name "$base")"
    base="$(normalize_hostname_base "$base")"

    if [ -n "$base" ]; then
        printf '%s' "$base"
    else
        printf 'mapped-client'
    fi
}

validate_evidence_path() {
    [ -e "$EVIDENCE_PATH" ] || error "Evidence path does not exist: ${EVIDENCE_PATH}"

    if [ -f "$EVIDENCE_PATH" ]; then
        local size
        size="$(wc -c < "$EVIDENCE_PATH" | tr -d '[:space:]')"
        if [ "${size:-0}" -lt 1024 ]; then
            warn "Evidence file is smaller than 1 KiB: ${EVIDENCE_PATH}"
            warn "Small text placeholders are not valid dead-disk images."
        fi
    fi
}

validate_remap_file() {
    local remap_file="$1"

    [ -s "$remap_file" ] || error "Remapping file was not created: ${remap_file}"

    if grep -qx 'remappings: true' "$remap_file"; then
        error "Generated remapping file is only a placeholder. Verify the evidence path points to a real image or mounted Windows directory."
    fi

    grep -q 'type: mount' "$remap_file" || \
        error "Generated remapping file does not contain any mount directives: ${remap_file}"
}

write_session_file() {
    local session_file="$1"
    local client_name="$2"
    local remap_file="$3"
    local client_pid="$4"
    local client_config="$5"
    local client_info_file="$6"
    local client_info_status="$7"

    {
        write_env_line "CLIENT_NAME" "$client_name"
        write_env_line "EVIDENCE_PATH" "$EVIDENCE_PATH"
        write_env_line "REMAP_FILE" "$remap_file"
        write_env_line "CLIENT_PID" "$client_pid"
        write_env_line "CLIENT_CONFIG" "$client_config"
        write_env_line "GUI_URL" "$(gui_url)"
        write_env_line "STARTED_AT" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        write_env_line "CLIENT_INFO_FILE" "$client_info_file"
        write_env_line "CLIENT_INFO_STATUS" "$client_info_status"
    } >"$session_file"
}

regex_escape() {
    printf '%s' "$1" | sed -e 's/[][(){}.^$*+?|\/\\]/\\&/g'
}

build_client_info_vql() {
    local hostname="$1"
    local escaped_hostname=""

    escaped_hostname="$(regex_escape "$hostname")"

    printf '%s' \
        "SELECT client_id," \
        "timestamp(epoch=first_seen_at) as FirstSeen," \
        "timestamp(epoch=last_seen_at) as LastSeen," \
        "os_info.hostname as Hostname," \
        "os_info.fqdn as Fqdn," \
        "os_info.system as OSType," \
        "os_info.release as OS," \
        "os_info.machine as Machine," \
        "agent_information.version as AgentVersion " \
        "FROM clients() WHERE os_info.hostname =~ '^${escaped_hostname}$' OR os_info.fqdn =~ '^${escaped_hostname}$' ORDER BY LastSeen DESC LIMIT 1"
}

find_client_info() {
    local hostname="$1"
    local client_info_file="$2"
    local client_info_log="$3"
    local tmp_file="${client_info_file}.tmp"
    local vql=""

    vql="$(build_client_info_vql "$hostname")"

    if ! "$VELOCIRAPTOR_BIN" -a "$API_CLIENT_CONFIG" --runas api \
        query --format json "$vql" >"$tmp_file" 2>>"$client_info_log"; then
        rm -f "$tmp_file"
        return 1
    fi

    mv "$tmp_file" "$client_info_file"
    grep -q '"client_id"' "$client_info_file"
}

wait_for_client_info() {
    local hostname="$1"
    local client_dir="$2"
    local client_info_file="${client_dir}/client-info.json"
    local client_info_log="${client_dir}/client-info.log"
    local tries=0

    : >"$client_info_log"

    while [ "$tries" -lt "$CLIENT_INFO_WAIT_SECONDS" ]; do
        if find_client_info "$hostname" "$client_info_file" "$client_info_log"; then
            return 0
        fi

        sleep 1
        tries=$((tries + 1))
    done

    return 1
}

escape_sed_replacement() {
    printf '%s' "$1" | sed 's/[\/&]/\\&/g'
}

build_client_config() {
    local client_dir="$1"
    local client_config="${client_dir}/client.config.yaml"
    local writeback_file="${client_dir}/Velociraptor.writeback.yaml"
    local temp_dir="${client_dir}/temp"
    local escaped_writeback_file=""
    local escaped_temp_dir=""

    mkdir -p "$temp_dir"
    cp "$CLIENT_CONFIG" "$client_config"

    escaped_writeback_file="$(escape_sed_replacement "$writeback_file")"
    escaped_temp_dir="$(escape_sed_replacement "$temp_dir")"

    sed -i.bak \
        -e "s|^  writeback_darwin: .*|  writeback_darwin: ${escaped_writeback_file}|" \
        -e "s|^  writeback_linux: .*|  writeback_linux: ${escaped_writeback_file}|" \
        -e "s|^  writeback_windows: .*|  writeback_windows: ${escaped_writeback_file}|" \
        -e "s|^  tempdir_linux: .*|  tempdir_linux: ${escaped_temp_dir}|" \
        -e "s|^  tempdir_windows: .*|  tempdir_windows: ${escaped_temp_dir}|" \
        -e "s|^  tempdir_darwin: .*|  tempdir_darwin: ${escaped_temp_dir}|" \
        "$client_config"
    rm -f "${client_config}.bak"

    printf '%s\n' "$client_config"
}

start_mapped_client() {
    local client_name="$1"
    local client_dir="$2"
    local remap_file="$3"
    local client_config="$4"
    local client_log="${client_dir}/client.log"
    local client_pid_file="${client_dir}/client.pid"
    local session_file="${client_dir}/session.env"
    local client_info_file="${client_dir}/client-info.json"
    local client_info_status="pending"
    local existing_pid=""

    if [ -f "$client_pid_file" ]; then
        existing_pid="$(cat "$client_pid_file" 2>/dev/null || true)"
        if [ -n "$existing_pid" ] && kill -0 "$existing_pid" >/dev/null 2>&1; then
            info "Mapped client ${client_name} is already running with PID ${existing_pid}"
            if wait_for_client_info "$client_name" "$client_dir"; then
                client_info_status="found"
            fi
            write_session_file "$session_file" "$client_name" "$remap_file" "$existing_pid" "$client_config" "$client_info_file" "$client_info_status"
            return 0
        fi
    fi

    info "Starting mapped Velociraptor client: ${client_name}"
    (
        cd "$WORKSPACE_DIR"
        nohup ./velociraptor client -v --config "$client_config" --remap "$remap_file" >"$client_log" 2>&1 &
        echo "$!" >"$client_pid_file"
    )

    sleep 2

    local client_pid
    client_pid="$(cat "$client_pid_file")"
    if ! kill -0 "$client_pid" >/dev/null 2>&1; then
        warn "Mapped client process exited early. Check: ${client_log}"
        return 1
    fi

    if wait_for_client_info "$client_name" "$client_dir"; then
        client_info_status="found"
    else
        warn "Client info was not available yet for ${client_name}. Check: ${client_dir}/client-info.log"
    fi

    write_session_file "$session_file" "$client_name" "$remap_file" "$client_pid" "$client_config" "$client_info_file" "$client_info_status"
    success "Mapped client ${client_name} is running with PID ${client_pid}"
}

build_remap() {
    local client_name="$1"
    local client_dir="$2"
    local remap_file="${client_dir}/remapping.yaml"

    if [ -d "$EVIDENCE_PATH" ]; then
        info "Generating remapping from mounted Windows directory"
        (
            cd "$WORKSPACE_DIR"
            ./velociraptor deaddisk --hostname "$client_name" --add_windows_directory "$EVIDENCE_PATH" "$remap_file"
        )
    else
        info "Generating remapping from disk image"
        (
            cd "$WORKSPACE_DIR"
            ./velociraptor deaddisk --hostname "$client_name" --add_windows_disk "$EVIDENCE_PATH" "$remap_file"
        )
    fi

    validate_remap_file "$remap_file"
    success "Remapping file created at: ${remap_file}"
}

while getopts "n:h" opt; do
    case "$opt" in
        n) HOSTNAME_OVERRIDE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

shift $((OPTIND - 1))

if [ "$#" -ne 1 ]; then
    usage
fi

EVIDENCE_PATH="$1"
require_cmd curl awk sed basename wc date nohup grep
ensure_workspace_ready
validate_evidence_path

CLIENT_NAME="${HOSTNAME_OVERRIDE:-$(default_hostname "$EVIDENCE_PATH")}"
CLIENT_DIR="${WORKSPACE_DIR}/mapped-clients/${CLIENT_NAME}"
CLIENT_RUNTIME_CONFIG=""

mkdir -p "$CLIENT_DIR"

start_gui_if_needed || error "Failed to start or reach the Velociraptor GUI"
build_remap "$CLIENT_NAME" "$CLIENT_DIR"
CLIENT_RUNTIME_CONFIG="$(build_client_config "$CLIENT_DIR")"
start_mapped_client "$CLIENT_NAME" "$CLIENT_DIR" "${CLIENT_DIR}/remapping.yaml" "$CLIENT_RUNTIME_CONFIG" || \
    error "Failed to start the mapped client for ${EVIDENCE_PATH}"

success "Mapped client ready. Open $(gui_url) and look for host: ${CLIENT_NAME}"
info "Client workspace: ${CLIENT_DIR}"
info "Client config: ${CLIENT_RUNTIME_CONFIG}"
info "Client log: ${CLIENT_DIR}/client.log"
