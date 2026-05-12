#!/usr/bin/env bash

set -euo pipefail

REMOTE_SSH_USER="root"
REMOTE_SUDO_USER="velociraptor"
REMOTE_BINARY="/usr/local/bin/velociraptor"
REMOTE_SERVER_CONFIG="/etc/velociraptor/server.config.yaml"
API_NAME="skynet"
SERVER=""
LOCAL_CONFIG_ROOT="${HOME}/.config"
LOCAL_FOLDER_NAME=""
IDENTITY_FILE="${HOME}/.ssh/infoguard"
SSH_PORT=""
REMOTE_OUTPUT_PATH=""
DRY_RUN=0

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
error()   { echo "[ERROR] $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage:
  ./skills/fetch-live-api-client/scripts/fetch_live_api_client.sh --server <host> [options]

Options:
  --server <host>            Remote SSH host or alias. Required.
  --api-name <name>          API client name to generate. Default: skynet
  --ssh-user <user>          Remote SSH user. Default: root
  --sudo-user <user>         Remote Velociraptor service user. Default: velociraptor
  --remote-binary <path>     Remote Velociraptor binary. Default: /usr/local/bin/velociraptor
  --remote-config <path>     Remote server.config.yaml path. Default: /etc/velociraptor/server.config.yaml
  --remote-output <path>     Remote api_client output path. Default: /etc/velociraptor/<api-name>_api_client.yaml
  --identity <path>          SSH identity file. Default: ~/.ssh/infoguard when present
  --port <port>              SSH port.
  --local-root <path>        Local config root. Default: ~/.config
  --local-folder <name>      Local folder under the root. Default: <server>
  --dry-run                  Print the SSH/SCP commands without executing them.
  -h, --help                 Show this help message.
EOF
    exit 0
}

require_cmd() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || error "Required command not found: $cmd"
    done
}

join_remote() {
    printf '%s@%s' "$REMOTE_SSH_USER" "$SERVER"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --server)
            SERVER="${2:?missing value for --server}"
            shift 2
            ;;
        --api-name)
            API_NAME="${2:?missing value for --api-name}"
            shift 2
            ;;
        --ssh-user)
            REMOTE_SSH_USER="${2:?missing value for --ssh-user}"
            shift 2
            ;;
        --sudo-user)
            REMOTE_SUDO_USER="${2:?missing value for --sudo-user}"
            shift 2
            ;;
        --remote-binary)
            REMOTE_BINARY="${2:?missing value for --remote-binary}"
            shift 2
            ;;
        --remote-config)
            REMOTE_SERVER_CONFIG="${2:?missing value for --remote-config}"
            shift 2
            ;;
        --remote-output)
            REMOTE_OUTPUT_PATH="${2:?missing value for --remote-output}"
            shift 2
            ;;
        --identity)
            IDENTITY_FILE="${2:?missing value for --identity}"
            shift 2
            ;;
        --port)
            SSH_PORT="${2:?missing value for --port}"
            shift 2
            ;;
        --local-root)
            LOCAL_CONFIG_ROOT="${2:?missing value for --local-root}"
            shift 2
            ;;
        --local-folder)
            LOCAL_FOLDER_NAME="${2:?missing value for --local-folder}"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            error "Unknown argument: $1"
            ;;
    esac
done

[ -n "$SERVER" ] || error "--server is required"

require_cmd ssh scp mkdir chmod

if [ -z "$REMOTE_OUTPUT_PATH" ]; then
    REMOTE_OUTPUT_PATH="/etc/velociraptor/${API_NAME}_api_client.yaml"
fi

if [ -z "$LOCAL_FOLDER_NAME" ]; then
    LOCAL_FOLDER_NAME="$SERVER"
fi

LOCAL_DEST_DIR="${LOCAL_CONFIG_ROOT}/${LOCAL_FOLDER_NAME}"
LOCAL_DEST_PATH="${LOCAL_DEST_DIR}/$(basename "$REMOTE_OUTPUT_PATH")"

SSH_ARGS=(-o BatchMode=yes)
SCP_ARGS=(-o BatchMode=yes)

if [ -n "$IDENTITY_FILE" ] && [ -f "$IDENTITY_FILE" ]; then
    SSH_ARGS+=(-i "$IDENTITY_FILE")
    SCP_ARGS+=(-i "$IDENTITY_FILE")
fi

if [ -n "$SSH_PORT" ]; then
    SSH_ARGS+=(-p "$SSH_PORT")
    SCP_ARGS+=(-P "$SSH_PORT")
fi

printf -v REMOTE_COMMAND \
    'sudo -u %q %q --config %q config api_client --name %q --role administrator %q' \
    "$REMOTE_SUDO_USER" \
    "$REMOTE_BINARY" \
    "$REMOTE_SERVER_CONFIG" \
    "$API_NAME" \
    "$REMOTE_OUTPUT_PATH"

if [ "$DRY_RUN" -eq 1 ]; then
    printf 'mkdir -p %q\n' "$LOCAL_DEST_DIR"
    printf 'ssh'
    printf ' %q' "${SSH_ARGS[@]}"
    printf ' %q %q\n' "$(join_remote)" "$REMOTE_COMMAND"
    printf 'scp'
    printf ' %q' "${SCP_ARGS[@]}"
    printf ' %q %q\n' "$(join_remote):${REMOTE_OUTPUT_PATH}" "$LOCAL_DEST_PATH"
    exit 0
fi

mkdir -p "$LOCAL_DEST_DIR"

info "Generating remote Velociraptor API client at ${REMOTE_OUTPUT_PATH}"
ssh "${SSH_ARGS[@]}" "$(join_remote)" "$REMOTE_COMMAND"

info "Copying API client to ${LOCAL_DEST_PATH}"
scp "${SCP_ARGS[@]}" "$(join_remote):${REMOTE_OUTPUT_PATH}" "$LOCAL_DEST_PATH"

chmod 600 "$LOCAL_DEST_PATH"

success "Saved live API client config to ${LOCAL_DEST_PATH}"
info "Example query:"
printf '  %q -a %q --runas api query --format json %q\n' \
    "$REMOTE_BINARY" \
    "$LOCAL_DEST_PATH" \
    "SELECT 1 AS ok FROM scope()"
