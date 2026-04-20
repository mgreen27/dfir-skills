#!/usr/bin/env bash
# =============================================================================
# prep_dfir_tools.sh
#
# Prepare common DFIR tools for Linux and macOS:
#   - Velociraptor  (https://github.com/Velocidex/velociraptor/releases)
#   - Volatility 3  (https://github.com/volatilityfoundation/volatility3)
#   - The Sleuth Kit / TSK  (https://github.com/sleuthkit/sleuthkit)
#
# Usage:
#   ./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh [OPTIONS]
#
# Options:
#   -d <dir>   Tool staging directory (default: repo root)
#   -t <tool>  Prepare a specific component: venv | velociraptor | volatility |
#              tsk | all
#              (default: all)
#   -h         Show this help message
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
VENV_DIR="${REPO_ROOT}/venv"
REQUIREMENTS_FILE="${REPO_ROOT}/requirements.txt"
VENV_PYTHON="${VENV_DIR}/bin/python"
VELOCIRAPTOR_INIT_SECONDS=10

DOWNLOAD_DIR="./"
TOOL="all"
OS="$(uname -s)"
ARCH="$(uname -m)"
VENV_READY=0

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
error()   { echo "[ERROR] $*" >&2; exit 1; }

wait_for_file() {
    local path="$1"
    local timeout="$2"
    local waited=0

    while [ ! -f "$path" ] && [ "$waited" -lt "$timeout" ]; do
        sleep 1
        waited=$((waited + 1))
    done

    [ -f "$path" ]
}

wait_for_velociraptor_api() {
    local workspace_dir="$1"
    local binary="${workspace_dir}/velociraptor"
    local api_client_file="${workspace_dir}/api_client.yaml"
    local timeout="${2:-20}"
    local waited=0

    while [ "$waited" -lt "$timeout" ]; do
        if "$binary" -a "$api_client_file" --runas api query --format json \
            "SELECT 'ready' AS status FROM scope()" >/dev/null 2>&1; then
            return 0
        fi

        sleep 1
        waited=$((waited + 1))
    done

    return 1
}

require_cmd() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || error "Required command not found: $cmd"
    done
}

github_latest_release_json() {
    local repo="$1"
    curl -fsSL "https://api.github.com/repos/${repo}/releases/latest"
}

github_latest_tag() {
    local repo="$1"
    github_latest_release_json "$repo" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

github_release_download_url() {
    local repo="$1"
    local asset_regex="$2"
    github_latest_release_json "$repo" \
        | grep '"browser_download_url"' \
        | sed -E 's/.*"browser_download_url": "([^"]+)".*/\1/' \
        | grep -E "/${asset_regex}$" \
        | grep -v '\.sig$' \
        | tail -1
}

usage() {
    printf '%s\n' \
        "Usage:" \
        " ./skills/prep-dfir-tools/scripts/prep_dfir_tools.sh [OPTIONS]" \
        "" \
        "Options:" \
        " -d <dir>   Tool staging directory (default: repo root)" \
        " -t <tool>  Prepare a specific component: venv | velociraptor | volatility | tsk | all" \
        "            (default: all)" \
        "            Creates or reuses the repo virtualenv at ./venv" \
        " -h         Show this help message"
    exit 0
}

ensure_repo_venv() {
    if ! command -v python3 >/dev/null 2>&1; then
        warn "python3 not found - cannot create repo virtual environment at ${VENV_DIR}"
        return 1
    fi

    if [ ! -d "$VENV_DIR" ]; then
        info "Creating repo virtual environment at: $VENV_DIR"
        python3 -m venv "$VENV_DIR" || {
            warn "Could not create repo virtual environment at ${VENV_DIR}"
            return 1
        }
    else
        info "Using repo virtual environment: $VENV_DIR"
    fi

    if [ ! -x "$VENV_PYTHON" ]; then
        warn "Repo virtual environment is missing Python executable: $VENV_PYTHON"
        return 1
    fi

    if [ -f "$REQUIREMENTS_FILE" ]; then
        info "Installing repo Python requirements into: $VENV_DIR"
        "$VENV_PYTHON" -m pip install --quiet -r "$REQUIREMENTS_FILE" 2>/dev/null || \
            warn "Could not install repo requirements from ${REQUIREMENTS_FILE}"
    fi

    VENV_READY=1
    success "Repo virtual environment ready at: $VENV_DIR"
}

check_velociraptor_import_connectivity() {
    info "Checking outbound HTTPS access required for Velociraptor artifact imports"

    curl -fsSL --max-time 10 -o /dev/null "https://sigma.velocidex.com/" || return 1
    curl -fsSL --max-time 10 -o /dev/null "https://api.github.com/" || return 1
}

collect_velociraptor_server_artifact() {
    local workspace_dir="$1"
    local artifact_name="$2"
    local binary="${workspace_dir}/velociraptor"
    local api_client_file="${workspace_dir}/api_client.yaml"
    local output_stem="${artifact_name//./-}"
    local import_log="${workspace_dir}/${output_stem}.log"
    local import_json="${workspace_dir}/${output_stem}.json"
    local attempt=""

    if [ ! -f "$api_client_file" ]; then
        warn "Cannot collect ${artifact_name} without API config: ${api_client_file}"
        return 1
    fi

    info "Collecting ${artifact_name} into the root org as API user 'api'"
    : >"$import_log"

    for attempt in 1 2 3; do
        if "$binary" -a "$api_client_file" --runas api \
            artifacts collect "$artifact_name" \
            --client_id server --org_id root --format json \
            >"$import_json" 2>>"$import_log"; then
            success "${artifact_name} completed in: ${workspace_dir}"
            return 0
        fi

        sleep 2
    done

    warn "${artifact_name} did not complete successfully"
    warn "Check import log: ${import_log}"
    return 1
}

initialize_velociraptor_workspace() {
    local workspace_dir="$1"
    local binary="${workspace_dir}/velociraptor"
    local config_file="${workspace_dir}/server.config.yaml"
    local api_client_file="${workspace_dir}/api_client.yaml"
    local gui_log="${workspace_dir}/gui-init.log"
    local pid=""

    info "Initializing Velociraptor workspace in: $workspace_dir"
    info "Starting GUI mode and waiting up to ${VELOCIRAPTOR_INIT_SECONDS} seconds for local config"

    (
        cd "$workspace_dir"
        ./velociraptor gui -v --datastore=. --nobrowser --noclient >"$gui_log" 2>&1
    ) &
    pid=$!

    if ! wait_for_file "$config_file" "$VELOCIRAPTOR_INIT_SECONDS"; then
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
            wait "$pid" || true
        else
            wait "$pid" || true
        fi
        warn "Velociraptor did not generate ${config_file}"
        warn "Check initialization log: ${gui_log}"
        return 1
    fi

    info "Generating Velociraptor API client config at: $api_client_file"
    "$binary" --config "$config_file" config api_client --name api --role administrator "$api_client_file" \
        || warn "Could not generate Velociraptor API client config at ${api_client_file}"

    if ! wait_for_velociraptor_api "$workspace_dir" 20; then
        warn "Velociraptor API did not become ready during initialization; skipping artifact imports"
    elif check_velociraptor_import_connectivity; then
        collect_velociraptor_server_artifact "$workspace_dir" "Server.Import.Extras" \
            || warn "Velociraptor extra artifact import did not complete cleanly"
        collect_velociraptor_server_artifact "$workspace_dir" "Server.Import.ArtifactExchange" \
            || warn "Velociraptor artifact exchange import did not complete cleanly"
        collect_velociraptor_server_artifact "$workspace_dir" "Server.Import.DetectRaptor" \
            || warn "Velociraptor DetectRaptor import did not complete cleanly"
    else
        warn "Outbound internet check failed; skipping Velociraptor community artifact imports"
    fi

    if kill -0 "$pid" >/dev/null 2>&1; then
        info "Stopping Velociraptor GUI initialization process"
        kill "$pid" >/dev/null 2>&1 || true
        wait "$pid" || true
    else
        wait "$pid" || true
    fi

    success "Velociraptor workspace initialized at: $workspace_dir"
}

make_velociraptor_root_only() {
    local workspace_dir="$1"
    local config_file="${workspace_dir}/server.config.yaml"
    local temp_file="${workspace_dir}/server.config.yaml.tmp"

    [ -f "$config_file" ] || return 0

    if grep -q '^  initial_orgs:$' "$config_file"; then
        info "Removing default Velociraptor tenant definitions and keeping root only"
        awk '
            {
                if (skip) {
                    if ($0 ~ /^  [A-Za-z_][A-Za-z0-9_]*:/) {
                        skip=0
                    } else {
                        next
                    }
                }

                if ($0 ~ /^  initial_orgs:$/) {
                    skip=1
                    next
                }

                print
            }
        ' "$config_file" > "$temp_file"
        mv "$temp_file" "$config_file"
    fi

    rm -rf "${workspace_dir}/orgs/O123" "${workspace_dir}/orgs/O123.json.db"
}

while getopts "d:t:h" opt; do
    case "$opt" in
        d) DOWNLOAD_DIR="$OPTARG" ;;
        t) TOOL="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

case "$OS" in
    Linux|Darwin) ;;
    *) error "Unsupported operating system: $OS (supported: Linux, Darwin/macOS)" ;;
esac

case "$TOOL" in
    venv|velociraptor|volatility|tsk|all) ;;
    *) error "Unknown tool '$TOOL'. Choose from: venv, velociraptor, volatility, tsk, all" ;;
esac

info "Repo root detected as: $REPO_ROOT"
info "Repo virtual environment path: $VENV_DIR"

if [ "$TOOL" = "venv" ]; then
    ensure_repo_venv || error "Failed to prepare repo virtual environment at ${VENV_DIR}"
    success "Done. Repo virtual environment is prepared at: $VENV_DIR"
    exit 0
fi

require_cmd curl tar

mkdir -p "$DOWNLOAD_DIR"
DOWNLOAD_DIR="$(cd "$DOWNLOAD_DIR" && pwd)"
info "Tools will be saved to: $DOWNLOAD_DIR"
ensure_repo_venv || true

download_velociraptor() {
    info "Fetching latest Velociraptor release tag..."
    local tag
    tag="$(github_latest_tag "Velocidex/velociraptor")"

    info "Latest Velociraptor release: $tag"

    local asset_regex
    case "$OS" in
        Linux)
            case "$ARCH" in
                x86_64|amd64) asset_regex='velociraptor-v[0-9.]+-linux-amd64' ;;
                aarch64|arm64) asset_regex='velociraptor-v[0-9.]+-linux-arm64' ;;
                *) error "Unsupported architecture for Velociraptor on Linux: $ARCH" ;;
            esac
            ;;
        Darwin)
            case "$ARCH" in
                x86_64) asset_regex='velociraptor-v[0-9.]+-darwin-amd64' ;;
                arm64)  asset_regex='velociraptor-v[0-9.]+-darwin-arm64' ;;
                *) error "Unsupported architecture for Velociraptor on macOS: $ARCH" ;;
            esac
            ;;
    esac

    local url
    url="$(github_release_download_url "Velocidex/velociraptor" "$asset_regex")"
    [ -n "$url" ] || error "Could not find a Velociraptor release asset matching: ${asset_regex}"
    local dest_dir="${DOWNLOAD_DIR}/velociraptor"
    local dest="${dest_dir}/velociraptor"

    mkdir -p "$dest_dir"

    info "Downloading Velociraptor from: $url"
    curl -fsSL --retry 3 -o "$dest" "$url"
    chmod +x "$dest"
    success "Velociraptor saved to: $dest"
    initialize_velociraptor_workspace "$dest_dir" || warn "Velociraptor workspace initialization did not complete cleanly"
    make_velociraptor_root_only "$dest_dir"
    info "Velociraptor workspace: $dest_dir"
    info "Run from that directory for local GUI mode:"
    info "  ./velociraptor gui -v --datastore=. --nobrowser --noclient"
    info "API client config is generated at:"
    info "  ${dest_dir}/api_client.yaml"
}

download_volatility() {
    info "Fetching latest Volatility 3 release tag..."
    local tag
    tag="$(github_latest_tag "volatilityfoundation/volatility3")"

    info "Latest Volatility 3 release: $tag"

    local archive_name="volatility3-${tag}.tar.gz"
    local url="https://github.com/volatilityfoundation/volatility3/archive/refs/tags/${tag}.tar.gz"
    local dest_archive="${DOWNLOAD_DIR}/${archive_name}"
    local dest_dir="${DOWNLOAD_DIR}/volatility3"

    info "Downloading Volatility 3 from: $url"
    curl -fsSL --retry 3 -o "$dest_archive" "$url"

    info "Extracting Volatility 3 archive..."
    mkdir -p "$dest_dir"
    tar -xzf "$dest_archive" -C "$dest_dir" --strip-components=1
    rm -f "$dest_archive"

    success "Volatility 3 extracted to: $dest_dir"

    if [ "$VENV_READY" -eq 1 ]; then
        if [ -f "${dest_dir}/requirements.txt" ]; then
            info "Installing Volatility 3 requirements.txt into: $VENV_DIR"
            "$VENV_PYTHON" -m pip install --quiet -r "${dest_dir}/requirements.txt" \
                || warn "Could not auto-install Volatility 3 requirements into ${VENV_DIR}"
        elif [ -f "${dest_dir}/pyproject.toml" ]; then
            info "Installing Volatility 3 package extras (full, cloud, arrow) into: $VENV_DIR"
            "$VENV_PYTHON" -m pip install --quiet -e "${dest_dir}[full,cloud,arrow]" \
                || warn "Could not auto-install Volatility 3 package extras into ${VENV_DIR}"
            if [ -f "$REQUIREMENTS_FILE" ]; then
                info "Re-applying repo Python requirements after Volatility 3 install"
                "$VENV_PYTHON" -m pip install --quiet -r "$REQUIREMENTS_FILE" \
                    || warn "Could not re-apply repo requirements after Volatility 3 install"
            fi
        else
            warn "Volatility 3 install metadata not found in ${dest_dir}"
        fi
    else
        warn "Repo virtual environment is not ready - create ${VENV_DIR} and install ${dest_dir}/requirements.txt manually"
    fi
}

download_tsk() {
    info "Fetching latest Sleuth Kit release tag..."
    local tag
    tag="$(github_latest_tag "sleuthkit/sleuthkit")"
    local version="${tag#sleuthkit-}"

    info "Latest Sleuth Kit release: $tag"

    case "$OS" in
        Darwin)
            if command -v brew >/dev/null 2>&1; then
                info "Installing Sleuth Kit via Homebrew..."
                brew install sleuthkit
                success "Sleuth Kit installed via Homebrew"
                return
            fi
            ;;
    esac

    local archive_name="sleuthkit-${version}.tar.gz"
    local url="https://github.com/sleuthkit/sleuthkit/releases/download/${tag}/${archive_name}"
    local dest_archive="${DOWNLOAD_DIR}/${archive_name}"
    local dest_dir="${DOWNLOAD_DIR}/sleuthkit-${version}"

    info "Downloading Sleuth Kit source from: $url"
    curl -fsSL --retry 3 -o "$dest_archive" "$url"

    info "Extracting Sleuth Kit archive..."
    tar -xzf "$dest_archive" -C "$DOWNLOAD_DIR"
    rm -f "$dest_archive"

    success "Sleuth Kit source extracted to: $dest_dir"
    info "To build, run:"
    info "  cd ${dest_dir} && ./configure && make && sudo make install"
}

case "$TOOL" in
    velociraptor) download_velociraptor ;;
    volatility)   download_volatility ;;
    tsk)          download_tsk ;;
    all)
        download_velociraptor
        download_volatility
        download_tsk
        ;;
esac

success "Done. All requested tools are prepared in: $DOWNLOAD_DIR"
