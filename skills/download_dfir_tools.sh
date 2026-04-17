#!/usr/bin/env bash
# =============================================================================
# download_dfir_tools.sh
#
# Download common DFIR tools for Linux and macOS:
#   - Velociraptor  (https://github.com/Velocidex/velociraptor/releases)
#   - Volatility 3  (https://github.com/volatilityfoundation/volatility3)
#   - The Sleuth Kit / TSK  (https://github.com/sleuthkit/sleuthkit)
#
# Usage:
#   chmod +x download_dfir_tools.sh
#   ./download_dfir_tools.sh [OPTIONS]
#
# Options:
#   -d <dir>   Destination directory (default: ./dfir-tools)
#   -t <tool>  Download a specific tool: velociraptor | volatility | tsk | all (default: all)
#   -h         Show this help message
# =============================================================================

set -euo pipefail

# ---- defaults ----------------------------------------------------------------
DOWNLOAD_DIR="./dfir-tools"
TOOL="all"
OS="$(uname -s)"
ARCH="$(uname -m)"

# ---- helpers -----------------------------------------------------------------
info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
error()   { echo "[ERROR] $*" >&2; exit 1; }

require_cmd() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || error "Required command not found: $cmd"
    done
}

github_latest_tag() {
    # Returns the latest release tag for a given owner/repo
    local repo="$1"
    curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

# ---- usage -------------------------------------------------------------------
usage() {
    sed -n '/^# Usage:/,/^# =====/p' "$0" | grep '^#' | sed 's/^# \{0,2\}//'
    exit 0
}

# ---- argument parsing --------------------------------------------------------
while getopts "d:t:h" opt; do
    case "$opt" in
        d) DOWNLOAD_DIR="$OPTARG" ;;
        t) TOOL="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# ---- validate OS -------------------------------------------------------------
case "$OS" in
    Linux|Darwin) ;;
    *) error "Unsupported operating system: $OS (supported: Linux, Darwin/macOS)" ;;
esac

# ---- validate tool argument --------------------------------------------------
case "$TOOL" in
    velociraptor|volatility|tsk|all) ;;
    *) error "Unknown tool '$TOOL'. Choose from: velociraptor, volatility, tsk, all" ;;
esac

# ---- setup -------------------------------------------------------------------
require_cmd curl tar

mkdir -p "$DOWNLOAD_DIR"
DOWNLOAD_DIR="$(cd "$DOWNLOAD_DIR" && pwd)"
info "Tools will be saved to: $DOWNLOAD_DIR"

# ==============================================================================
# Velociraptor
# ==============================================================================
download_velociraptor() {
    info "Fetching latest Velociraptor release tag..."
    local tag
    tag="$(github_latest_tag "Velocidex/velociraptor")"
    local version="${tag#v}"

    info "Latest Velociraptor release: $tag"

    # Map OS and architecture to the binary name used in GitHub releases
    local binary_name
    case "$OS" in
        Linux)
            case "$ARCH" in
                x86_64|amd64) binary_name="velociraptor-v${version}-linux-amd64" ;;
                aarch64|arm64) binary_name="velociraptor-v${version}-linux-arm64" ;;
                *) error "Unsupported architecture for Velociraptor on Linux: $ARCH" ;;
            esac
            ;;
        Darwin)
            case "$ARCH" in
                x86_64)        binary_name="velociraptor-v${version}-darwin-amd64" ;;
                arm64)         binary_name="velociraptor-v${version}-darwin-arm64" ;;
                *) error "Unsupported architecture for Velociraptor on macOS: $ARCH" ;;
            esac
            ;;
    esac

    local url="https://github.com/Velocidex/velociraptor/releases/download/${tag}/${binary_name}"
    local dest="${DOWNLOAD_DIR}/velociraptor"

    info "Downloading Velociraptor from: $url"
    curl -fsSL --retry 3 -o "$dest" "$url"
    chmod +x "$dest"
    success "Velociraptor saved to: $dest"
}

# ==============================================================================
# Volatility 3
# ==============================================================================
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

    if command -v python3 >/dev/null 2>&1; then
        info "Installing Volatility 3 Python dependencies..."
        python3 -m pip install --quiet -r "${dest_dir}/requirements.txt" 2>/dev/null \
            || warn "Could not auto-install Volatility 3 dependencies. Run: pip install -r ${dest_dir}/requirements.txt"
    else
        warn "python3 not found – install it and then run: pip install -r ${dest_dir}/requirements.txt"
    fi
}

# ==============================================================================
# The Sleuth Kit (TSK)
# ==============================================================================
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

    # Download the source tarball for Linux (or macOS without Homebrew)
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

# ==============================================================================
# Main
# ==============================================================================
case "$TOOL" in
    velociraptor) download_velociraptor ;;
    volatility)   download_volatility   ;;
    tsk)          download_tsk          ;;
    all)
        download_velociraptor
        download_volatility
        download_tsk
        ;;
esac

success "Done. All requested tools are in: $DOWNLOAD_DIR"
