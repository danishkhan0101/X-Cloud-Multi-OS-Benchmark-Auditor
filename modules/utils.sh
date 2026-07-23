#!/bin/bash
# ======================================================
# modules/utils.sh
# Shared logging, SSH helpers, and generic utilities.
# No cloud-provider or OS-specific logic lives here —
# this module must be safe to source before CLOUD_PROVIDER
# or any distro is known.
# ======================================================

# Guard against double-sourcing
if [ -n "${__UTILS_SH_LOADED:-}" ]; then
    return 0
fi
__UTILS_SH_LOADED=1

# ------------------------------------------------------
# COLORS
# ------------------------------------------------------
BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; MAGENTA='\033[0;35m'; NC='\033[0m'

# ------------------------------------------------------
# LOGGING HELPERS
# Usage: log_info "[Phase1/Ubuntu] message"
# Every line gets a timestamp so multi-host parallel output
# stays sortable/greppable after the fact.
# ------------------------------------------------------
_ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

log_info()  { echo -e "$(_ts) ${CYAN}ℹ️  $*${NC}"; }
log_ok()    { echo -e "$(_ts) ${GREEN}✅ $*${NC}"; }
log_warn()  { echo -e "$(_ts) ${YELLOW}⚠️  $*${NC}" >&2; }
log_error() { echo -e "$(_ts) ${RED}❌ $*${NC}" >&2; }

# ------------------------------------------------------
# SSH MULTIPLEXING SETUP
# Call once, early, from the orchestrator.
# ------------------------------------------------------
setup_ssh_multiplexing() {
    mkdir -p ~/.ssh/cm
    cat > ~/.ssh/config <<EOF
Host *
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ControlMaster auto
    ControlPath ~/.ssh/cm/%r@%h:%p
    ControlPersist 15m
    ServerAliveInterval 30
    Compression yes
EOF
    chmod 600 ~/.ssh/config
    log_info "SSH multiplexing configured (~/.ssh/config)"
}

# ------------------------------------------------------
# HELPER: wait_for_ssh
# Blocks until user@ip accepts a key-based SSH connection,
# or times out (default: 12 attempts * 10s = 120s).
# ------------------------------------------------------
wait_for_ssh() {
    local ip="$1"
    local user="$2"
    local max_attempts="${3:-12}"
    local sleep_secs="${4:-10}"

    log_info "Waiting for ${user}@${ip} to be responsive..."
    local count=0
    until ssh -n -o BatchMode=yes -o ConnectTimeout=5 \
              -o StrictHostKeyChecking=no "${user}@${ip}" "exit" >/dev/null 2>&1; do
        count=$((count + 1))
        if [ "$count" -ge "$max_attempts" ]; then
            log_error "Timeout waiting for ${user}@${ip} after $((max_attempts * sleep_secs))s"
            return 1
        fi
        sleep "$sleep_secs"
    done
    return 0
}

# ------------------------------------------------------
# HELPER: run_win_ssh
# Runs a PowerShell command on a Windows host over SSH.
# ------------------------------------------------------
run_win_ssh() {
    local ip="$1"
    local cmd="$2"
    local user="${3:-${WIN_GHOST_USER}}"

    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "${user}@${ip}" "powershell -NoProfile -NonInteractive -Command \"${cmd}\""
}

# ------------------------------------------------------
# HELPER: check_windows_agent_alive
# Cheap liveness probe — just confirms SSH answers, doesn't
# validate any particular service state.
# ------------------------------------------------------
check_windows_agent_alive() {
    local ip="$1"
    local user="${2:-${WIN_GHOST_USER}}"

    ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
        "${user}@${ip}" "echo ALIVE" 2>/dev/null | grep -q ALIVE
}

# ------------------------------------------------------
# HELPER: fetch_remote_report
# Pulls a file off a remote host via scp, falling back to
# `ssh ... sudo cat` if scp is blocked/misconfigured.
# Args: user ip remote_path local_path tag(for logging)
# ------------------------------------------------------
fetch_remote_report() {
    local user="$1"
    local ip="$2"
    local remote="$3"
    local local_path="$4"
    local tag="$5"

    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "${user}@${ip}" "sudo chmod 644 ${remote} 2>/dev/null" >/dev/null 2>&1

    scp -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "${user}@${ip}:${remote}" "${local_path}" >/dev/null 2>&1
    if [ $? -eq 0 ] && [ -s "${local_path}" ]; then
        return 0
    fi

    log_warn "[Fetch/${tag}] SCP failed — falling back to sudo cat on ${ip}"
    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
        -o ConnectTimeout=10 \
        "${user}@${ip}" "sudo cat ${remote}" > "${local_path}" 2>/dev/null
    if [ $? -eq 0 ] && [ -s "${local_path}" ]; then
        return 0
    fi

    rm -f "${local_path}"
    log_error "[Fetch/${tag}] All fetch strategies failed for ${remote} on ${ip}"
    return 1
}

# ------------------------------------------------------
# HELPER: require_env
# Fails fast with a clear message if a required env var is
# unset/empty. Use for anything the script cannot safely
# default (e.g. GHOST_USER, HW_PROJECT_ID).
# Usage: require_env GHOST_USER HW_PROJECT_ID
# ------------------------------------------------------
require_env() {
    local missing=()
    local var
    for var in "$@"; do
        if [ -z "${!var:-}" ]; then
            missing+=("$var")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required environment variable(s): ${missing[*]}"
        return 1
    fi
    return 0
}
