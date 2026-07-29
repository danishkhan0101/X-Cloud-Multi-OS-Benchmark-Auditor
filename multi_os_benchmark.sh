#!/bin/bash
# ======================================================
# multi_os_benchmark.sh
# Orchestrator: loads config, discovers infra, builds the
# Ansible inventory, and dispatches to the phase functions
# defined in modules/audit_runner.sh.
#
# This file owns:
#   - .env loading + config variable defaults
#   - CLOUD_PROVIDER-aware dispatcher functions (thin
#     wrappers around azure_* / hw_* implementations)
#   - VM discovery orchestration (_map_vm + inventory arrays)
#   - CLI arg parsing (--headless, --mode, etc.)
#   - The interactive menu / headless CI runner
#
# Everything else (SCAP tooling, scan/remediate/verify/
# cleanup logic, Windows helpers) lives in modules/*.sh.
# ======================================================
set +H
set -uo pipefail   # no -e: many steps intentionally continue past failures

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ------------------------------------------------------
# Load .env (if present) BEFORE sourcing modules, since
# modules reference these vars at call-time, not load-time.
# ------------------------------------------------------
if [ -f "${SCRIPT_DIR}/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.env"
    set +a
fi

# ------------------------------------------------------
# SOURCE MODULES
# Order matters: utils has no deps; discovery_* depend on
# utils (log_*); audit_runner depends on utils + the cloud
# dispatcher functions defined further down this file.
# ------------------------------------------------------
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/utils.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/discovery_azure.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/discovery_cae.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/audit_runner.sh"

# ======================================================
# CONFIGURATION - DYNAMIC ENVIRONMENT VARIABLES
# ======================================================
ORG_NAME="${ORG_NAME:-Custom}"
ORG_PREFIX="${ORG_PREFIX:-custom}"
CUSTOM_XCCDF_PROFILE="${CUSTOM_XCCDF_PROFILE:-xccdf_com.org_profile_lsb}"
RG_NAME="${AZURE_RG_NAME:-DEFAULT_RG}"

CLOUD_PROVIDER="${CLOUD_PROVIDER:-azure}"

# GHOST_USER has no safe default — if it's unset, every Linux
# SSH call in audit_runner.sh silently becomes `ssh @${IP}`.
# Fail fast instead of limping through with broken commands.
require_env GHOST_USER || exit 1

HW_REGION="${HW_REGION:-ap-southeast-1}"
HW_PROJECT_ID="${HW_PROJECT_ID:-}"
HW_ECS_TAG_KEY="${HW_ECS_TAG_KEY:-Environment}"
HW_ECS_TAG_VAL="${HW_ECS_TAG_VAL:-}"
HW_VPC_ID="${HW_VPC_ID:-}"
# No hardcoded org-specific default here — if these aren't in
# .env/CI secrets, fail rather than silently pointing at a
# stale/wrong endpoint.
HW_ECS_ENDPOINT="${HW_ECS_ENDPOINT:-}"
HW_VPC_ENDPOINT="${HW_VPC_ENDPOINT:-}"

UBUNTU_CUSTOM_DIR="${SCRIPT_DIR}/ubuntu-custom"
UBUNTU_CUSTOM_XCCDF="${UBUNTU_CUSTOM_DIR}/${ORG_PREFIX}_xccdf.xml"
UBUNTU_CUSTOM_OVAL="${UBUNTU_CUSTOM_DIR}/${ORG_PREFIX}_ubuntu_rules.xml"
UBUNTU_CUSTOM_PLAYBOOK="${UBUNTU_CUSTOM_DIR}/ubuntu_custom_playbook.yml"

RHEL_CUSTOM_DIR="${SCRIPT_DIR}/rhel-custom"
RHEL_CUSTOM_XCCDF="${RHEL_CUSTOM_DIR}/${ORG_PREFIX}_rhel_xccdf.xml"
RHEL_CUSTOM_OVAL="${RHEL_CUSTOM_DIR}/${ORG_PREFIX}_rhel_rules.xml"
RHEL_CUSTOM_PLAYBOOK="${RHEL_CUSTOM_DIR}/rhel_custom_playbook.yml"

WIN_SSH_USER="${WIN_SSH_USER:-Administrator}"
WIN_SERVER_ROLE="${WIN_SERVER_ROLE:-member_server}"
WIN_GHOST_USER="${WIN_GHOST_USER:-svc_audit}"
WIN_CUSTOM_DIR="${SCRIPT_DIR}/windows-custom"
WIN_CUSTOM_BENCHMARK="${WIN_CUSTOM_DIR}/${ORG_PREFIX}_baseline.rb"
WIN_CUSTOM_PLAYBOOK="${WIN_CUSTOM_DIR}/${ORG_PREFIX}_remediate.yml"

WIN_CIS_DIR="${SCRIPT_DIR}/windows-default-cis"
WIN_CIS_BENCHMARK="${WIN_CIS_DIR}/windows-baseline"
WIN_PS1_REMEDIATE="${WIN_CIS_BENCHMARK}/Invoke-CISRemediation-Combined.ps1"

WIN_REBOOT_SETTLE_SEC="${WIN_REBOOT_SETTLE_SEC:-45}"
WIN_REBOOT_HEALTH_WAIT_SEC="${WIN_REBOOT_HEALTH_WAIT_SEC:-360}"
WIN_SCAN_TIMEOUT_SEC="${WIN_SCAN_TIMEOUT_SEC:-1200}"
WIN_REBOOT_AFTER_REMEDIATION="${WIN_REBOOT_AFTER_REMEDIATION:-true}"
WIN_AGENT_PROBE_SEC="${WIN_AGENT_PROBE_SEC:-180}"

export INSPEC_SSH_CONFIG_NO_SECURE=true

# ======================================================
# REMEDIATION CONSTANTS
# ======================================================
REMEDIATION_TIMEOUT_SEC=1800
ALLOW_OPENSSL_AUTO_UPDATE="${ALLOW_OPENSSL_AUTO_UPDATE:-false}"
REMEDIATION_SSH_OPTS="-n -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o ControlMaster=no -o ControlPath=none \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
    -o ConnectTimeout=10"

SCAP_CACHE_DIR="/tmp/scap_runner_cache"

# ======================================================
# CLOUD DISPATCHERS
# audit_runner.sh calls these generic names; each one
# routes to the provider-specific implementation based on
# CLOUD_PROVIDER. Keeping the dispatch here (not inside the
# modules) means discovery_azure.sh / discovery_cae.sh never
# need to know about each other.
# ======================================================
cloud_add_port_rule() {
    # Azure's 3rd positional arg is a rule LABEL (e.g. "Allow_SSH_Runner_Only_Win").
    # Huawei's 3rd positional arg is a PROTOCOL (e.g. "tcp"). These are NOT the
    # same parameter — forwarding "$@" blindly sends the Azure-style label into
    # Huawei's protocol slot, which the VPC API rejects (SecurityGroupRuleInvalidProtocol).
    # Route explicitly per provider instead of assuming a shared signature.
    local ip="$1" port="$2" label="${3:-}"
    case "${CLOUD_PROVIDER}" in
        azure)       azure_add_port_rule "$ip" "$port" "$label" ;;
        huaweicloud) hw_add_port_rule "$ip" "$port" ;;  # protocol defaults to tcp inside hw_add_port_rule
    esac
}

cloud_vm_run_shell() {
    case "${CLOUD_PROVIDER}" in
        azure)       azure_vm_run_shell "$@" ;;
        huaweicloud) hw_vm_run_shell "$@" ;;
    esac
}

cloud_vm_restart() {
    case "${CLOUD_PROVIDER}" in
        azure)       azure_vm_restart "$@" ;;
        huaweicloud) hw_vm_restart "$@" ;;
    esac
}

# Repair-only fallback for when SSH is unreachable on a Windows host.
# Azure can push OpenSSH via the run-command control-plane channel;
# Huawei Cloud has no equivalent out-of-band channel for Windows, so
# this is intentionally a no-op there — the caller must treat that as
# "no automated recovery available" rather than retrying forever.
cloud_vm_bootstrap_ssh() {
    case "${CLOUD_PROVIDER}" in
        azure)       azure_vm_bootstrap_ssh "$@" ;;
        huaweicloud) log_warn "[HW] No out-of-band SSH-repair channel for Windows — manual intervention required"; return 1 ;;
    esac
}

cloud_vm_get_power_state() {
    case "${CLOUD_PROVIDER}" in
        azure)       azure_vm_get_power_state "$@" ;;
        huaweicloud) hw_vm_get_power_state "$@" ;;
        *)           echo "unknown" ;;
    esac
}

reassert_ssh_rule_all_linux() {
    [ "${CLOUD_PROVIDER}" != "huaweicloud" ] && return 0
    local all_linux_ips=(
        "${UBUNTU_MACHINES[@]}" "${RHEL_MACHINES[@]}"
        "${ROCKY_MACHINES[@]}"  "${ALMA_MACHINES[@]}"
    )
    hw_reassert_ssh_rule_all "${all_linux_ips[@]}"
}

reassert_ssh_rule_all_windows() {
    [ "${CLOUD_PROVIDER}" != "huaweicloud" ] && return 0
    hw_reassert_ssh_rule_all "${WINDOWS_MACHINES[@]}"
}

# ======================================================
# HEADLESS MODE PARSER
# ======================================================
HEADLESS=false
H_PROFILE="custom"
H_MODE="scan"
H_TARGETS="all"
H_TICKET="None"
DEBUG_MODE=false
H_CLEANUP=false
H_TARGET_OS="all"
H_TARGET_IP="all"
H_CLOUD=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --headless)   HEADLESS=true ;;
        --profile)    H_PROFILE="$2";    shift ;;
        --mode)       H_MODE="$2";       shift ;;
        --targets)    H_TARGETS="$2";    shift ;;
        --ticket)     H_TICKET="$2";     shift ;;
        --debug)      DEBUG_MODE="$2";   shift ;;
        --cleanup)    H_CLEANUP="$2";    shift ;;
        --target-os)  H_TARGET_OS="$2";  shift ;;
        --target-ip)  H_TARGET_IP="$2";  shift ;;
        --cloud)      H_CLOUD="$2";      shift ;;
        *) log_error "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

[ -n "$H_CLOUD" ] && CLOUD_PROVIDER="${H_CLOUD,,}"
case "${CLOUD_PROVIDER}" in
    azure|huaweicloud) ;;
    *) log_error "Unknown --cloud value '${CLOUD_PROVIDER}'. Use: azure | huaweicloud"; exit 1 ;;
esac

if [ "${CLOUD_PROVIDER}" == "huaweicloud" ]; then
    require_env HUAWEICLOUD_ACCESS_KEY HUAWEICLOUD_SECRET_KEY HW_PROJECT_ID \
        HW_ECS_ENDPOINT HW_VPC_ENDPOINT || exit 1
fi

CIS_LEVEL="${CIS_LEVEL:-Level 1}"

# ======================================================
# ENTERPRISE GUARDRAILS
# ======================================================
if [ "$HEADLESS" == true ]; then
    log_info "HEADLESS CI/CD MODE ACTIVATED — cloud provider: ${CLOUD_PROVIDER}"
    if [ -n "$H_TICKET" ] && [ "$H_TICKET" != "None" ]; then
        log_ok "AUDIT AUTHORIZATION: Ticket ID: $H_TICKET"
    fi
    if [ "$DEBUG_MODE" == "true" ]; then set -x; fi
fi

setup_ssh_multiplexing

# ======================================================
# PHASE 0.1: ZERO-TRUST DISCOVERY
# ======================================================
UBUNTU_MACHINES=(); RHEL_MACHINES=(); ROCKY_MACHINES=()
ALMA_MACHINES=();   WINDOWS_MACHINES=()
declare -A IP_TO_VM_NAME
declare -A IP_TO_VM_ID
declare -A IP_TO_SG_ID

# ------------------------------------------------------
# reclassify_hosts_by_actual_os
# _map_vm's initial bucketing is a best-effort guess based
# on VM name / image offer string, which can be wrong (e.g.
# a VM named "ecs-audit-rocky" that's actually AlmaLinux, or
# a cloud API reporting an ambiguous/incorrect OS family).
# This corrects EVERY bucket — Linux distro AND Windows —
# using live detection against the host itself, now that
# GHOST_USER / WIN_GHOST_USER are provisioned and reachable
# post-bootstrap. Must run AFTER Phase 0.3, before inventory
# is built or any phase logic runs.
# ------------------------------------------------------
reclassify_hosts_by_actual_os() {
    log_info "PHASE 0.4: VERIFYING ACTUAL OS PER HOST (live detection, overriding name-based guess)"

    local all_linux_ips=(
        "${UBUNTU_MACHINES[@]}" "${RHEL_MACHINES[@]}"
        "${ROCKY_MACHINES[@]}"  "${ALMA_MACHINES[@]}"
    )
    local all_win_ips=( "${WINDOWS_MACHINES[@]}" )

    local NEW_UBUNTU=() NEW_RHEL=() NEW_ROCKY=() NEW_ALMA=() NEW_WINDOWS=()

    # ---------- Verify hosts currently bucketed as Linux ----------
    local ip
    for ip in "${all_linux_ips[@]}"; do
        local old_bucket=""
        for b in "${UBUNTU_MACHINES[@]}"; do [ "$b" == "$ip" ] && old_bucket="ubuntu"; done
        for b in "${RHEL_MACHINES[@]}";   do [ "$b" == "$ip" ] && old_bucket="rhel";   done
        for b in "${ROCKY_MACHINES[@]}";  do [ "$b" == "$ip" ] && old_bucket="rocky";  done
        for b in "${ALMA_MACHINES[@]}";   do [ "$b" == "$ip" ] && old_bucket="alma";   done

        local distro_raw distro_id distro_ver
        distro_raw="$(ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
            -o ConnectTimeout=10 \
            "${GHOST_USER}@${ip}" \
            '. /etc/os-release && echo "$ID ${VERSION_ID%%.*}"' 2>/dev/null)"
        read -r distro_id distro_ver <<< "$distro_raw"

        if [ -n "$distro_id" ]; then
            local new_bucket=""
            case "${distro_id,,}" in
                ubuntu)      new_bucket="ubuntu" ;;
                rhel|redhat) new_bucket="rhel"    ;;
                rocky)       new_bucket="rocky"   ;;
                almalinux)   new_bucket="alma"    ;;
                *)
                    log_warn "[Phase0.4] Unrecognized live distro_id='${distro_id}' on ${ip} — keeping original bucket '${old_bucket}'"
                    new_bucket="$old_bucket"
                    ;;
            esac

            if [ "$old_bucket" != "$new_bucket" ]; then
                log_warn "[Phase0.4] RECLASSIFIED ${ip}: name suggested '${old_bucket}' but actual OS is '${new_bucket}' (${distro_id}${distro_ver})"
            else
                log_ok "[Phase0.4] ${ip} confirmed as '${new_bucket}' (${distro_id}${distro_ver})"
            fi

            case "$new_bucket" in
                ubuntu) NEW_UBUNTU+=("$ip") ;;
                rhel)   NEW_RHEL+=("$ip")   ;;
                rocky)  NEW_ROCKY+=("$ip")  ;;
                alma)   NEW_ALMA+=("$ip")   ;;
            esac
            continue
        fi

        # /etc/os-release check failed — see if this is secretly a Windows host
        # (mapped wrong at the fabric/name level) before giving up.
        if ssh -n -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
                "${WIN_GHOST_USER}@${ip}" "echo WIN_PROBE_OK" 2>/dev/null | grep -q WIN_PROBE_OK; then
            log_warn "[Phase0.4] RECLASSIFIED ${ip}: was bucketed as Linux ('${old_bucket}') but responds as Windows over SSH — moving to Windows"
            NEW_WINDOWS+=("$ip")
        else
            log_warn "[Phase0.4] Could not verify OS on ${ip} (neither Linux os-release nor Windows SSH responded) — keeping original bucket '${old_bucket}', may fail later"
            case "$old_bucket" in
                ubuntu) NEW_UBUNTU+=("$ip") ;;
                rhel)   NEW_RHEL+=("$ip")   ;;
                rocky)  NEW_ROCKY+=("$ip")  ;;
                alma)   NEW_ALMA+=("$ip")   ;;
            esac
        fi
    done

    # ---------- Verify hosts currently bucketed as Windows ----------
    for ip in "${all_win_ips[@]}"; do
        local win_caption win_ver
        win_caption=$(ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
            "${WIN_GHOST_USER}@${ip}" \
            "powershell -NoProfile -Command \"(Get-CimInstance Win32_OperatingSystem).Caption\"" 2>/dev/null)

        if [ -n "$win_caption" ]; then
            win_ver=$(detect_windows_version "$ip")
            log_ok "[Phase0.4] ${ip} confirmed as Windows (${win_caption} -> WS${win_ver})"
            NEW_WINDOWS+=("$ip")
            continue
        fi

        # PowerShell probe failed — check if it's secretly a Linux host instead.
        local linux_check
        linux_check="$(ssh -n -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
            "${GHOST_USER}@${ip}" '. /etc/os-release && echo "$ID"' 2>/dev/null)"

        if [ -n "$linux_check" ]; then
            log_warn "[Phase0.4] RECLASSIFIED ${ip}: was bucketed as Windows but reports Linux distro_id='${linux_check}' — moving to appropriate Linux bucket"
            case "${linux_check,,}" in
                ubuntu)      NEW_UBUNTU+=("$ip") ;;
                rhel|redhat) NEW_RHEL+=("$ip")   ;;
                rocky)       NEW_ROCKY+=("$ip")  ;;
                almalinux)   NEW_ALMA+=("$ip")   ;;
                *)
                    log_error "[Phase0.4] ${ip} reports unrecognized distro_id='${linux_check}' — dropping from this run, needs manual triage"
                    ;;
            esac
        else
            log_warn "[Phase0.4] Could not verify OS on ${ip} (neither Windows PowerShell nor Linux os-release responded) — keeping as Windows, may fail later"
            NEW_WINDOWS+=("$ip")
        fi
    done

    UBUNTU_MACHINES=("${NEW_UBUNTU[@]}")
    RHEL_MACHINES=("${NEW_RHEL[@]}")
    ROCKY_MACHINES=("${NEW_ROCKY[@]}")
    ALMA_MACHINES=("${NEW_ALMA[@]}")
    WINDOWS_MACHINES=("${NEW_WINDOWS[@]}")

    log_ok "[Phase0.4] Reclassification complete — Ubuntu:${#UBUNTU_MACHINES[@]} RHEL:${#RHEL_MACHINES[@]} Rocky:${#ROCKY_MACHINES[@]} Alma:${#ALMA_MACHINES[@]} Windows:${#WINDOWS_MACHINES[@]}"
}


# _map_vm is called BY the discovery modules (azure_discover_vms,
# hw_discover_vms) for each host they find, so it must be defined
# here before those functions run.
_map_vm() {
    local vm_name="$1" ip="$2" os="$3" power="$4" offer="$5"
    ip=$(echo "$ip" | tr -d '\r' | xargs)
    [ -z "$ip" ] || [ "$ip" == "None" ] || [[ "$power" != *"running"* ]] && return
    IP_TO_VM_NAME["$ip"]="$vm_name"
    if [[ "$os" == *"Linux"* ]] || [[ "$os" == *"Ubuntu"* ]] || [[ "$os" == *"linux"* ]]; then
        offer="${offer,,}"
        if   [[ "$offer" == *"rocky"* ]] || [[ "${vm_name,,}" == *"rocky"* ]]; then
            ROCKY_MACHINES+=("$ip");  log_info "Mapped Rocky Node:    $ip"
        elif [[ "$offer" == *"alma"*  ]] || [[ "${vm_name,,}" == *"alma"*  ]]; then
            ALMA_MACHINES+=("$ip");   log_info "Mapped AlmaLinux Node: $ip"
        elif [[ "$offer" == *"rhel"*  ]] || [[ "${vm_name,,}" == *"rhel"*  ]]; then
            RHEL_MACHINES+=("$ip");   log_info "Mapped RHEL Node:      $ip"
        else
            UBUNTU_MACHINES+=("$ip"); log_info "Mapped Ubuntu Node:    $ip"
        fi
    elif [[ "$os" == *"Windows"* ]] || [[ "$os" == *"windows"* ]]; then
        WINDOWS_MACHINES+=("$ip");    log_info "Mapped Windows Node:   $ip"
    fi
}

case "${CLOUD_PROVIDER}" in
    azure)       azure_discover_vms "$H_TARGETS" ;;
    huaweicloud) hw_check_prereqs && hw_discover_vms "$H_TARGETS" ;;
esac

if [ "$HEADLESS" == true ] && [ ${#UBUNTU_MACHINES[@]} -eq 0 ] && \
   [ ${#RHEL_MACHINES[@]} -eq 0 ] && [ ${#ROCKY_MACHINES[@]} -eq 0 ] && \
   [ ${#ALMA_MACHINES[@]} -eq 0 ] && [ ${#WINDOWS_MACHINES[@]} -eq 0 ]; then
    log_warn "No matching VMs found for environment '${H_TARGETS}' — nothing to audit. Exiting cleanly."
    exit 0
fi

if [ "$H_TARGET_IP" != "all" ] && [ -n "$H_TARGET_IP" ]; then
    log_info "MATRIX SHARDING: Isolating to node $H_TARGET_IP"
    UBUNTU_MACHINES=(); RHEL_MACHINES=(); ROCKY_MACHINES=()
    ALMA_MACHINES=();   WINDOWS_MACHINES=()

    SHARD_VM_NAME="${IP_TO_VM_NAME[$H_TARGET_IP]:-}"
    if [ -z "$SHARD_VM_NAME" ]; then
        case "${CLOUD_PROVIDER}" in
            azure)       SHARD_VM_NAME=$(azure_resolve_vm_name_by_ip "$H_TARGET_IP")
                         [ -n "$SHARD_VM_NAME" ] && IP_TO_VM_NAME["$H_TARGET_IP"]="$SHARD_VM_NAME" ;;
            huaweicloud) SHARD_VM_NAME=$(hw_resolve_vm_by_ip "$H_TARGET_IP") ;;
        esac
    fi

    case "${H_TARGET_OS,,}" in
        ubuntu)  UBUNTU_MACHINES=("$H_TARGET_IP")  ;;
        rhel)    RHEL_MACHINES=("$H_TARGET_IP")    ;;
        rocky)   ROCKY_MACHINES=("$H_TARGET_IP")   ;;
        alma)    ALMA_MACHINES=("$H_TARGET_IP")    ;;
        windows) WINDOWS_MACHINES=("$H_TARGET_IP") ;;
    esac
fi

# ======================================================
# PHASE 0.2: EARLY EXIT
# ======================================================
if [ "$HEADLESS" == true ] && [ "$H_TARGET_OS" != "all" ]; then
    case "${H_TARGET_OS,,}" in
        ubuntu)  [ ${#UBUNTU_MACHINES[@]}  -eq 0 ] && exit 0 ;;
        rhel)    [ ${#RHEL_MACHINES[@]}    -eq 0 ] && exit 0 ;;
        rocky)   [ ${#ROCKY_MACHINES[@]}   -eq 0 ] && exit 0 ;;
        alma)    [ ${#ALMA_MACHINES[@]}    -eq 0 ] && exit 0 ;;
        windows) [ ${#WINDOWS_MACHINES[@]} -eq 0 ] && exit 0 ;;
    esac
fi

# ======================================================
# PHASE 0.3: AUTO-HEALER
# Self-heal only — bootstraps the dedicated audit account
# if unreachable. For Huawei Cloud this still requires
# LINUX_ADMIN_USER's key to already be trusted on the
# instance (image bake or cloud-init), since there is no
# out-of-band run-command channel like Azure's.
# ======================================================
log_info "PHASE 0.3: PARALLEL INFRASTRUCTURE BOOTSTRAPPING"
RUNNER_IP=$(curl -s https://api.ipify.org)

if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" =~ ^(ubuntu|rhel|rocky|alma)$ ]]; then
    for ip in "${UBUNTU_MACHINES[@]}" "${RHEL_MACHINES[@]}" "${ROCKY_MACHINES[@]}" "${ALMA_MACHINES[@]}"; do
        (
            if [ "$(ssh -n -o BatchMode=yes -o ConnectTimeout=5 \
                    -o StrictHostKeyChecking=no "${GHOST_USER}@${ip}" \
                    "echo SSH_OK" 2>/dev/null)" != "SSH_OK" ]; then
                cloud_add_port_rule "$ip" 22 "Allow_SSH_Runner_Only"
                PUB_KEY=$(cat ~/.ssh/id_rsa.pub)
                cloud_vm_run_shell "$ip" "useradd -m -s /bin/bash ${GHOST_USER} || true
                   echo '${GHOST_USER} ALL=(ALL) NOPASSWD:ALL' \
                       > /etc/sudoers.d/99-${GHOST_USER}
                   chmod 440 /etc/sudoers.d/99-${GHOST_USER}
                   mkdir -p /home/${GHOST_USER}/.ssh
                   echo '${PUB_KEY}' > /home/${GHOST_USER}/.ssh/authorized_keys
                   chown -R ${GHOST_USER}:${GHOST_USER} /home/${GHOST_USER}/.ssh
                   chmod 700 /home/${GHOST_USER}/.ssh
                   chmod 600 /home/${GHOST_USER}/.ssh/authorized_keys
                   command -v restorecon &>/dev/null && \
                       restorecon -Rv /home/${GHOST_USER}/.ssh >/dev/null 2>&1 || true
                   if grep -qE '^AllowUsers' /etc/ssh/sshd_config; then
                       grep -q \"\\b${GHOST_USER}\\b\" /etc/ssh/sshd_config || \
                           sed -i \"s/^AllowUsers.*/& ${GHOST_USER}/\" /etc/ssh/sshd_config
                   fi
                   systemctl restart sshd" || true
                sleep 15
            fi
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
                "${GHOST_USER}@${ip}" \
                "sudo grep -q '^MaxStartups 100:' /etc/ssh/sshd_config.d/00-maxstartups-override.conf 2>/dev/null || {
                    echo 'MaxStartups 100:30:200' | sudo tee /etc/ssh/sshd_config.d/00-maxstartups-override.conf >/dev/null
                    sudo systemctl reload sshd
                }" 2>/dev/null
        ) &
    done
fi

if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
    for ip in "${WINDOWS_MACHINES[@]}"; do
        (
            cloud_add_port_rule "$ip" 22 "Allow_SSH_Runner_Only_Win"

            svc_audit_ok=false
            for _attempt in 1 2 3 4; do
                if ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
                       "${WIN_GHOST_USER}@${ip}" "echo SSH_OK" 2>/dev/null | grep -q SSH_OK; then
                    svc_audit_ok=true
                    break
                fi
                sleep 5
            done

            if [ "$svc_audit_ok" == true ]; then
                log_ok "[Win Bootstrap] ${WIN_GHOST_USER} already reachable on ${ip} — skipping Administrator bootstrap"
            else
                log_warn "[Win Bootstrap] ${WIN_GHOST_USER} unreachable on ${ip} after retries — falling back to ${WIN_SSH_USER}"
                if ! wait_for_ssh "$ip" "$WIN_SSH_USER"; then
                    log_warn "[Win Bootstrap] SSH unreachable via ${WIN_SSH_USER} on ${ip} — attempting repair"
                    if cloud_vm_bootstrap_ssh "$ip" && wait_for_ssh "$ip" "$WIN_SSH_USER" 6 10; then
                        log_ok "[Win Bootstrap] SSH repaired on ${ip} — continuing"
                    else
                        log_error "[Win Bootstrap] SSH unreachable via both ${WIN_GHOST_USER} and ${WIN_SSH_USER}, and repair failed/unavailable: $ip"
                        exit 1
                    fi
                fi
                ensure_windows_ghost_user "$ip" || \
                    log_error "[Win Bootstrap] Ghost user provisioning failed: $ip"
            fi
        ) &
    done
fi
wait
reclassify_hosts_by_actual_os
# ======================================================
# INVENTORY BUILDER
# ======================================================
{
    echo "[ubuntu_nodes]"
    for ip in "${UBUNTU_MACHINES[@]}"; do echo "${ip} ansible_user=${GHOST_USER}"; done

    echo -e "\n[rhel_nodes]"
    for ip in "${RHEL_MACHINES[@]}"; do echo "${ip} ansible_user=${GHOST_USER}"; done

    echo -e "\n[rocky_nodes]"
    for ip in "${ROCKY_MACHINES[@]}"; do echo "${ip} ansible_user=${GHOST_USER}"; done

    echo -e "\n[alma_nodes]"
    for ip in "${ALMA_MACHINES[@]}"; do echo "${ip} ansible_user=${GHOST_USER}"; done

    echo -e "\n[windows_nodes]"
    for ip in "${WINDOWS_MACHINES[@]}"; do
        echo "${ip} ansible_user=${WIN_GHOST_USER} ansible_connection=ssh \
ansible_shell_type=powershell ansible_ssh_common_args='-o StrictHostKeyChecking=no'"
    done
} > inventory.ini

RUN_ORG=false; RUN_CIS=false
if [ "$HEADLESS" == true ]; then
    if [[ "${H_PROFILE,,}" == "${ORG_PREFIX,,}" ]] || [[ "${H_PROFILE,,}" == "both" ]]; then RUN_ORG=true; fi
    if [[ "${H_PROFILE,,}" == "cis" ]] || [[ "${H_PROFILE,,}" == "both" ]]; then RUN_CIS=true; fi
else
    echo -e "\n1) CUSTOM BASELINE\n2) CIS BASELINE\n3) BOTH"
    read -r -p "Choose profile [1-3]: " pc
    if [ "$pc" == "1" ] || [ "$pc" == "3" ]; then RUN_ORG=true; fi
    if [ "$pc" == "2" ] || [ "$pc" == "3" ]; then RUN_CIS=true; fi
fi

update_profile_vars() {
    if [ "$RUN_CIS" == true ]; then
        if [ "$CIS_LEVEL" == "Level 1" ]; then
            UBUNTU_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis_level1_server"
            RHEL_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis_server_l1"
            OS_LVL="1"
            WIN_INSPEC_LVL="1"
        else
            UBUNTU_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis_level2_server"
            RHEL_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis"
            OS_LVL="2"
            WIN_INSPEC_LVL="2"
        fi
    fi
}

# ======================================================
# EXECUTION ENGINE
# ======================================================
execute_phases() {
    case $H_MODE in
        scan)      run_phase_1 ;;
        remediate) run_remediation; run_phase_4 ;;
        full)      run_phase_1; run_remediation; run_phase_4 ;;
    esac
}

# ======================================================
# HEADLESS (CI/CD) RUNNER
# ======================================================
if [ "$HEADLESS" == true ]; then
    log_info "======================================================"
    log_info "CI/CD WORKFLOW: MODE -> $H_MODE | OS -> $H_TARGET_OS"
    log_info "======================================================"

    if [ "${H_PROFILE,,}" == "all" ]; then
        prefetch_scap_packages || { log_error "Aborting — package prefetch failed."; exit 1; }

        export CIS_LEVEL="Level 1"; export RUN_CIS=true; export RUN_ORG=false
        update_profile_vars
        log_info "STEP 1/3: CIS LEVEL 1"
        execute_phases

        export CIS_LEVEL="Level 2"; export RUN_CIS=true; export RUN_ORG=false
        update_profile_vars
        log_info "STEP 2/3: CIS LEVEL 2"
        execute_phases

        export RUN_CIS=false; export RUN_ORG=true
        update_profile_vars
        log_info "STEP 3/3: ${ORG_PREFIX^^} BASELINE"
        execute_phases
    else
        prefetch_scap_packages || { log_error "Aborting — package prefetch failed."; exit 1; }
        update_profile_vars
        execute_phases
    fi

    if [ "$H_CLEANUP" == "true" ]; then run_cleanup; fi

    chmod 755 ./*.json ./*.html 2>/dev/null || true
    log_ok "CI/CD Pipeline complete. All reports generated."
    exit 0
fi

# ======================================================
# INTERACTIVE MODE
# ======================================================
prefetch_scap_packages || { log_error "Aborting — package prefetch failed."; exit 1; }

while true; do
    update_profile_vars
    echo -e "\n${CYAN}------------------------------------------------------${NC}"
    echo -e "1) ${BOLD}SCAN ONLY${NC}"
    echo -e "2) ${BOLD}REMEDIATE ONLY${NC}"
    echo -e "3) ${BOLD}FULL PIPELINE${NC}"
    echo -e "4) ${BOLD}CLEANUP${NC}"
    echo -e "5) ${BOLD}EXIT${NC}"
    read -r -p "Choose an option [1-5]: " choice
    case $choice in
        1) run_phase_1 ;;
        2) run_remediation; run_phase_4 ;;
        3) run_phase_1; run_remediation; run_phase_4 ;;
        4) run_cleanup ;;
        5) exit 0 ;;
        *) echo -e "${RED}Invalid choice.${NC}" ;;
    esac
done
