#!/bin/bash
# ======================================================
# modules/discovery_cae.sh
# Huawei Cloud (CAE) discovery, security-group rule
# management, and power-state helpers.
# Depends on: modules/utils.sh (log_*, require_env)
# Requires: HW_PROJECT_ID, HUAWEICLOUD_ACCESS_KEY,
#           HUAWEICLOUD_SECRET_KEY, HW_ECS_ENDPOINT,
#           HW_VPC_ENDPOINT, scripts/hw_ecs_discover.py,
#           scripts/hw_sg_rule_manage.py
# ======================================================

if [ -n "${__DISCOVERY_CAE_SH_LOADED:-}" ]; then
    return 0
fi
__DISCOVERY_CAE_SH_LOADED=1

# ------------------------------------------------------
# hw_check_prereqs
# Verifies the Python SDK is installed and credentials are
# present, then does a live auth/connectivity check via
# hw_ecs_discover.py before any real work starts.
# ------------------------------------------------------
hw_check_prereqs() {
    if ! python3 -c "import huaweicloudsdkecs" 2>/dev/null; then
        log_error "[HuaweiCloud] Python SDK not installed. Run: pip3 install huaweicloudsdkcore huaweicloudsdkecs"
        return 1
    fi

    require_env HUAWEICLOUD_ACCESS_KEY HUAWEICLOUD_SECRET_KEY HW_PROJECT_ID || return 1

    local err_log
    err_log=$(mktemp /tmp/hw_check_err_XXXXXX.log)
    if ! timeout 20 env \
        HUAWEICLOUD_ACCESS_KEY="${HUAWEICLOUD_ACCESS_KEY}" \
        HUAWEICLOUD_SECRET_KEY="${HUAWEICLOUD_SECRET_KEY}" \
        HW_PROJECT_ID="${HW_PROJECT_ID}" \
        HW_ECS_ENDPOINT="${HW_ECS_ENDPOINT}" \
        HW_EPS_ID="${HW_EPS_ID:-}" \
        python3 "${SCRIPT_DIR}/scripts/hw_ecs_discover.py" >/dev/null 2>"$err_log"; then
        log_error "[HuaweiCloud] SDK auth/connectivity check failed."
        [ -s "$err_log" ] && cat "$err_log" >&2
        rm -f "$err_log"
        return 1
    fi
    rm -f "$err_log"
    log_ok "[HuaweiCloud] SDK authenticated (endpoint: ${HW_ECS_ENDPOINT})"
    return 0
}

# ------------------------------------------------------
# hw_discover_vms
# Populates IP_TO_VM_ID / IP_TO_SG_ID and calls _map_vm
# (defined in the orchestrator) for each running instance.
# Args: tag_val ("all" or a specific Environment tag value)
# ------------------------------------------------------
hw_discover_vms() {
    local tag_val="$1"

    log_info "[HuaweiCloud] Querying ECS instances via SDK [endpoint: ${HW_ECS_ENDPOINT}]..."

    local hw_raw hw_rc
    hw_raw=$(
        HUAWEICLOUD_ACCESS_KEY="${HUAWEICLOUD_ACCESS_KEY}" \
        HUAWEICLOUD_SECRET_KEY="${HUAWEICLOUD_SECRET_KEY}" \
        HW_PROJECT_ID="${HW_PROJECT_ID}" \
        HW_ECS_ENDPOINT="${HW_ECS_ENDPOINT}" \
        HW_ECS_TAG_KEY="${HW_ECS_TAG_KEY}" \
        HW_ECS_TAG_VAL="${tag_val}" \
        HW_EPS_ID="${HW_EPS_ID:-}" \
        python3 "${SCRIPT_DIR}/scripts/hw_ecs_discover.py" --tsv
    )
    hw_rc=$?

    if [ $hw_rc -ne 0 ] || [ -z "$hw_raw" ]; then
        log_error "[HuaweiCloud] ECS list returned empty or failed."
        [ -n "${HW_EPS_ID:-}" ] && \
            log_warn "HW_EPS_ID='${HW_EPS_ID}' is set — verify instances belong to this enterprise project."
        return 1
    fi

    # hw_ecs_discover.py --tsv emits: os_type, offer, name, ip, srv_id, sg_id
    # (already filtered to ACTIVE/RUNNING, so we pass a literal "running")
    while IFS=$'\t' read -r os_type offer vm_name ip srv_id sg_id; do
        IP_TO_VM_ID["$ip"]="$srv_id"
        IP_TO_SG_ID["$ip"]="$sg_id"
        _map_vm "$vm_name" "$ip" "$os_type" "running" "$offer"
    done <<< "$hw_raw"
}

# ------------------------------------------------------
# hw_resolve_vm_by_ip
# Used by the matrix-sharding path (--target-ip) to resolve
# name/id/sg for a single IP not yet in the maps.
# ------------------------------------------------------
hw_resolve_vm_by_ip() {
    local target_ip="$1"
    local hw_raw
    hw_raw=$(
        HUAWEICLOUD_ACCESS_KEY="${HUAWEICLOUD_ACCESS_KEY}" \
        HUAWEICLOUD_SECRET_KEY="${HUAWEICLOUD_SECRET_KEY}" \
        HW_PROJECT_ID="${HW_PROJECT_ID}" \
        HW_ECS_ENDPOINT="${HW_ECS_ENDPOINT}" \
        HW_EPS_ID="${HW_EPS_ID:-}" \
        python3 "${SCRIPT_DIR}/scripts/hw_ecs_discover.py" --tsv
    )

    while IFS=$'\t' read -r os_type offer vm_name ip srv_id sg_id; do
        [ "$ip" == "$target_ip" ] || continue
        IP_TO_VM_NAME["$ip"]="$vm_name"
        IP_TO_VM_ID["$ip"]="$srv_id"
        IP_TO_SG_ID["$ip"]="$sg_id"
        echo "$vm_name"
        return 0
    done <<< "$hw_raw"

    log_warn "[HuaweiCloud] Could not resolve VM name/ID for ${target_ip} — reboot/power-state helpers will no-op for this host."
    return 1
}

# ------------------------------------------------------
# hw_add_port_rule
# Adds/refreshes an SG rule allowing the runner's IP on the
# given port. Requires IP_TO_SG_ID[$ip] to already be set
# by hw_discover_vms/hw_resolve_vm_by_ip.
# Args: ip port [protocol]
# ------------------------------------------------------
hw_add_port_rule() {
    local ip="$1" port="$2" protocol="${3:-tcp}"
    local sg_id="${IP_TO_SG_ID[$ip]:-}"
    local runner_ip="${RUNNER_IP:-$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null)}"

    if [ -z "$sg_id" ]; then
        log_warn "[HW] No SG ID resolved for ${ip} — skipping rule add/refresh"
        return 1
    fi

    HW_VPC_ENDPOINT="${HW_VPC_ENDPOINT}" \
    python3 "${SCRIPT_DIR}/scripts/hw_sg_rule_manage.py" \
        --sg-id "$sg_id" \
        --port "$port" \
        --remote-ip "$runner_ip" \
        --protocol "$protocol"
}

# ------------------------------------------------------
# hw_reassert_ssh_rule_all
# Re-applies the port-22 SG rule for a list of IPs. Guards
# against the SG rule being overwritten/expired between
# discovery and the remediation phase actually running.
# Args: ip1 [ip2 ...]
# ------------------------------------------------------
hw_reassert_ssh_rule_all() {
    local ips=("$@")
    [ ${#ips[@]} -eq 0 ] && return 0

    local runner_ip
    runner_ip="${RUNNER_IP:-$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null)}"
    log_info "[SG-Reassert] Refreshing port-22 rule for ${#ips[@]} host(s) -> runner ${runner_ip}"

    local ip
    for ip in "${ips[@]}"; do
        hw_add_port_rule "$ip" 22 tcp
    done
}

# ------------------------------------------------------
# hw_vm_run_shell
# Runs a shell command over keyed SSH. Unlike Azure, there
# is no out-of-band run-command channel here — this assumes
# LINUX_ADMIN_USER's key is already trusted on the instance
# (baked into the image or injected via cloud-init/user-data
# at creation time). This function cannot bootstrap trust
# from zero.
# ------------------------------------------------------
hw_vm_run_shell() {
    local ip="$1"
    local script="$2"
    local user="${3:-${LINUX_ADMIN_USER:-root}}"

    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        "${user}@${ip}" "$script" >/dev/null 2>&1
}

# ------------------------------------------------------
# hw_vm_restart
# Fire-and-forget hard reboot via the hcloud CLI.
# ------------------------------------------------------
hw_vm_restart() {
    local ip="$1"
    local vm_id="${IP_TO_VM_ID[$ip]:-}"

    if [ -z "$vm_id" ]; then
        log_warn "[HW] No ECS ID for ${ip} — cannot restart"
        return 1
    fi

    timeout 120 hcloud ECS RebootServer \
        --server-id "$vm_id" \
        --type.type "HARD" \
        --cli-region "${HW_REGION}" \
        --cli-output json >/dev/null 2>&1 || true
}

# ------------------------------------------------------
# hw_vm_get_power_state
# Prints "running" or a lowercased status string, or
# "unknown" on failure. Verbose SDK errors go to stderr
# rather than getting silently swallowed.
# ------------------------------------------------------
hw_vm_get_power_state() {
    local ip="$1"
    local vm_id="${IP_TO_VM_ID[$ip]:-}"

    if [ -z "$vm_id" ]; then
        echo "unknown"
        return
    fi

    local err_log raw
    err_log=$(mktemp "/tmp/hw_power_err_$(echo "$ip" | tr '.' '_')_XXXXXX.log")
    raw=$(
        HUAWEICLOUD_ACCESS_KEY="${HUAWEICLOUD_ACCESS_KEY}" \
        HUAWEICLOUD_SECRET_KEY="${HUAWEICLOUD_SECRET_KEY}" \
        HW_PROJECT_ID="${HW_PROJECT_ID}" \
        HW_ECS_ENDPOINT="${HW_ECS_ENDPOINT}" \
        timeout 30 python3 - "$vm_id" <<'PYEOF' 2>"$err_log"
import sys, os
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkecs.v2 import EcsClient, ShowServerRequest

server_id = sys.argv[1]
try:
    creds = BasicCredentials(
        os.environ['HUAWEICLOUD_ACCESS_KEY'],
        os.environ['HUAWEICLOUD_SECRET_KEY'],
        os.environ.get('HW_PROJECT_ID'),
    )
    client = EcsClient.new_builder() \
        .with_credentials(creds) \
        .with_endpoint(os.environ['HW_ECS_ENDPOINT']) \
        .build()
    resp = client.show_server(ShowServerRequest(server_id=server_id))
    status = resp.server.status
    print('running' if status == 'ACTIVE' else status.lower())
except Exception as e:
    print(str(e), file=sys.stderr)
PYEOF
    )

    if [ -z "$raw" ] && [ -s "$err_log" ]; then
        log_warn "[PowerState] SDK call failed for ${ip}:"
        cat "$err_log" >&2
    fi
    rm -f "$err_log"

    [[ "$raw" == *"running"* ]] && echo "running" || echo "${raw:-unknown}"
}
