#!/bin/bash
# ======================================================
# modules/discovery_azure.sh
# Azure-specific VM discovery, NSG rule management, and
# run-command/restart/power-state helpers.
# Depends on: modules/utils.sh (log_*, require_env)
# Requires: RG_NAME, az CLI authenticated in the environment.
# ======================================================

if [ -n "${__DISCOVERY_AZURE_SH_LOADED:-}" ]; then
    return 0
fi
__DISCOVERY_AZURE_SH_LOADED=1

# ------------------------------------------------------
# azure_discover_vms
# Populates the shared IP_TO_VM_NAME map and calls _map_vm
# (defined in the orchestrator) for each running VM found.
# Args: targets_filter ("all" or an Environment tag value)
# ------------------------------------------------------
azure_discover_vms() {
    local targets="$1"

    require_env RG_NAME || return 1

    log_info "[Azure] Querying VMs in resource group [${RG_NAME}]..."

    local vm_data
    if [ "$targets" == "all" ] || [ -z "$targets" ]; then
        vm_data=$(az vm list -d -g "$RG_NAME" \
            --query "[].[name, publicIps, storageProfile.osDisk.osType, powerState, storageProfile.imageReference.offer]" \
            -o tsv)
    else
        vm_data=$(az vm list -d -g "$RG_NAME" \
            --query "[?tags.Environment=='$targets'].[name, publicIps, storageProfile.osDisk.osType, powerState, storageProfile.imageReference.offer]" \
            -o tsv)
    fi

    if [ -z "$vm_data" ]; then
        log_warn "[Azure] No VMs returned for targets='${targets}'"
        return 0
    fi

    while IFS=$'\t' read -r raw_name raw_ip raw_os raw_power raw_offer; do
        local vm_name ip os power offer
        vm_name=$(echo "$raw_name"  | tr -d '\r' | xargs)
        ip=$(echo "$raw_ip"         | tr -d '\r' | xargs)
        os=$(echo "$raw_os"         | tr -d '\r' | xargs)
        power=$(echo "$raw_power"   | tr -d '\r' | xargs)
        offer=$(echo "$raw_offer"   | tr -d '\r' | xargs)
        _map_vm "$vm_name" "$ip" "$os" "$power" "$offer"
    done <<< "$vm_data"
}

# ------------------------------------------------------
# azure_resolve_vm_name_by_ip
# Used by the matrix-sharding path (--target-ip) when a
# single IP wasn't already captured in IP_TO_VM_NAME.
# ------------------------------------------------------
azure_resolve_vm_name_by_ip() {
    local ip="$1"
    az vm list -d -g "$RG_NAME" \
        --query "[?publicIps=='${ip}'].name | [0]" -o tsv 2>/dev/null
}

# ------------------------------------------------------
# azure_add_port_rule
# Opens an inbound NSG rule for the given port, scoped to
# the runner's own public IP.
# Args: ip port [rule_name]
# ------------------------------------------------------
azure_add_port_rule() {
    local ip="$1" port="$2" rule_name="${3:-Allow_Port_${2}_Runner}"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"
    local runner_ip="${RUNNER_IP:-$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null)}"

    if [ -z "$vm_name" ]; then
        log_warn "[Azure] No VM name resolved for ${ip} — cannot add NSG rule"
        return 1
    fi

    local nic_id nsg_id nsg_name
    nic_id=$(az vm show -g "$RG_NAME" -n "$vm_name" \
        --query "networkProfile.networkInterfaces[0].id" -o tsv 2>/dev/null)
    nsg_id=$(az network nic show --ids "$nic_id" \
        --query "networkSecurityGroup.id" -o tsv 2>/dev/null)

    if [ -z "$nsg_id" ]; then
        log_warn "[Azure] No NSG attached to ${vm_name} (${ip}) — skipping rule add"
        return 0
    fi

    nsg_name=$(basename "$nsg_id")
    az network nsg rule create -g "$RG_NAME" --nsg-name "$nsg_name" \
        --name "$rule_name" --priority 998 \
        --destination-port-ranges "$port" \
        --source-address-prefixes "$runner_ip" \
        --access Allow --protocol Tcp -o none >/dev/null 2>&1 || true
}

# ------------------------------------------------------
# azure_vm_run_shell
# Executes a shell script on the VM via az vm run-command
# (out-of-band control plane, doesn't require SSH access).
# ------------------------------------------------------
azure_vm_run_shell() {
    local ip="$1"
    local script="$2"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"
    local timeout_secs="${3:-${WIN_AGENT_PROBE_SEC:-180}}"

    if [ -z "$vm_name" ]; then
        log_warn "[Azure] No VM name resolved for ${ip} — cannot run-command"
        return 1
    fi

    timeout "$timeout_secs" az vm run-command invoke \
        -g "$RG_NAME" -n "$vm_name" \
        --command-id RunShellScript \
        --scripts "$script" \
        -o none >/dev/null 2>&1
}

# ------------------------------------------------------
# azure_vm_restart
# Fire-and-forget restart; caller is responsible for
# polling azure_vm_get_power_state afterwards.
# ------------------------------------------------------
azure_vm_restart() {
    local ip="$1"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"

    if [ -z "$vm_name" ]; then
        log_warn "[Azure] No VM name resolved for ${ip} — cannot restart"
        return 1
    fi

    timeout 120 az vm restart -g "$RG_NAME" -n "$vm_name" --no-wait -o none 2>/dev/null || true
}

# ------------------------------------------------------
# azure_vm_get_power_state
# Prints "running" or the raw Azure PowerState string
# (e.g. "stopped", "deallocated"), or "unknown" on failure.
# ------------------------------------------------------
azure_vm_get_power_state() {
    local ip="$1"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"

    if [ -z "$vm_name" ]; then
        echo "unknown"
        return
    fi

    local raw
    raw=$(timeout 30 az vm get-instance-view -g "$RG_NAME" -n "$vm_name" \
        --query "instanceView.statuses[?starts_with(code,'PowerState')].displayStatus" \
        -o tsv 2>/dev/null | tr -d '\r')

    [[ "$raw" == *"running"* ]] && echo "running" || echo "${raw:-unknown}"
}
