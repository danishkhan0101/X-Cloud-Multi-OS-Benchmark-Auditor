#!/bin/bash
set +H

# ======================================================
# CONFIGURATION - DYNAMIC ENVIRONMENT VARIABLES
# ======================================================
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

ORG_NAME="${ORG_NAME:-Custom}"
ORG_PREFIX="${ORG_PREFIX:-custom}"
GHOST_USER="${GHOST_USER:-audit_ghost}"
CUSTOM_XCCDF_PROFILE="${CUSTOM_XCCDF_PROFILE:-xccdf_com.org_profile_lsb}"
RG_NAME="${AZURE_RG_NAME:-DEFAULT_RG}"
KV_NAME="${AZURE_KV_NAME:-YOUR-KEYVAULT-NAME}"
SECRET_NAME="${AZURE_KV_SECRET:-AuditPassword}"
UBUNTU_USER="${LINUX_ADMIN_USER:-ubuntu}"
AUDIT_USER="${WINDOWS_ADMIN_USER:-Windows_Admin}"

UBUNTU_CUSTOM_DIR="ubuntu-custom"
UBUNTU_CUSTOM_XCCDF="${UBUNTU_CUSTOM_DIR}/${ORG_PREFIX}_xccdf.xml"
UBUNTU_CUSTOM_OVAL="${UBUNTU_CUSTOM_DIR}/${ORG_PREFIX}_ubuntu_rules.xml"
UBUNTU_CUSTOM_PLAYBOOK="${UBUNTU_CUSTOM_DIR}/ubuntu_custom_playbook.yml"

RHEL_CUSTOM_DIR="rhel-custom"
RHEL_CUSTOM_XCCDF="${RHEL_CUSTOM_DIR}/${ORG_PREFIX}_rhel_xccdf.xml"
RHEL_CUSTOM_OVAL="${RHEL_CUSTOM_DIR}/${ORG_PREFIX}_rhel_rules.xml"
RHEL_CUSTOM_PLAYBOOK="${RHEL_CUSTOM_DIR}/rhel_custom_playbook.yml"

WIN_CUSTOM_DIR="window-custom"
WIN_CUSTOM_BENCHMARK="${WIN_CUSTOM_DIR}/${ORG_PREFIX}_baseline.rb"
WIN_CUSTOM_PLAYBOOK="${WIN_CUSTOM_DIR}/${ORG_PREFIX}_remediate.yml"

WIN_CIS_DIR="window-default-cis"
WIN_CIS_BENCHMARK="${WIN_CIS_DIR}/window-baseline"
# NOTE: WIN_CIS_PLAYBOOK is no longer used directly — remediate_windows_host()
# selects the per-version playbook (cis_remediate_2022.yml / _2025.yml / etc).

# ======================================================
# GOSS AUDIT CONFIG (replaces cinc-auditor for Win CIS)
# ======================================================
GOSS_BINARY_LOCAL="./window-default-cis/goss-windows-amd64.exe"  
GOSS_AUDIT_REPO_2019="./window-default-cis/Windows-2019-CIS-Audit"
GOSS_REMOTE_DIR="C:\\goss_audit"
GOSS_OUTPUT_FORMAT="json"   # json | junit | documentation

export INSPEC_SSH_CONFIG_NO_SECURE=true
BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; MAGENTA='\033[0;35m'; NC='\033[0m'
clear

# ======================================================
# REMEDIATION CONSTANTS (Layer 1 + Layer 2 hardening)
# ======================================================
# Per-host timeout for oscap --remediate. Tune per your slowest
# CIS profile. Ubuntu Level 2 can take 30+ min on first run.
REMEDIATION_TIMEOUT_SEC=1800   # 30 min

# SSH options used for every remediation call.
#  -o ControlMaster=no    → ignore the multiplex pool entirely
#  -o ControlPath=none    → don't even try to reuse a socket
#  -o ServerAliveInterval → send a keepalive every 15s
#  -o ServerAliveCountMax → give up after 4 missed = 60s dead
#  -o ConnectTimeout      → initial TCP connect fails fast
REMEDIATION_SSH_OPTS="-n -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o ControlMaster=no -o ControlPath=none \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
    -o ConnectTimeout=10"

# ======================================================
# HELPER: detect_windows_version
# ------------------------------------------------------
# Asks the target what version of Windows it is.
# Returns: 2019 | 2022 | 2025 | 10 | 11 | unknown
# ======================================================
detect_windows_version() {
    local ip="$1"

    local caption
    caption=$(ansible -i inventory.ini "${ip}" -m ansible.windows.win_shell \
        -a '(Get-CimInstance Win32_OperatingSystem).Caption' \
        2>/dev/null | grep -oE 'Windows (Server (2019|2022|2025)|1[01])' | head -1)

    case "$caption" in
        *"Server 2019"*) echo "2019" ;;
        *"Server 2022"*) echo "2022" ;;
        *"Server 2025"*) echo "2025" ;;
        *"Windows 10"*)  echo "10"   ;;
        *"Windows 11"*)  echo "11"   ;;
        *)               echo "unknown" ;;
    esac
}

# ======================================================
# HELPER: remediate_windows_host
# ------------------------------------------------------
# Detects version, installs the right role, runs the
# right playbook with the right tags.
# Args: $1 ip, $2 cis_level ("Level 1" or "Level 2")
# ======================================================
remediate_windows_host() {
    local ip="$1"
    local cis_level="$2"

    echo -e "${CYAN}🔍 [Win] Detecting OS version on ${ip}...${NC}"
    local ver
    ver=$(detect_windows_version "$ip")

    if [ "$ver" == "unknown" ]; then
        echo -e "${RED}❌ [Win] Could not detect OS version on ${ip} — skipping${NC}"
        return 1
    fi
    echo -e "${CYAN}   → Detected: Windows ${ver}${NC}"

    # Map version → role + playbook + tag scope
    #   role_name           = what the playbook's `roles:` block references
    #   role_install_target = what we pass to `ansible-galaxy role install`
    # For Galaxy-published roles these are the same. For roles only on
    # GitHub (e.g. Windows-2025-CIS), we install via git URL and the role
    # lands under the repo name, so the two values differ.
    local role_name
    local role_install_target
    local playbook_file
    local tag_scope_l1
    case "$ver" in
        2019) role_name="ansible-lockdown.windows_2019_cis"
          role_install_target="ansible-lockdown.windows_2019_cis,3.0.0"
          playbook_file="window-default-cis/cis_remediate_2019.yml"
          tag_scope_l1="level1-memberserver" ;;
        2022) role_name="ansible-lockdown.windows_2022_cis"
          role_install_target="ansible-lockdown.windows_2022_cis,3.0.0"
          playbook_file="window-default-cis/cis_remediate_2022.yml"
          tag_scope_l1="level1-memberserver" ;;
        2025) role_name="Windows-2025-CIS"
          role_install_target="git+https://github.com/ansible-lockdown/Windows-2025-CIS.git"
          playbook_file="window-default-cis/cis_remediate_2025.yml"
          tag_scope_l1="level1-memberserver" ;;
        10)   role_name="ansible-lockdown.windows_10_cis"
              role_install_target="ansible-lockdown.windows_10_cis"
              playbook_file="window-default-cis/cis_remediate_win10.yml"
              tag_scope_l1="level1-corporate-enterprise-environment" ;;
        11)   role_name="ansible-lockdown.windows_11_cis"
              role_install_target="ansible-lockdown.windows_11_cis"
              playbook_file="window-default-cis/cis_remediate_win11.yml"
              tag_scope_l1="level1-corporate-enterprise-environment" ;;
    esac

    if [ ! -f "$playbook_file" ]; then
        echo -e "${RED}❌ [Win/${ver}] Playbook missing: ${playbook_file}${NC}"
        echo -e "${YELLOW}   You need to create ${playbook_file} for Windows ${ver}${NC}"
        return 1
    fi

    # Install matching role (force-refresh to catch upstream updates)
    echo -e "${CYAN}📦 [Win/${ver}] Installing ${role_name} (from ${role_install_target})...${NC}"

    # Build tag list — Level 2 includes Level 1
    local tags
    if [ "$cis_level" == "Level 2" ]; then
        if [ "$ver" -ge 10 ] 2>/dev/null && [ "$ver" -le 11 ] 2>/dev/null; then
            tags="level1-corporate-enterprise-environment,level2-corporate-enterprise-environment"
        else
            tags="level1-memberserver,level2-memberserver"
        fi
        echo -e "${CYAN}   → Applying Level 1 + Level 2 controls${NC}"
    else
        tags="$tag_scope_l1"
        echo -e "${CYAN}   → Applying Level 1 controls only${NC}"
    fi

    # Run it
    echo -e "${CYAN}🛠️  [Win/${ver}] Running ${playbook_file} (tags: ${tags})...${NC}"
    ANSIBLE_HOST_KEY_CHECKING=False \
        ansible-playbook -i inventory.ini "$playbook_file" \
        --limit "$ip" \
        --tags "$tags"
    local rc=$?
    if [ $rc -eq 0 ]; then
        echo -e "${GREEN}✅ [Win/${ver}] ${ip} completed successfully${NC}"
    else
        echo -e "${RED}❌ [Win/${ver}] ${ip} failed (rc=${rc})${NC}"
    fi
    return $rc
}

# ======================================================
# HELPER: run_goss_windows_audit
# ------------------------------------------------------
# Detects version → selects correct audit repo
# Pushes goss.exe + YAML → runs on target → fetches result
# Args: $1=ip, $2=cis_level_num (1 or 2), $3=phase_label
# ======================================================
run_goss_windows_audit() {
    local ip="$1"
    local lvl="$2"
    local phase_label="$3"

    # Detect version to pick the right audit repo
    local ver
    ver=$(detect_windows_version "$ip")
    if [ "$ver" == "unknown" ]; then
        echo -e "${RED}❌ [GOSS/${phase_label}] Cannot detect OS version on ${ip} — skipping${NC}"
        return 1
    fi

    # Select audit repo based on version
    local audit_repo
    case "$ver" in
        2019) audit_repo="$GOSS_AUDIT_REPO_2019" ;;
        2022) audit_repo="$GOSS_AUDIT_REPO_2022" ;;
        2025) audit_repo="$GOSS_AUDIT_REPO_2025" ;;
        *)
            echo -e "${RED}❌ [GOSS/${phase_label}] No GOSS audit repo mapped for Windows ${ver} on ${ip}${NC}"
            return 1
            ;;
    esac

    # Check audit repo folder exists
    if [ ! -d "$audit_repo" ]; then
        echo -e "${RED}❌ [GOSS/${phase_label}] Audit repo missing: ${audit_repo}${NC}"
        echo -e "${YELLOW}   Clone it: git clone https://github.com/ansible-lockdown/Windows-${ver}-CIS-Audit.git${NC}"
        return 1
    fi

    # Check goss.yml exists at ROOT of repo (not in goss/ subfolder)
    if [ ! -f "${audit_repo}/goss.yml" ]; then
        echo -e "${RED}❌ [GOSS/${phase_label}] goss.yml missing in ${audit_repo}/${NC}"
        echo -e "${YELLOW}   Contents: $(ls ${audit_repo}/ 2>/dev/null)${NC}"
        return 1
    fi

    # Check goss binary exists
    if [ ! -f "$GOSS_BINARY_LOCAL" ]; then
        echo -e "${RED}❌ [GOSS/${phase_label}] goss binary missing: ${GOSS_BINARY_LOCAL}${NC}"
        echo -e "${YELLOW}   Download from: https://github.com/goss-org/goss/releases${NC}"
        return 1
    fi

    local out_file="goss_${phase_label}_CIS_L${lvl}_WIN_${ip}.json"

    echo -e "${GREEN}🔎 [GOSS/${phase_label}/Win${ver}/CIS L${lvl}] Scanning ${ip}...${NC}"

    # ── Step 1: Create remote directory ──────────────────
    echo -e "${CYAN}   [1/5] Creating remote directory...${NC}"
    local step1
    step1=$(ansible -i inventory.ini "${ip}" -m ansible.windows.win_file \
        -a "path=${GOSS_REMOTE_DIR} state=directory" 2>&1)
    if echo "$step1" | grep -q "FAILED"; then
        echo -e "${RED}❌ [GOSS/${phase_label}] Failed to create remote dir on ${ip}${NC}"
        echo -e "${RED}   $step1${NC}"
        return 1
    fi
    echo -e "${GREEN}   ✅ Remote dir ready${NC}"

    # ── Step 2: Copy goss binary ──────────────────────────
    echo -e "${CYAN}   [2/5] Copying goss binary...${NC}"
    local step2
    step2=$(ansible -i inventory.ini "${ip}" -m ansible.windows.win_copy \
        -a "src=${GOSS_BINARY_LOCAL} dest=${GOSS_REMOTE_DIR}\\goss.exe" 2>&1)
    if echo "$step2" | grep -q "FAILED"; then
        echo -e "${RED}❌ [GOSS/${phase_label}] Failed to copy goss.exe to ${ip}${NC}"
        echo -e "${RED}   $step2${NC}"
        return 1
    fi
    echo -e "${GREEN}   ✅ goss.exe copied${NC}"

    # ── Step 3: Copy audit content (repo root → remote content dir) ──
    echo -e "${CYAN}   [3/5] Copying audit content...${NC}"
    local step3
    # Copy audit content — src trailing slash copies CONTENTS not the folder itself
    step3=$(ansible -i inventory.ini "${ip}" -m ansible.windows.win_copy \
        -a "src=${audit_repo}/ dest=${GOSS_REMOTE_DIR}\\content\\" 2>&1)
    if echo "$step3" | grep -q "FAILED"; then
        echo -e "${RED}❌ [GOSS/${phase_label}] Failed to copy audit content to ${ip}${NC}"
        echo -e "${RED}   $step3${NC}"
        return 1
    fi
    echo -e "${GREEN}   ✅ Audit content copied${NC}"

    # ── Step 4: Run via run_audit.ps1 ────────────────────
    echo -e "${CYAN}   [4/5] Running GOSS audit via run_audit.ps1...${NC}"

    # Get just the folder name from audit_repo path
    local audit_folder
    audit_folder=$(basename "${audit_repo}")

    local raw_result
    raw_result=$(ansible -i inventory.ini "${ip}" -m ansible.windows.win_shell \
        -a "powershell.exe -ExecutionPolicy Bypass \
            -File ${GOSS_REMOTE_DIR}\\content\\${audit_folder}\\run_audit.ps1 \
            -auditbin ${GOSS_REMOTE_DIR}\\goss.exe \
            -auditdir ${GOSS_REMOTE_DIR}\\content\\${audit_folder} \
            -outfile ${GOSS_REMOTE_DIR}\\result.json" \
        2>&1)
    local rc=$?
    echo -e "${YELLOW}=== Step 4 raw output ===${NC}"
    echo "$raw_result"
    echo -e "${YELLOW}=== End Step 4 (rc=${rc}) ===${NC}"

    if [ $rc -eq 0 ] || [ $rc -eq 1 ]; then
        echo -e "${GREEN}   ✅ Audit script completed (rc=${rc})${NC}"
    else
        echo -e "${RED}❌ [GOSS/${phase_label}/Win${ver}] run_audit.ps1 failed (rc=${rc})${NC}"
        echo -e "${YELLOW}   Raw output: ${raw_result}${NC}"
    fi

    # ── Step 5: Fetch result JSON from target ─────────────
    echo -e "${CYAN}   [5/5] Fetching result file...${NC}"

    # Read file content directly via win_shell then save locally
    local file_content
    file_content=$(ansible -i inventory.ini "${ip}" -m ansible.windows.win_shell \
        -a "Get-Content -Path ${GOSS_REMOTE_DIR}\\result.json -Raw" \
        2>&1 | grep -v "^172\." | grep -v "^$" | grep -v "SUCCESS\|CHANGED\|FAILED\|rc=")

    if [ -n "$file_content" ]; then
        echo "$file_content" > "${out_file}"
        echo -e "${GREEN}✅ [GOSS/${phase_label}/Win${ver}] ${ip} scan complete → ${out_file}${NC}"
    else
        # Fallback: use ansible slurp module
        local slurp_result
        slurp_result=$(ansible -i inventory.ini "${ip}" -m ansible.windows.win_shell \
            -a "[Convert]::ToBase64String([IO.File]::ReadAllBytes('${GOSS_REMOTE_DIR}\\result.json'))" \
            2>&1 | grep -v "^172\." | grep -v "SUCCESS\|CHANGED\|rc=")

        if [ -n "$slurp_result" ]; then
            echo "$slurp_result" | base64 -d > "${out_file}" 2>/dev/null
            echo -e "${GREEN}✅ [GOSS/${phase_label}/Win${ver}] ${ip} scan complete (base64) → ${out_file}${NC}"
        else
            echo -e "${RED}❌ [GOSS/${phase_label}/Win${ver}] Result file empty or missing: ${out_file}${NC}"
        fi
    fi

    # ── Cleanup remote artifacts ──────────────────────────
    ansible -i inventory.ini "${ip}" -m ansible.windows.win_file \
        -a "path=${GOSS_REMOTE_DIR} state=absent" > /dev/null 2>&1 || true

    return 0
}

# ======================================================
# HELPER: fetch_remote_report (bulletproof 3-step fetch)
# ------------------------------------------------------
# 1. sudo chmod 644 the report on the target
# 2. scp (fast path)
# 3. ssh "sudo cat" fallback (survives post-CIS perms)
# ======================================================
fetch_remote_report() {
    local user="$1"
    local ip="$2"
    local remote="$3"
    local local_path="$4"
    local tag="$5"

    # Step 1: ensure the file is readable by the audit user
    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
        -o ConnectTimeout=10 \
        "${user}@${ip}" "sudo chmod 644 ${remote} 2>/dev/null" >/dev/null 2>&1

    # Step 2: try regular SCP (fast path)
    scp -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        -o ConnectTimeout=10 \
        "${user}@${ip}:${remote}" "${local_path}" >/dev/null 2>&1
    if [ $? -eq 0 ] && [ -s "${local_path}" ]; then
        return 0
    fi

    # Step 3: fall back to `ssh ... sudo cat` — always works
    echo -e "${YELLOW}🔄 [Fetch/${tag}] SCP failed for ${remote} on ${ip} — falling back to sudo cat${NC}"
    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
        -o ConnectTimeout=10 \
        "${user}@${ip}" "sudo cat ${remote}" > "${local_path}" 2>/dev/null
    if [ $? -eq 0 ] && [ -s "${local_path}" ]; then
        return 0
    fi

    # All three strategies failed
    rm -f "${local_path}"  # don't leave a zero-byte file lying around
    echo -e "${RED}❌ [Fetch/${tag}] All fetch strategies failed for ${remote} on ${ip}${NC}"
    return 1
}

# ======================================================
# TOOL GUARD: Ensure SCAP tooling exists on Linux node
# ======================================================
ensure_linux_scap_tools() {
    local user="$1"
    local ip="$2"
    local pkg_mgr="$3"

    local install_cmd
    if [ "$pkg_mgr" == "apt" ]; then
        install_cmd="sudo apt-get update -qq && sudo apt-get install -y openscap-scanner ssg-base"
    else
        install_cmd="sudo dnf install -y openscap-scanner scap-security-guide"
    fi

    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no "${user}@${ip}" "
        set -e
        if ! command -v oscap >/dev/null 2>&1 \
           || [ ! -d /usr/share/xml/scap/ssg/content ] \
           || [ -z \"\$(ls -A /usr/share/xml/scap/ssg/content 2>/dev/null)\" ]; then
            echo '[INSTALL] SCAP tools missing — installing...' | sudo tee /tmp/install_${ip}.log
            ${install_cmd} 2>&1 | sudo tee -a /tmp/install_${ip}.log
        fi
        command -v oscap >/dev/null 2>&1 || { echo '[FATAL] oscap still missing after install'; exit 10; }
        [ -d /usr/share/xml/scap/ssg/content ]   || { echo '[FATAL] SCAP content dir missing'; exit 11; }
        ls /usr/share/xml/scap/ssg/content/ssg-*-ds.xml >/dev/null 2>&1 || { echo '[FATAL] No SCAP datastreams found'; exit 12; }
    "
    local rc=$?
    if [ $rc -ne 0 ]; then
        echo -e "${RED}❌ [Tool Guard] SCAP tooling unavailable on ${ip} (rc=$rc). See /tmp/install_${ip}.log on the host.${NC}"
        return $rc
    fi
    return 0
}

# ======================================================
# AUTO-HEAL HELPER (Prevents SSH Lockout)
# ======================================================
wait_for_ssh() {
    local ip=$1
    local user=$2
    echo "🔍 Waiting for $user@$ip to be responsive..."
    local count=0
    until ssh -n -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no ${user}@${ip} "exit" >/dev/null 2>&1; do
        count=$((count+1))
        if [ $count -ge 12 ]; then echo "❌ Timeout waiting for $ip"; return 1; fi
        sleep 10
    done
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

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --headless) HEADLESS=true ;;
        --profile) H_PROFILE="$2"; shift ;;
        --mode) H_MODE="$2"; shift ;;
        --targets) H_TARGETS="$2"; shift ;;
        --ticket) H_TICKET="$2"; shift ;;
        --debug) DEBUG_MODE="$2"; shift ;;
        --cleanup) H_CLEANUP="$2"; shift ;;
        --target-os) H_TARGET_OS="$2"; shift ;;
        --target-ip) H_TARGET_IP="$2"; shift ;;
        *) echo -e "${RED}Unknown parameter: $1${NC}"; exit 1 ;;
    esac
    shift
done

CIS_LEVEL="${CIS_LEVEL:-Level 1}"

# ======================================================
# ENTERPRISE GUARDRAILS
# ======================================================
if [ "$HEADLESS" == true ]; then
    echo -e "${CYAN}${BOLD}🤖 HEADLESS CI/CD MODE ACTIVATED${NC}"
    if [ -n "$H_TICKET" ] && [ "$H_TICKET" != "None" ]; then
        echo -e "${GREEN}🎫 AUDIT AUTHORIZATION: Execution tracked under Ticket ID: ${BOLD}$H_TICKET${NC}"
    fi
    if [ "$DEBUG_MODE" == "true" ]; then set -x; fi
fi

if [ -z "$AUDIT_PASS" ]; then
    echo -e "${YELLOW}🔐 Fetching Credentials from Azure KeyVault...${NC}"
    az login --identity --allow-no-subscriptions > /dev/null 2>&1 || true
    AUDIT_PASS=$(az keyvault secret show --name "$SECRET_NAME" --vault-name "$KV_NAME" --query value -o tsv 2>/dev/null | tr -d '\r\n')
fi

if [ -z "$AUDIT_PASS" ]; then
    echo -e "${RED}❌ ERROR: Failed to retrieve password from KeyVault! Aborting.${NC}"
    exit 1
fi

# ======================================================
# ⚡ ACCELERATION: SSH MULTIPLEXING
# ======================================================
echo -e "${CYAN}⚡ Configuring SSH Multiplexing...${NC}"
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

# ======================================================
# PHASE 0.1: ZERO-TRUST DISCOVERY (MAP ONLY)
# ======================================================
echo -e "${CYAN}📡 Querying Azure for VMs in [$RG_NAME]...${NC}"

if [ "$H_TARGETS" == "all" ] || [ -z "$H_TARGETS" ]; then
    VM_DATA=$(az vm list -d -g "$RG_NAME" --query "[].[name, publicIps, storageProfile.osDisk.osType, powerState, storageProfile.imageReference.offer]" -o tsv)
else
    VM_DATA=$(az vm list -d -g "$RG_NAME" --query "[?tags.Environment=='$H_TARGETS'].[name, publicIps, storageProfile.osDisk.osType, powerState, storageProfile.imageReference.offer]" -o tsv)
fi

UBUNTU_MACHINES=()
RHEL_MACHINES=()
ROCKY_MACHINES=()
ALMA_MACHINES=()
WINDOWS_MACHINES=()

declare -A IP_TO_VM_NAME

while IFS=$'\t' read -r raw_name raw_ip raw_os raw_power raw_offer; do
    vm_name=$(echo "$raw_name" | tr -d '\r' | xargs); ip=$(echo "$raw_ip" | tr -d '\r' | xargs); os=$(echo "$raw_os" | tr -d '\r' | xargs); power=$(echo "$raw_power" | tr -d '\r' | xargs); offer=$(echo "$raw_offer" | tr -d '\r' | tr '[:upper:]' '[:lower:]' | xargs)
    
    if [ -z "$ip" ] || [ "$ip" == "None" ] || [[ "$power" != *"VM running"* ]]; then continue; fi
    IP_TO_VM_NAME["$ip"]="$vm_name"
    
    if [[ "$os" == *"Linux"* ]] || [[ "$os" == *"Ubuntu"* ]]; then
        if [[ "${offer,,}" == *"rocky"* ]] || [[ "${vm_name,,}" == *"rocky"* ]]; then ROCKY_MACHINES+=("$ip"); echo -e "${CYAN}🏔️ Mapped Rocky Node: $ip${NC}"
        elif [[ "${offer,,}" == *"alma"* ]] || [[ "${vm_name,,}" == *"alma"* ]]; then ALMA_MACHINES+=("$ip"); echo -e "${CYAN}🦙 Mapped AlmaLinux Node: $ip${NC}"
        elif [[ "${offer,,}" == *"rhel"* ]] || [[ "${vm_name,,}" == *"rhel"* ]]; then RHEL_MACHINES+=("$ip"); echo -e "${CYAN}🔴 Mapped RHEL Node: $ip${NC}"
        else UBUNTU_MACHINES+=("$ip"); echo -e "${CYAN}🟠 Mapped Ubuntu Node: $ip${NC}"; fi
    elif [[ "$os" == *"Windows"* ]]; then 
        WINDOWS_MACHINES+=("$ip"); echo -e "${CYAN}🪟 Mapped Windows Node: $ip${NC}"
    fi
done <<< "$VM_DATA"

# 🚨 MATRIX SHARDING: Force target to single IP if requested
if [ "$H_TARGET_IP" != "all" ] && [ -n "$H_TARGET_IP" ]; then
    echo -e "${MAGENTA}🎯 MATRIX SHARDING: Isolating execution to node $H_TARGET_IP${NC}"
    UBUNTU_MACHINES=(); RHEL_MACHINES=(); ROCKY_MACHINES=(); ALMA_MACHINES=(); WINDOWS_MACHINES=()
    if [ "${H_TARGET_OS,,}" == "ubuntu" ]; then UBUNTU_MACHINES=("$H_TARGET_IP"); fi
    if [ "${H_TARGET_OS,,}" == "rhel" ]; then RHEL_MACHINES=("$H_TARGET_IP"); fi
    if [ "${H_TARGET_OS,,}" == "rocky" ]; then ROCKY_MACHINES=("$H_TARGET_IP"); fi
    if [ "${H_TARGET_OS,,}" == "alma" ]; then ALMA_MACHINES=("$H_TARGET_IP"); fi
    if [ "${H_TARGET_OS,,}" == "windows" ]; then WINDOWS_MACHINES=("$H_TARGET_IP"); fi
fi

# ======================================================
# 🚨 PHASE 0.2: EARLY EXIT
# ======================================================
if [ "$HEADLESS" == true ] && [ "$H_TARGET_OS" != "all" ]; then
    if [ "${H_TARGET_OS,,}" == "ubuntu" ] && [ ${#UBUNTU_MACHINES[@]} -eq 0 ]; then exit 0; fi
    if [ "${H_TARGET_OS,,}" == "rhel" ] && [ ${#RHEL_MACHINES[@]} -eq 0 ]; then exit 0; fi
    if [ "${H_TARGET_OS,,}" == "rocky" ] && [ ${#ROCKY_MACHINES[@]} -eq 0 ]; then exit 0; fi
    if [ "${H_TARGET_OS,,}" == "alma" ] && [ ${#ALMA_MACHINES[@]} -eq 0 ]; then exit 0; fi
    if [ "${H_TARGET_OS,,}" == "windows" ] && [ ${#WINDOWS_MACHINES[@]} -eq 0 ]; then exit 0; fi
fi

# ======================================================
# 🛡️ PHASE 0.3: AUTO-HEALER
# ======================================================
echo -e "\n${CYAN}⚙️ PHASE 0.3: PARALLEL INFRASTRUCTURE BOOTSTRAPPING${NC}"
RUNNER_IP=$(curl -s https://api.ipify.org)

if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
    for ip in "${UBUNTU_MACHINES[@]}"; do
        (
            if [ "$(ssh -n -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no ${UBUNTU_USER}@${ip} "echo SSH_OK" 2>/dev/null)" != "SSH_OK" ]; then
                VM_NAME="${IP_TO_VM_NAME[$ip]}"
                NIC_ID=$(az vm show -g "$RG_NAME" -n "$VM_NAME" --query "networkProfile.networkInterfaces[0].id" -o tsv); NSG_ID=$(az network nic show --ids "$NIC_ID" --query "networkSecurityGroup.id" -o tsv); NSG_NAME=$(basename "$NSG_ID")
                az network nsg rule create -g "$RG_NAME" --nsg-name "$NSG_NAME" --name "Allow_SSH_Runner_Only" --priority 998 --destination-port-ranges 22 --source-address-prefixes "$RUNNER_IP" --access Allow --protocol Tcp -o none > /dev/null 2>&1 || true
                PUB_KEY=$(cat ~/.ssh/id_rsa.pub)
                az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunShellScript --scripts "useradd -m -s /bin/bash ${UBUNTU_USER} || true; echo '${UBUNTU_USER} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/99-${UBUNTU_USER}; chmod 440 /etc/sudoers.d/99-${UBUNTU_USER}; mkdir -p /home/${UBUNTU_USER}/.ssh; echo '$PUB_KEY' > /home/${UBUNTU_USER}/.ssh/authorized_keys; chown -R ${UBUNTU_USER}:${UBUNTU_USER} /home/${UBUNTU_USER}/.ssh; chmod 700 /home/${UBUNTU_USER}/.ssh; chmod 600 /home/${UBUNTU_USER}/.ssh/authorized_keys; systemctl restart sshd" -o none > /dev/null 2>&1 || true
                sleep 15
            fi
        ) &
    done
fi

if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" =~ ^(rhel|rocky|alma)$ ]]; then
    for ip in "${RHEL_MACHINES[@]}" "${ROCKY_MACHINES[@]}" "${ALMA_MACHINES[@]}"; do
        (
            if [ "$(ssh -n -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no ${GHOST_USER}@${ip} "echo SSH_OK" 2>/dev/null)" != "SSH_OK" ]; then
                VM_NAME="${IP_TO_VM_NAME[$ip]}"
                NIC_ID=$(az vm show -g "$RG_NAME" -n "$VM_NAME" --query "networkProfile.networkInterfaces[0].id" -o tsv); NSG_ID=$(az network nic show --ids "$NIC_ID" --query "networkSecurityGroup.id" -o tsv); NSG_NAME=$(basename "$NSG_ID")
                az network nsg rule create -g "$RG_NAME" --nsg-name "$NSG_NAME" --name "Allow_SSH_Runner_Only" --priority 998 --destination-port-ranges 22 --source-address-prefixes "$RUNNER_IP" --access Allow --protocol Tcp -o none > /dev/null 2>&1 || true
                PUB_KEY=$(cat ~/.ssh/id_rsa.pub)
                az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunShellScript --scripts "useradd -m -s /bin/bash ${GHOST_USER} || true; echo '${GHOST_USER} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/99-${GHOST_USER}; chmod 440 /etc/sudoers.d/99-${GHOST_USER}; mkdir -p /home/${GHOST_USER}/.ssh; echo '$PUB_KEY' > /home/${GHOST_USER}/.ssh/authorized_keys; chown -R ${GHOST_USER}:${GHOST_USER} /home/${GHOST_USER}/.ssh; chmod 700 /home/${GHOST_USER}/.ssh; chmod 600 /home/${GHOST_USER}/.ssh/authorized_keys; if command -v restorecon &> /dev/null; then restorecon -Rv /home/${GHOST_USER}/.ssh >/dev/null 2>&1 || true; fi; echo 'PubkeyAcceptedKeyTypes +ssh-rsa' > /etc/ssh/sshd_config.d/99-runner-key.conf 2>/dev/null || true; systemctl restart sshd" -o none > /dev/null 2>&1 || true
                sleep 15
            fi
        ) &
    done
fi

if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
    for ip in "${WINDOWS_MACHINES[@]}"; do
        (
            VM_NAME="${IP_TO_VM_NAME[$ip]}"
            NIC_ID=$(az vm show -g "$RG_NAME" -n "$VM_NAME" --query "networkProfile.networkInterfaces[0].id" -o tsv); NSG_ID=$(az network nic show --ids "$NIC_ID" --query "networkSecurityGroup.id" -o tsv)
            if [ -n "$NSG_ID" ]; then
                NSG_NAME=$(basename "$NSG_ID")
                az network nsg rule create -g "$RG_NAME" --nsg-name "$NSG_NAME" --name "Allow_WinRM_Runner_Only" --priority 999 --destination-port-ranges 5985 --source-address-prefixes "$RUNNER_IP" --access Allow --protocol Tcp -o none > /dev/null 2>&1 || true
            fi
            az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunPowerShellScript --scripts "Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM' -Recurse -Force -ErrorAction SilentlyContinue; net user ${AUDIT_USER} '${AUDIT_PASS}' /add /y 2>&1 | Out-Null; net user ${AUDIT_USER} '${AUDIT_PASS}' 2>&1 | Out-Null; net localgroup Administrators ${AUDIT_USER} /add 2>&1 | Out-Null; WMIC USERACCOUNT WHERE Name='${AUDIT_USER}' SET PasswordExpires=FALSE 2>&1 | Out-Null; Enable-PSRemoting -SkipNetworkProfileCheck -Force; winrm set winrm/config/service/auth '@{Basic=\"true\"}'; winrm set winrm/config/service '@{AllowUnencrypted=\"true\"}'; New-ItemProperty -Name LocalAccountTokenFilterPolicy -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -PropertyType DWord -Value 1 -Force; Set-NetFirewallRule -DisplayGroup 'Windows Remote Management' -Enabled True -Profile Any -ErrorAction SilentlyContinue; Restart-Service WinRM -Force;" -o none > /dev/null 2>&1 || true
            sleep 20
        ) &
    done
fi
wait

# ======================================================
# INVENTORY BUILDER
# ======================================================
echo "[ubuntu_nodes]" > inventory.ini
for ip in "${UBUNTU_MACHINES[@]}"; do echo "${ip} ansible_user=${UBUNTU_USER}" >> inventory.ini; done
echo -e "\n[rhel_nodes]" >> inventory.ini
for ip in "${RHEL_MACHINES[@]}"; do echo "${ip} ansible_user=${GHOST_USER}" >> inventory.ini; done
echo -e "\n[rocky_nodes]" >> inventory.ini
for ip in "${ROCKY_MACHINES[@]}"; do echo "${ip} ansible_user=${GHOST_USER}" >> inventory.ini; done
echo -e "\n[alma_nodes]" >> inventory.ini
for ip in "${ALMA_MACHINES[@]}"; do echo "${ip} ansible_user=${GHOST_USER}" >> inventory.ini; done
echo -e "\n[windows_nodes]" >> inventory.ini
for ip in "${WINDOWS_MACHINES[@]}"; do echo "${ip} ansible_user=${AUDIT_USER} ansible_password=\"${AUDIT_PASS}\" ansible_port=5985 ansible_winrm_scheme=http ansible_connection=winrm ansible_winrm_transport=basic ansible_winrm_server_cert_validation=ignore" >> inventory.ini; done

RUN_ORG=false; RUN_CIS=false
if [ "$HEADLESS" == true ]; then
    if [[ "${H_PROFILE,,}" == "tm" ]] || [[ "${H_PROFILE,,}" == "${ORG_PREFIX,,}" ]] || [[ "${H_PROFILE,,}" == "both" ]]; then RUN_ORG=true; fi
    if [[ "${H_PROFILE,,}" == "cis" ]] || [[ "${H_PROFILE,,}" == "both" ]]; then RUN_CIS=true; fi
else
    echo -e "\n1) CUSTOM BASELINE\n2) CIS BASELINE\n3) BOTH"
    read -p "Choose profile [1-3]: " pc
    if [ "$pc" == "1" ] || [ "$pc" == "3" ]; then RUN_ORG=true; fi
    if [ "$pc" == "2" ] || [ "$pc" == "3" ]; then RUN_CIS=true; fi
fi

update_profile_vars() {
    if [ "$RUN_CIS" == true ]; then
        if [ "$CIS_LEVEL" == "Level 1" ]; then
            UBUNTU_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis_level1_server"
            RHEL_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis_server_l1"
            OS_LVL="1"; WIN_INSPEC_LVL="1"
        else
            UBUNTU_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis_level2_server"
            RHEL_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis"
            OS_LVL="2"; WIN_INSPEC_LVL="2"
        fi
    fi
}

# ======================================================
# PHASE 1: SCAN
# ======================================================
run_phase_1() {
    echo -e "\n${BOLD}🔍 PHASE 1: Running Initial Baselines (Asynchronous)...${NC}"

    # -------------------- UBUNTU --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "ubuntu" ]; then
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ]; then
            for IP in "${UBUNTU_MACHINES[@]}"; do
                (
                    if ! ensure_linux_scap_tools "$UBUNTU_USER" "$IP" "apt"; then
                        echo -e "${RED}❌ [Phase1/Ubuntu] Skipping $IP — tools unavailable.${NC}"
                        exit 1
                    fi

                    RAW_VER=$(ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} \
                        "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
                    UBUNTU_VER=${RAW_VER:-2404}
                    UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Ubuntu/CIS L${OS_LVL}] Scanning $IP...${NC}"
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} \
                            "sudo oscap xccdf eval --profile $UBUNTU_CIS_PROFILE \
                             --report /tmp/report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html \
                             $UBUNTU_CIS_XCCDF"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${UBUNTU_USER}@${IP}:/tmp/report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html \
                                ./report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-CIS report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/Ubuntu/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Ubuntu/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                            "$UBUNTU_CUSTOM_OVAL" "$UBUNTU_CUSTOM_XCCDF" ${UBUNTU_USER}@${IP}:/tmp/ \
                            || { echo -e "${RED}❌ [Phase1] SCP of custom content failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} \
                            "sudo oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report /tmp/report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html \
                             /tmp/$(basename $UBUNTU_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${UBUNTU_USER}@${IP}:/tmp/report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html \
                                ./report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-${ORG_PREFIX^^} report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/Ubuntu/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- RHEL --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rhel" ]; then
        if [ ${#RHEL_MACHINES[@]} -gt 0 ]; then
            for IP in "${RHEL_MACHINES[@]}"; do
                (
                    if ! ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf"; then
                        echo -e "${RED}❌ [Phase1/RHEL] Skipping $IP — tools unavailable.${NC}"
                        exit 1
                    fi

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/RHEL/CIS L${OS_LVL}] Scanning $IP...${NC}"
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} \
                            "TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1); \
                             sudo /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE \
                             --report /tmp/report_before_CIS_L${OS_LVL}_RHEL_${IP}.html \"\$TARGET_XML\""
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${GHOST_USER}@${IP}:/tmp/report_before_CIS_L${OS_LVL}_RHEL_${IP}.html \
                                ./report_before_CIS_L${OS_LVL}_RHEL_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-CIS report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/RHEL/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/RHEL/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                            "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" ${GHOST_USER}@${IP}:/tmp/ \
                            || { echo -e "${RED}❌ [Phase1] SCP of custom content failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} \
                            "sudo env OSCAP_CPE_DICT_PATH=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-cpe-dictionary.xml' | sort -V | tail -n 1) \
                             /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report /tmp/report_before_${ORG_PREFIX^^}_RHEL_${IP}.html \
                             /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${GHOST_USER}@${IP}:/tmp/report_before_${ORG_PREFIX^^}_RHEL_${IP}.html \
                                ./report_before_${ORG_PREFIX^^}_RHEL_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-${ORG_PREFIX^^} report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/RHEL/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- ROCKY --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rocky" ]; then
        if [ ${#ROCKY_MACHINES[@]} -gt 0 ]; then
            for IP in "${ROCKY_MACHINES[@]}"; do
                (
                    if ! ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf"; then
                        echo -e "${RED}❌ [Phase1/Rocky] Skipping $IP — tools unavailable.${NC}"
                        exit 1
                    fi

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Rocky/CIS L${OS_LVL}] Scanning $IP...${NC}"
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "
                            ROCKY_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-rl\${ROCKY_VER}-ds.xml\"
                            if [ ! -f \"\$TARGET_XML\" ]; then
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            fi
                            if [ -z \"\$TARGET_XML\" ] || [ ! -f \"\$TARGET_XML\" ]; then echo 'NO_SCAP_CONTENT'; exit 99; fi
                            sudo /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE \
                                --report /tmp/report_before_CIS_L${OS_LVL}_ROCKY_${IP}.html \"\$TARGET_XML\"
                        "
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${GHOST_USER}@${IP}:/tmp/report_before_CIS_L${OS_LVL}_ROCKY_${IP}.html \
                                ./report_before_CIS_L${OS_LVL}_ROCKY_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-CIS report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/Rocky/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Rocky/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                            "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" ${GHOST_USER}@${IP}:/tmp/ \
                            || { echo -e "${RED}❌ [Phase1] SCP of custom content failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report /tmp/report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html \
                             /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${GHOST_USER}@${IP}:/tmp/report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html \
                                ./report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-${ORG_PREFIX^^} report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/Rocky/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- ALMA --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "alma" ]; then
        if [ ${#ALMA_MACHINES[@]} -gt 0 ]; then
            for IP in "${ALMA_MACHINES[@]}"; do
                (
                    if ! ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf"; then
                        echo -e "${RED}❌ [Phase1/Alma] Skipping $IP — tools unavailable.${NC}"
                        exit 1
                    fi

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Alma/CIS L${OS_LVL}] Scanning $IP...${NC}"
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "
                            ALMA_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-almalinux\${ALMA_VER}-ds.xml\"
                            if [ ! -f \"\$TARGET_XML\" ]; then
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            fi
                            if [ -z \"\$TARGET_XML\" ] || [ ! -f \"\$TARGET_XML\" ]; then echo 'NO_SCAP_CONTENT'; exit 99; fi
                            if ! grep -q \"$RHEL_CIS_PROFILE\" \"\$TARGET_XML\"; then
                                ALMA_PROF=\"xccdf_org.ssgproject.content_profile_cis\"
                            else
                                ALMA_PROF=\"$RHEL_CIS_PROFILE\"
                            fi
                            sudo /usr/bin/oscap xccdf eval --profile \$ALMA_PROF \
                                --report /tmp/report_before_CIS_L${OS_LVL}_ALMA_${IP}.html \"\$TARGET_XML\"
                        "
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${GHOST_USER}@${IP}:/tmp/report_before_CIS_L${OS_LVL}_ALMA_${IP}.html \
                                ./report_before_CIS_L${OS_LVL}_ALMA_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-CIS report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/Alma/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Alma/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                            "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" ${GHOST_USER}@${IP}:/tmp/ \
                            || { echo -e "${RED}❌ [Phase1] SCP of custom content failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report /tmp/report_before_${ORG_PREFIX^^}_ALMA_${IP}.html \
                             /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${GHOST_USER}@${IP}:/tmp/report_before_${ORG_PREFIX^^}_ALMA_${IP}.html \
                                ./report_before_${ORG_PREFIX^^}_ALMA_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-${ORG_PREFIX^^} report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/Alma/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- WINDOWS --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "windows" ]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            for IP in "${WINDOWS_MACHINES[@]}"; do
                (
                    if [ "$RUN_CIS" == true ]; then
                        run_goss_windows_audit "$IP" "$WIN_INSPEC_LVL" "before"
                    fi
                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Win/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        cinc-auditor exec "$WIN_CUSTOM_BENCHMARK" -t winrm://${IP} \
                            --user="${AUDIT_USER}" --password="${AUDIT_PASS}" \
                            --reporter json:heimdall_before_${ORG_PREFIX^^}_WIN_${IP}.json
                    fi
                ) &
            done
            wait
        fi
    fi
}

# ======================================================
# PHASE 2/3: REMEDIATION (Hardened SSH + Win multi-version)
# ======================================================
run_remediation() {
    echo -e "\n${BOLD}🛠️  PHASE 2 & 3: Executing Remediation (Hardened SSH)...${NC}"

    # -------------------- UBUNTU --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "ubuntu" ]; then
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ] && [ "$RUN_CIS" == true ]; then
            for IP in "${UBUNTU_MACHINES[@]}"; do
                (
                    echo -e "${CYAN}🛠️  [Remediation/Ubuntu] Starting on ${IP} (max ${REMEDIATION_TIMEOUT_SEC}s)...${NC}"
                    timeout $REMEDIATION_TIMEOUT_SEC \
                        ssh $REMEDIATION_SSH_OPTS ${UBUNTU_USER}@${IP} \
                        "XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-ubuntu*-ds.xml' | sort -V | tail -n 1); \
                         sudo /usr/bin/oscap xccdf eval --remediate --profile $UBUNTU_CIS_PROFILE \
                         --report /tmp/report_remediation_CIS_${IP}.html \"\$XML_FILE\""
                    rc=$?
                    if [ $rc -eq 124 ]; then
                        echo -e "${RED}⏱️  [Remediation/Ubuntu] TIMEOUT after ${REMEDIATION_TIMEOUT_SEC}s on ${IP} — likely sshd restart mid-scan${NC}"
                    elif [ $rc -eq 255 ]; then
                        echo -e "${RED}🔌 [Remediation/Ubuntu] SSH dropped on ${IP} (rc=255) — sshd likely restarted${NC}"
                    elif [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                        echo -e "${GREEN}✅ [Remediation/Ubuntu] ${IP} finished (oscap rc=${rc})${NC}"
                    else
                        echo -e "${YELLOW}⚠️  [Remediation/Ubuntu] ${IP} finished with rc=${rc}${NC}"
                    fi
                ) &
            done
            wait
        fi
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ] && [ "$RUN_ORG" == true ]; then
            ansible-playbook -i inventory.ini $UBUNTU_CUSTOM_PLAYBOOK --limit ubuntu_nodes > /dev/null 2>&1 || true
        fi
    fi

    # -------------------- RHEL --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rhel" ]; then
        if [ ${#RHEL_MACHINES[@]} -gt 0 ] && [ "$RUN_CIS" == true ]; then
            for IP in "${RHEL_MACHINES[@]}"; do
                (
                    echo -e "${CYAN}🛠️  [Remediation/RHEL] Starting on ${IP} (max ${REMEDIATION_TIMEOUT_SEC}s)...${NC}"
                    timeout $REMEDIATION_TIMEOUT_SEC \
                        ssh $REMEDIATION_SSH_OPTS ${GHOST_USER}@${IP} \
                        "XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1); \
                         sudo /usr/bin/oscap xccdf eval --remediate --profile $RHEL_CIS_PROFILE \
                         --report /tmp/report_remediation_CIS_${IP}.html \"\$XML_FILE\""
                    rc=$?
                    if [ $rc -eq 124 ]; then
                        echo -e "${RED}⏱️  [Remediation/RHEL] TIMEOUT after ${REMEDIATION_TIMEOUT_SEC}s on ${IP}${NC}"
                    elif [ $rc -eq 255 ]; then
                        echo -e "${RED}🔌 [Remediation/RHEL] SSH dropped on ${IP} (rc=255)${NC}"
                    elif [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                        echo -e "${GREEN}✅ [Remediation/RHEL] ${IP} finished (oscap rc=${rc})${NC}"
                    else
                        echo -e "${YELLOW}⚠️  [Remediation/RHEL] ${IP} finished with rc=${rc}${NC}"
                    fi
                ) &
            done
            wait
        fi
        if [ ${#RHEL_MACHINES[@]} -gt 0 ] && [ "$RUN_ORG" == true ]; then
            ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK --limit rhel_nodes > /dev/null 2>&1 || true
        fi
    fi

    # -------------------- ROCKY --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rocky" ]; then
        if [ ${#ROCKY_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                for IP in "${ROCKY_MACHINES[@]}"; do
                    (
                        echo -e "${CYAN}🛠️  [Remediation/Rocky] Starting on ${IP} (max ${REMEDIATION_TIMEOUT_SEC}s)...${NC}"
                        timeout $REMEDIATION_TIMEOUT_SEC \
                            ssh $REMEDIATION_SSH_OPTS ${GHOST_USER}@${IP} "
                                ROCKY_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                                TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-rl\${ROCKY_VER}-ds.xml\"
                                if [ ! -f \"\$TARGET_XML\" ]; then
                                    TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                                fi
                                if [ -z \"\$TARGET_XML\" ] || [ ! -f \"\$TARGET_XML\" ]; then exit 99; fi
                                sudo /usr/bin/oscap xccdf eval --remediate --profile $RHEL_CIS_PROFILE \
                                    --report /tmp/report_remediation_CIS_ROCKY_${IP}.html \"\$TARGET_XML\"
                            "
                        rc=$?
                        if [ $rc -eq 124 ]; then
                            echo -e "${RED}⏱️  [Remediation/Rocky] TIMEOUT after ${REMEDIATION_TIMEOUT_SEC}s on ${IP}${NC}"
                        elif [ $rc -eq 255 ]; then
                            echo -e "${RED}🔌 [Remediation/Rocky] SSH dropped on ${IP} (rc=255)${NC}"
                        elif [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            echo -e "${GREEN}✅ [Remediation/Rocky] ${IP} finished (oscap rc=${rc})${NC}"
                        else
                            echo -e "${YELLOW}⚠️  [Remediation/Rocky] ${IP} finished with rc=${rc}${NC}"
                        fi
                    ) &
                done
                wait
            fi
            if [ "$RUN_ORG" == true ]; then
                ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK --limit rocky_nodes > /dev/null 2>&1 || true
            fi
        fi
    fi

    # -------------------- ALMA --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "alma" ]; then
        if [ ${#ALMA_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                for IP in "${ALMA_MACHINES[@]}"; do
                    (
                        echo -e "${CYAN}🛠️  [Remediation/Alma] Starting on ${IP} (max ${REMEDIATION_TIMEOUT_SEC}s)...${NC}"
                        timeout $REMEDIATION_TIMEOUT_SEC \
                            ssh $REMEDIATION_SSH_OPTS ${GHOST_USER}@${IP} "
                                ALMA_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                                TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-almalinux\${ALMA_VER}-ds.xml\"
                                if [ ! -f \"\$TARGET_XML\" ]; then
                                    TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                                fi
                                if [ -z \"\$TARGET_XML\" ] || [ ! -f \"\$TARGET_XML\" ]; then exit 99; fi
                                if ! grep -q \"$RHEL_CIS_PROFILE\" \"\$TARGET_XML\"; then
                                    ALMA_PROF=\"xccdf_org.ssgproject.content_profile_cis\"
                                else
                                    ALMA_PROF=\"$RHEL_CIS_PROFILE\"
                                fi
                                sudo /usr/bin/oscap xccdf eval --remediate --profile \$ALMA_PROF \
                                    --report /tmp/report_remediation_CIS_ALMA_${IP}.html \"\$TARGET_XML\"
                            "
                        rc=$?
                        if [ $rc -eq 124 ]; then
                            echo -e "${RED}⏱️  [Remediation/Alma] TIMEOUT after ${REMEDIATION_TIMEOUT_SEC}s on ${IP}${NC}"
                        elif [ $rc -eq 255 ]; then
                            echo -e "${RED}🔌 [Remediation/Alma] SSH dropped on ${IP} (rc=255)${NC}"
                        elif [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            echo -e "${GREEN}✅ [Remediation/Alma] ${IP} finished (oscap rc=${rc})${NC}"
                        else
                            echo -e "${YELLOW}⚠️  [Remediation/Alma] ${IP} finished with rc=${rc}${NC}"
                        fi
                    ) &
                done
                wait
            fi
            if [ "$RUN_ORG" == true ]; then
                ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK --limit alma_nodes > /dev/null 2>&1 || true
            fi
        fi
    fi

    # -------------------- WINDOWS (multi-version dispatcher) --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "windows" ]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                for IP in "${WINDOWS_MACHINES[@]}"; do
                    ( remediate_windows_host "$IP" "$CIS_LEVEL" ) &
                done
                wait
            fi
            if [ "$RUN_ORG" == true ]; then
                echo -e "${CYAN}🛠️  [Remediation/Win/${ORG_PREFIX^^}] Running custom playbook...${NC}"
                ansible-playbook -i inventory.ini "$WIN_CUSTOM_PLAYBOOK" --limit windows_nodes
                rc=$?
                if [ $rc -eq 0 ]; then
                    echo -e "${GREEN}✅ [Remediation/Win/${ORG_PREFIX^^}] Completed${NC}"
                else
                    echo -e "${RED}❌ [Remediation/Win/${ORG_PREFIX^^}] failed (rc=$rc)${NC}"
                fi
            fi
        fi
    fi
}

# ======================================================
# PHASE 4: VERIFICATION (bulletproof fetch)
# ======================================================
run_phase_4() {
    echo -e "\n${BOLD}🔄 PHASE 4: Running Verification Scans (Asynchronous)...${NC}"

    local SCAN_SSH_OPTS="-n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
        -o ConnectTimeout=10"

    # -------------------- UBUNTU VERIFY --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "ubuntu" ]; then
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ]; then
            for IP in "${UBUNTU_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$UBUNTU_USER" || { echo -e "${RED}❌ [Phase4/Ubuntu] SSH unreachable: $IP${NC}"; exit 1; }
                    ensure_linux_scap_tools "$UBUNTU_USER" "$IP" "apt" || { echo -e "${RED}❌ [Phase4/Ubuntu] Tools missing on $IP${NC}"; exit 1; }

                    UBUNTU_VER=$(ssh $SCAN_SSH_OPTS ${UBUNTU_USER}@${IP} \
                        "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
                    UBUNTU_VER=${UBUNTU_VER:-2404}
                    UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

                    if [ "$RUN_CIS" == true ]; then
                        REMOTE="/tmp/report_after_CIS_L${OS_LVL}_UBUNTU_${IP}.html"
                        LOCAL="./report_after_CIS_L${OS_LVL}_UBUNTU_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/Ubuntu/CIS L${OS_LVL}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${UBUNTU_USER}@${IP} \
                            "sudo oscap xccdf eval --profile $UBUNTU_CIS_PROFILE \
                             --report ${REMOTE} $UBUNTU_CIS_XCCDF"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$UBUNTU_USER" "$IP" "$REMOTE" "$LOCAL" "Ubuntu/CIS"
                        else
                            echo -e "${RED}❌ [Phase4/Ubuntu/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/Ubuntu/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${UBUNTU_USER}@${IP} \
                            "sudo oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report ${REMOTE} /tmp/$(basename $UBUNTU_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$UBUNTU_USER" "$IP" "$REMOTE" "$LOCAL" "Ubuntu/${ORG_PREFIX^^}"
                        else
                            echo -e "${RED}❌ [Phase4/Ubuntu/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- RHEL VERIFY --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rhel" ]; then
        if [ ${#RHEL_MACHINES[@]} -gt 0 ]; then
            for IP in "${RHEL_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$GHOST_USER" || { echo -e "${RED}❌ [Phase4/RHEL] SSH unreachable: $IP${NC}"; exit 1; }
                    ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || { echo -e "${RED}❌ [Phase4/RHEL] Tools missing on $IP${NC}"; exit 1; }

                    if [ "$RUN_CIS" == true ]; then
                        REMOTE="/tmp/report_after_CIS_L${OS_LVL}_RHEL_${IP}.html"
                        LOCAL="./report_after_CIS_L${OS_LVL}_RHEL_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/RHEL/CIS L${OS_LVL}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1); \
                             sudo /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE \
                             --report ${REMOTE} \"\$TARGET_XML\""
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "RHEL/CIS"
                        else
                            echo -e "${RED}❌ [Phase4/RHEL/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_RHEL_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_RHEL_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/RHEL/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report ${REMOTE} /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "RHEL/${ORG_PREFIX^^}"
                        else
                            echo -e "${RED}❌ [Phase4/RHEL/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- ROCKY VERIFY --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rocky" ]; then
        if [ ${#ROCKY_MACHINES[@]} -gt 0 ]; then
            for IP in "${ROCKY_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$GHOST_USER" || { echo -e "${RED}❌ [Phase4/Rocky] SSH unreachable: $IP${NC}"; exit 1; }
                    ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || { echo -e "${RED}❌ [Phase4/Rocky] Tools missing on $IP${NC}"; exit 1; }

                    if [ "$RUN_CIS" == true ]; then
                        REMOTE="/tmp/report_after_CIS_L${OS_LVL}_ROCKY_${IP}.html"
                        LOCAL="./report_after_CIS_L${OS_LVL}_ROCKY_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/Rocky/CIS L${OS_LVL}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} "
                            ROCKY_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-rl\${ROCKY_VER}-ds.xml\"
                            if [ ! -f \"\$TARGET_XML\" ]; then
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            fi
                            if [ -z \"\$TARGET_XML\" ] || [ ! -f \"\$TARGET_XML\" ]; then echo 'NO_SCAP_CONTENT'; exit 99; fi
                            sudo /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE \
                                --report ${REMOTE} \"\$TARGET_XML\"
                        "
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Rocky/CIS"
                        else
                            echo -e "${RED}❌ [Phase4/Rocky/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/Rocky/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report ${REMOTE} /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Rocky/${ORG_PREFIX^^}"
                        else
                            echo -e "${RED}❌ [Phase4/Rocky/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- ALMA VERIFY --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "alma" ]; then
        if [ ${#ALMA_MACHINES[@]} -gt 0 ]; then
            for IP in "${ALMA_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$GHOST_USER" || { echo -e "${RED}❌ [Phase4/Alma] SSH unreachable: $IP${NC}"; exit 1; }
                    ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || { echo -e "${RED}❌ [Phase4/Alma] Tools missing on $IP${NC}"; exit 1; }

                    if [ "$RUN_CIS" == true ]; then
                        REMOTE="/tmp/report_after_CIS_L${OS_LVL}_ALMA_${IP}.html"
                        LOCAL="./report_after_CIS_L${OS_LVL}_ALMA_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/Alma/CIS L${OS_LVL}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} "
                            ALMA_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-almalinux\${ALMA_VER}-ds.xml\"
                            if [ ! -f \"\$TARGET_XML\" ]; then
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            fi
                            if [ -z \"\$TARGET_XML\" ] || [ ! -f \"\$TARGET_XML\" ]; then echo 'NO_SCAP_CONTENT'; exit 99; fi
                            if ! grep -q \"$RHEL_CIS_PROFILE\" \"\$TARGET_XML\"; then
                                ALMA_PROF=\"xccdf_org.ssgproject.content_profile_cis\"
                            else
                                ALMA_PROF=\"$RHEL_CIS_PROFILE\"
                            fi
                            sudo /usr/bin/oscap xccdf eval --profile \$ALMA_PROF \
                                --report ${REMOTE} \"\$TARGET_XML\"
                        "
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Alma/CIS"
                        else
                            echo -e "${RED}❌ [Phase4/Alma/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_ALMA_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_ALMA_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/Alma/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report ${REMOTE} /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Alma/${ORG_PREFIX^^}"
                        else
                            echo -e "${RED}❌ [Phase4/Alma/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

   # -------------------- WINDOWS VERIFY --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "windows" ]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            for IP in "${WINDOWS_MACHINES[@]}"; do
                (
                    if [ "$RUN_CIS" == true ]; then
                        run_goss_windows_audit "$IP" "$WIN_INSPEC_LVL" "after"
                    fi
                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Win/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        cinc-auditor exec "$WIN_CUSTOM_BENCHMARK" -t winrm://${IP} \
                            --user="${AUDIT_USER}" --password="${AUDIT_PASS}" \
                            --reporter json:heimdall_after_${ORG_PREFIX^^}_WIN_${IP}.json
                    fi
                ) &
            done
            wait
        fi
    fi
}

# ======================================================
# PHASE 5: CLEANUP
# ======================================================
run_cleanup() {
    echo -e "\n${BOLD}${RED}🧹 PHASE 5: POST-AUDIT CLEANUP (THE GHOST METHOD)${NC}"
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "ubuntu" ]; then
        for IP in "${UBUNTU_MACHINES[@]}"; do
            echo -e "   ${YELLOW}Removing tools & nuking user from Ubuntu: $IP...${NC}"
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "sudo apt-get purge -y openscap-scanner ssg-base && sudo apt-get autoremove -y" > /dev/null 2>&1
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            if [ -n "$VM_NAME" ]; then az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunShellScript --scripts "userdel -r ${UBUNTU_USER}" -o none > /dev/null 2>&1 || true; fi
        done
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rhel" ]; then
        for IP in "${RHEL_MACHINES[@]}"; do
            echo -e "   ${YELLOW}Removing tools & nuking user from RHEL: $IP...${NC}"
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "sudo dnf remove -y openscap-scanner scap-security-guide -C --setopt=metadata_expire=never" > /dev/null 2>&1
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            if [ -n "$VM_NAME" ]; then az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunShellScript --scripts "userdel -r ${GHOST_USER}" -o none > /dev/null 2>&1 || true; fi
        done
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rocky" ]; then
        for IP in "${ROCKY_MACHINES[@]}"; do
            echo -e "   ${YELLOW}Removing tools & nuking user from Rocky: $IP...${NC}"
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "sudo dnf remove -y openscap-scanner scap-security-guide -C --setopt=metadata_expire=never" > /dev/null 2>&1
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            if [ -n "$VM_NAME" ]; then az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunShellScript --scripts "userdel -r ${GHOST_USER}" -o none > /dev/null 2>&1 || true; fi
        done
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "alma" ]; then
        for IP in "${ALMA_MACHINES[@]}"; do
            echo -e "   ${YELLOW}Removing tools & nuking user from AlmaLinux: $IP...${NC}"
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "sudo dnf remove -y openscap-scanner scap-security-guide -C --setopt=metadata_expire=never" > /dev/null 2>&1
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            if [ -n "$VM_NAME" ]; then az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunShellScript --scripts "userdel -r ${GHOST_USER}" -o none > /dev/null 2>&1 || true; fi
        done
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "windows" ]; then
        for IP in "${WINDOWS_MACHINES[@]}"; do
            echo -e "   ${CYAN}🧹 Reversing security changes & nuking user on Windows: $IP...${NC}"
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            if [ -n "$VM_NAME" ]; then
                NIC_ID=$(az vm show -g "$RG_NAME" -n "$VM_NAME" --query "networkProfile.networkInterfaces[0].id" -o tsv)
                NSG_ID=$(az network nic show --ids "$NIC_ID" --query "networkSecurityGroup.id" -o tsv)
                if [ -n "$NSG_ID" ]; then
                    NSG_NAME=$(basename "$NSG_ID")
                    az network nsg rule delete -g "$RG_NAME" --nsg-name "$NSG_NAME" --name "Allow_WinRM_Runner_Only" -o none > /dev/null 2>&1 || true
                fi
                az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunPowerShellScript --scripts "Stop-Service WinRM -WarningAction SilentlyContinue; Set-Service WinRM -StartupType Disabled; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Force -ErrorAction SilentlyContinue; Disable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue; Remove-LocalUser -Name '$AUDIT_USER' -ErrorAction SilentlyContinue" -o none > /dev/null 2>&1 || true
            fi
        done
    fi
}

# ======================================================
# EXECUTION ENGINE
# ======================================================
execute_phases() {
    case $H_MODE in
        scan) run_phase_1 ;;
        remediate) run_remediation ;;
        full) run_phase_1; run_remediation; run_phase_4 ;;
    esac
}

if [ "$HEADLESS" == true ]; then
    echo -e "\n${CYAN}${BOLD}======================================================"
    echo -e "🚀 EXECUTING CI/CD WORKFLOW: MODE -> $H_MODE"
    echo -e "======================================================${NC}"
    
    if [ "${H_PROFILE,,}" == "all" ]; then
        echo -e "\n${MAGENTA}======================================================${NC}"
        echo -e "${MAGENTA} 🔄 INITIATING FULL FLEET AUDIT (L1, L2, TM)...${NC}"
        echo -e "${MAGENTA}======================================================${NC}"

        export CIS_LEVEL="Level 1"; export RUN_CIS=true; export RUN_ORG=false
        update_profile_vars
        echo -e "\n${CYAN}▶️ STEP 1/3: EXECUTING CIS LEVEL 1${NC}"
        execute_phases

        export CIS_LEVEL="Level 2"; export RUN_CIS=true; export RUN_ORG=false
        update_profile_vars
        echo -e "\n${CYAN}▶️ STEP 2/3: EXECUTING CIS LEVEL 2${NC}"
        execute_phases

        export RUN_CIS=false; export RUN_ORG=true
        update_profile_vars
        echo -e "\n${CYAN}▶️ STEP 3/3: EXECUTING TM BASELINE${NC}"
        execute_phases
    else
        update_profile_vars
        execute_phases
    fi

    if [ "$H_CLEANUP" == "true" ]; then run_cleanup; fi

    chmod 755 *.json *.html 2>/dev/null || true
    echo -e "\n${GREEN}✅ CI/CD Pipeline Execution Complete. All reports generated.${NC}"
    exit 0
fi

# INTERACTIVE MODE
while true; do
    update_profile_vars
    echo -e "\n${CYAN}------------------------------------------------------${NC}"
    echo -e "1) ${BOLD}SCAN ONLY${NC}      (Initial Baseline)"
    echo -e "2) ${BOLD}REMEDIATE ONLY${NC} (Ansible Fixes)"
    echo -e "3) ${BOLD}FULL PIPELINE${NC}  (Run all phases in order)"
    echo -e "4) ${BOLD}EXIT${NC}"
    read -p "Choose an option [1-4]: " choice
    case $choice in
        1) run_phase_1 ;;
        2) run_remediation ;;
        3) run_phase_1; run_remediation; run_phase_4 ;;
        4) exit 0 ;;
    esac
done
