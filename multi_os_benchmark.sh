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

export INSPEC_SSH_CONFIG_NO_SECURE=true
BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; MAGENTA='\033[0;35m'; NC='\033[0m'
clear

# ======================================================
# REMEDIATION CONSTANTS (Layer 1 + Layer 2 hardening)
# ======================================================
REMEDIATION_TIMEOUT_SEC=1800   # 30 min

REMEDIATION_SSH_OPTS="-n -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o ControlMaster=no -o ControlPath=none \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
    -o ConnectTimeout=10"

# ======================================================
# SCAP OFFLINE CACHE (runner-side, internet-facing)
# ======================================================
SCAP_CACHE_DIR="/tmp/scap_runner_cache"

# ======================================================
# PHASE 0.2b: PRE-FETCH SCAP PACKAGES ON RUNNER
# ------------------------------------------------------
# Called ONCE at startup. Runner has internet; VMs do not.
# Cache persists across runs — re-download only when empty.
#
# Windows-only runs skip this entirely — cinc-auditor runs
# from the runner, so no SCAP packages are needed on the VM.
#
# RPM packages are fetched via Docker containers (runner is
# Ubuntu-based; dnf is not available natively).
# ======================================================
prefetch_scap_packages() {
    echo -e "\n${BOLD}${CYAN}📦 PHASE 0.2b: SCAP PACKAGE PRE-FETCH (runner has internet)${NC}"

    # ---- Windows-only run: no SCAP packages needed ----
    if [[ "${H_TARGET_OS,,}" == "windows" ]]; then
        echo -e "${GREEN}   ✅ Windows-only run — cinc-auditor runs from runner. No SCAP packages needed. Skipping.${NC}"
        return 0
    fi

    mkdir -p "${SCAP_CACHE_DIR}"/{rhel9,rhel10,alma9,alma10,rocky9,rocky10,ubuntu2204,ubuntu2404}

    # ---- RHEL 9 / Rocky 9 (same RPMs, use Rocky9 container) ----
    if [ ! "$(ls -A "${SCAP_CACHE_DIR}/rhel9/"*.rpm 2>/dev/null)" ]; then
        echo -e "${CYAN}   Fetching RHEL9 packages...${NC}"
        docker run --rm \
            -v "${SCAP_CACHE_DIR}/rhel9:/output" \
            rockylinux:9 \
            bash -c "dnf install -y --downloadonly --downloaddir=/output \
                     openscap-scanner scap-security-guide 2>/dev/null" \
            && echo -e "${GREEN}   ✅ RHEL9 cached${NC}" \
            || echo -e "${RED}   ❌ RHEL9 fetch failed${NC}"
        cp -f "${SCAP_CACHE_DIR}"/rhel9/*.rpm \
              "${SCAP_CACHE_DIR}/rocky9/" 2>/dev/null || true
    else
        echo -e "${GREEN}   ✅ RHEL9/Rocky9 cache valid — skipping download${NC}"
    fi

    # ---- RHEL 10 / Rocky 10 (use Rocky10 container) ----
    if [ ! "$(ls -A "${SCAP_CACHE_DIR}/rhel10/"*.rpm 2>/dev/null)" ]; then
        echo -e "${CYAN}   Fetching RHEL10 packages...${NC}"
        if docker pull rockylinux:10 >/dev/null 2>&1; then
            docker run --rm \
                -v "${SCAP_CACHE_DIR}/rhel10:/output" \
                rockylinux:10 \
                bash -c "dnf install -y --downloadonly --downloaddir=/output \
                         openscap-scanner scap-security-guide 2>/dev/null" \
                && echo -e "${GREEN}   ✅ RHEL10 cached${NC}" \
                || echo -e "${RED}   ❌ RHEL10 fetch failed${NC}"
            cp -f "${SCAP_CACHE_DIR}"/rhel10/*.rpm \
                  "${SCAP_CACHE_DIR}/rocky10/" 2>/dev/null || true
        else
            echo -e "${YELLOW}   ⚠️  rockylinux:10 image not yet on Docker Hub — marking as skipped${NC}"
            touch "${SCAP_CACHE_DIR}/rhel10/.skipped"
            touch "${SCAP_CACHE_DIR}/rocky10/.skipped"
        fi
    else
        echo -e "${GREEN}   ✅ RHEL10/Rocky10 cache valid — skipping download${NC}"
    fi

    # ---- AlmaLinux 9 ----
    if [ ! "$(ls -A "${SCAP_CACHE_DIR}/alma9/"*.rpm 2>/dev/null)" ]; then
        echo -e "${CYAN}   Fetching Alma9 packages...${NC}"
        docker run --rm \
            -v "${SCAP_CACHE_DIR}/alma9:/output" \
            almalinux:9 \
            bash -c "dnf install -y --downloadonly --downloaddir=/output \
                     openscap-scanner scap-security-guide 2>/dev/null" \
            && echo -e "${GREEN}   ✅ Alma9 cached${NC}" \
            || echo -e "${RED}   ❌ Alma9 fetch failed${NC}"
    else
        echo -e "${GREEN}   ✅ Alma9 cache valid — skipping download${NC}"
    fi

    # ---- AlmaLinux 10 ----
    if [ ! "$(ls -A "${SCAP_CACHE_DIR}/alma10/"*.rpm 2>/dev/null)" ]; then
        echo -e "${CYAN}   Fetching Alma10 packages...${NC}"
        docker run --rm \
            -v "${SCAP_CACHE_DIR}/alma10:/output" \
            almalinux:10 \
            bash -c "dnf install -y --downloadonly --downloaddir=/output \
                     openscap-scanner scap-security-guide 2>/dev/null" \
            && echo -e "${GREEN}   ✅ Alma10 cached${NC}" \
            || echo -e "${RED}   ❌ Alma10 fetch failed${NC}"
    else
        echo -e "${GREEN}   ✅ Alma10 cache valid — skipping download${NC}"
    fi

    # ---- Ubuntu 22.04 ----
    if [ ! "$(ls -A "${SCAP_CACHE_DIR}/ubuntu2204/"*.deb 2>/dev/null)" ]; then
        echo -e "${CYAN}   Fetching Ubuntu2204 packages...${NC}"
        sudo apt-get install --download-only -y \
            openscap-scanner ssg-base 2>/dev/null
        sudo find /var/cache/apt/archives/ \
            \( -name "openscap*.deb" -o -name "ssg*.deb" \) \
            -not -path "*/partial/*" \
            | xargs -I{} cp {} "${SCAP_CACHE_DIR}/ubuntu2204/" 2>/dev/null
        echo -e "${GREEN}   ✅ Ubuntu2204 cached${NC}"
    else
        echo -e "${GREEN}   ✅ Ubuntu2204 cache valid — skipping download${NC}"
    fi

    # ---- Ubuntu 24.04 ----
    if [ ! "$(ls -A "${SCAP_CACHE_DIR}/ubuntu2404/"*.deb 2>/dev/null)" ]; then
        echo -e "${CYAN}   Fetching Ubuntu2404 packages...${NC}"
        sudo apt-get install --download-only -y \
            openscap-scanner ssg-base 2>/dev/null
        sudo find /var/cache/apt/archives/ \
            \( -name "openscap*.deb" -o -name "ssg*.deb" \) \
            -not -path "*/partial/*" \
            | xargs -I{} cp {} "${SCAP_CACHE_DIR}/ubuntu2404/" 2>/dev/null
        echo -e "${GREEN}   ✅ Ubuntu2404 cached${NC}"
    else
        echo -e "${GREEN}   ✅ Ubuntu2404 cache valid — skipping download${NC}"
    fi

    # ---- Validate all required caches are populated ----
    local failed=0
    for d in rhel9 rhel10 alma9 alma10 rocky9 rocky10 ubuntu2204 ubuntu2404; do
        # Skip dirs that were intentionally marked unavailable (e.g. image not yet released)
        if [ -f "${SCAP_CACHE_DIR}/${d}/.skipped" ]; then
            echo -e "${YELLOW}⚠️  [Phase 0.2b] ${d} skipped (image unavailable) — runtime will skip these targets${NC}"
            continue
        fi
        if [ ! "$(ls -A "${SCAP_CACHE_DIR}/${d}/" 2>/dev/null)" ]; then
            echo -e "${RED}⚠️  [Phase 0.2b] Cache still empty: ${d}${NC}"
            failed=1
        fi
    done
    
    if [ $failed -eq 0 ]; then
        echo -e "${GREEN}✅ [Phase 0.2b] All SCAP packages ready on runner. No VM internet needed.${NC}"
    else
        echo -e "${RED}❌ [Phase 0.2b] Some caches failed — check errors above.${NC}"
    fi
    return $failed
}

# ======================================================
# TOOL GUARD: ensure_linux_scap_tools (OFFLINE via SCP)
# ======================================================
ensure_linux_scap_tools() {
    local user="$1"
    local ip="$2"
    local pkg_mgr="$3"

    # ---- Fast path: already installed ----
    if ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
           -o ControlMaster=no -o ControlPath=none \
           -o ConnectTimeout=10 \
           "${user}@${ip}" \
           "command -v oscap >/dev/null 2>&1 && \
            ls /usr/share/xml/scap/ssg/content/ssg-*-ds.xml \
            >/dev/null 2>&1" 2>/dev/null; then
        echo -e "${GREEN}✅ [Tool Guard] SCAP already present on ${ip} — skipping push${NC}"
        return 0
    fi

    # ---- Detect distro + major version on VM ----
    local distro_id distro_ver cache_key
    read -r distro_id distro_ver <<< "$(ssh -n \
        -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        -o ConnectTimeout=10 \
        "${user}@${ip}" \
        "source /etc/os-release && echo \"\$ID \${VERSION_ID%%.*}\"" 2>/dev/null)"

    # Map distro+ver → runner cache key
    case "${distro_id}${distro_ver}" in
        rhel9)       cache_key="rhel9"      ;;
        rhel10)      cache_key="rhel10"     ;;
        almalinux9)  cache_key="alma9"      ;;
        almalinux10) cache_key="alma10"     ;;
        rocky9)      cache_key="rocky9"     ;;
        rocky10)     cache_key="rocky10"    ;;
        ubuntu22)    cache_key="ubuntu2204" ;;
        ubuntu24)    cache_key="ubuntu2404" ;;
        *)
            echo -e "${RED}❌ [Tool Guard] Unknown distro: '${distro_id}${distro_ver}' on ${ip}${NC}"
            return 1
            ;;
    esac

    local cache_dir="${SCAP_CACHE_DIR}/${cache_key}"

    # ---- Validate cache exists ----
    if [ ! "$(ls -A "${cache_dir}" 2>/dev/null)" ]; then
        echo -e "${RED}❌ [Tool Guard] Cache empty: ${cache_dir}${NC}"
        echo -e "${YELLOW}   Re-run Phase 0.2b (prefetch_scap_packages) on the runner first.${NC}"
        return 1
    fi

    echo -e "${CYAN}📦 [Tool Guard] Pushing ${cache_key} packages → ${ip} (SCP/port 22)${NC}"

    # ---- Create temp staging dir on VM ----
    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        "${user}@${ip}" \
        "sudo mkdir -p /tmp/scap_offline && sudo chmod 777 /tmp/scap_offline" 2>/dev/null

    # ---- Push packages via SCP (port 22 — survives CIS hardening) ----
    scp -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        -o ConnectTimeout=10 \
        "${cache_dir}"/* "${user}@${ip}:/tmp/scap_offline/"

    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ [Tool Guard] SCP push failed to ${ip}${NC}"
        return 1
    fi

    # ---- Install offline (zero outbound connections) ----
    local install_cmd
    if [ "$pkg_mgr" == "apt" ]; then
        install_cmd="sudo dpkg -i /tmp/scap_offline/*.deb 2>/dev/null; \
                     sudo apt-get install -f -y --no-download 2>/dev/null || true"
    else
        install_cmd="sudo rpm -Uvh --nodeps /tmp/scap_offline/*.rpm 2>/dev/null || \
                     sudo dnf install -y --disablerepo='*' \
                         /tmp/scap_offline/*.rpm 2>/dev/null"
    fi

    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        "${user}@${ip}" "
        set -e
        ${install_cmd}
        rm -rf /tmp/scap_offline

        command -v oscap >/dev/null 2>&1 \
            || { echo '[FATAL] oscap missing after offline install'; exit 10; }
        ls /usr/share/xml/scap/ssg/content/ssg-*-ds.xml >/dev/null 2>&1 \
            || { echo '[FATAL] SCAP content datastreams missing'; exit 11; }
        echo '[OK] SCAP tools installed offline successfully'
    "

    local rc=$?
    if [ $rc -ne 0 ]; then
        echo -e "${RED}❌ [Tool Guard] Offline install failed on ${ip} (rc=${rc})${NC}"
        return $rc
    fi

    echo -e "${GREEN}✅ [Tool Guard] SCAP ready on ${ip} (offline SCP install — no VM internet used)${NC}"
    return 0
}

# ======================================================
# HELPER: detect_windows_version
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

    local role_name role_install_target playbook_file tag_scope_l1
    case "$ver" in
        2019) role_name="ansible-lockdown.windows_2019_cis"
              role_install_target="ansible-lockdown.windows_2019_cis"
              playbook_file="window-default-cis/cis_remediate_2019.yml"
              tag_scope_l1="level1-memberserver" ;;
        2022) role_name="ansible-lockdown.windows_2022_cis"
              role_install_target="ansible-lockdown.windows_2022_cis"
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
        echo -e "${YELLOW}   Create ${playbook_file} for Windows ${ver} and retry.${NC}"
        return 1
    fi

    echo -e "${CYAN}📦 [Win/${ver}] Installing role: ${role_name}...${NC}"
    ansible-galaxy role install -f "$role_install_target"

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
# HELPER: fetch_remote_report (bulletproof 3-step fetch)
# ======================================================
fetch_remote_report() {
    local user="$1"
    local ip="$2"
    local remote="$3"
    local local_path="$4"
    local tag="$5"

    # Step 1: chmod so audit user can read root-owned file
    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
        -o ConnectTimeout=10 \
        "${user}@${ip}" "sudo chmod 644 ${remote} 2>/dev/null" >/dev/null 2>&1

    # Step 2: try SCP (fast path)
    scp -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        -o ConnectTimeout=10 \
        "${user}@${ip}:${remote}" "${local_path}" >/dev/null 2>&1
    if [ $? -eq 0 ] && [ -s "${local_path}" ]; then
        return 0
    fi

    # Step 3: fall back to ssh + sudo cat (always works post-CIS)
    echo -e "${YELLOW}🔄 [Fetch/${tag}] SCP failed — falling back to sudo cat on ${ip}${NC}"
    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
        -o ConnectTimeout=10 \
        "${user}@${ip}" "sudo cat ${remote}" > "${local_path}" 2>/dev/null
    if [ $? -eq 0 ] && [ -s "${local_path}" ]; then
        return 0
    fi

    rm -f "${local_path}"
    echo -e "${RED}❌ [Fetch/${tag}] All fetch strategies failed for ${remote} on ${ip}${NC}"
    return 1
}

# ======================================================
# AUTO-HEAL HELPER: wait_for_ssh
# ======================================================
wait_for_ssh() {
    local ip=$1
    local user=$2
    echo "🔍 Waiting for ${user}@${ip} to be responsive..."
    local count=0
    until ssh -n -o BatchMode=yes -o ConnectTimeout=5 \
              -o StrictHostKeyChecking=no "${user}@${ip}" "exit" >/dev/null 2>&1; do
        count=$((count+1))
        if [ $count -ge 12 ]; then echo "❌ Timeout waiting for $ip"; return 1; fi
        sleep 10
    done
}

# ======================================================
# HELPER: wait_for_winrm
# ======================================================
WINRM_TIMEOUT_SEC="${WINRM_TIMEOUT_SEC:-180}"
WINRM_RETRY_INTERVAL="${WINRM_RETRY_INTERVAL:-10}"

wait_for_winrm() {
    local ip="$1"
    local elapsed=0
    echo -e "${CYAN}⏳ [WinRM] Waiting for port 5985 on ${ip} (max ${WINRM_TIMEOUT_SEC}s)...${NC}"
    while true; do
        if bash -c ">/dev/tcp/${ip}/5985" 2>/dev/null; then
            echo -e "${GREEN}✅ [WinRM] ${ip} accepting connections (${elapsed}s elapsed)${NC}"
            return 0
        fi
        if [ "$elapsed" -ge "$WINRM_TIMEOUT_SEC" ]; then
            echo -e "${RED}❌ [WinRM] Timeout after ${WINRM_TIMEOUT_SEC}s on ${ip}:5985${NC}"
            return 1
        fi
        sleep "$WINRM_RETRY_INTERVAL"
        elapsed=$((elapsed + WINRM_RETRY_INTERVAL))
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
        --headless)   HEADLESS=true ;;
        --profile)    H_PROFILE="$2";    shift ;;
        --mode)       H_MODE="$2";       shift ;;
        --targets)    H_TARGETS="$2";    shift ;;
        --ticket)     H_TICKET="$2";     shift ;;
        --debug)      DEBUG_MODE="$2";   shift ;;
        --cleanup)    H_CLEANUP="$2";    shift ;;
        --target-os)  H_TARGET_OS="$2";  shift ;;
        --target-ip)  H_TARGET_IP="$2";  shift ;;
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
        echo -e "${GREEN}🎫 AUDIT AUTHORIZATION: Ticket ID: ${BOLD}$H_TICKET${NC}"
    fi
    if [ "$DEBUG_MODE" == "true" ]; then set -x; fi
fi

if [ -z "$AUDIT_PASS" ]; then
    echo -e "${YELLOW}🔐 Fetching Credentials from Azure KeyVault...${NC}"
    az login --identity --allow-no-subscriptions > /dev/null 2>&1 || true
    AUDIT_PASS=$(az keyvault secret show \
        --name "$SECRET_NAME" \
        --vault-name "$KV_NAME" \
        --query value -o tsv 2>/dev/null | tr -d '\r\n')
fi

if [ -z "$AUDIT_PASS" ]; then
    echo -e "${RED}❌ ERROR: Failed to retrieve password from KeyVault. Aborting.${NC}"
    exit 1
fi

# ======================================================
# ⚡ SSH MULTIPLEXING
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
# PHASE 0.1: ZERO-TRUST DISCOVERY
# ======================================================
echo -e "${CYAN}📡 Querying Azure for VMs in [${RG_NAME}]...${NC}"

if [ "$H_TARGETS" == "all" ] || [ -z "$H_TARGETS" ]; then
    VM_DATA=$(az vm list -d -g "$RG_NAME" \
        --query "[].[name, publicIps, storageProfile.osDisk.osType, powerState, storageProfile.imageReference.offer]" \
        -o tsv)
else
    VM_DATA=$(az vm list -d -g "$RG_NAME" \
        --query "[?tags.Environment=='$H_TARGETS'].[name, publicIps, storageProfile.osDisk.osType, powerState, storageProfile.imageReference.offer]" \
        -o tsv)
fi

UBUNTU_MACHINES=()
RHEL_MACHINES=()
ROCKY_MACHINES=()
ALMA_MACHINES=()
WINDOWS_MACHINES=()
declare -A IP_TO_VM_NAME

while IFS=$'\t' read -r raw_name raw_ip raw_os raw_power raw_offer; do
    vm_name=$(echo "$raw_name"  | tr -d '\r' | xargs)
    ip=$(echo "$raw_ip"         | tr -d '\r' | xargs)
    os=$(echo "$raw_os"         | tr -d '\r' | xargs)
    power=$(echo "$raw_power"   | tr -d '\r' | xargs)
    offer=$(echo "$raw_offer"   | tr -d '\r' | tr '[:upper:]' '[:lower:]' | xargs)

    if [ -z "$ip" ] || [ "$ip" == "None" ] || [[ "$power" != *"VM running"* ]]; then continue; fi
    IP_TO_VM_NAME["$ip"]="$vm_name"

    if [[ "$os" == *"Linux"* ]] || [[ "$os" == *"Ubuntu"* ]]; then
        if   [[ "${offer}" == *"rocky"* ]] || [[ "${vm_name,,}" == *"rocky"* ]]; then
            ROCKY_MACHINES+=("$ip"); echo -e "${CYAN}🏔️  Mapped Rocky Node:    $ip${NC}"
        elif [[ "${offer}" == *"alma"*  ]] || [[ "${vm_name,,}" == *"alma"*  ]]; then
            ALMA_MACHINES+=("$ip");  echo -e "${CYAN}🦙 Mapped AlmaLinux Node: $ip${NC}"
        elif [[ "${offer}" == *"rhel"*  ]] || [[ "${vm_name,,}" == *"rhel"*  ]]; then
            RHEL_MACHINES+=("$ip");  echo -e "${CYAN}🔴 Mapped RHEL Node:      $ip${NC}"
        else
            UBUNTU_MACHINES+=("$ip"); echo -e "${CYAN}🟠 Mapped Ubuntu Node:    $ip${NC}"
        fi
    elif [[ "$os" == *"Windows"* ]]; then
        WINDOWS_MACHINES+=("$ip"); echo -e "${CYAN}🪟 Mapped Windows Node:   $ip${NC}"
    fi
done <<< "$VM_DATA"

# Matrix sharding — isolate to single IP if requested
if [ "$H_TARGET_IP" != "all" ] && [ -n "$H_TARGET_IP" ]; then
    echo -e "${MAGENTA}🎯 MATRIX SHARDING: Isolating to node $H_TARGET_IP${NC}"
    UBUNTU_MACHINES=(); RHEL_MACHINES=(); ROCKY_MACHINES=()
    ALMA_MACHINES=();   WINDOWS_MACHINES=()
    case "${H_TARGET_OS,,}" in
        ubuntu)  UBUNTU_MACHINES=("$H_TARGET_IP")  ;;
        rhel)    RHEL_MACHINES=("$H_TARGET_IP")    ;;
        rocky)   ROCKY_MACHINES=("$H_TARGET_IP")   ;;
        alma)    ALMA_MACHINES=("$H_TARGET_IP")    ;;
        windows) WINDOWS_MACHINES=("$H_TARGET_IP") ;;
    esac
fi

# ======================================================
# PHASE 0.2: EARLY EXIT (headless, single-OS runs)
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
# PHASE 0.3: AUTO-HEALER (parallel infrastructure bootstrap)
# ======================================================
echo -e "\n${CYAN}⚙️  PHASE 0.3: PARALLEL INFRASTRUCTURE BOOTSTRAPPING${NC}"
RUNNER_IP=$(curl -s https://api.ipify.org)

if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
    for ip in "${UBUNTU_MACHINES[@]}"; do
        (
            if [ "$(ssh -n -o BatchMode=yes -o ConnectTimeout=5 \
                    -o StrictHostKeyChecking=no ${UBUNTU_USER}@${ip} \
                    "echo SSH_OK" 2>/dev/null)" != "SSH_OK" ]; then
                VM_NAME="${IP_TO_VM_NAME[$ip]}"
                NIC_ID=$(az vm show -g "$RG_NAME" -n "$VM_NAME" \
                    --query "networkProfile.networkInterfaces[0].id" -o tsv)
                NSG_ID=$(az network nic show --ids "$NIC_ID" \
                    --query "networkSecurityGroup.id" -o tsv)
                NSG_NAME=$(basename "$NSG_ID")
                az network nsg rule create -g "$RG_NAME" --nsg-name "$NSG_NAME" \
                    --name "Allow_SSH_Runner_Only" --priority 998 \
                    --destination-port-ranges 22 \
                    --source-address-prefixes "$RUNNER_IP" \
                    --access Allow --protocol Tcp -o none >/dev/null 2>&1 || true
                PUB_KEY=$(cat ~/.ssh/id_rsa.pub)
                az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" \
                    --command-id RunShellScript \
                    --scripts "useradd -m -s /bin/bash ${UBUNTU_USER} || true
                               echo '${UBUNTU_USER} ALL=(ALL) NOPASSWD:ALL' \
                                   > /etc/sudoers.d/99-${UBUNTU_USER}
                               chmod 440 /etc/sudoers.d/99-${UBUNTU_USER}
                               mkdir -p /home/${UBUNTU_USER}/.ssh
                               echo '$PUB_KEY' \
                                   > /home/${UBUNTU_USER}/.ssh/authorized_keys
                               chown -R ${UBUNTU_USER}:${UBUNTU_USER} \
                                   /home/${UBUNTU_USER}/.ssh
                               chmod 700 /home/${UBUNTU_USER}/.ssh
                               chmod 600 /home/${UBUNTU_USER}/.ssh/authorized_keys
                               systemctl restart sshd" \
                    -o none >/dev/null 2>&1 || true
                sleep 15
            fi
        ) &
    done
fi

if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" =~ ^(rhel|rocky|alma)$ ]]; then
    for ip in "${RHEL_MACHINES[@]}" "${ROCKY_MACHINES[@]}" "${ALMA_MACHINES[@]}"; do
        (
            if [ "$(ssh -n -o BatchMode=yes -o ConnectTimeout=5 \
                    -o StrictHostKeyChecking=no ${GHOST_USER}@${ip} \
                    "echo SSH_OK" 2>/dev/null)" != "SSH_OK" ]; then
                VM_NAME="${IP_TO_VM_NAME[$ip]}"
                NIC_ID=$(az vm show -g "$RG_NAME" -n "$VM_NAME" \
                    --query "networkProfile.networkInterfaces[0].id" -o tsv)
                NSG_ID=$(az network nic show --ids "$NIC_ID" \
                    --query "networkSecurityGroup.id" -o tsv)
                NSG_NAME=$(basename "$NSG_ID")
                az network nsg rule create -g "$RG_NAME" --nsg-name "$NSG_NAME" \
                    --name "Allow_SSH_Runner_Only" --priority 998 \
                    --destination-port-ranges 22 \
                    --source-address-prefixes "$RUNNER_IP" \
                    --access Allow --protocol Tcp -o none >/dev/null 2>&1 || true
                PUB_KEY=$(cat ~/.ssh/id_rsa.pub)
                az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" \
                    --command-id RunShellScript \
                    --scripts "useradd -m -s /bin/bash ${GHOST_USER} || true
                               echo '${GHOST_USER} ALL=(ALL) NOPASSWD:ALL' \
                                   > /etc/sudoers.d/99-${GHOST_USER}
                               chmod 440 /etc/sudoers.d/99-${GHOST_USER}
                               mkdir -p /home/${GHOST_USER}/.ssh
                               echo '$PUB_KEY' \
                                   > /home/${GHOST_USER}/.ssh/authorized_keys
                               chown -R ${GHOST_USER}:${GHOST_USER} \
                                   /home/${GHOST_USER}/.ssh
                               chmod 700 /home/${GHOST_USER}/.ssh
                               chmod 600 /home/${GHOST_USER}/.ssh/authorized_keys
                               command -v restorecon &>/dev/null && \
                                   restorecon -Rv /home/${GHOST_USER}/.ssh \
                                   >/dev/null 2>&1 || true
                               echo 'PubkeyAcceptedKeyTypes +ssh-rsa' \
                                   > /etc/ssh/sshd_config.d/99-runner-key.conf \
                                   2>/dev/null || true
                               systemctl restart sshd" \
                    -o none >/dev/null 2>&1 || true
                sleep 15
            fi
        ) &
    done
fi

if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
    for ip in "${WINDOWS_MACHINES[@]}"; do
        (
            VM_NAME="${IP_TO_VM_NAME[$ip]}"
            NIC_ID=$(az vm show -g "$RG_NAME" -n "$VM_NAME" \
                --query "networkProfile.networkInterfaces[0].id" -o tsv)
            NSG_ID=$(az network nic show --ids "$NIC_ID" \
                --query "networkSecurityGroup.id" -o tsv)
            if [ -n "$NSG_ID" ]; then
                NSG_NAME=$(basename "$NSG_ID")
                az network nsg rule create -g "$RG_NAME" --nsg-name "$NSG_NAME" \
                    --name "Allow_WinRM_Runner_Only" --priority 999 \
                    --destination-port-ranges 5985 \
                    --source-address-prefixes "$RUNNER_IP" \
                    --access Allow --protocol Tcp -o none >/dev/null 2>&1 || true
            fi
            az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" \
                --command-id RunPowerShellScript \
                --scripts "Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM' \
                               -Recurse -Force -ErrorAction SilentlyContinue
                           net user ${AUDIT_USER} '${AUDIT_PASS}' /add /y 2>&1 | Out-Null
                           net user ${AUDIT_USER} '${AUDIT_PASS}' 2>&1 | Out-Null
                           net localgroup Administrators ${AUDIT_USER} /add 2>&1 | Out-Null
                           WMIC USERACCOUNT WHERE Name='${AUDIT_USER}' \
                               SET PasswordExpires=FALSE 2>&1 | Out-Null
                           Enable-PSRemoting -SkipNetworkProfileCheck -Force
                           winrm set winrm/config/service/auth '@{Basic=\"true\"}'
                           winrm set winrm/config/service '@{AllowUnencrypted=\"true\"}'
                           New-ItemProperty -Name LocalAccountTokenFilterPolicy \
                               -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System \
                               -PropertyType DWord -Value 1 -Force
                           Set-NetFirewallRule -DisplayGroup 'Windows Remote Management' \
                               -Enabled True -Profile Any -ErrorAction SilentlyContinue
                           Restart-Service WinRM -Force" \
                -o none >/dev/null 2>&1 || true
            sleep 20
        ) &
    done
fi
wait

# ======================================================
# INVENTORY BUILDER
# ======================================================
echo "[ubuntu_nodes]" > inventory.ini
for ip in "${UBUNTU_MACHINES[@]}"; do
    echo "${ip} ansible_user=${UBUNTU_USER}" >> inventory.ini
done
echo -e "\n[rhel_nodes]" >> inventory.ini
for ip in "${RHEL_MACHINES[@]}"; do
    echo "${ip} ansible_user=${GHOST_USER}" >> inventory.ini
done
echo -e "\n[rocky_nodes]" >> inventory.ini
for ip in "${ROCKY_MACHINES[@]}"; do
    echo "${ip} ansible_user=${GHOST_USER}" >> inventory.ini
done
echo -e "\n[alma_nodes]" >> inventory.ini
for ip in "${ALMA_MACHINES[@]}"; do
    echo "${ip} ansible_user=${GHOST_USER}" >> inventory.ini
done
echo -e "\n[windows_nodes]" >> inventory.ini
for ip in "${WINDOWS_MACHINES[@]}"; do
    echo "${ip} ansible_user=${AUDIT_USER} ansible_password=\"${AUDIT_PASS}\" \
ansible_port=5985 ansible_winrm_scheme=http ansible_connection=winrm \
ansible_winrm_transport=basic ansible_winrm_server_cert_validation=ignore" \
        >> inventory.ini
done

RUN_ORG=false; RUN_CIS=false
if [ "$HEADLESS" == true ]; then
    if [[ "${H_PROFILE,,}" == "${ORG_PREFIX,,}" ]] || \
       [[ "${H_PROFILE,,}" == "both" ]]; then RUN_ORG=true; fi
    if [[ "${H_PROFILE,,}" == "cis" ]] || \
       [[ "${H_PROFILE,,}" == "both" ]]; then RUN_CIS=true; fi
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
            OS_LVL="1"; WIN_INSPEC_LVL="1"
        else
            UBUNTU_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis_level2_server"
            RHEL_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis"
            OS_LVL="2"; WIN_INSPEC_LVL="2"
        fi
    fi
}

# ======================================================
# PHASE 1: INITIAL SCAN
# ======================================================
run_phase_1() {
    echo -e "\n${BOLD}🔍 PHASE 1: Initial Baselines (SCP install → scan)...${NC}"

    # -------------------- UBUNTU --------------------
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ]; then
            for IP in "${UBUNTU_MACHINES[@]}"; do
                (
                    if ! ensure_linux_scap_tools "$UBUNTU_USER" "$IP" "apt"; then
                        echo -e "${RED}❌ [Phase1/Ubuntu] Skipping $IP — tools unavailable.${NC}"
                        exit 1
                    fi

                    RAW_VER=$(ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                        ${UBUNTU_USER}@${IP} \
                        "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
                    UBUNTU_VER=${RAW_VER:-2404}
                    UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Ubuntu/CIS L${OS_LVL}] Scanning $IP...${NC}"
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                            ${UBUNTU_USER}@${IP} \
                            "sudo oscap xccdf eval --profile $UBUNTU_CIS_PROFILE \
                             --report /tmp/report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html \
                             $UBUNTU_CIS_XCCDF"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$UBUNTU_USER" "$IP" \
                                "/tmp/report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html" \
                                "./report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html" \
                                "Ubuntu/CIS-before"
                        else
                            echo -e "${RED}❌ [Phase1/Ubuntu/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Ubuntu/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                            "$UBUNTU_CUSTOM_OVAL" "$UBUNTU_CUSTOM_XCCDF" \
                            ${UBUNTU_USER}@${IP}:/tmp/ \
                            || { echo -e "${RED}❌ [Phase1] SCP of custom content failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                            ${UBUNTU_USER}@${IP} \
                            "sudo oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report /tmp/report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html \
                             /tmp/$(basename $UBUNTU_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$UBUNTU_USER" "$IP" \
                                "/tmp/report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html" \
                                "./report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html" \
                                "Ubuntu/${ORG_PREFIX^^}-before"
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
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rhel" ]]; then
        if [ ${#RHEL_MACHINES[@]} -gt 0 ]; then
            for IP in "${RHEL_MACHINES[@]}"; do
                (
                    if ! ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf"; then
                        echo -e "${RED}❌ [Phase1/RHEL] Skipping $IP — tools unavailable.${NC}"
                        exit 1
                    fi

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/RHEL/CIS L${OS_LVL}] Scanning $IP...${NC}"
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                            ${GHOST_USER}@${IP} \
                            "TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ \
                                 -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                             sudo /usr/bin/oscap xccdf eval \
                                 --profile $RHEL_CIS_PROFILE \
                                 --report /tmp/report_before_CIS_L${OS_LVL}_RHEL_${IP}.html \
                                 \"\$TARGET_XML\""
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$GHOST_USER" "$IP" \
                                "/tmp/report_before_CIS_L${OS_LVL}_RHEL_${IP}.html" \
                                "./report_before_CIS_L${OS_LVL}_RHEL_${IP}.html" \
                                "RHEL/CIS-before"
                        else
                            echo -e "${RED}❌ [Phase1/RHEL/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/RHEL/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                            "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" \
                            ${GHOST_USER}@${IP}:/tmp/ \
                            || { echo -e "${RED}❌ [Phase1] SCP of custom content failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                            ${GHOST_USER}@${IP} \
                            "sudo env OSCAP_CPE_DICT_PATH=\$(find /usr/share/xml/scap/ssg/content/ \
                                 -name 'ssg-rhel*-cpe-dictionary.xml' | sort -V | tail -n 1) \
                             /usr/bin/oscap xccdf eval \
                                 --profile $CUSTOM_XCCDF_PROFILE \
                                 --report /tmp/report_before_${ORG_PREFIX^^}_RHEL_${IP}.html \
                                 /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$GHOST_USER" "$IP" \
                                "/tmp/report_before_${ORG_PREFIX^^}_RHEL_${IP}.html" \
                                "./report_before_${ORG_PREFIX^^}_RHEL_${IP}.html" \
                                "RHEL/${ORG_PREFIX^^}-before"
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
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rocky" ]]; then
        if [ ${#ROCKY_MACHINES[@]} -gt 0 ]; then
            for IP in "${ROCKY_MACHINES[@]}"; do
                (
                    if ! ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf"; then
                        echo -e "${RED}❌ [Phase1/Rocky] Skipping $IP — tools unavailable.${NC}"
                        exit 1
                    fi

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Rocky/CIS L${OS_LVL}] Scanning $IP...${NC}"
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                            ${GHOST_USER}@${IP} "
                            ROCKY_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-rl\${ROCKY_VER}-ds.xml\"
                            if [ ! -f \"\$TARGET_XML\" ]; then
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ \
                                    -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            fi
                            [ -z \"\$TARGET_XML\" ] || [ ! -f \"\$TARGET_XML\" ] && \
                                { echo 'NO_SCAP_CONTENT'; exit 99; }
                            sudo /usr/bin/oscap xccdf eval \
                                --profile $RHEL_CIS_PROFILE \
                                --report /tmp/report_before_CIS_L${OS_LVL}_ROCKY_${IP}.html \
                                \"\$TARGET_XML\"
                        "
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$GHOST_USER" "$IP" \
                                "/tmp/report_before_CIS_L${OS_LVL}_ROCKY_${IP}.html" \
                                "./report_before_CIS_L${OS_LVL}_ROCKY_${IP}.html" \
                                "Rocky/CIS-before"
                        else
                            echo -e "${RED}❌ [Phase1/Rocky/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Rocky/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                            "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" \
                            ${GHOST_USER}@${IP}:/tmp/ \
                            || { echo -e "${RED}❌ [Phase1] SCP of custom content failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                            ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval \
                                 --profile $CUSTOM_XCCDF_PROFILE \
                                 --report /tmp/report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html \
                                 /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$GHOST_USER" "$IP" \
                                "/tmp/report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html" \
                                "./report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html" \
                                "Rocky/${ORG_PREFIX^^}-before"
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
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "alma" ]]; then
        if [ ${#ALMA_MACHINES[@]} -gt 0 ]; then
            for IP in "${ALMA_MACHINES[@]}"; do
                (
                    if ! ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf"; then
                        echo -e "${RED}❌ [Phase1/Alma] Skipping $IP — tools unavailable.${NC}"
                        exit 1
                    fi

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Alma/CIS L${OS_LVL}] Scanning $IP...${NC}"
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                            ${GHOST_USER}@${IP} "
                            ALMA_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-almalinux\${ALMA_VER}-ds.xml\"
                            if [ ! -f \"\$TARGET_XML\" ]; then
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ \
                                    -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            fi
                            [ -z \"\$TARGET_XML\" ] || [ ! -f \"\$TARGET_XML\" ] && \
                                { echo 'NO_SCAP_CONTENT'; exit 99; }
                            if ! grep -q \"$RHEL_CIS_PROFILE\" \"\$TARGET_XML\"; then
                                ALMA_PROF=\"xccdf_org.ssgproject.content_profile_cis\"
                            else
                                ALMA_PROF=\"$RHEL_CIS_PROFILE\"
                            fi
                            sudo /usr/bin/oscap xccdf eval \
                                --profile \$ALMA_PROF \
                                --report /tmp/report_before_CIS_L${OS_LVL}_ALMA_${IP}.html \
                                \"\$TARGET_XML\"
                        "
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$GHOST_USER" "$IP" \
                                "/tmp/report_before_CIS_L${OS_LVL}_ALMA_${IP}.html" \
                                "./report_before_CIS_L${OS_LVL}_ALMA_${IP}.html" \
                                "Alma/CIS-before"
                        else
                            echo -e "${RED}❌ [Phase1/Alma/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Alma/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                            "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" \
                            ${GHOST_USER}@${IP}:/tmp/ \
                            || { echo -e "${RED}❌ [Phase1] SCP of custom content failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                            ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval \
                                 --profile $CUSTOM_XCCDF_PROFILE \
                                 --report /tmp/report_before_${ORG_PREFIX^^}_ALMA_${IP}.html \
                                 /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$GHOST_USER" "$IP" \
                                "/tmp/report_before_${ORG_PREFIX^^}_ALMA_${IP}.html" \
                                "./report_before_${ORG_PREFIX^^}_ALMA_${IP}.html" \
                                "Alma/${ORG_PREFIX^^}-before"
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
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            for IP in "${WINDOWS_MACHINES[@]}"; do
                (
                    wait_for_winrm "$IP" || {
                        echo -e "${RED}❌ [Phase1/Win] WinRM unreachable: $IP — skipping${NC}"
                        exit 1
                    }
                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Win/CIS L${WIN_INSPEC_LVL}] Scanning $IP...${NC}"
                        cinc-auditor exec "$WIN_CIS_BENCHMARK" -t winrm://${IP} \
                            --user="${AUDIT_USER}" --password="${AUDIT_PASS}" \
                            --input level_1_or_2=$WIN_INSPEC_LVL \
                            --reporter json:heimdall_before_CIS_L${WIN_INSPEC_LVL}_WIN_${IP}.json
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 100 ] || [ $rc -eq 101 ]; then
                            echo -e "${GREEN}✅ [Phase1/Win/CIS] $IP scan complete (rc=$rc)${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/Win/CIS] cinc-auditor failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Win/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        cinc-auditor exec "$WIN_CUSTOM_BENCHMARK" -t winrm://${IP} \
                            --user="${AUDIT_USER}" --password="${AUDIT_PASS}" \
                            --reporter json:heimdall_before_${ORG_PREFIX^^}_WIN_${IP}.json
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 100 ] || [ $rc -eq 101 ]; then
                            echo -e "${GREEN}✅ [Phase1/Win/${ORG_PREFIX^^}] $IP scan complete (rc=$rc)${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/Win/${ORG_PREFIX^^}] cinc-auditor failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi
}

# ======================================================
# PHASE 2/3: REMEDIATION
# ======================================================
run_remediation() {
    echo -e "\n${BOLD}🛠️  PHASE 2 & 3: Executing Remediation (Hardened SSH)...${NC}"

    # -------------------- UBUNTU --------------------
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ] && [ "$RUN_CIS" == true ]; then
            for IP in "${UBUNTU_MACHINES[@]}"; do
                (
                    echo -e "${CYAN}🛠️  [Remediation/Ubuntu] Starting on ${IP} (max ${REMEDIATION_TIMEOUT_SEC}s)...${NC}"
                    timeout $REMEDIATION_TIMEOUT_SEC \
                        ssh $REMEDIATION_SSH_OPTS ${UBUNTU_USER}@${IP} \
                        "XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ \
                             -name 'ssg-ubuntu*-ds.xml' | sort -V | tail -n 1)
                         sudo /usr/bin/oscap xccdf eval --remediate \
                             --profile $UBUNTU_CIS_PROFILE \
                             --report /tmp/report_remediation_CIS_${IP}.html \"\$XML_FILE\""
                    rc=$?
                    case $rc in
                        124) echo -e "${RED}⏱️  [Remediation/Ubuntu] TIMEOUT on ${IP}${NC}" ;;
                        255) echo -e "${RED}🔌 [Remediation/Ubuntu] SSH dropped on ${IP} (sshd restart expected)${NC}" ;;
                        0|2) echo -e "${GREEN}✅ [Remediation/Ubuntu] ${IP} done (rc=${rc})${NC}" ;;
                        *)   echo -e "${YELLOW}⚠️  [Remediation/Ubuntu] ${IP} rc=${rc}${NC}" ;;
                    esac
                ) &
            done
            wait
        fi
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ] && [ "$RUN_ORG" == true ]; then
            ansible-playbook -i inventory.ini $UBUNTU_CUSTOM_PLAYBOOK \
                --limit ubuntu_nodes >/dev/null 2>&1 || true
        fi
    fi

    # -------------------- RHEL --------------------
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rhel" ]]; then
        if [ ${#RHEL_MACHINES[@]} -gt 0 ] && [ "$RUN_CIS" == true ]; then
            for IP in "${RHEL_MACHINES[@]}"; do
                (
                    echo -e "${CYAN}🛠️  [Remediation/RHEL] Starting on ${IP} (max ${REMEDIATION_TIMEOUT_SEC}s)...${NC}"
                    timeout $REMEDIATION_TIMEOUT_SEC \
                        ssh $REMEDIATION_SSH_OPTS ${GHOST_USER}@${IP} \
                        "XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ \
                             -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                         sudo /usr/bin/oscap xccdf eval --remediate \
                             --profile $RHEL_CIS_PROFILE \
                             --report /tmp/report_remediation_CIS_${IP}.html \"\$XML_FILE\""
                    rc=$?
                    case $rc in
                        124) echo -e "${RED}⏱️  [Remediation/RHEL] TIMEOUT on ${IP}${NC}" ;;
                        255) echo -e "${RED}🔌 [Remediation/RHEL] SSH dropped on ${IP}${NC}" ;;
                        0|2) echo -e "${GREEN}✅ [Remediation/RHEL] ${IP} done (rc=${rc})${NC}" ;;
                        *)   echo -e "${YELLOW}⚠️  [Remediation/RHEL] ${IP} rc=${rc}${NC}" ;;
                    esac
                ) &
            done
            wait
        fi
        if [ ${#RHEL_MACHINES[@]} -gt 0 ] && [ "$RUN_ORG" == true ]; then
            ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK \
                --limit rhel_nodes >/dev/null 2>&1 || true
        fi
    fi

    # -------------------- ROCKY --------------------
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rocky" ]]; then
        if [ ${#ROCKY_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                for IP in "${ROCKY_MACHINES[@]}"; do
                    (
                        echo -e "${CYAN}🛠️  [Remediation/Rocky] Starting on ${IP}...${NC}"
                        timeout $REMEDIATION_TIMEOUT_SEC \
                            ssh $REMEDIATION_SSH_OPTS ${GHOST_USER}@${IP} "
                            ROCKY_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-rl\${ROCKY_VER}-ds.xml\"
                            [ ! -f \"\$TARGET_XML\" ] && \
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ \
                                    -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            [ -z \"\$TARGET_XML\" ] && exit 99
                            sudo /usr/bin/oscap xccdf eval --remediate \
                                --profile $RHEL_CIS_PROFILE \
                                --report /tmp/report_remediation_CIS_ROCKY_${IP}.html \
                                \"\$TARGET_XML\"
                        "
                        rc=$?
                        case $rc in
                            124) echo -e "${RED}⏱️  [Remediation/Rocky] TIMEOUT on ${IP}${NC}" ;;
                            255) echo -e "${RED}🔌 [Remediation/Rocky] SSH dropped on ${IP}${NC}" ;;
                            0|2) echo -e "${GREEN}✅ [Remediation/Rocky] ${IP} done (rc=${rc})${NC}" ;;
                            *)   echo -e "${YELLOW}⚠️  [Remediation/Rocky] ${IP} rc=${rc}${NC}" ;;
                        esac
                    ) &
                done
                wait
            fi
            if [ "$RUN_ORG" == true ]; then
                ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK \
                    --limit rocky_nodes >/dev/null 2>&1 || true
            fi
        fi
    fi

    # -------------------- ALMA --------------------
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "alma" ]]; then
        if [ ${#ALMA_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                for IP in "${ALMA_MACHINES[@]}"; do
                    (
                        echo -e "${CYAN}🛠️  [Remediation/Alma] Starting on ${IP}...${NC}"
                        timeout $REMEDIATION_TIMEOUT_SEC \
                            ssh $REMEDIATION_SSH_OPTS ${GHOST_USER}@${IP} "
                            ALMA_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-almalinux\${ALMA_VER}-ds.xml\"
                            [ ! -f \"\$TARGET_XML\" ] && \
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ \
                                    -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            [ -z \"\$TARGET_XML\" ] && exit 99
                            if ! grep -q \"$RHEL_CIS_PROFILE\" \"\$TARGET_XML\"; then
                                ALMA_PROF=\"xccdf_org.ssgproject.content_profile_cis\"
                            else
                                ALMA_PROF=\"$RHEL_CIS_PROFILE\"
                            fi
                            sudo /usr/bin/oscap xccdf eval --remediate \
                                --profile \$ALMA_PROF \
                                --report /tmp/report_remediation_CIS_ALMA_${IP}.html \
                                \"\$TARGET_XML\"
                        "
                        rc=$?
                        case $rc in
                            124) echo -e "${RED}⏱️  [Remediation/Alma] TIMEOUT on ${IP}${NC}" ;;
                            255) echo -e "${RED}🔌 [Remediation/Alma] SSH dropped on ${IP}${NC}" ;;
                            0|2) echo -e "${GREEN}✅ [Remediation/Alma] ${IP} done (rc=${rc})${NC}" ;;
                            *)   echo -e "${YELLOW}⚠️  [Remediation/Alma] ${IP} rc=${rc}${NC}" ;;
                        esac
                    ) &
                done
                wait
            fi
            if [ "$RUN_ORG" == true ]; then
                ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK \
                    --limit alma_nodes >/dev/null 2>&1 || true
            fi
        fi
    fi

    # -------------------- WINDOWS --------------------
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                for IP in "${WINDOWS_MACHINES[@]}"; do
                    (
                        wait_for_winrm "$IP" || {
                            echo -e "${RED}❌ [Remediation/Win] WinRM unreachable: $IP — skipping${NC}"
                            exit 1
                        }
                        remediate_windows_host "$IP" "$CIS_LEVEL"
                    ) &
                done
                wait
            fi
            if [ "$RUN_ORG" == true ]; then
                for IP in "${WINDOWS_MACHINES[@]}"; do
                    wait_for_winrm "$IP" || \
                        echo -e "${YELLOW}⚠️  [Remediation/Win/${ORG_PREFIX^^}] WinRM not ready on $IP${NC}"
                done
                echo -e "${CYAN}🛠️  [Remediation/Win/${ORG_PREFIX^^}] Running custom playbook...${NC}"
                ansible-playbook -i inventory.ini "$WIN_CUSTOM_PLAYBOOK" \
                    --limit windows_nodes
                rc=$?
                [ $rc -eq 0 ] \
                    && echo -e "${GREEN}✅ [Remediation/Win/${ORG_PREFIX^^}] Completed${NC}" \
                    || echo -e "${RED}❌ [Remediation/Win/${ORG_PREFIX^^}] failed (rc=$rc)${NC}"
            fi
        fi
    fi
}

# ======================================================
# PHASE 4: VERIFICATION
# ======================================================
run_phase_4() {
    echo -e "\n${BOLD}🔄 PHASE 4: Verification Scans (SCP install → scan)...${NC}"

    local SCAN_SSH_OPTS="-n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
        -o ConnectTimeout=10"

    # -------------------- UBUNTU VERIFY --------------------
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ]; then
            for IP in "${UBUNTU_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$UBUNTU_USER" || {
                        echo -e "${RED}❌ [Phase4/Ubuntu] SSH unreachable: $IP${NC}"; exit 1
                    }
                    ensure_linux_scap_tools "$UBUNTU_USER" "$IP" "apt" || {
                        echo -e "${RED}❌ [Phase4/Ubuntu] Tools missing on $IP${NC}"; exit 1
                    }

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
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$UBUNTU_USER" "$IP" "$REMOTE" "$LOCAL" "Ubuntu/CIS" || \
                            echo -e "${RED}❌ [Phase4/Ubuntu/CIS] oscap failed on $IP (rc=$rc)${NC}"
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/Ubuntu/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${UBUNTU_USER}@${IP} \
                            "sudo oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report ${REMOTE} /tmp/$(basename $UBUNTU_CUSTOM_XCCDF)"
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$UBUNTU_USER" "$IP" "$REMOTE" "$LOCAL" \
                                "Ubuntu/${ORG_PREFIX^^}" || \
                            echo -e "${RED}❌ [Phase4/Ubuntu/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- RHEL VERIFY --------------------
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rhel" ]]; then
        if [ ${#RHEL_MACHINES[@]} -gt 0 ]; then
            for IP in "${RHEL_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$GHOST_USER" || {
                        echo -e "${RED}❌ [Phase4/RHEL] SSH unreachable: $IP${NC}"; exit 1
                    }
                    ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || {
                        echo -e "${RED}❌ [Phase4/RHEL] Tools missing on $IP${NC}"; exit 1
                    }

                    if [ "$RUN_CIS" == true ]; then
                        REMOTE="/tmp/report_after_CIS_L${OS_LVL}_RHEL_${IP}.html"
                        LOCAL="./report_after_CIS_L${OS_LVL}_RHEL_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/RHEL/CIS L${OS_LVL}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ \
                                 -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                             sudo /usr/bin/oscap xccdf eval \
                                 --profile $RHEL_CIS_PROFILE \
                                 --report ${REMOTE} \"\$TARGET_XML\""
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "RHEL/CIS" || \
                            echo -e "${RED}❌ [Phase4/RHEL/CIS] oscap failed on $IP (rc=$rc)${NC}"
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_RHEL_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_RHEL_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/RHEL/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval \
                                 --profile $CUSTOM_XCCDF_PROFILE \
                                 --report ${REMOTE} /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" \
                                "RHEL/${ORG_PREFIX^^}" || \
                            echo -e "${RED}❌ [Phase4/RHEL/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- ROCKY VERIFY --------------------
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rocky" ]]; then
        if [ ${#ROCKY_MACHINES[@]} -gt 0 ]; then
            for IP in "${ROCKY_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$GHOST_USER" || {
                        echo -e "${RED}❌ [Phase4/Rocky] SSH unreachable: $IP${NC}"; exit 1
                    }
                    ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || {
                        echo -e "${RED}❌ [Phase4/Rocky] Tools missing on $IP${NC}"; exit 1
                    }

                    if [ "$RUN_CIS" == true ]; then
                        REMOTE="/tmp/report_after_CIS_L${OS_LVL}_ROCKY_${IP}.html"
                        LOCAL="./report_after_CIS_L${OS_LVL}_ROCKY_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/Rocky/CIS L${OS_LVL}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} "
                            ROCKY_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-rl\${ROCKY_VER}-ds.xml\"
                            [ ! -f \"\$TARGET_XML\" ] && \
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ \
                                    -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            [ -z \"\$TARGET_XML\" ] && { echo 'NO_SCAP_CONTENT'; exit 99; }
                            sudo /usr/bin/oscap xccdf eval \
                                --profile $RHEL_CIS_PROFILE \
                                --report ${REMOTE} \"\$TARGET_XML\"
                        "
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Rocky/CIS" || \
                            echo -e "${RED}❌ [Phase4/Rocky/CIS] oscap failed on $IP (rc=$rc)${NC}"
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/Rocky/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval \
                                 --profile $CUSTOM_XCCDF_PROFILE \
                                 --report ${REMOTE} /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" \
                                "Rocky/${ORG_PREFIX^^}" || \
                            echo -e "${RED}❌ [Phase4/Rocky/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- ALMA VERIFY --------------------
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "alma" ]]; then
        if [ ${#ALMA_MACHINES[@]} -gt 0 ]; then
            for IP in "${ALMA_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$GHOST_USER" || {
                        echo -e "${RED}❌ [Phase4/Alma] SSH unreachable: $IP${NC}"; exit 1
                    }
                    ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || {
                        echo -e "${RED}❌ [Phase4/Alma] Tools missing on $IP${NC}"; exit 1
                    }

                    if [ "$RUN_CIS" == true ]; then
                        REMOTE="/tmp/report_after_CIS_L${OS_LVL}_ALMA_${IP}.html"
                        LOCAL="./report_after_CIS_L${OS_LVL}_ALMA_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/Alma/CIS L${OS_LVL}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} "
                            ALMA_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-almalinux\${ALMA_VER}-ds.xml\"
                            [ ! -f \"\$TARGET_XML\" ] && \
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ \
                                    -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            [ -z \"\$TARGET_XML\" ] && { echo 'NO_SCAP_CONTENT'; exit 99; }
                            if ! grep -q \"$RHEL_CIS_PROFILE\" \"\$TARGET_XML\"; then
                                ALMA_PROF=\"xccdf_org.ssgproject.content_profile_cis\"
                            else
                                ALMA_PROF=\"$RHEL_CIS_PROFILE\"
                            fi
                            sudo /usr/bin/oscap xccdf eval \
                                --profile \$ALMA_PROF \
                                --report ${REMOTE} \"\$TARGET_XML\"
                        "
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Alma/CIS" || \
                            echo -e "${RED}❌ [Phase4/Alma/CIS] oscap failed on $IP (rc=$rc)${NC}"
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_ALMA_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_ALMA_${IP}.html"
                        echo -e "${GREEN}✅ [Phase4/Alma/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval \
                                 --profile $CUSTOM_XCCDF_PROFILE \
                                 --report ${REMOTE} /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" \
                                "Alma/${ORG_PREFIX^^}" || \
                            echo -e "${RED}❌ [Phase4/Alma/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- WINDOWS VERIFY --------------------
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            for IP in "${WINDOWS_MACHINES[@]}"; do
                (
                    wait_for_winrm "$IP" || {
                        echo -e "${RED}❌ [Phase4/Win] WinRM unreachable: $IP — skipping${NC}"
                        exit 1
                    }
                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Win/CIS L${WIN_INSPEC_LVL}] Verifying $IP...${NC}"
                        cinc-auditor exec "$WIN_CIS_BENCHMARK" -t winrm://${IP} \
                            --user="${AUDIT_USER}" --password="${AUDIT_PASS}" \
                            --input level_1_or_2=$WIN_INSPEC_LVL \
                            --reporter json:heimdall_after_CIS_L${WIN_INSPEC_LVL}_WIN_${IP}.json
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 100 ] || [ $rc -eq 101 ]; then
                            echo -e "${GREEN}✅ [Phase4/Win/CIS] $IP verify complete (rc=$rc)${NC}"
                        else
                            echo -e "${RED}❌ [Phase4/Win/CIS] cinc-auditor failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Win/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        cinc-auditor exec "$WIN_CUSTOM_BENCHMARK" -t winrm://${IP} \
                            --user="${AUDIT_USER}" --password="${AUDIT_PASS}" \
                            --reporter json:heimdall_after_${ORG_PREFIX^^}_WIN_${IP}.json
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 100 ] || [ $rc -eq 101 ]; then
                            echo -e "${GREEN}✅ [Phase4/Win/${ORG_PREFIX^^}] $IP verify complete (rc=$rc)${NC}"
                        else
                            echo -e "${RED}❌ [Phase4/Win/${ORG_PREFIX^^}] cinc-auditor failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi
}

# ======================================================
# PHASE 5: CLEANUP — tools removed, VM stays HARDENED
# ======================================================
run_cleanup() {
    echo -e "\n${BOLD}${RED}🧹 PHASE 5: POST-AUDIT CLEANUP${NC}"
    echo -e "${CYAN}   VM stays HARDENED — only SCAP tools + audit user are removed.${NC}"
    echo -e "${CYAN}   Next audit: Phase 0.2b SCP re-installs offline. ✅${NC}\n"

    local remove_rpm="sudo rpm -e --nodeps \
        openscap openscap-scanner scap-security-guide 2>/dev/null || true; \
        sudo rm -rf /tmp/scap_offline /tmp/report_*.html"

    local remove_deb="sudo dpkg -r openscap-scanner ssg-base 2>/dev/null || true; \
        sudo rm -rf /tmp/scap_offline /tmp/report_*.html"

    # ---- Ubuntu ----
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
        for IP in "${UBUNTU_MACHINES[@]}"; do
            echo -e "   ${YELLOW}[Cleanup/Ubuntu] Removing tools from $IP...${NC}"
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                -o ControlMaster=no -o ControlPath=none \
                ${UBUNTU_USER}@${IP} "$remove_deb" >/dev/null 2>&1 || true
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            [ -n "$VM_NAME" ] && az vm run-command invoke \
                -g "$RG_NAME" -n "$VM_NAME" \
                --command-id RunShellScript \
                --scripts "userdel -r ${UBUNTU_USER} 2>/dev/null || true" \
                -o none >/dev/null 2>&1 || true &
        done
    fi

    # ---- RHEL ----
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rhel" ]]; then
        for IP in "${RHEL_MACHINES[@]}"; do
            echo -e "   ${YELLOW}[Cleanup/RHEL] Removing tools from $IP...${NC}"
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                -o ControlMaster=no -o ControlPath=none \
                ${GHOST_USER}@${IP} "$remove_rpm" >/dev/null 2>&1 || true
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            [ -n "$VM_NAME" ] && az vm run-command invoke \
                -g "$RG_NAME" -n "$VM_NAME" \
                --command-id RunShellScript \
                --scripts "userdel -r ${GHOST_USER} 2>/dev/null || true" \
                -o none >/dev/null 2>&1 || true &
        done
    fi

    # ---- Rocky ----
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rocky" ]]; then
        for IP in "${ROCKY_MACHINES[@]}"; do
            echo -e "   ${YELLOW}[Cleanup/Rocky] Removing tools from $IP...${NC}"
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                -o ControlMaster=no -o ControlPath=none \
                ${GHOST_USER}@${IP} "$remove_rpm" >/dev/null 2>&1 || true
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            [ -n "$VM_NAME" ] && az vm run-command invoke \
                -g "$RG_NAME" -n "$VM_NAME" \
                --command-id RunShellScript \
                --scripts "userdel -r ${GHOST_USER} 2>/dev/null || true" \
                -o none >/dev/null 2>&1 || true &
        done
    fi

    # ---- Alma ----
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "alma" ]]; then
        for IP in "${ALMA_MACHINES[@]}"; do
            echo -e "   ${YELLOW}[Cleanup/Alma] Removing tools from $IP...${NC}"
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                -o ControlMaster=no -o ControlPath=none \
                ${GHOST_USER}@${IP} "$remove_rpm" >/dev/null 2>&1 || true
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            [ -n "$VM_NAME" ] && az vm run-command invoke \
                -g "$RG_NAME" -n "$VM_NAME" \
                --command-id RunShellScript \
                --scripts "userdel -r ${GHOST_USER} 2>/dev/null || true" \
                -o none >/dev/null 2>&1 || true &
        done
    fi

    # ---- Windows ----
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
        for IP in "${WINDOWS_MACHINES[@]}"; do
            echo -e "   ${CYAN}[Cleanup/Windows] Reversing WinRM + removing audit user: $IP...${NC}"
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            if [ -n "$VM_NAME" ]; then
                NIC_ID=$(az vm show -g "$RG_NAME" -n "$VM_NAME" \
                    --query "networkProfile.networkInterfaces[0].id" -o tsv)
                NSG_ID=$(az network nic show --ids "$NIC_ID" \
                    --query "networkSecurityGroup.id" -o tsv)
                if [ -n "$NSG_ID" ]; then
                    NSG_NAME=$(basename "$NSG_ID")
                    az network nsg rule delete -g "$RG_NAME" \
                        --nsg-name "$NSG_NAME" \
                        --name "Allow_WinRM_Runner_Only" \
                        -o none >/dev/null 2>&1 || true
                fi
                az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" \
                    --command-id RunPowerShellScript \
                    --scripts "Stop-Service WinRM -WarningAction SilentlyContinue
                               Set-Service WinRM -StartupType Disabled
                               Remove-ItemProperty \
                                   -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' \
                                   -Name 'LocalAccountTokenFilterPolicy' \
                                   -Force -ErrorAction SilentlyContinue
                               Disable-NetFirewallRule \
                                   -DisplayGroup 'Windows Remote Management' \
                                   -ErrorAction SilentlyContinue
                               Remove-LocalUser -Name '$AUDIT_USER' \
                                   -ErrorAction SilentlyContinue" \
                    -o none >/dev/null 2>&1 || true
            fi
        done
    fi

    wait
    echo -e "\n${GREEN}✅ [Phase 5] Tools removed. VM remains HARDENED. Audit user deleted.${NC}"
    echo -e "${GREEN}   Next month: Phase 0.2b SCP flow will re-install cleanly. ✅${NC}"
}

# ======================================================
# EXECUTION ENGINE
# ======================================================
execute_phases() {
    case $H_MODE in
        scan)
            run_phase_1
            ;;
        remediate)
            run_remediation
            ;;
        full)
            run_phase_1
            run_remediation
            run_phase_4
            ;;
    esac
}

# ======================================================
# HEADLESS (CI/CD) RUNNER
# ======================================================
if [ "$HEADLESS" == true ]; then
    echo -e "\n${CYAN}${BOLD}======================================================"
    echo -e "🚀 CI/CD WORKFLOW: MODE → $H_MODE | OS → $H_TARGET_OS"
    echo -e "======================================================${NC}"

    if [ "${H_PROFILE,,}" == "all" ]; then
        echo -e "\n${MAGENTA}======================================================${NC}"
        echo -e "${MAGENTA} 🔄 FULL FLEET AUDIT (L1 + L2 + ${ORG_PREFIX^^})...${NC}"
        echo -e "${MAGENTA}======================================================${NC}"

        prefetch_scap_packages || { echo -e "${RED}❌ Aborting — package prefetch failed.${NC}"; exit 1; }

        export CIS_LEVEL="Level 1"; export RUN_CIS=true; export RUN_ORG=false
        update_profile_vars
        echo -e "\n${CYAN}▶️ STEP 1/3: CIS LEVEL 1${NC}"
        execute_phases

        export CIS_LEVEL="Level 2"; export RUN_CIS=true; export RUN_ORG=false
        update_profile_vars
        echo -e "\n${CYAN}▶️ STEP 2/3: CIS LEVEL 2${NC}"
        execute_phases

        export RUN_CIS=false; export RUN_ORG=true
        update_profile_vars
        echo -e "\n${CYAN}▶️ STEP 3/3: ${ORG_PREFIX^^} BASELINE${NC}"
        execute_phases

    else
        prefetch_scap_packages || { echo -e "${RED}❌ Aborting — package prefetch failed.${NC}"; exit 1; }
        update_profile_vars
        execute_phases
    fi

    if [ "$H_CLEANUP" == "true" ]; then run_cleanup; fi

    chmod 755 ./*.json ./*.html 2>/dev/null || true
    echo -e "\n${GREEN}✅ CI/CD Pipeline complete. All reports generated.${NC}"
    exit 0
fi

# ======================================================
# INTERACTIVE MODE
# ======================================================
prefetch_scap_packages || { echo -e "${RED}❌ Aborting — package prefetch failed.${NC}"; exit 1; }

while true; do
    update_profile_vars
    echo -e "\n${CYAN}------------------------------------------------------${NC}"
    echo -e "1) ${BOLD}SCAN ONLY${NC}      (Phase 0.2b done ✅ — SCP install → scan)"
    echo -e "2) ${BOLD}REMEDIATE ONLY${NC} (Ansible / oscap --remediate)"
    echo -e "3) ${BOLD}FULL PIPELINE${NC}  (Scan → Remediate → Verify)"
    echo -e "4) ${BOLD}CLEANUP${NC}        (Remove tools + user; VM stays hardened)"
    echo -e "5) ${BOLD}EXIT${NC}"
    read -r -p "Choose an option [1-5]: " choice
    case $choice in
        1) run_phase_1 ;;
        2) run_remediation ;;
        3) run_phase_1; run_remediation; run_phase_4 ;;
        4) run_cleanup ;;
        5) exit 0 ;;
        *) echo -e "${RED}Invalid choice.${NC}" ;;
    esac
done
