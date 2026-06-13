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

# ------------------------------------------------------------------
# Windows cinc-auditor profile settings (single-file, CIS WS2022 v5)
#
# WIN_SERVER_ROLE : 'member_server' (default) or 'domain_controller'
#                  Controls DC-only / member-server-only rules inside
#                  the InSpec profile.  Set via env or .env file.
#
# Profile layout committed directly to the repo (no zip / extraction):
#   window-default-cis/
#   └── window-baseline/              ← WIN_CIS_BENCHMARK points here
#       ├── inspec.yml                ← profile metadata + input defaults
#       ├── Invoke-CISRemediation-Combined.ps1  ← self-contained PS1 (no helper)
#       └── controls/
#           └── cis_ws2022_v5_0_0_benchmark.rb  ← 433 controls, one file
# ------------------------------------------------------------------
WIN_SERVER_ROLE="${WIN_SERVER_ROLE:-member_server}"

# >>> PATCH 1: reboot Windows hosts after remediation so boot-time CIS settings
#     (VBS / Credential Guard / user-rights / per-user hive keys) actually take
#     effect before the verification scan. Set to "false" to skip.
WIN_REBOOT_AFTER_REMEDIATION="${WIN_REBOOT_AFTER_REMEDIATION:-true}"
# How long to wait (seconds) for a Windows host to be back on the network
# after `az vm restart`, before WinRM polling begins.
WIN_REBOOT_SETTLE_SEC="${WIN_REBOOT_SETTLE_SEC:-45}"

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

WIN_PS1_REMEDIATE="${WIN_CIS_BENCHMARK}/Invoke-CISRemediation-Combined.ps1"

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
# ======================================================
prefetch_scap_packages() {
    echo -e "\n${BOLD}${CYAN}📦 PHASE 0.2b: SCAP PACKAGE PRE-FETCH (runner has internet)${NC}"

    if [[ "${H_TARGET_OS,,}" == "windows" ]]; then
        echo -e "${GREEN}   ✅ Windows-only run — cinc-auditor runs from runner via WinRM. No SCAP packages needed. Skipping.${NC}"
        return 0
    fi

    local need_rhel=false need_alma=false need_rocky=false need_ubuntu=false

    case "${H_TARGET_OS,,}" in
        rhel)   need_rhel=true ;;
        alma)   need_alma=true ;;
        rocky)  need_rocky=true ;;
        ubuntu) need_ubuntu=true ;;
        all)    need_rhel=true; need_alma=true; need_rocky=true; need_ubuntu=true ;;
    esac

    $need_rhel   && mkdir -p "${SCAP_CACHE_DIR}"/{rhel9,rhel10}
    $need_rocky  && mkdir -p "${SCAP_CACHE_DIR}"/{rocky9,rocky10}
    $need_alma   && mkdir -p "${SCAP_CACHE_DIR}"/{alma9,alma10}
    $need_ubuntu && mkdir -p "${SCAP_CACHE_DIR}"/{ubuntu2204,ubuntu2404}

    if $need_rhel || $need_rocky; then
        if [ ! "$(ls -A "${SCAP_CACHE_DIR}/rhel9/"*.rpm 2>/dev/null)" ]; then
            echo -e "${CYAN}   Fetching RHEL9 packages...${NC}"
            docker run --rm \
                -v "${SCAP_CACHE_DIR}/rhel9:/output" \
                rockylinux:9 \
                bash -c "dnf install -y --downloadonly --downloaddir=/output \
                         openscap-scanner scap-security-guide 2>/dev/null" \
                && echo -e "${GREEN}   ✅ RHEL9 cached${NC}" \
                || echo -e "${RED}   ❌ RHEL9 fetch failed${NC}"
            $need_rocky && cp -f "${SCAP_CACHE_DIR}"/rhel9/*.rpm \
                "${SCAP_CACHE_DIR}/rocky9/" 2>/dev/null || true
        else
            echo -e "${GREEN}   ✅ RHEL9/Rocky9 cache valid — skipping download${NC}"
        fi
    fi

    if $need_rhel || $need_rocky; then
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
                $need_rocky && cp -f "${SCAP_CACHE_DIR}"/rhel10/*.rpm \
                    "${SCAP_CACHE_DIR}/rocky10/" 2>/dev/null || true
            else
                echo -e "${YELLOW}   ⚠️  rockylinux:10 image not yet on Docker Hub — marking as skipped${NC}"
                touch "${SCAP_CACHE_DIR}/rhel10/.skipped"
                touch "${SCAP_CACHE_DIR}/rocky10/.skipped"
            fi
        else
            echo -e "${GREEN}   ✅ RHEL10/Rocky10 cache valid — skipping download${NC}"
        fi
    fi

    if $need_alma; then
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
    fi

    if $need_alma; then
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
    fi

    if $need_ubuntu; then
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
    fi

    if $need_ubuntu; then
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
    fi

    local failed=0
    local check_dirs=()
    $need_rhel   && check_dirs+=(rhel9)
    $need_rocky  && check_dirs+=(rocky9)
    $need_alma   && check_dirs+=(alma9 alma10)
    $need_ubuntu && check_dirs+=(ubuntu2204 ubuntu2404)

    for d in "${check_dirs[@]}"; do
        if [ -f "${SCAP_CACHE_DIR}/${d}/.skipped" ]; then
            echo -e "${YELLOW}⚠️  [Phase 0.2b] ${d} skipped (image unavailable)${NC}"
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
# GUARD: validate_win_cis_profile
# ======================================================
validate_win_cis_profile() {
    local ok=true
    local rb_file="${WIN_CIS_BENCHMARK}/controls/cis_ws2022_v5_0_0_benchmark.rb"
    local inspec_yml="${WIN_CIS_BENCHMARK}/inspec.yml"
    local ps1_file="${WIN_PS1_REMEDIATE}"

    if [ ! -f "${inspec_yml}" ]; then
        echo -e "${RED}❌ [Profile Guard] ${inspec_yml} not found.${NC}"
        echo -e "${YELLOW}   Expected layout:${NC}"
        echo -e "${YELLOW}     ${WIN_CIS_BENCHMARK}/inspec.yml${NC}"
        echo -e "${YELLOW}     ${WIN_CIS_BENCHMARK}/controls/cis_ws2022_v5_0_0_benchmark.rb${NC}"
        echo -e "${YELLOW}     ${WIN_CIS_BENCHMARK}/Invoke-CISRemediation-Combined.ps1${NC}"
        ok=false
    fi

    if [ ! -f "${rb_file}" ]; then
        echo -e "${RED}❌ [Profile Guard] ${rb_file} not found.${NC}"
        echo -e "${YELLOW}   Commit cis_ws2022_v5_0_0_benchmark.rb to ${WIN_CIS_BENCHMARK}/controls/${NC}"
        ok=false
    fi

    if [ ! -f "${ps1_file}" ]; then
        echo -e "${YELLOW}⚠️  [Profile Guard] ${ps1_file} not found — PS1 remediation path unavailable.${NC}"
        echo -e "${YELLOW}   Commit Invoke-CISRemediation-Combined.ps1 to ${WIN_CIS_BENCHMARK}/${NC}"
        # Non-fatal: scan still works without the PS1
    fi

    if [ "$ok" == "false" ]; then
        return 1
    fi

    local ctrl_count
    ctrl_count=$(grep -c "^control " "${rb_file}" 2>/dev/null || echo 0)
    local l1_count l2_count
    l1_count=$(grep -c "tag level: \['L1'\]" "${rb_file}" 2>/dev/null || echo 0)
    l2_count=$(grep -c "tag level: \['L2'\]" "${rb_file}" 2>/dev/null || echo 0)
    echo -e "${GREEN}✅ [Profile Guard] CIS WS2022 v5 profile OK — ${ctrl_count} controls (L1: ${l1_count}, L2: ${l2_count}).${NC}"
    echo -e "${CYAN}   server_role=${WIN_SERVER_ROLE} | profile_level driven by CIS_LEVEL at scan time${NC}"
    return 0
}

# ======================================================
# HELPER: run_win_ps1_remediation
# ======================================================
run_win_ps1_remediation() {
    local ip="$1"
    local cis_level="${2:-Level 1}"
    local sections="${3:-}"

    if [ ! -f "$WIN_PS1_REMEDIATE" ]; then
        echo -e "${RED}❌ [WinPS1] ${WIN_PS1_REMEDIATE} not found.${NC}"
        echo -e "${YELLOW}   Commit Invoke-CISRemediation-Combined.ps1 to ${WIN_CIS_BENCHMARK}/${NC}"
        return 1
    fi

    local vm_name="${IP_TO_VM_NAME[$ip]:-}"
    if [ -z "$vm_name" ]; then
        echo -e "${RED}❌ [WinPS1] No VM name mapped for IP ${ip}${NC}"
        return 1
    fi

    # Build optional -Sections argument (e.g. -Sections @("1","2","17"))
    local sections_arg=""
    if [ -n "$sections" ]; then
        local quoted
        quoted=$(echo "$sections" | tr ' ' '\n' | awk '{printf "\"%s\",",$0}' | sed 's/,$//')
        sections_arg="-Sections @(${quoted})"
    fi

    echo -e "${CYAN}📤 [WinPS1/${ip}] Uploading + running Invoke-CISRemediation-Combined.ps1${NC}"
    echo -e "${CYAN}   role=${WIN_SERVER_ROLE} | sections=${sections:-all} | level_note=${cis_level} (scan-time only)${NC}"

    local encoded_main
    encoded_main=$(base64 -w0 < "$WIN_PS1_REMEDIATE")

    az vm run-command invoke \
        -g "$RG_NAME" -n "$vm_name" \
        --command-id RunPowerShellScript \
        --scripts "
\$ErrorActionPreference = 'Continue'
# Decode + write combined remediation script (self-contained, no helper needed)
[IO.File]::WriteAllBytes('C:\Windows\Temp\Invoke-CISRemediation-Combined.ps1',
    [Convert]::FromBase64String('${encoded_main}'))
# Execute — applies all sections unless -Sections filters them
& 'C:\Windows\Temp\Invoke-CISRemediation-Combined.ps1' \`
    -ServerRole '${WIN_SERVER_ROLE}' \`
    ${sections_arg}
# Cleanup
Remove-Item 'C:\Windows\Temp\Invoke-CISRemediation-Combined.ps1' \`
    -Force -ErrorAction SilentlyContinue
" -o tsv 2>/dev/null

    local rc=$?
    if [ $rc -eq 0 ]; then
        echo -e "${GREEN}✅ [WinPS1/${ip}] PS1 remediation complete (role=${WIN_SERVER_ROLE})${NC}"
    else
        echo -e "${RED}❌ [WinPS1/${ip}] az run-command failed (rc=${rc})${NC}"
    fi
    return $rc
}

# ======================================================
# TOOL GUARD: ensure_linux_scap_tools (OFFLINE via SCP)
# ======================================================
ensure_linux_scap_tools() {
    local user="$1"
    local ip="$2"
    local pkg_mgr="$3"

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

    local distro_id distro_ver cache_key
    read -r distro_id distro_ver <<< "$(ssh -n \
        -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        -o ConnectTimeout=10 \
        "${user}@${ip}" \
        "source /etc/os-release && echo \"\$ID \${VERSION_ID%%.*}\"" 2>/dev/null)"

    case "${distro_id}${distro_ver}" in
        rhel9)       cache_key="rhel9"      ;;
        rhel10)      cache_key="rhel10"     ;;
        almalinux9)  cache_key="alma9"      ;;
        almalinux10) cache_key="alma10"     ;;
        rocky9)      cache_key="rocky9"     ;;
        rocky10)     cache_key="rocky10"    ;;
        ubuntu22)    cache_key="ubuntu2204" ;;
        ubuntu24)    cache_key="ubuntu2404" ;;
        *9)
            echo -e "${YELLOW}⚠️  [Tool Guard] Unknown distro '${distro_id}${distro_ver}' — falling back to rhel9 cache${NC}"
            cache_key="rhel9"
            ;;
        *10)
            echo -e "${YELLOW}⚠️  [Tool Guard] Unknown distro '${distro_id}${distro_ver}' — falling back to alma10 cache${NC}"
            cache_key="alma10"
            ;;
        *)
            echo -e "${RED}❌ [Tool Guard] Unknown distro: '${distro_id}${distro_ver}' on ${ip} — cannot determine cache${NC}"
            return 1
            ;;
    esac

    local cache_dir="${SCAP_CACHE_DIR}/${cache_key}"

    if [ ! "$(ls -A "${cache_dir}" 2>/dev/null)" ]; then
        echo -e "${RED}❌ [Tool Guard] Cache empty: ${cache_dir}${NC}"
        echo -e "${YELLOW}   Re-run Phase 0.2b (prefetch_scap_packages) on the runner first.${NC}"
        return 1
    fi

    echo -e "${CYAN}📦 [Tool Guard] Pushing ${cache_key} packages → ${ip} (SCP/port 22)${NC}"

    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        "${user}@${ip}" \
        "sudo mkdir -p /tmp/scap_offline && sudo chmod 777 /tmp/scap_offline" 2>/dev/null

    scp -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        -o ConnectTimeout=10 \
        "${cache_dir}"/* "${user}@${ip}:/tmp/scap_offline/"

    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ [Tool Guard] SCP push failed to ${ip}${NC}"
        return 1
    fi

    local install_cmd
    if [ "$pkg_mgr" == "apt" ]; then
        install_cmd="sudo dpkg -i /tmp/scap_offline/*.deb 2>/dev/null || true; \
                     sudo apt-get install -f -y 2>/dev/null || true"
    else
        install_cmd="sudo dnf install -y --disablerepo='*' --allowerasing \
                         /tmp/scap_offline/*.rpm 2>/dev/null || \
                     sudo rpm -Uvh --nodeps --replacepkgs \
                         /tmp/scap_offline/*.rpm 2>/dev/null || true"
    fi

    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        "${user}@${ip}" "
        set +e
        ${install_cmd}
        sudo rm -rf /tmp/scap_offline 2>/dev/null || true

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
# >>> PATCH 2: az vm run-command fallback + default-to-2022 instead of "unknown"
#     Old behaviour relied solely on Ansible (ansible.windows.win_shell). On a
#     CI runner without the ansible.windows collection or without WinRM the
#     query returned empty -> "unknown" -> the host was SKIPPED entirely.
#     Now: try Ansible, then fall back to `az vm run-command` (ARM channel,
#     always works), and if both fail assume WS2022 rather than skipping.
# ======================================================
detect_windows_version() {
    local ip="$1"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"
    local caption=""

    # Fast path: Ansible (only if ansible.windows + WinRM connectivity present)
    caption=$(ansible -i inventory.ini "${ip}" -m ansible.windows.win_shell \
        -a '(Get-CimInstance Win32_OperatingSystem).Caption' \
        2>/dev/null | grep -oE 'Windows (Server (2019|2022|2025)|1[01])' | head -1)

    # Fallback: az vm run-command — no Ansible/WinRM dependency
    if [ -z "$caption" ] && [ -n "$vm_name" ]; then
        caption=$(az vm run-command invoke \
            -g "$RG_NAME" -n "$vm_name" \
            --command-id RunPowerShellScript \
            --scripts '(Get-CimInstance Win32_OperatingSystem).Caption' \
            --query 'value[0].message' -o tsv 2>/dev/null \
            | grep -oE 'Windows (Server (2019|2022|2025)|1[01])' | head -1)
    fi

    case "$caption" in
        *"Server 2019"*) echo "2019" ;;
        *"Server 2022"*) echo "2022" ;;
        *"Server 2025"*) echo "2025" ;;
        *"Windows 10"*)  echo "10"   ;;
        *"Windows 11"*)  echo "11"   ;;
        *)
            echo -e "${YELLOW}⚠️  [Win] Version detection failed for ${ip} — assuming WS2022${NC}" >&2
            echo "2022"
            ;;
    esac
}

# ======================================================
# HELPER: ensure_winrm_powershell
# >>> PATCH 3: repair the WSMan PowerShell provider host.
#     Fixes "WSMAN ERROR CODE: 2 / The WSMan service could not launch a host
#     process to process the given request" that cinc-auditor hits when opening
#     a PowerShell shell. Common causes after a hardening pass:
#       * the Microsoft.PowerShell PSSession config got unregistered
#       * winrs shell limits (MaxShellsPerUser / MaxMemoryPerShellMB) were zeroed
#       * CIS WinRM Service policy keys (18.10.90.x) disabled Basic/Unencrypted,
#         locking out an HTTP/Basic runner
#       * RunAsPPL (18.9.27.2) / Credential Guard disrupted remoting
#     Runs over the Azure ARM channel (az vm run-command), NOT WinRM, so it
#     works even when WinRM itself is currently broken.
#
#     NOTE: step (4) re-opens Basic/Unencrypted so an HTTP/Basic runner can
#     reconnect after hardening. That makes 18.10.90.x show NON-compliant in the
#     scan that follows. To keep those controls hardened, scan over HTTPS with a
#     cert + Negotiate/Kerberos and set WINRM_REOPEN_BASIC=false.
# ======================================================
WINRM_REOPEN_BASIC="${WINRM_REOPEN_BASIC:-true}"

ensure_winrm_powershell() {
    local ip="$1"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"
    if [ -z "$vm_name" ]; then
        echo -e "${YELLOW}⚠️  [WinRM-Heal] No VM name mapped for ${ip} — skipping repair${NC}"
        return 1
    fi

    local reopen_block=""
    if [ "${WINRM_REOPEN_BASIC}" == "true" ]; then
        reopen_block="
\$svc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
if (-not (Test-Path \$svc)) { New-Item -Path \$svc -Force | Out-Null }
New-ItemProperty -Path \$svc -Name 'AllowBasic'              -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path \$svc -Name 'AllowUnencryptedTraffic' -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 1 -PropertyType DWord -Force | Out-Null
winrm set winrm/config/service/auth '@{Basic=\"true\"}'          2>&1 | Out-Null
winrm set winrm/config/service      '@{AllowUnencrypted=\"true\"}' 2>&1 | Out-Null
"
    fi

    echo -e "${CYAN}🩺 [WinRM-Heal/${ip}] Re-registering PowerShell provider + restoring shell limits...${NC}"
    az vm run-command invoke -g "$RG_NAME" -n "$vm_name" \
        --command-id RunPowerShellScript \
        --scripts "
\$ErrorActionPreference = 'Continue'
Set-Service WinRM -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service WinRM -ErrorAction SilentlyContinue
winrm quickconfig -quiet -force 2>&1 | Out-Null
try { Register-PSSessionConfiguration -Name 'Microsoft.PowerShell' -Force -ErrorAction Stop | Out-Null }
catch { Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction SilentlyContinue | Out-Null }
# restore shell limits that a partial hardening can zero out
winrm set winrm/config/winrs '@{MaxShellsPerUser=\"30\"}'    2>&1 | Out-Null
winrm set winrm/config/winrs '@{MaxConcurrentUsers=\"10\"}'  2>&1 | Out-Null
winrm set winrm/config/winrs '@{MaxMemoryPerShellMB=\"1024\"}' 2>&1 | Out-Null
${reopen_block}
Set-NetFirewallRule -DisplayGroup 'Windows Remote Management' -Enabled True -Profile Any -ErrorAction SilentlyContinue
Restart-Service WinRM -Force -ErrorAction SilentlyContinue
Write-Output 'WinRM PowerShell provider re-initialized'
" -o none >/dev/null 2>&1

    local rc=$?
    if [ $rc -eq 0 ]; then
        echo -e "${GREEN}✅ [WinRM-Heal/${ip}] provider re-registered${NC}"
    else
        echo -e "${YELLOW}⚠️  [WinRM-Heal/${ip}] az run-command rc=${rc} (continuing)${NC}"
    fi
    sleep 5
    return 0
}

# ======================================================
# HELPER: reboot_windows_host (apply boot-time CIS settings)
# >>> PATCH 4: VBS / Credential Guard / user-rights / per-user keys only take
#     effect after a reboot. Restart + wait for WinRM + repair the provider.
# ======================================================
reboot_windows_host() {
    local ip="$1"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"
    [ -z "$vm_name" ] && { echo -e "${YELLOW}⚠️  [Reboot] No VM name for ${ip}${NC}"; return 0; }

    echo -e "${CYAN}🔁 [Reboot/${ip}] Restarting ${vm_name} to apply boot-time CIS settings...${NC}"
    az vm restart -g "$RG_NAME" -n "$vm_name" -o none >/dev/null 2>&1 || true
    sleep "${WIN_REBOOT_SETTLE_SEC}"
    wait_for_winrm "$ip" || echo -e "${YELLOW}⚠️  [Reboot/${ip}] WinRM not back within timeout${NC}"
    ensure_winrm_powershell "$ip"
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
        echo -e "${YELLOW}   Falling back to PS1 remediation...${NC}"
        run_win_ps1_remediation "$ip" "$cis_level"
        return $?
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
        echo -e "${RED}❌ [Win/${ver}] Ansible failed (rc=${rc}) — falling back to PS1 remediation${NC}"
        run_win_ps1_remediation "$ip" "$cis_level"
        rc=$?
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

    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
        -o ConnectTimeout=10 \
        "${user}@${ip}" "sudo chmod 644 ${remote} 2>/dev/null" >/dev/null 2>&1

    scp -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ControlMaster=no -o ControlPath=none \
        -o ConnectTimeout=10 \
        "${user}@${ip}:${remote}" "${local_path}" >/dev/null 2>&1
    if [ $? -eq 0 ] && [ -s "${local_path}" ]; then
        return 0
    fi

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

if [ "$H_TARGET_IP" != "all" ] && [ -n "$H_TARGET_IP" ]; then
    echo -e "${MAGENTA}🎯 MATRIX SHARDING: Isolating to node $H_TARGET_IP${NC}"
    UBUNTU_MACHINES=(); RHEL_MACHINES=(); ROCKY_MACHINES=()
    ALMA_MACHINES=();   WINDOWS_MACHINES=()
    # >>> PATCH 5: also map IP_TO_VM_NAME when sharding to a single node, so the
    #     az-based fallbacks (detect_windows_version / ensure_winrm_powershell /
    #     reboot_windows_host / run_win_ps1_remediation) have a VM name to use.
    SHARD_VM_NAME="${IP_TO_VM_NAME[$H_TARGET_IP]:-}"
    if [ -z "$SHARD_VM_NAME" ]; then
        SHARD_VM_NAME=$(az vm list -d -g "$RG_NAME" \
            --query "[?publicIps=='${H_TARGET_IP}'].name | [0]" -o tsv 2>/dev/null)
        [ -n "$SHARD_VM_NAME" ] && IP_TO_VM_NAME["$H_TARGET_IP"]="$SHARD_VM_NAME"
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
            # >>> PATCH 6: added winrm quickconfig + Register-PSSessionConfiguration
            #     + winrs shell-limit restore so the WSMan PowerShell provider host
            #     can actually launch (fixes WSMAN ERROR CODE: 2 in cinc-auditor).
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
                           winrm quickconfig -quiet -force 2>&1 | Out-Null
                           try { Register-PSSessionConfiguration -Name 'Microsoft.PowerShell' -Force -ErrorAction Stop | Out-Null } catch {}
                           winrm set winrm/config/winrs '@{MaxShellsPerUser=\"30\"}' 2>&1 | Out-Null
                           winrm set winrm/config/winrs '@{MaxMemoryPerShellMB=\"1024\"}' 2>&1 | Out-Null
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

    # ================================================================
    # WINDOWS — cinc-auditor (CIS WS2022 v5.0.0, single-file profile)
    # ================================================================
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then

            validate_win_cis_profile || {
                echo -e "${RED}❌ [Phase1/Win] Profile validation failed — skipping all Windows hosts.${NC}"
                return 1
            }

            for IP in "${WINDOWS_MACHINES[@]}"; do
                (
                    wait_for_winrm "$IP" || {
                        echo -e "${RED}❌ [Phase1/Win] WinRM unreachable: $IP — skipping${NC}"
                        exit 1
                    }
                    # >>> PATCH 7: repair the PowerShell provider before scanning so
                    #     cinc-auditor can open a shell (avoids WSMAN ERROR CODE: 2).
                    ensure_winrm_powershell "$IP"

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Win/CIS L${WIN_INSPEC_LVL}] Scanning $IP${NC}"
                        echo -e "${CYAN}   profile: ${WIN_CIS_BENCHMARK} | role: ${WIN_SERVER_ROLE} | level: ${WIN_INSPEC_LVL}${NC}"

                        cinc-auditor exec "${WIN_CIS_BENCHMARK}" \
                            -t "winrm://${IP}" \
                            --user="${AUDIT_USER}" \
                            --password="${AUDIT_PASS}" \
                            --input "server_role=${WIN_SERVER_ROLE}" \
                            --input "profile_level=${WIN_INSPEC_LVL}" \
                            --reporter "json:heimdall_before_CIS_L${WIN_INSPEC_LVL}_WIN_${IP}.json"
                        rc=$?

                        case $rc in
                            0|100|101)
                                echo -e "${GREEN}✅ [Phase1/Win/CIS L${WIN_INSPEC_LVL}] $IP scan complete (rc=$rc)${NC}" ;;
                            *)
                                echo -e "${RED}❌ [Phase1/Win/CIS L${WIN_INSPEC_LVL}] cinc-auditor failed on $IP (rc=$rc)${NC}" ;;
                        esac
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Win/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        cinc-auditor exec "${WIN_CUSTOM_BENCHMARK}" \
                            -t "winrm://${IP}" \
                            --user="${AUDIT_USER}" \
                            --password="${AUDIT_PASS}" \
                            --reporter "json:heimdall_before_${ORG_PREFIX^^}_WIN_${IP}.json"
                        rc=$?
                        case $rc in
                            0|100|101)
                                echo -e "${GREEN}✅ [Phase1/Win/${ORG_PREFIX^^}] $IP scan complete (rc=$rc)${NC}" ;;
                            *)
                                echo -e "${RED}❌ [Phase1/Win/${ORG_PREFIX^^}] cinc-auditor failed on $IP (rc=$rc)${NC}" ;;
                        esac
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
            ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK --limit rhel_nodes
        fi
    fi

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
                ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK --limit rocky_nodes
            fi
        fi
    fi

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
                ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK --limit alma_nodes
            fi
        fi
    fi

    # -------------------- WINDOWS --------------------
    # Primary path: Ansible (cis_remediate_2022.yml / _2025.yml / etc.)
    # Fallback:     run_win_ps1_remediation() → Invoke-CISRemediation-Combined.ps1
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
                ansible-playbook -i inventory.ini "$WIN_CUSTOM_PLAYBOOK" \
                    --limit windows_nodes
            fi

            # >>> PATCH 8: reboot Windows hosts after CIS remediation so boot-time
            #     settings (VBS, Credential Guard, user-rights, per-user keys)
            #     take effect before Phase 4 verification. Skipped for ORG-only
            #     runs and when WIN_REBOOT_AFTER_REMEDIATION=false.
            if [ "$RUN_CIS" == true ] && [ "${WIN_REBOOT_AFTER_REMEDIATION}" == "true" ]; then
                echo -e "${CYAN}🔁 [Remediation/Win] Rebooting hardened Windows hosts...${NC}"
                for IP in "${WINDOWS_MACHINES[@]}"; do
                    reboot_windows_host "$IP" &
                done
                wait
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

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
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
                        ssh $SCAN_SSH_OPTS ${UBUNTU_USER}@${IP} \
                            "sudo oscap xccdf eval --profile $UBUNTU_CIS_PROFILE --report ${REMOTE} $UBUNTU_CIS_XCCDF"
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$UBUNTU_USER" "$IP" "$REMOTE" "$LOCAL" "Ubuntu/CIS" || \
                            echo -e "${RED}❌ [Phase4/Ubuntu/CIS] oscap failed on $IP (rc=$rc)${NC}"
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html"
                        ssh $SCAN_SSH_OPTS ${UBUNTU_USER}@${IP} \
                            "sudo oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE --report ${REMOTE} /tmp/$(basename $UBUNTU_CUSTOM_XCCDF)"
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$UBUNTU_USER" "$IP" "$REMOTE" "$LOCAL" "Ubuntu/${ORG_PREFIX^^}" || \
                            echo -e "${RED}❌ [Phase4/Ubuntu/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                    fi
                ) &
            done
            wait
        fi
    fi

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rhel" ]]; then
        if [ ${#RHEL_MACHINES[@]} -gt 0 ]; then
            for IP in "${RHEL_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$GHOST_USER" || { echo -e "${RED}❌ [Phase4/RHEL] SSH unreachable: $IP${NC}"; exit 1; }
                    ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || { echo -e "${RED}❌ [Phase4/RHEL] Tools missing on $IP${NC}"; exit 1; }

                    if [ "$RUN_CIS" == true ]; then
                        REMOTE="/tmp/report_after_CIS_L${OS_LVL}_RHEL_${IP}.html"
                        LOCAL="./report_after_CIS_L${OS_LVL}_RHEL_${IP}.html"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                             sudo /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE --report ${REMOTE} \"\$TARGET_XML\""
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "RHEL/CIS" || \
                            echo -e "${RED}❌ [Phase4/RHEL/CIS] oscap failed on $IP (rc=$rc)${NC}"
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_RHEL_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_RHEL_${IP}.html"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE --report ${REMOTE} /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "RHEL/${ORG_PREFIX^^}" || \
                            echo -e "${RED}❌ [Phase4/RHEL/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                    fi
                ) &
            done
            wait
        fi
    fi

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rocky" ]]; then
        if [ ${#ROCKY_MACHINES[@]} -gt 0 ]; then
            for IP in "${ROCKY_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$GHOST_USER" || { echo -e "${RED}❌ [Phase4/Rocky] SSH unreachable: $IP${NC}"; exit 1; }
                    ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || { echo -e "${RED}❌ [Phase4/Rocky] Tools missing on $IP${NC}"; exit 1; }

                    if [ "$RUN_CIS" == true ]; then
                        REMOTE="/tmp/report_after_CIS_L${OS_LVL}_ROCKY_${IP}.html"
                        LOCAL="./report_after_CIS_L${OS_LVL}_ROCKY_${IP}.html"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} "
                            ROCKY_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-rl\${ROCKY_VER}-ds.xml\"
                            [ ! -f \"\$TARGET_XML\" ] && TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            sudo /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE --report ${REMOTE} \"\$TARGET_XML\"
                        "
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Rocky/CIS" || \
                            echo -e "${RED}❌ [Phase4/Rocky/CIS] oscap failed on $IP (rc=$rc)${NC}"
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE --report ${REMOTE} /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Rocky/${ORG_PREFIX^^}" || \
                            echo -e "${RED}❌ [Phase4/Rocky/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                    fi
                ) &
            done
            wait
        fi
    fi

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "alma" ]]; then
        if [ ${#ALMA_MACHINES[@]} -gt 0 ]; then
            for IP in "${ALMA_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$GHOST_USER" || { echo -e "${RED}❌ [Phase4/Alma] SSH unreachable: $IP${NC}"; exit 1; }
                    ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || { echo -e "${RED}❌ [Phase4/Alma] Tools missing on $IP${NC}"; exit 1; }

                    if [ "$RUN_CIS" == true ]; then
                        REMOTE="/tmp/report_after_CIS_L${OS_LVL}_ALMA_${IP}.html"
                        LOCAL="./report_after_CIS_L${OS_LVL}_ALMA_${IP}.html"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} "
                            ALMA_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-almalinux\${ALMA_VER}-ds.xml\"
                            [ ! -f \"\$TARGET_XML\" ] && TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            if ! grep -q \"$RHEL_CIS_PROFILE\" \"\$TARGET_XML\"; then ALMA_PROF=\"xccdf_org.ssgproject.content_profile_cis\"; else ALMA_PROF=\"$RHEL_CIS_PROFILE\"; fi
                            sudo /usr/bin/oscap xccdf eval --profile \$ALMA_PROF --report ${REMOTE} \"\$TARGET_XML\"
                        "
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Alma/CIS" || \
                            echo -e "${RED}❌ [Phase4/Alma/CIS] oscap failed on $IP (rc=$rc)${NC}"
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_ALMA_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_ALMA_${IP}.html"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE --report ${REMOTE} /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Alma/${ORG_PREFIX^^}" || \
                            echo -e "${RED}❌ [Phase4/Alma/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                    fi
                ) &
            done
            wait
        fi
    fi

    # ================================================================
    # WINDOWS VERIFY — cinc-auditor (CIS WS2022 v5.0.0, single-file)
    # ================================================================
    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then

            validate_win_cis_profile || {
                echo -e "${RED}❌ [Phase4/Win] Profile validation failed — skipping all Windows hosts.${NC}"
                return 1
            }

            for IP in "${WINDOWS_MACHINES[@]}"; do
                (
                    wait_for_winrm "$IP" || {
                        echo -e "${RED}❌ [Phase4/Win] WinRM unreachable: $IP — skipping${NC}"
                        exit 1
                    }
                    # >>> PATCH 9: remediation/hardening can disable the WSMan
                    #     PowerShell provider or lock out HTTP/Basic. Repair it
                    #     before the verify scan so cinc-auditor can connect
                    #     (fixes WSMAN ERROR CODE: 2 on the post-remediation scan).
                    ensure_winrm_powershell "$IP"

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Win/CIS L${WIN_INSPEC_LVL}] Verifying $IP...${NC}"
                        echo -e "${CYAN}   profile: ${WIN_CIS_BENCHMARK} | role: ${WIN_SERVER_ROLE} | level: ${WIN_INSPEC_LVL}${NC}"

                        cinc-auditor exec "${WIN_CIS_BENCHMARK}" \
                            -t "winrm://${IP}" \
                            --user="${AUDIT_USER}" \
                            --password="${AUDIT_PASS}" \
                            --input "server_role=${WIN_SERVER_ROLE}" \
                            --input "profile_level=${WIN_INSPEC_LVL}" \
                            --reporter "json:heimdall_after_CIS_L${WIN_INSPEC_LVL}_WIN_${IP}.json"
                        rc=$?

                        case $rc in
                            0|100|101)
                                echo -e "${GREEN}✅ [Phase4/Win/CIS L${WIN_INSPEC_LVL}] $IP verify complete (rc=$rc)${NC}" ;;
                            *)
                                echo -e "${RED}❌ [Phase4/Win/CIS L${WIN_INSPEC_LVL}] cinc-auditor failed on $IP (rc=$rc)${NC}" ;;
                        esac
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Win/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        cinc-auditor exec "${WIN_CUSTOM_BENCHMARK}" \
                            -t "winrm://${IP}" \
                            --user="${AUDIT_USER}" \
                            --password="${AUDIT_PASS}" \
                            --reporter "json:heimdall_after_${ORG_PREFIX^^}_WIN_${IP}.json"
                        rc=$?
                        case $rc in
                            0|100|101)
                                echo -e "${GREEN}✅ [Phase4/Win/${ORG_PREFIX^^}] $IP verify complete (rc=$rc)${NC}" ;;
                            *)
                                echo -e "${RED}❌ [Phase4/Win/${ORG_PREFIX^^}] cinc-auditor failed on $IP (rc=$rc)${NC}" ;;
                        esac
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
    echo -e "\n${BOLD}${RED}🧹 PHASE 5: POST-AUDIT CLEANUP${NC}"
    echo -e "${CYAN}   VM stays HARDENED — only SCAP tools + audit user are removed.${NC}"

    local remove_rpm="sudo rpm -e --nodeps \
        openscap openscap-scanner scap-security-guide 2>/dev/null || true; \
        sudo rm -rf /tmp/scap_offline /tmp/report_*.html"

    local remove_deb="sudo dpkg -r openscap-scanner ssg-base 2>/dev/null || true; \
        sudo rm -rf /tmp/scap_offline /tmp/report_*.html"

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
        for IP in "${UBUNTU_MACHINES[@]}"; do
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

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rhel" ]]; then
        for IP in "${RHEL_MACHINES[@]}"; do
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

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rocky" ]]; then
        for IP in "${ROCKY_MACHINES[@]}"; do
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

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "alma" ]]; then
        for IP in "${ALMA_MACHINES[@]}"; do
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

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
        for IP in "${WINDOWS_MACHINES[@]}"; do
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
                # NOTE: cleanup restores LocalAccountTokenFilterPolicy to the CIS
                # value by removing it. If you need 18.4.1 to PASS in the final
                # scan, run cleanup BEFORE that scan (or scan with a domain
                # account); the runner's WinRM access depends on this key = 1.
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
    echo -e "2) ${BOLD}REMEDIATE ONLY${NC} (Ansible / Invoke-CISRemediation-Combined.ps1)"
    echo -e "3) ${BOLD}FULL PIPELINE${NC}  (Scan → Remediate → Verify)"
    echo -e "4) ${BOLD}CLEANUP${NC}        (Remove tools + user; VM stays hardened)"
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
