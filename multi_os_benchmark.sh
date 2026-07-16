#!/bin/bash
set +H

# ======================================================
# CONFIGURATION - DYNAMIC ENVIRONMENT VARIABLES
# ======================================================
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Resolve script directory ONCE at startup — used for absolute path refs
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ORG_NAME="${ORG_NAME:-Custom}"
ORG_PREFIX="${ORG_PREFIX:-custom}"
CUSTOM_XCCDF_PROFILE="${CUSTOM_XCCDF_PROFILE:-xccdf_com.org_profile_lsb}"
RG_NAME="${AZURE_RG_NAME:-DEFAULT_RG}"


CLOUD_PROVIDER="${CLOUD_PROVIDER:-azure}"

HW_REGION="${HW_REGION:-ap-southeast-1}"
HW_PROJECT_ID="${HW_PROJECT_ID:-}"
HW_ECS_TAG_KEY="${HW_ECS_TAG_KEY:-Environment}"
HW_ECS_TAG_VAL="${HW_ECS_TAG_VAL:-}"
HW_VPC_ID="${HW_VPC_ID:-}"
HW_ECS_ENDPOINT="${HW_ECS_ENDPOINT:-https://ecs.${HW_REGION}.alphaedge.tmone.com.my}"
HW_VPC_ENDPOINT="${HW_VPC_ENDPOINT:-https://vpc.${HW_REGION}.alphaedge.tmone.com.my}"

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
WIN_CUSTOM_DIR="${SCRIPT_DIR}/window-custom"
WIN_CUSTOM_BENCHMARK="${WIN_CUSTOM_DIR}/${ORG_PREFIX}_baseline.rb"
WIN_CUSTOM_PLAYBOOK="${WIN_CUSTOM_DIR}/${ORG_PREFIX}_remediate.yml"

WIN_CIS_DIR="${SCRIPT_DIR}/window-default-cis"
WIN_CIS_BENCHMARK="${WIN_CIS_DIR}/window-baseline"
WIN_PS1_REMEDIATE="${WIN_CIS_BENCHMARK}/Invoke-CISRemediation-Combined.ps1"

WIN_REBOOT_SETTLE_SEC="${WIN_REBOOT_SETTLE_SEC:-45}"
WIN_REBOOT_HEALTH_WAIT_SEC="${WIN_REBOOT_HEALTH_WAIT_SEC:-360}"
WIN_SCAN_TIMEOUT_SEC="${WIN_SCAN_TIMEOUT_SEC:-1200}"
WIN_REBOOT_AFTER_REMEDIATION="${WIN_REBOOT_AFTER_REMEDIATION:-true}"
WIN_AGENT_PROBE_SEC="${WIN_AGENT_PROBE_SEC:-180}"

export INSPEC_SSH_CONFIG_NO_SECURE=true
BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; MAGENTA='\033[0;35m'; NC='\033[0m'
clear

# ======================================================
# REMEDIATION CONSTANTS
# ======================================================
REMEDIATION_TIMEOUT_SEC=1800

REMEDIATION_SSH_OPTS="-n -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o ControlMaster=no -o ControlPath=none \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
    -o ConnectTimeout=10"

# ======================================================
# SCAP OFFLINE CACHE
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
        rm -rf "${SCAP_CACHE_DIR}/ubuntu2204/"* && mkdir -p "${SCAP_CACHE_DIR}/ubuntu2204/"
        echo -e "${CYAN}   Fetching Ubuntu 22.04 packages via Docker...${NC}"
        docker run --rm \
            -v "${SCAP_CACHE_DIR}/ubuntu2204:/output" \
            ubuntu:22.04 \
            bash -c "
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq 2>/dev/null
                echo 'deb http://archive.ubuntu.com/ubuntu jammy universe' >> /etc/apt/sources.list
                echo 'deb http://archive.ubuntu.com/ubuntu jammy-updates universe' >> /etc/apt/sources.list
                apt-get update -qq 2>/dev/null
                apt-get install --download-only -y openscap-scanner 2>/dev/null || true
                apt-get install --download-only -y ssg-base 2>/dev/null || true
                apt-get install --download-only -y 'libopenscap*' 2>/dev/null || true
                apt-get install --download-only -y 'libopendbx*' 2>/dev/null || true
                cp /var/cache/apt/archives/*.deb /output/ 2>/dev/null || true
            " \
            && echo -e "${GREEN}   ✅ Ubuntu2204 cached${NC}" \
            || echo -e "${RED}   ❌ Ubuntu2204 Docker step failed${NC}"
    fi

    if $need_ubuntu; then
        rm -rf "${SCAP_CACHE_DIR}/ubuntu2404/"* && mkdir -p "${SCAP_CACHE_DIR}/ubuntu2404/"
        echo -e "${CYAN}   Fetching Ubuntu 24.04 packages via Docker...${NC}"
        docker run --rm \
            -v "${SCAP_CACHE_DIR}/ubuntu2404:/output" \
            ubuntu:24.04 \
            bash -c "
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq 2>/dev/null
                apt-get install --download-only -y openscap-scanner ssg-base 2>/dev/null || true
                apt-get install --download-only -y 'libopenscap*' 'libopendbx*' 2>/dev/null || true
                cp /var/cache/apt/archives/*.deb /output/ 2>/dev/null || true
            " \
            && echo -e "${GREEN}   ✅ Ubuntu2404 cached${NC}" \
            || echo -e "${RED}   ❌ Ubuntu2404 Docker step failed${NC}"
    fi

    if $need_ubuntu; then
        echo -e "${CYAN}   Fetching SCAP datastreams via ssg-debderived (Docker install)...${NC}"
        local ds_tmp
        ds_tmp=$(mktemp -d /tmp/ssg_ds_XXXXXX)
        chmod 777 "${ds_tmp}"

        docker run --rm \
            -v "${ds_tmp}:/output" \
            ubuntu:24.04 \
            bash -c "
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq 2>/dev/null
                apt-get install -y --no-install-recommends \
                    ssg-debderived ssg-base 2>/dev/null || true
                find /usr/share/xml/scap/ssg/content/ \
                    -name 'ssg-ubuntu*-ds.xml' \
                    -exec cp -v {} /output/ \; 2>/dev/null || true
            " \
            && echo -e "${GREEN}   ✅ ssg-debderived installed in Docker${NC}" \
            || echo -e "${YELLOW}   ⚠️  Docker step exited non-zero (checking output anyway)${NC}"

        for _ds_file in "${ds_tmp}"/ssg-ubuntu*-ds.xml; do
            [ -f "$_ds_file" ] || continue
            _fname=$(basename "$_ds_file")
            if [[ "$_fname" == *"2204"* ]]; then
                cp -f "$_ds_file" "${SCAP_CACHE_DIR}/ubuntu2204/"
                echo -e "${GREEN}   ✅ ${_fname} → ubuntu2204 cache${NC}"
            elif [[ "$_fname" == *"2404"* ]]; then
                cp -f "$_ds_file" "${SCAP_CACHE_DIR}/ubuntu2404/"
                echo -e "${GREEN}   ✅ ${_fname} → ubuntu2404 cache${NC}"
            fi
        done

        docker run --rm \
            -v "${ds_tmp}:/output" \
            ubuntu:24.04 \
            bash -c "
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq 2>/dev/null
                apt-get install --download-only -y --no-install-recommends \
                    ssg-debderived ssg-base 2>/dev/null || true
                cp /var/cache/apt/archives/ssg-debderived*.deb /output/ 2>/dev/null || true
            " 2>/dev/null || true

        local _ssg_deb
        _ssg_deb=$(find "${ds_tmp}" -name 'ssg-debderived*.deb' | head -1)
        if [ -n "$_ssg_deb" ]; then
            cp -f "$_ssg_deb" "${SCAP_CACHE_DIR}/ubuntu2204/" 2>/dev/null || true
            cp -f "$_ssg_deb" "${SCAP_CACHE_DIR}/ubuntu2404/" 2>/dev/null || true
        fi

        rm -rf "${ds_tmp}"

        if ! ls "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" >/dev/null 2>&1; then
            echo -e "${CYAN}   Fetching ssg-ubuntu2404-ds.xml from upstream ComplianceAsCode release...${NC}"
            SSG_VER="${SSG_VER:-$(curl -sL https://api.github.com/repos/ComplianceAsCode/content/releases/latest \
                | python3 -c "import json,sys; print(json.load(sys.stdin).get('tag_name','').lstrip('v'))" 2>/dev/null)}"
            if [ -n "$SSG_VER" ]; then
                curl -sL -o /tmp/scap-security-guide.tar.bz2 \
                    "https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VER}/scap-security-guide-${SSG_VER}.tar.bz2"
                if [ -s /tmp/scap-security-guide.tar.bz2 ]; then
                    tar -xjf /tmp/scap-security-guide.tar.bz2 -C /tmp 2>/dev/null
                    found=$(find /tmp -name 'ssg-ubuntu2404-ds.xml' 2>/dev/null | head -1)
                    if [ -n "$found" ]; then
                        cp -f "$found" "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml"
                        echo -e "${GREEN}   ✅ Real ssg-ubuntu2404-ds.xml fetched from upstream release v${SSG_VER}${NC}"
                    fi
                fi
            fi
            rm -f /tmp/scap-security-guide.tar.bz2
            rm -rf /tmp/scap-security-guide-*
        fi

        # ══ INSERT THE DOCKER SOURCE-BUILD BLOCK HERE ══
        if ! ls "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" >/dev/null 2>&1; then
            echo -e "${YELLOW}   ⚠️  Pre-built release lacks ubuntu2404 — building from source via Docker (this takes a few minutes)...${NC}"
            docker run --rm -v "${SCAP_CACHE_DIR}/ubuntu2404:/output" ubuntu:24.04 bash -c "
                set -e
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq
                apt-get install -y --no-install-recommends git cmake make python3 python3-pip \
                    libxml2-utils xsltproc python3-jinja2 python3-yaml ca-certificates \
                    openscap-scanner libopenscap-dev
                git clone --depth 1 --branch v0.1.81 https://github.com/ComplianceAsCode/content.git /tmp/content
                mkdir -p /tmp/content/build
                cd /tmp/content/build
                cmake ..
                make -j\$(nproc) ubuntu2404-content
                FOUND=\$(find /tmp/content/build -name 'ssg-ubuntu2404-ds.xml' | head -1)
                if [ -z \"\$FOUND\" ]; then
                    echo '[FATAL] Build completed but ssg-ubuntu2404-ds.xml was not produced'
                    exit 1
                fi
                cp -v \"\$FOUND\" /output/
                if ! oscap info /output/ssg-ubuntu2404-ds.xml 2>/dev/null | grep -q 'xccdf_org.ssgproject.content_profile_cis_level1_server'; then
                echo '[FATAL] Built datastream is missing cis_level1_server profile — likely built from unstable/dev content'
                exit 1
            fi
            "
            _rc=$?
            if [ $_rc -eq 0 ] && ls "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" >/dev/null 2>&1; then
                echo -e "${GREEN}   ✅ Built ssg-ubuntu2404-ds.xml from source${NC}"
            else
                echo -e "${RED}   ❌ Source build failed (docker rc=${_rc}) — see output above for the real error${NC}"
                rm -f "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml"
            fi
        fi
        # ══ END INSERTED BLOCK ══

        # ── Only now fall back to the jammy hack as an absolute last resort ──
        if ! ls "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" >/dev/null 2>&1; then
            if ls "${SCAP_CACHE_DIR}/ubuntu2204/ssg-ubuntu2204-ds.xml" >/dev/null 2>&1; then
                echo -e "${YELLOW}   ⚠️  Upstream fetch failed too — using 2204 as last-resort fallback (results will be unreliable)${NC}"
                cp -f "${SCAP_CACHE_DIR}/ubuntu2204/ssg-ubuntu2204-ds.xml" \
                    "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" 2>/dev/null || true
        
                # NEW: validate the copy actually has profiles before trusting it
                if ! oscap info "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" 2>/dev/null \
                        | grep -q 'xccdf_org.ssgproject.content_profile_cis_level1_server'; then
                    echo -e "${RED}   ❌ 2204 fallback copy has no valid CIS profile — removing broken file${NC}"
                    rm -f "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml"
                fi
            else
                echo -e "${RED}   ❌ No 2204 datastream available either — ubuntu2404 cache will be empty${NC}"
            fi
        fi
    fi

    local failed=0
    local check_dirs=()
    $need_rhel   && check_dirs+=(rhel9)
    $need_rocky  && check_dirs+=(rocky9)
    $need_alma   && check_dirs+=(alma9 alma10)

    if $need_ubuntu; then
        echo -e "${CYAN}   🔍 Diagnostic: ubuntu2404 cache contents:${NC}"
        ls -la "${SCAP_CACHE_DIR}/ubuntu2404/" 2>&1
        if [ -f "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" ]; then
            echo "   File size: $(stat -c%s "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" 2>/dev/null) bytes"
            oscap info "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" 2>&1 | head -20
        fi
    fi
    
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
        if [[ "${d}" == ubuntu* ]]; then
            if ! ls "${SCAP_CACHE_DIR}/${d}/ssg-"*.xml >/dev/null 2>&1; then
                if ls "${SCAP_CACHE_DIR}"/ubuntu*/ssg-*.xml >/dev/null 2>&1; then
                    echo -e "${YELLOW}⚠️  [Phase 0.2b] No SCAP xml in ${d} — will use available datastream at runtime${NC}"
                else
                    echo -e "${RED}⚠️  [Phase 0.2b] SCAP datastream xml missing from ${d} — no Ubuntu content at all${NC}"
                    failed=1
                fi
            fi
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
        ok=false
    fi
    if [ ! -f "${rb_file}" ]; then
        echo -e "${RED}❌ [Profile Guard] ${rb_file} not found.${NC}"
        ok=false
    fi
    if [ ! -f "${ps1_file}" ]; then
        echo -e "${YELLOW}⚠️  [Profile Guard] ${ps1_file} not found — PS1 remediation path unavailable.${NC}"
    fi
    if [ "$ok" == "false" ]; then return 1; fi

    local ctrl_count l1_count l2_count
    ctrl_count=$(grep -c "^control " "${rb_file}" 2>/dev/null || echo 0)
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
        return 1
    fi

    echo -e "${CYAN}📤 [WinPS1/${ip}] Uploading + running via SSH${NC}"
    scp -o BatchMode=yes -o StrictHostKeyChecking=no \
        "$WIN_PS1_REMEDIATE" "$WIN_GHOST_USER@${ip}:C:/Windows/Temp/Invoke-CISRemediation-Combined.ps1"

    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no "$WIN_GHOST_USER@${ip}" \
        "powershell -NoProfile -File C:\\Windows\\Temp\\Invoke-CISRemediation-Combined.ps1 -ServerRole '${WIN_SERVER_ROLE}'"

    local rc=$?
    ssh -n "$WIN_GHOST_USER@${ip}" "Remove-Item C:\\Windows\\Temp\\Invoke-CISRemediation-Combined.ps1 -Force -ErrorAction SilentlyContinue" 2>/dev/null

    [ $rc -eq 0 ] && echo -e "${GREEN}✅ [WinPS1/${ip}] Remediation complete${NC}" \
                  || echo -e "${RED}❌ [WinPS1/${ip}] Remediation failed (rc=${rc})${NC}"
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
           -o ConnectTimeout=10 \
           "${user}@${ip}" \
           "command -v oscap >/dev/null 2>&1 && \
            ls /usr/share/xml/scap/ssg/content/ssg-*-ds.xml \
            >/dev/null 2>&1" 2>/dev/null; then
        echo -e "${GREEN}✅ [Tool Guard] SCAP already present on ${ip} — skipping push${NC}"
        return 0
    fi

    local distro_id distro_ver cache_key distro_raw distro_err
    distro_raw="$(ssh -n \
        -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "${user}@${ip}" \
        '. /etc/os-release && echo "$ID ${VERSION_ID%%.*}"' 2>&1)"
    distro_err=$?
    read -r distro_id distro_ver <<< "$distro_raw"

    if [ -z "$distro_id" ] || [ -z "$distro_ver" ]; then
        echo -e "${RED}❌ [Tool Guard] Could not determine distro on ${ip} (ssh rc=${distro_err}). Raw output:${NC}"
        echo -e "${RED}   ${distro_raw}${NC}"
        return 1
    fi

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
        return 1
    fi

    echo -e "${CYAN}📦 [Tool Guard] Pushing ${cache_key} packages → ${ip} (SCP/port 22)${NC}"

    # Never let openssl/openssl-libs RPMs leave the runner's cache dir —
    # closes the gap in the rpm -Uvh fallback below, which has no --exclude.
    find "${cache_dir}" -maxdepth 1 -name '*.rpm' \
        \( -iname 'openssl-[0-9]*' -o -iname 'openssl-libs-*' \) \
        -exec echo "   ⛔ Excluding from push: {}" \; -exec rm -f {} \;

    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        "${user}@${ip}" \
        "sudo mkdir -p /tmp/scap_offline && sudo chmod 777 /tmp/scap_offline" 2>/dev/null

    scp -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "${cache_dir}"/* "${user}@${ip}:/tmp/scap_offline/"

    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ [Tool Guard] SCP push failed to ${ip}${NC}"
        return 1
    fi

    local install_cmd
    if [ "$pkg_mgr" == "apt" ]; then
        install_cmd='
            export DEBIAN_FRONTEND=noninteractive
            sudo dpkg -i --force-overwrite /tmp/scap_offline/*.deb 2>/dev/null || true
            sudo dpkg --configure -a 2>/dev/null || true
            if ! command -v oscap >/dev/null 2>&1; then
                echo "[Tool Guard] oscap not available after offline install — trying apt fallback"
                sudo apt-get install -y --no-install-recommends openscap-scanner 2>/dev/null || true
                command -v oscap >/dev/null 2>&1 || \
                    sudo apt-get install -y --no-install-recommends libopenscap8 2>/dev/null || true
            fi

            # FIX: always copy any datastreams we pushed, regardless of whether
            # dpkg already dropped its own (older/incomplete) set from ssg-debderived.
            if ls /tmp/scap_offline/ssg-*-ds.xml >/dev/null 2>&1; then
                sudo mkdir -p /usr/share/xml/scap/ssg/content
                sudo cp -f /tmp/scap_offline/ssg-*-ds.xml \
                    /usr/share/xml/scap/ssg/content/ 2>/dev/null || true
                sudo chmod 644 /usr/share/xml/scap/ssg/content/ssg-*-ds.xml 2>/dev/null || true
            elif ls /tmp/scap_offline/ssg-debderived*.deb >/dev/null 2>&1; then
                _deb_extract=$(mktemp -d /tmp/ssg_deb_XXXXXX)
                dpkg-deb -x /tmp/scap_offline/ssg-debderived*.deb \
                    "$_deb_extract" 2>/dev/null || true
                sudo mkdir -p /usr/share/xml/scap/ssg/content
                find "$_deb_extract" -name "ssg-ubuntu*-ds.xml" \
                    -exec sudo cp -f {} /usr/share/xml/scap/ssg/content/ \;
                rm -rf "$_deb_extract"
            elif ! ls /usr/share/xml/scap/ssg/content/ssg-*-ds.xml >/dev/null 2>&1; then
                sudo apt-get install -y --no-install-recommends \
                    ssg-base ssg-debderived 2>/dev/null || true
            fi
        '
    else
        install_cmd="sudo dnf install -y --disablerepo='*' --allowerasing \
                         --exclude=openssl-libs --exclude=openssl \
                         /tmp/scap_offline/*.rpm 2>/dev/null || \
                     sudo rpm -Uvh --nodeps --replacepkgs \
                         /tmp/scap_offline/*.rpm 2>/dev/null || true"
    fi

    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        "${user}@${ip}" "
        set +e
        ${install_cmd}
        sudo rm -rf /tmp/scap_offline 2>/dev/null || true

        command -v oscap >/dev/null 2>&1 \
            || { echo '[FATAL] oscap missing after offline install'; exit 10; }

        oscap --version >/dev/null 2>&1
        if [ \$? -ne 0 ]; then
            echo '[WARN] oscap present but failed to run — checking for missing shared libs...'
            oscap --version 2>&1
            if oscap --version 2>&1 | grep -q 'libltdl'; then
                echo '[INFO] Attempting targeted online fix: installing libtool-ltdl from VM repos...'
                sudo dnf install -y libtool-ltdl 2>&1
                oscap --version >/dev/null 2>&1 \
                    || { echo '[FATAL] oscap still broken after libtool-ltdl install'; exit 12; }
            else
                echo '[FATAL] oscap broken for an unrelated reason (see above)'; exit 13
            fi
        fi

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
# HELPER: scp_custom_content
# FIX: Centralised helper so Phase 1, Phase 2, and Phase 4
#      all use the same logic and never forget to re-SCP.
# ======================================================
scp_custom_content_ubuntu() {
    local user="$1"
    local ip="$2"
    echo -e "${CYAN}📤 [SCP] Pushing custom XCCDF/OVAL to ${ip}...${NC}"
    scp -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "$UBUNTU_CUSTOM_OVAL" "$UBUNTU_CUSTOM_XCCDF" \
        "${user}@${ip}:/tmp/"
    local rc=$?
    if [ $rc -ne 0 ]; then
        echo -e "${RED}❌ [SCP] Failed to push custom content to ${ip} (rc=${rc})${NC}"
        return 1
    fi
    echo -e "${GREEN}✅ [SCP] Custom content ready on ${ip}${NC}"
    return 0
}

scp_custom_content_rhel() {
    local user="$1"
    local ip="$2"
    echo -e "${CYAN}📤 [SCP] Pushing custom RHEL XCCDF/OVAL to ${ip}...${NC}"
    scp -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" \
        "${user}@${ip}:/tmp/"
    local rc=$?
    if [ $rc -ne 0 ]; then
        echo -e "${RED}❌ [SCP] Failed to push custom RHEL content to ${ip} (rc=${rc})${NC}"
        return 1
    fi
    echo -e "${GREEN}✅ [SCP] Custom RHEL content ready on ${ip}${NC}"
    return 0
}

# ======================================================
# HELPER: detect_windows_version
# ======================================================
detect_windows_version() {
    local ip="$1"
    local caption
    caption=$(ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
        "${WIN_GHOST_USER}@${ip}" \
        "powershell -NoProfile -Command \"(Get-CimInstance Win32_OperatingSystem).Caption\"" 2>/dev/null \
        | grep -oE 'Windows (Server (2019|2022|2025)|1[01])' | head -1)

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

run_win_ssh() {
    local ip="$1"
    local cmd="$2"
    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "${WIN_GHOST_USER}@${ip}" "powershell -NoProfile -NonInteractive -Command \"${cmd}\""
        
}

check_windows_agent_alive() {
    local ip="$1"
    ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
        "${WIN_GHOST_USER}@${ip}" "echo ALIVE" 2>/dev/null | grep -q ALIVE
}

# ======================================================
# HELPER: ensure_windows_ghost_user
# Creates a dedicated local admin account for audit ops,
# mirroring the Linux GHOST_USER pattern.
# ======================================================
ensure_windows_ghost_user() {
    local ip="$1"
    if ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
           "${WIN_GHOST_USER}@${ip}" "echo SSH_OK" 2>/dev/null | grep -q SSH_OK; then
        echo -e "${GREEN}✅ [WinGhost] ${WIN_GHOST_USER} already provisioned on ${ip}${NC}"
        return 0
    fi
    echo -e "${CYAN}👤 [WinGhost] Provisioning ${WIN_GHOST_USER} on ${ip} via ${WIN_SSH_USER}...${NC}"
    local pub_key
    pub_key=$(cat ~/.ssh/id_rsa.pub)
    # Build the PowerShell script in a local file — no bash quoting involved at all
    local ps_script
    ps_script=$(mktemp /tmp/winghost_XXXXXX.ps1)
    cat > "$ps_script" <<PS1EOF
\$ProgressPreference = 'SilentlyContinue'
\$chars = [char[]]((48..57)+(65..90)+(97..122)+(33,35,36,37,38))
\$pass = -join (\$chars | Get-Random -Count 24)
\$secure = ConvertTo-SecureString \$pass -AsPlainText -Force
if (-not (Get-LocalUser -Name '${WIN_GHOST_USER}' -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name '${WIN_GHOST_USER}' -Password \$secure -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop
}
Add-LocalGroupMember -Group 'Administrators' -Member '${WIN_GHOST_USER}' -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path 'C:\ProgramData\ssh' | Out-Null
Add-Content -Path 'C:\ProgramData\ssh\administrators_authorized_keys' -Value '${pub_key}'
Get-Content 'C:\ProgramData\ssh\administrators_authorized_keys' | Select-Object -Unique | Set-Content 'C:\ProgramData\ssh\administrators_authorized_keys'
icacls 'C:\ProgramData\ssh\administrators_authorized_keys' /inheritance:r | Out-Null
icacls 'C:\ProgramData\ssh\administrators_authorized_keys' /grant 'Administrators:F' | Out-Null
icacls 'C:\ProgramData\ssh\administrators_authorized_keys' /grant 'SYSTEM:F' | Out-Null
Restart-Service sshd
Write-Output 'GHOST_USER_READY'
PS1EOF
    # Encode to UTF-16LE base64 (what -EncodedCommand requires)
    local encoded_cmd
    encoded_cmd=$(iconv -f UTF-8 -t UTF-16LE "$ps_script" | base64 -w 0)
    rm -f "$ps_script"
    local ssh_output
    ssh_output=$(ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
        "${WIN_SSH_USER}@${ip}" "powershell -NoProfile -EncodedCommand ${encoded_cmd}" 2>&1)
    echo "$ssh_output" | grep -q GHOST_USER_READY
    local rc=$?
    if [ $rc -ne 0 ]; then
        echo -e "${RED}❌ [WinGhost] Failed to provision ${WIN_GHOST_USER} on ${ip}${NC}"
        echo -e "${RED}$ssh_output${NC}"
        return 1
    fi
    sleep 5
    if ! ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
             "${WIN_GHOST_USER}@${ip}" "echo SSH_OK" 2>/dev/null | grep -q SSH_OK; then
        echo -e "${RED}❌ [WinGhost] ${WIN_GHOST_USER} still not reachable after provisioning on ${ip}${NC}"
        return 1
    fi
    echo -e "${GREEN}✅ [WinGhost] ${WIN_GHOST_USER} ready on ${ip}${NC}"
    return 0
}

# ======================================================
# HELPER: reboot_windows_host
# ======================================================
reboot_windows_host() {
    local ip="$1"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"
    [ -z "$vm_name" ] && { echo -e "${YELLOW}⚠️  [Reboot] No VM name for ${ip}${NC}"; return 0; }

    echo -e "${CYAN}🔁 [Reboot/${ip}] Restarting ${vm_name} (non-blocking)...${NC}"
    
    cloud_vm_restart "$ip"

    sleep 20

    local deadline=$(( SECONDS + 480 ))
    echo -e "${CYAN}⏳ [Reboot/${ip}] Waiting for VM to return to running state...${NC}"
    while [ $SECONDS -lt $deadline ]; do
        local ps
        ps=$(cloud_vm_get_power_state "$ip")
        if [[ "$ps" == "running" ]]; then
            echo -e "${GREEN}✅ [Reboot/${ip}] VM back to 'running' (fabric level)${NC}"
            break
        fi
        echo -e "${CYAN}   [Reboot/${ip}] PowerState: ${ps:-unknown} — waiting...${NC}"
        sleep 15
    done

    sleep "${WIN_REBOOT_SETTLE_SEC}"

    echo -e "${CYAN}🩺 [Reboot/${ip}] Probing guest agent (max ${WIN_REBOOT_HEALTH_WAIT_SEC}s)...${NC}"
    local hb_deadline=$(( SECONDS + WIN_REBOOT_HEALTH_WAIT_SEC ))
    local agent_ok=false
    while [ $SECONDS -lt $hb_deadline ]; do
        if check_windows_agent_alive "$ip"; then
            agent_ok=true
            break
        fi
        echo -e "${CYAN}   [Reboot/${ip}] Guest agent not answering yet — waiting...${NC}"
        sleep 20
    done

    if [ "$agent_ok" != "true" ]; then
        echo -e "${RED}❌ [Reboot/${ip}] Guest agent did NOT respond after reboot.${NC}"
        echo -e "${RED}   The OS is hung at boot — a CIS control likely broke startup.${NC}"
        return 2
    fi

    echo -e "${GREEN}✅ [Reboot/${ip}] Guest agent alive — OS booted${NC}"
    wait_for_ssh "$ip" "$WIN_GHOST_USER" || echo -e "${YELLOW}⚠️  [Reboot/${ip}] SSH not open yet (will retry at scan time)${NC}"
    return 0
}

# ======================================================
# HELPER: remediate_windows_host
# ======================================================
remediate_windows_host() {
    local ip="$1"
    local cis_level="$2"
    echo -e "${CYAN}🛠️  [Win] Remediating ${ip} via SSH+PS1 (Level: ${cis_level})...${NC}"
    run_win_ps1_remediation "$ip" "$cis_level"
    return $?
}

# ======================================================
# HELPER: fetch_remote_report
# ======================================================
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

    echo -e "${YELLOW}🔄 [Fetch/${tag}] SCP failed — falling back to sudo cat on ${ip}${NC}"
    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
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
# CLOUD PROVIDER ABSTRACTION LAYER
# ======================================================

cloud_hcloud_check() {
    if ! python3 -c "import huaweicloudsdkecs" 2>/dev/null; then
        echo -e "${RED}❌ [HuaweiCloud] Python SDK not installed.${NC}"
        echo -e "${YELLOW}   Run: pip3 install huaweicloudsdkcore huaweicloudsdkecs${NC}"
        return 1
    fi
    if [ -z "${HUAWEICLOUD_ACCESS_KEY}" ] || [ -z "${HUAWEICLOUD_SECRET_KEY}" ] || [ -z "${HW_PROJECT_ID}" ]; then
        echo -e "${RED}❌ [HuaweiCloud] Missing credentials.${NC}"
        return 1
    fi

    if ! timeout 20 env \
        HUAWEICLOUD_ACCESS_KEY="${HUAWEICLOUD_ACCESS_KEY}" \
        HUAWEICLOUD_SECRET_KEY="${HUAWEICLOUD_SECRET_KEY}" \
        HW_PROJECT_ID="${HW_PROJECT_ID}" \
        HW_ECS_ENDPOINT="${HW_ECS_ENDPOINT}" \
        HW_EPS_ID="${HW_EPS_ID}" \
        python3 "${SCRIPT_DIR}/hw_ecs_discover.py" >/dev/null 2>/tmp/hw_check_err.log; then
        echo -e "${RED}❌ [HuaweiCloud] SDK auth/connectivity check failed.${NC}"
        [ -s /tmp/hw_check_err.log ] && cat /tmp/hw_check_err.log
        return 1
    fi
    echo -e "${GREEN}✅ [HuaweiCloud] SDK authenticated (endpoint: ${HW_ECS_ENDPOINT})${NC}"
    return 0
}

cloud_add_port_rule() {
    local ip="$1" port="$2" rule_name="${3:-Allow_Port_${2}_Runner}"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"
    local vm_id="${IP_TO_VM_ID[$ip]:-}"
    local runner_ip
    runner_ip="${RUNNER_IP:-$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null)}"

    case "${CLOUD_PROVIDER}" in
    azure)
        [ -z "$vm_name" ] && return 1
        local nic_id nsg_id nsg_name
        nic_id=$(az vm show -g "$RG_NAME" -n "$vm_name" \
            --query "networkProfile.networkInterfaces[0].id" -o tsv 2>/dev/null)
        nsg_id=$(az network nic show --ids "$nic_id" \
            --query "networkSecurityGroup.id" -o tsv 2>/dev/null)
        [ -z "$nsg_id" ] && return 0
        nsg_name=$(basename "$nsg_id")
        az network nsg rule create -g "$RG_NAME" --nsg-name "$nsg_name" \
            --name "$rule_name" --priority 998 \
            --destination-port-ranges "$port" \
            --source-address-prefixes "$runner_ip" \
            --access Allow --protocol Tcp -o none >/dev/null 2>&1 || true
        ;;
    huaweicloud)
        [ -z "$vm_id" ] && { echo -e "${YELLOW}⚠️  [HW] No ECS ID for ${ip}${NC}"; return 1; }

        # Need the SG ID attached to this ECS instance. There is no SDK
        # "list SGs by server" shortcut confirmed yet, so this assumes
        # HW_VPC_ID / a per-server SG lookup already resolved elsewhere.
        # If you already resolve sg_id via ECS server details, wire it in here.
        local sg_id="${IP_TO_SG_ID[$ip]:-}"
        if [ -z "$sg_id" ]; then
            echo -e "${YELLOW}⚠️  [HW] No SG ID resolved for ${ip} — skipping rule refresh${NC}"
            return 1
        fi
    
        HW_VPC_ENDPOINT="${HW_VPC_ENDPOINT}" \
        python3 "${SCRIPT_DIR}/hw_sg_rule_manage.py" \
            --sg-id "$sg_id" \
            --port "$port" \
            --remote-ip "$runner_ip" \
            --protocol tcp
        return $?
        ;;
    esac
}

# ======================================================
# HELPER: reassert_ssh_rule_all_linux
# Re-applies the port-22 SG rule for every discovered Linux IP right
# before Ansible runs, regardless of distro. Covers the gap where the
# Phase 0.3 rule may have been overwritten by the time remediation starts.
# No-op on Azure (SG is NSG-based there and az vm run-command doesn't
# have this race in the same way — safe to skip).
# ======================================================
reassert_ssh_rule_all_linux() {
    [ "${CLOUD_PROVIDER}" != "huaweicloud" ] && return 0

    local all_linux_ips=(
        "${UBUNTU_MACHINES[@]}" "${RHEL_MACHINES[@]}"
        "${ROCKY_MACHINES[@]}"  "${ALMA_MACHINES[@]}"
    )
    [ ${#all_linux_ips[@]} -eq 0 ] && return 0

    local runner_ip
    runner_ip="${RUNNER_IP:-$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null)}"
    echo -e "${CYAN}🔁 [SG-Reassert] Refreshing port-22 rule for ${#all_linux_ips[@]} host(s) → runner ${runner_ip}${NC}"

    for ip in "${all_linux_ips[@]}"; do
        local sg_id="${IP_TO_SG_ID[$ip]:-}"
        if [ -z "$sg_id" ]; then
            echo -e "${YELLOW}⚠️  [SG-Reassert] No SG ID for ${ip} — skipping${NC}"
            continue
        fi
        HW_VPC_ENDPOINT="${HW_VPC_ENDPOINT}" \
        python3 "${SCRIPT_DIR}/hw_sg_rule_manage.py" \
            --sg-id "$sg_id" --port 22 --remote-ip "$runner_ip" --protocol tcp
    done
}


# ======================================================
# HELPER: cloud_vm_run_shell
# NOTE (SSH key migration): For huaweicloud this is a plain keyed SSH call
#   (BatchMode=yes → fails fast, never prompts for a password). There is no
#   Huawei equivalent of Azure's `az vm run-command` (an out-of-band control
#   plane channel) wired up in this script, so this call can only ever
#   succeed if "${LINUX_ADMIN_USER:-root}" already trusts the runner's
#   public key. That trust must be established OUTSIDE this pipeline —
#   e.g. baked into the ECS image or injected via cloud-init/user-data at
#   instance-creation time. The pipeline no longer pushes a password to
#   establish it at runtime (see fleet-commander.yml).
# ======================================================
cloud_vm_run_shell() {
    local ip="$1"
    local script="$2"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"

    case "${CLOUD_PROVIDER}" in
    azure)
        [ -z "$vm_name" ] && return 1
        timeout "${WIN_AGENT_PROBE_SEC}" az vm run-command invoke \
            -g "$RG_NAME" -n "$vm_name" \
            --command-id RunShellScript \
            --scripts "$script" \
            -o none >/dev/null 2>&1
        return $?
        ;;
    huaweicloud)
        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
            "${LINUX_ADMIN_USER:-root}@${ip}" "$script" >/dev/null 2>&1
        return $?
        ;;
    esac
}

cloud_vm_restart() {
    local ip="$1"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"
    local vm_id="${IP_TO_VM_ID[$ip]:-}"

    case "${CLOUD_PROVIDER}" in
    azure)
        [ -z "$vm_name" ] && return 1
        timeout 120 az vm restart -g "$RG_NAME" -n "$vm_name" --no-wait -o none 2>/dev/null || true
        ;;
    huaweicloud)
        [ -z "$vm_id" ] && return 1
        timeout 120 hcloud ECS RebootServer \
            --server-id "$vm_id" \
            --type.type "HARD" \
            --cli-region "${HW_REGION}" \
            --cli-output json >/dev/null 2>&1 || true
        ;;
    esac
}

cloud_vm_get_power_state() {
    local ip="$1"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"
    local vm_id="${IP_TO_VM_ID[$ip]:-}"
    local raw=""

    case "${CLOUD_PROVIDER}" in
    azure)
        [ -z "$vm_name" ] && { echo "unknown"; return; }
        raw=$(timeout 30 az vm get-instance-view -g "$RG_NAME" -n "$vm_name" \
            --query "instanceView.statuses[?starts_with(code,'PowerState')].displayStatus" \
            -o tsv 2>/dev/null | tr -d '\r')
        ;;
    huaweicloud)
        [ -z "$vm_id" ] && { echo "unknown"; return; }
        raw=$(timeout 30 hcloud ECS ShowServer \
            --server-id "$vm_id" \
            --cli-region "${HW_REGION}" \
            --cli-output json 2>/dev/null \
            | python3 -c "
import json,sys
d=json.load(sys.stdin)
st=d.get('server',{}).get('status','')
print('running' if st=='ACTIVE' else st.lower())
" 2>/dev/null)
        ;;
    esac

    [[ "$raw" == *"running"* || "$raw" == "running" ]] && echo "running" || echo "${raw:-unknown}"
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
        *) echo -e "${RED}Unknown parameter: $1${NC}"; exit 1 ;;
    esac
    shift
done

[ -n "$H_CLOUD" ] && CLOUD_PROVIDER="${H_CLOUD,,}"
case "${CLOUD_PROVIDER}" in
    azure|huaweicloud) ;;
    *) echo -e "${RED}❌ Unknown --cloud value '${CLOUD_PROVIDER}'. Use: azure | huaweicloud${NC}"; exit 1 ;;
esac

CIS_LEVEL="${CIS_LEVEL:-Level 1}"

# ======================================================
# ENTERPRISE GUARDRAILS
# ======================================================
if [ "$HEADLESS" == true ]; then
    echo -e "${CYAN}${BOLD}🤖 HEADLESS CI/CD MODE ACTIVATED${NC}"
    echo -e "${CYAN}   Cloud provider: ${BOLD}${CLOUD_PROVIDER}${NC}"
    if [ -n "$H_TICKET" ] && [ "$H_TICKET" != "None" ]; then
        echo -e "${GREEN}🎫 AUDIT AUTHORIZATION: Ticket ID: ${BOLD}$H_TICKET${NC}"
    fi
    if [ "$DEBUG_MODE" == "true" ]; then set -x; fi
fi


# ======================================================
# SSH MULTIPLEXING
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
UBUNTU_MACHINES=()
RHEL_MACHINES=()
ROCKY_MACHINES=()
ALMA_MACHINES=()
WINDOWS_MACHINES=()
declare -A IP_TO_VM_NAME
declare -A IP_TO_VM_ID
declare -A IP_TO_SG_ID

_map_vm() {
    local vm_name="$1" ip="$2" os="$3" power="$4" offer="$5"
    ip=$(echo "$ip" | tr -d '\r' | xargs)
    [ -z "$ip" ] || [ "$ip" == "None" ] || [[ "$power" != *"running"* ]] && return
    IP_TO_VM_NAME["$ip"]="$vm_name"
    if [[ "$os" == *"Linux"* ]] || [[ "$os" == *"Ubuntu"* ]] || [[ "$os" == *"linux"* ]]; then
        offer="${offer,,}"
        if   [[ "$offer" == *"rocky"* ]] || [[ "${vm_name,,}" == *"rocky"* ]]; then
            ROCKY_MACHINES+=("$ip");  echo -e "${CYAN}🏔️  Mapped Rocky Node:    $ip${NC}"
        elif [[ "$offer" == *"alma"*  ]] || [[ "${vm_name,,}" == *"alma"*  ]]; then
            ALMA_MACHINES+=("$ip");   echo -e "${CYAN}🦙 Mapped AlmaLinux Node: $ip${NC}"
        elif [[ "$offer" == *"rhel"*  ]] || [[ "${vm_name,,}" == *"rhel"*  ]]; then
            RHEL_MACHINES+=("$ip");   echo -e "${CYAN}🔴 Mapped RHEL Node:      $ip${NC}"
        else
            UBUNTU_MACHINES+=("$ip"); echo -e "${CYAN}🟠 Mapped Ubuntu Node:    $ip${NC}"
        fi
    elif [[ "$os" == *"Windows"* ]] || [[ "$os" == *"windows"* ]]; then
        WINDOWS_MACHINES+=("$ip");    echo -e "${CYAN}🪟 Mapped Windows Node:   $ip${NC}"
    fi
}

case "${CLOUD_PROVIDER}" in
azure)
    echo -e "${CYAN}📡 [Azure] Querying VMs in resource group [${RG_NAME}]...${NC}"
    if [ "$H_TARGETS" == "all" ] || [ -z "$H_TARGETS" ]; then
        VM_DATA=$(az vm list -d -g "$RG_NAME" \
            --query "[].[name, publicIps, storageProfile.osDisk.osType, powerState, storageProfile.imageReference.offer]" \
            -o tsv)
    else
        VM_DATA=$(az vm list -d -g "$RG_NAME" \
            --query "[?tags.Environment=='$H_TARGETS'].[name, publicIps, storageProfile.osDisk.osType, powerState, storageProfile.imageReference.offer]" \
            -o tsv)
    fi
    while IFS=$'\t' read -r raw_name raw_ip raw_os raw_power raw_offer; do
        vm_name=$(echo "$raw_name"  | tr -d '\r' | xargs)
        ip=$(echo "$raw_ip"         | tr -d '\r' | xargs)
        os=$(echo "$raw_os"         | tr -d '\r' | xargs)
        power=$(echo "$raw_power"   | tr -d '\r' | xargs)
        offer=$(echo "$raw_offer"   | tr -d '\r' | xargs)
        _map_vm "$vm_name" "$ip" "$os" "$power" "$offer"
    done <<< "$VM_DATA"
    ;;

huaweicloud)
    echo -e "${CYAN}📡 [HuaweiCloud] Querying ECS instances via SDK [endpoint: ${HW_ECS_ENDPOINT}]...${NC}"
    HW_RAW=$(
        HUAWEICLOUD_ACCESS_KEY="${HUAWEICLOUD_ACCESS_KEY}" \
        HUAWEICLOUD_SECRET_KEY="${HUAWEICLOUD_SECRET_KEY}" \
        HW_PROJECT_ID="${HW_PROJECT_ID}" \
        HW_ECS_ENDPOINT="${HW_ECS_ENDPOINT}" \
        HW_ECS_TAG_KEY="${HW_ECS_TAG_KEY}" \
        HW_ECS_TAG_VAL="${HW_ECS_TAG_VAL}" \
        HW_EPS_ID="${HW_EPS_ID}" \
        python3 "${SCRIPT_DIR}/hw_ecs_discover.py" --tsv
    )
    _hw_rc=$?

    if [ $_hw_rc -ne 0 ] || [ -z "$HW_RAW" ]; then
        echo -e "${RED}❌ [HuaweiCloud] ECS list returned empty or failed.${NC}"
        [ -n "${HW_EPS_ID}" ] && \
            echo -e "${YELLOW}   ⚠️  HW_EPS_ID='${HW_EPS_ID}' is set — verify instances belong to this enterprise project.${NC}"
    else
        # hw_ecs_discover.py --tsv emits 5 columns:
        #   os_type, img_name, name, target_ip, srv_id
        # (it already filters to ACTIVE/RUNNING before printing, so there is
        # no separate "power" column — we pass a literal "running" to _map_vm)
        while IFS=$'\t' read -r os_type offer vm_name ip srv_id sg_id; do
            IP_TO_VM_ID["$ip"]="$srv_id"
            IP_TO_SG_ID["$ip"]="$sg_id"
            _map_vm "$vm_name" "$ip" "$os_type" "running" "$offer"
        done <<< "$HW_RAW"
    fi
    ;;
esac

if [ "$HEADLESS" == true ] && [ ${#UBUNTU_MACHINES[@]} -eq 0 ] && \
   [ ${#RHEL_MACHINES[@]} -eq 0 ] && [ ${#ROCKY_MACHINES[@]} -eq 0 ] && \
   [ ${#ALMA_MACHINES[@]} -eq 0 ] && [ ${#WINDOWS_MACHINES[@]} -eq 0 ]; then
    echo -e "${YELLOW}⚠️  No matching VMs found for environment '${H_TARGETS}' — nothing to audit. Exiting cleanly.${NC}"
    exit 0
fi

if [ "$H_TARGET_IP" != "all" ] && [ -n "$H_TARGET_IP" ]; then
    echo -e "${MAGENTA}🎯 MATRIX SHARDING: Isolating to node $H_TARGET_IP${NC}"
    UBUNTU_MACHINES=(); RHEL_MACHINES=(); ROCKY_MACHINES=()
    ALMA_MACHINES=();   WINDOWS_MACHINES=()

    SHARD_VM_NAME="${IP_TO_VM_NAME[$H_TARGET_IP]:-}"
    if [ -z "$SHARD_VM_NAME" ]; then
        case "${CLOUD_PROVIDER}" in
        azure)
            SHARD_VM_NAME=$(az vm list -d -g "$RG_NAME" \
                --query "[?publicIps=='${H_TARGET_IP}'].name | [0]" -o tsv 2>/dev/null)
            [ -n "$SHARD_VM_NAME" ] && IP_TO_VM_NAME["$H_TARGET_IP"]="$SHARD_VM_NAME"
            ;;
        huaweicloud)
            HW_SHARD_RAW=$(
                HUAWEICLOUD_ACCESS_KEY="${HUAWEICLOUD_ACCESS_KEY}" \
                HUAWEICLOUD_SECRET_KEY="${HUAWEICLOUD_SECRET_KEY}" \
                HW_PROJECT_ID="${HW_PROJECT_ID}" \
                HW_ECS_ENDPOINT="${HW_ECS_ENDPOINT}" \
                HW_EPS_ID="${HW_EPS_ID}" \
                python3 "${SCRIPT_DIR}/hw_ecs_discover.py" --tsv
            )
            while IFS=$'\t' read -r os_type offer vm_name ip srv_id sg_id; do
                [ "$ip" == "$H_TARGET_IP" ] || continue
                IP_TO_VM_NAME["$ip"]="$vm_name"
                IP_TO_VM_ID["$ip"]="$srv_id"
                IP_TO_SG_ID["$ip"]="$sg_id"
                SHARD_VM_NAME="$vm_name"
            done <<< "$HW_SHARD_RAW"
            if [ -z "$SHARD_VM_NAME" ]; then
                echo -e "${YELLOW}⚠️  [HuaweiCloud] Could not resolve VM name/ID for ${H_TARGET_IP} — reboot/power-state helpers will no-op for this host.${NC}"
            fi
            ;;
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
# NOTE (SSH key migration): the blocks below are a *self-heal*, not the
# primary bootstrap path. They only fire if the dedicated audit account
# (GHOST_USER) can't already be reached — and for Huawei
# Cloud, the recovery call (cloud_vm_run_shell) itself needs SSH key trust
# for LINUX_ADMIN_USER to already exist (see cloud_vm_run_shell above).
# In other words: this heals a missing *audit* account, it cannot bootstrap
# SSH access to a VM from zero. The precondition — LINUX_ADMIN_USER's key
# trusted via cloud-init/user-data at ECS creation — must hold for Huawei
# before this pipeline runs at all.
# ======================================================
echo -e "\n${CYAN}⚙️  PHASE 0.3: PARALLEL INFRASTRUCTURE BOOTSTRAPPING${NC}"
RUNNER_IP=$(curl -s https://api.ipify.org)

if [ "${CLOUD_PROVIDER}" == "huaweicloud" ]; then
    cloud_hcloud_check || exit 1
fi


if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" =~ ^(ubuntu|rhel|rocky|alma)$ ]]; then
    for ip in "${UBUNTU_MACHINES[@]}" "${RHEL_MACHINES[@]}" "${ROCKY_MACHINES[@]}" "${ALMA_MACHINES[@]}"; do
        (
            if [ "$(ssh -n -o BatchMode=yes -o ConnectTimeout=5 \
                    -o StrictHostKeyChecking=no ${GHOST_USER}@${ip} \
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
                               systemctl restart sshd" || true
                sleep 15
            fi

            # Same MaxStartups guard the RHEL block has — now applies to Ubuntu too
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
            wait_for_ssh "$ip" "$WIN_SSH_USER" || {
                echo -e "${RED}❌ [Win Bootstrap] SSH unreachable: $ip${NC}"
                exit 1
            }
            ensure_windows_ghost_user "$ip" || \
                echo -e "${RED}❌ [Win Bootstrap] Ghost user provisioning failed: $ip${NC}"
        ) &
    done
fi
wait

# ======================================================
# INVENTORY BUILDER
# ======================================================
echo "[ubuntu_nodes]" > inventory.ini
for ip in "${UBUNTU_MACHINES[@]}"; do
    echo "${ip} ansible_user=${GHOST_USER}" >> inventory.ini
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
    echo "${ip} ansible_user=${WIN_GHOST_USER} ansible_connection=ssh \
ansible_shell_type=powershell ansible_ssh_common_args='-o StrictHostKeyChecking=no'" \
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

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ]; then
            for IP in "${UBUNTU_MACHINES[@]}"; do
                (
                    if ! ensure_linux_scap_tools "$GHOST_USER" "$IP" "apt"; then
                        echo -e "${RED}❌ [Phase1/Ubuntu] Skipping $IP — tools unavailable.${NC}"
                        exit 1
                    fi
                    RAW_VER=$(ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                        ${GHOST_USER}@${IP} \
                        "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
                    UBUNTU_VER=${RAW_VER:-2404}
                    UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"
                    
                    EFFECTIVE_UBUNTU_CIS_PROFILE="$UBUNTU_CIS_PROFILE"
                    PROFILE_OK=true
                    
                    # Dump every profile ID once so fallback logic + diagnostics both use real data
                    AVAILABLE_PROFILES=$(ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                        ${GHOST_USER}@${IP} \
                        "sudo oscap info '$UBUNTU_CIS_XCCDF' 2>/dev/null | grep -oE 'xccdf_org\.ssgproject\.content_profile_[a-zA-Z0-9_]+'")
                    
                    if [ "$RUN_CIS" == true ] && [ "$OS_LVL" == "2" ]; then
                        if ! echo "$AVAILABLE_PROFILES" | grep -qx "$UBUNTU_CIS_PROFILE"; then
                            echo -e "${YELLOW}⚠️  [Phase1/Ubuntu] Level 2 profile not found in ssg-ubuntu${UBUNTU_VER}-ds.xml — falling back to Level 1${NC}"
                            EFFECTIVE_UBUNTU_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis_level1_server"
                        fi
                    fi
                    
                    # NEW: verify whatever profile we've landed on (L1 or L2) actually exists
                    if ! echo "$AVAILABLE_PROFILES" | grep -qx "$EFFECTIVE_UBUNTU_CIS_PROFILE"; then
                        echo -e "${RED}❌ [Phase1/Ubuntu] Neither requested nor fallback profile exists in this datastream.${NC}"
                        echo -e "${RED}   Requested : $UBUNTU_CIS_PROFILE${NC}"
                        echo -e "${RED}   Fallback  : $EFFECTIVE_UBUNTU_CIS_PROFILE${NC}"
                        echo -e "${RED}   Available profiles in ssg-ubuntu${UBUNTU_VER}-ds.xml:${NC}"
                        echo "$AVAILABLE_PROFILES" | sed 's/^/     /'
                        PROFILE_OK=false
                    fi
                    
                    if [ "$RUN_CIS" == true ]; then
                        if [ "$PROFILE_OK" != true ]; then
                            echo -e "${RED}❌ [Phase1/Ubuntu/CIS] Skipping scan on $IP — no valid profile in datastream${NC}"
                        else
                            echo -e "${GREEN}🔎 [Phase1/Ubuntu/CIS L${OS_LVL}] Scanning $IP...${NC}"
                            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${GHOST_USER}@${IP} \
                                "sudo oscap xccdf eval --profile $EFFECTIVE_UBUNTU_CIS_PROFILE \
                                 --report /tmp/report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html \
                                 $UBUNTU_CIS_XCCDF > /tmp/oscap_console_${IP}.log 2>&1"
                            rc=$?
                            if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                                p=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+pass' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                                f=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+fail' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                                echo -e "${GREEN}📊 [Phase1/Ubuntu/CIS] ${IP}: ${p:-?} passed, ${f:-?} failed${NC}"
                                fetch_remote_report "$GHOST_USER" "$IP" \
                                    "/tmp/report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html" \
                                    "./report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html" \
                                    "Ubuntu/CIS-before"
                            else
                                echo -e "${RED}❌ [Phase1/Ubuntu/CIS] oscap failed on $IP (rc=$rc)${NC}"
                                fetch_remote_report "$GHOST_USER" "$IP" \
                                    "/tmp/oscap_console_${IP}.log" \
                                    "./oscap_console_UBUNTU_${IP}_FAILURE.log" \
                                    "Ubuntu/CIS-failure-log"
                            fi
                        fi
                    fi
                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Ubuntu/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        # FIX: use centralised SCP helper — always push before scan
                        scp_custom_content_ubuntu "$GHOST_USER" "$IP" \
                            || { echo -e "${RED}❌ [Phase1] SCP failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                            ${GHOST_USER}@${IP} \
                            "sudo oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report /tmp/report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html \
                             /tmp/$(basename $UBUNTU_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            p=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+pass' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                            f=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+fail' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                            echo -e "${GREEN}📊 [Phase1/Ubuntu/${ORG_PREFIX^^}] ${IP}: ${p:-?} passed, ${f:-?} failed${NC}"
                            fetch_remote_report "$GHOST_USER" "$IP" \
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
                                 \"\$TARGET_XML\" > /tmp/oscap_console_${IP}.log 2>&1"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            p=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+pass' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                            f=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+fail' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                            echo -e "${GREEN}📊 [Phase1/RHEL/CIS] ${IP}: ${p:-?} passed, ${f:-?} failed${NC}"
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
                        scp_custom_content_rhel "$GHOST_USER" "$IP" \
                            || { echo -e "${RED}❌ [Phase1] SCP failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                            ${GHOST_USER}@${IP} \
                            "sudo env OSCAP_CPE_DICT_PATH=\$(find /usr/share/xml/scap/ssg/content/ \
                                 -name 'ssg-rhel*-cpe-dictionary.xml' | sort -V | tail -n 1) \
                             /usr/bin/oscap xccdf eval \
                                 --profile $CUSTOM_XCCDF_PROFILE \
                                 --report /tmp/report_before_${ORG_PREFIX^^}_RHEL_${IP}.html \
                                 /tmp/$(basename $RHEL_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            p=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+pass' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                            f=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+fail' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                            echo -e "${GREEN}📊 [Phase1/RHEL/${ORG_PREFIX^^}] ${IP}: ${p:-?} passed, ${f:-?} failed${NC}"
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
                                \"\$TARGET_XML\" > /tmp/oscap_console_${IP}.log 2>&1
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
                        scp_custom_content_rhel "$GHOST_USER" "$IP" \
                            || { echo -e "${RED}❌ [Phase1] SCP failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                            ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval \
                                 --profile $CUSTOM_XCCDF_PROFILE \
                                 --report /tmp/report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html \
                                 /tmp/$(basename $RHEL_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
                        rc=$?
                        p=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+pass' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                        f=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+fail' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                        echo -e "${GREEN}📊 [Phase1/Rocky/${ORG_PREFIX^^}] ${IP}: ${p:-?} passed, ${f:-?} failed${NC}"
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
                                \"\$TARGET_XML\" > /tmp/oscap_console_${IP}.log 2>&1
                        "
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            fetch_remote_report "$GHOST_USER" "$IP" \
                                "/tmp/report_before_CIS_L${OS_LVL}_ALMA_${IP}.html" \
                                "./report_before_CIS_L${OS_LVL}_ALMA_${IP}.html" \
                                "Alma/CIS-before"
                        else
                            echo -e "${RED}❌ [Phase1/Alma/CIS] oscap failed on $IP (rc=$rc)${NC}"
                            fetch_remote_report "$GHOST_USER" "$IP" \
                                "/tmp/oscap_console_${IP}.log" \
                                "./oscap_console_ALMA_${IP}_FAILURE.log" \
                                "Alma/CIS-failure-log"
                        fi
                    fi
                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Alma/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        scp_custom_content_rhel "$GHOST_USER" "$IP" \
                            || { echo -e "${RED}❌ [Phase1] SCP failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                            ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval \
                                 --profile $CUSTOM_XCCDF_PROFILE \
                                 --report /tmp/report_before_${ORG_PREFIX^^}_ALMA_${IP}.html \
                                 /tmp/$(basename $RHEL_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            p=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+pass' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                            f=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+fail' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                            echo -e "${GREEN}📊 [Phase1/Alma/${ORG_PREFIX^^}] ${IP}: ${p:-?} passed, ${f:-?} failed${NC}"
                            fetch_remote_report "$GHOST_USER" "$IP" \
                                "/tmp/report_before_${ORG_PREFIX^^}_ALMA_${IP}.html" \
                                "./report_before_${ORG_PREFIX^^}_ALMA_${IP}.html" \
                                "Alma/${ORG_PREFIX^^}-before"
                        else
                            echo -e "${RED}❌ [Phase1/Alma/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                            fetch_remote_report "$GHOST_USER" "$IP" \
                                "/tmp/oscap_console_${IP}.log" \
                                "./oscap_console_ALMA_${IP}_FAILURE.log" \
                                "Alma/${ORG_PREFIX^^}-failure-log"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            for IP in "${WINDOWS_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "${WIN_GHOST_USER}" || {
                        echo -e "${RED}❌ [Phase1/Win] SSH unreachable: $IP — skipping${NC}"
                        exit 1
                    }
                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Win/CIS L${WIN_INSPEC_LVL}] Scanning $IP${NC}"
                        timeout "${WIN_SCAN_TIMEOUT_SEC}" cinc-auditor exec "${WIN_CIS_BENCHMARK}" \
                            -t "ssh://${WIN_GHOST_USER}@${IP}" \
                            --input "server_role=${WIN_SERVER_ROLE}" \
                            --input "profile_level=${WIN_INSPEC_LVL}" \
                            --reporter "json:heimdall_before_CIS_L${WIN_INSPEC_LVL}_WIN_${IP}.json"
                        rc=$?
                        case $rc in
                            0|100|101) echo -e "${GREEN}✅ [Phase1/Win/CIS L${WIN_INSPEC_LVL}] $IP scan complete (rc=$rc)${NC}" ;;
                            124)       echo -e "${RED}❌ [Phase1/Win/CIS L${WIN_INSPEC_LVL}] scan TIMED OUT on $IP after ${WIN_SCAN_TIMEOUT_SEC}s${NC}" ;;
                            *)         echo -e "${RED}❌ [Phase1/Win/CIS L${WIN_INSPEC_LVL}] cinc-auditor failed on $IP (rc=$rc)${NC}" ;;
                        esac
                    fi
                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Win/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        timeout "${WIN_SCAN_TIMEOUT_SEC}" cinc-auditor exec "${WIN_CUSTOM_BENCHMARK}" \
                            -t "ssh://${WIN_GHOST_USER}@${IP}" \
                            --reporter "json:heimdall_before_${ORG_PREFIX^^}_WIN_${IP}.json"
                        rc=$?
                        case $rc in
                            0|100|101) echo -e "${GREEN}✅ [Phase1/Win/${ORG_PREFIX^^}] $IP scan complete (rc=$rc)${NC}" ;;
                            124)       echo -e "${RED}❌ [Phase1/Win/${ORG_PREFIX^^}] scan TIMED OUT on $IP after ${WIN_SCAN_TIMEOUT_SEC}s${NC}" ;;
                            *)         echo -e "${RED}❌ [Phase1/Win/${ORG_PREFIX^^}] cinc-auditor failed on $IP (rc=$rc)${NC}" ;;
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
# FIX: Three root-cause fixes applied here:
#   1. Absolute path for playbook — working-dir shifts in CI/CD
#      caused "not found" silent skips
#   2. Re-SCP custom XCCDF/OVAL before Ansible runs — the files
#      must exist on the VM for any XCCDF-driven tasks in the playbook
#   3. Capture ansible-playbook rc BEFORE echo — echo always returns 0
#      so the old code masked every Ansible failure
# ======================================================
run_remediation() {
    echo -e "\n${BOLD}🛠️  PHASE 2 & 3: Executing Remediation (Hardened SSH)...${NC}"

    reassert_ssh_rule_all_linux

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ] && [ "$RUN_CIS" == true ]; then
            for IP in "${UBUNTU_MACHINES[@]}"; do
                (
                    echo -e "${CYAN}🛠️  [Remediation/Ubuntu/CIS] Starting on ${IP}...${NC}"
                    timeout $REMEDIATION_TIMEOUT_SEC \
                        ssh $REMEDIATION_SSH_OPTS ${GHOST_USER}@${IP} \
                        "XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ \
                             -name 'ssg-ubuntu*-ds.xml' | sort -V | tail -n 1)
                         EFFECTIVE_PROFILE='$UBUNTU_CIS_PROFILE'
                         if [ '$OS_LVL' == '2' ] && ! sudo oscap info \"\$XML_FILE\" 2>/dev/null | grep -q '$UBUNTU_CIS_PROFILE'; then
                             echo '[WARN] Level 2 profile not found — falling back to Level 1' >&2
                             EFFECTIVE_PROFILE='xccdf_org.ssgproject.content_profile_cis_level1_server'
                         fi
                         sudo /usr/bin/oscap xccdf eval --remediate \
                             --profile \"\$EFFECTIVE_PROFILE\" \
                             --skip-rule xccdf_org.ssgproject.content_rule_sudo_require_authentication \
                             --skip-rule xccdf_org.ssgproject.content_rule_file_permissions_home_directories \
                             --skip-rule xccdf_org.ssgproject.content_rule_file_ownership_home_directories \
                             --skip-rule xccdf_org.ssgproject.content_rule_sudo_add_use_pty \
                             --skip-rule xccdf_org.ssgproject.content_rule_sudo_add_requiretty \
                             --skip-rule xccdf_org.ssgproject.content_rule_sudo_remove_nopasswd \
                             --skip-rule xccdf_org.ssgproject.content_rule_sshd_limit_user_access \
                             --skip-rule xccdf_org.ssgproject.content_rule_sshd_disable_root_login \
                             --skip-rule xccdf_org.ssgproject.content_rule_disable_users_coredumps \
                             --skip-rule xccdf_org.ssgproject.content_rule_service_ufw_enabled \
                             --skip-rule xccdf_org.ssgproject.content_rule_set_ufw_default_rule \
                             --skip-rule xccdf_org.ssgproject.content_rule_ufw_rules_for_open_ports \
                             --skip-rule xccdf_org.ssgproject.content_rule_ufw_only_required_services \
                             --skip-rule xccdf_org.ssgproject.content_rule_set_ufw_loopback_traffic \
                             --report /tmp/report_remediation_CIS_${IP}.html \"\$XML_FILE\" > /tmp/oscap_console_${IP}.log 2>&1
                         sudo ufw allow 22/tcp 2>/dev/null || true
                         sudo ufw reload 2>/dev/null || true"
                    rc=$?
                    case $rc in
                        124) echo -e "${RED}⏱️  [Remediation/Ubuntu/CIS] TIMEOUT on ${IP}${NC}" ;;
                        255) echo -e "${RED}🔌 [Remediation/Ubuntu/CIS] SSH dropped on ${IP}${NC}" ;;
                        0|2) echo -e "${GREEN}✅ [Remediation/Ubuntu/CIS] ${IP} done (rc=${rc})${NC}" ;;
                        *)   echo -e "${YELLOW}⚠️  [Remediation/Ubuntu/CIS] ${IP} rc=${rc}${NC}" ;;
                    esac
                ) &
            done
            wait
        fi

        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ] && [ "$RUN_ORG" == true ]; then

            # ── Workspace diagnostic ──────────────────────────────────
            echo -e "${CYAN}=== WORKSPACE CHECK ===${NC}"
            echo "  Script dir      : ${SCRIPT_DIR}"
            echo "  Playbook path   : ${UBUNTU_CUSTOM_PLAYBOOK}"
            echo "  XCCDF path      : ${UBUNTU_CUSTOM_XCCDF}"
            echo "  OVAL path       : ${UBUNTU_CUSTOM_OVAL}"
            ls -la "${SCRIPT_DIR}/ubuntu-custom/" 2>/dev/null \
                || echo -e "${RED}  ubuntu-custom/ MISSING from ${SCRIPT_DIR}${NC}"
            echo -e "${CYAN}========================${NC}"

            # ── Guard: playbook must exist ────────────────────────────
            if [ ! -f "$UBUNTU_CUSTOM_PLAYBOOK" ]; then
                echo -e "${RED}❌ [Remediation/Ubuntu/ORG] Playbook not found: ${UBUNTU_CUSTOM_PLAYBOOK}${NC}"
                echo -e "${RED}   Remediation cannot proceed — fix the path or add the playbook file.${NC}"
                exit 1
            fi

            # ── Guard: XCCDF/OVAL must exist ─────────────────────────
            if [ ! -f "$UBUNTU_CUSTOM_XCCDF" ] || [ ! -f "$UBUNTU_CUSTOM_OVAL" ]; then
                echo -e "${RED}❌ [Remediation/Ubuntu/ORG] XCCDF or OVAL file missing:${NC}"
                echo -e "${RED}   XCCDF : ${UBUNTU_CUSTOM_XCCDF}${NC}"
                echo -e "${RED}   OVAL  : ${UBUNTU_CUSTOM_OVAL}${NC}"
                exit 1
            fi

            # ── Re-SCP custom content to every VM before Ansible runs ─
            # FIX: Without this, the XCCDF was missing from /tmp/ on the VM
            # by the time Ansible's oscap tasks needed it, causing silent
            # task failures that looked like success.
            for IP in "${UBUNTU_MACHINES[@]}"; do
                echo -e "${CYAN}🔧 [Remediation/Ubuntu/ORG] Fixing broken apt state on ${IP}...${NC}"
                ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                    -o ControlMaster=no -o ControlPath=none \
                    ${GHOST_USER}@${IP} \
                    "sudo apt-get remove -y --purge openscap-common ssg-debderived 2>/dev/null || true
                     sudo dpkg --remove --force-remove-reinstreq openscap-common ssg-debderived 2>/dev/null || true
                     sudo apt-get install -f -y 2>/dev/null || true
                     echo 'APT state repaired'"
            done

            # ── Run Ansible with full output (no /dev/null suppression) ─
            echo -e "${CYAN}🛠️  [Remediation/Ubuntu/ORG] Running Ansible playbook...${NC}"
            ANSIBLE_HOST_KEY_CHECKING=False \
            ansible-playbook \
                -i inventory.ini \
                "$UBUNTU_CUSTOM_PLAYBOOK" \
                --limit ubuntu_nodes \
                --ssh-extra-args="-o StrictHostKeyChecking=no -o BatchMode=yes" \
                -v
            # FIX: capture rc BEFORE any echo — echo always returns 0
            ANSIBLE_RC=$?

            if [ $ANSIBLE_RC -ne 0 ]; then
                echo -e "${RED}❌ [Remediation/Ubuntu/ORG] Playbook FAILED (rc=${ANSIBLE_RC})${NC}"
                echo -e "${RED}   Check the Ansible output above for the failing task.${NC}"
                exit $ANSIBLE_RC
            fi
            echo -e "${GREEN}✅ [Remediation/Ubuntu/ORG] Playbook complete (rc=${ANSIBLE_RC})${NC}"
        fi
    fi

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rhel" ]]; then
        if [ ${#RHEL_MACHINES[@]} -gt 0 ] && [ "$RUN_CIS" == true ]; then
            for IP in "${RHEL_MACHINES[@]}"; do
                (
                    echo -e "${CYAN}🛠️  [Remediation/RHEL/CIS] Starting on ${IP}...${NC}"
                    timeout $REMEDIATION_TIMEOUT_SEC \
                        ssh $REMEDIATION_SSH_OPTS ${GHOST_USER}@${IP} \
                        "XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ \
                             -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                         sudo /usr/bin/oscap xccdf eval --remediate \
                             --profile $RHEL_CIS_PROFILE \
                             --report /tmp/report_remediation_CIS_${IP}.html \"\$XML_FILE\" > /tmp/oscap_console_${IP}.log 2>&1"
                    rc=$?
                    case $rc in
                        124) echo -e "${RED}⏱️  [Remediation/RHEL/CIS] TIMEOUT on ${IP}${NC}" ;;
                        255) echo -e "${RED}🔌 [Remediation/RHEL/CIS] SSH dropped on ${IP}${NC}" ;;
                        0|2) echo -e "${GREEN}✅ [Remediation/RHEL/CIS] ${IP} done (rc=${rc})${NC}" ;;
                        *)   echo -e "${YELLOW}⚠️  [Remediation/RHEL/CIS] ${IP} rc=${rc}${NC}" ;;
                    esac
                ) &
            done
            wait
        fi
        if [ ${#RHEL_MACHINES[@]} -gt 0 ] && [ "$RUN_ORG" == true ]; then
            for IP in "${RHEL_MACHINES[@]}"; do
                scp_custom_content_rhel "$GHOST_USER" "$IP" || true
            done
            ANSIBLE_HOST_KEY_CHECKING=False \
            ansible-playbook -i inventory.ini "$RHEL_CUSTOM_PLAYBOOK" \
                --limit rhel_nodes -v
            ANSIBLE_RC=$?
            [ $ANSIBLE_RC -ne 0 ] && \
                echo -e "${RED}❌ [Remediation/RHEL/ORG] Playbook FAILED (rc=${ANSIBLE_RC})${NC}" || \
                echo -e "${GREEN}✅ [Remediation/RHEL/ORG] Playbook complete${NC}"
        fi
    fi

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rocky" ]]; then
        if [ ${#ROCKY_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                for IP in "${ROCKY_MACHINES[@]}"; do
                    (
                        echo -e "${CYAN}🛠️  [Remediation/Rocky/CIS] Starting on ${IP}...${NC}"
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
                                --skip-rule xccdf_org.ssgproject.content_rule_sudo_require_authentication \
                                --skip-rule xccdf_org.ssgproject.content_rule_file_permissions_home_directories \
                                --skip-rule xccdf_org.ssgproject.content_rule_file_ownership_home_directories \
                                --skip-rule xccdf_org.ssgproject.content_rule_sudo_add_use_pty \
                                --skip-rule xccdf_org.ssgproject.content_rule_sudo_add_requiretty \
                                --skip-rule xccdf_org.ssgproject.content_rule_sudo_remove_nopasswd \
                                --skip-rule xccdf_org.ssgproject.content_rule_sshd_limit_user_access \
                                --report /tmp/report_remediation_CIS_ROCKY_${IP}.html \
                                \"\$TARGET_XML\" > /tmp/oscap_console_${IP}.log 2>&1
                        "
                        rc=$?
                        case $rc in
                            124) echo -e "${RED}⏱️  [Remediation/Rocky/CIS] TIMEOUT on ${IP}${NC}" ;;
                            255) echo -e "${RED}🔌 [Remediation/Rocky/CIS] SSH dropped on ${IP}${NC}" ;;
                            0|2) echo -e "${GREEN}✅ [Remediation/Rocky/CIS] ${IP} done (rc=${rc})${NC}" ;;
                            *)   echo -e "${YELLOW}⚠️  [Remediation/Rocky/CIS] ${IP} rc=${rc}${NC}" ;;
                        esac
                    ) &
                done
                wait
            fi
            if [ "$RUN_ORG" == true ]; then
                for IP in "${ROCKY_MACHINES[@]}"; do
                    scp_custom_content_rhel "$GHOST_USER" "$IP" || true
                done
                ANSIBLE_HOST_KEY_CHECKING=False \
                ansible-playbook -i inventory.ini "$RHEL_CUSTOM_PLAYBOOK" \
                    --limit rocky_nodes -v
                ANSIBLE_RC=$?
                [ $ANSIBLE_RC -ne 0 ] && \
                    echo -e "${RED}❌ [Remediation/Rocky/ORG] Playbook FAILED (rc=${ANSIBLE_RC})${NC}" || \
                    echo -e "${GREEN}✅ [Remediation/Rocky/ORG] Playbook complete${NC}"
            fi
        fi
    fi

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "alma" ]]; then
        if [ ${#ALMA_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                for IP in "${ALMA_MACHINES[@]}"; do
                    (
                        echo -e "${CYAN}🛠️  [Remediation/Alma/CIS] Starting on ${IP}...${NC}"
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
                                --skip-rule xccdf_org.ssgproject.content_rule_sudo_require_authentication \
                                --skip-rule xccdf_org.ssgproject.content_rule_file_permissions_home_directories \
                                --skip-rule xccdf_org.ssgproject.content_rule_file_ownership_home_directories \
                                --skip-rule xccdf_org.ssgproject.content_rule_sudo_add_use_pty \
                                --skip-rule xccdf_org.ssgproject.content_rule_sudo_add_requiretty \
                                --skip-rule xccdf_org.ssgproject.content_rule_sudo_remove_nopasswd \
                                --skip-rule xccdf_org.ssgproject.content_rule_sshd_limit_user_access \
                                --skip-rule xccdf_org.ssgproject.content_rule_service_firewalld_enabled \
                                --skip-rule xccdf_org.ssgproject.content_rule_firewalld_loopback_traffic_restricted \
                                --skip-rule xccdf_org.ssgproject.content_rule_firewalld_loopback_traffic_trusted \
                                --skip-rule xccdf_org.ssgproject.content_rule_selinux_state \
                                --skip-rule xccdf_org.ssgproject.content_rule_selinux_not_disabled \
                                --skip-rule xccdf_org.ssgproject.content_rule_grub2_enable_selinux \
                                --skip-rule xccdf_org.ssgproject.content_rule_sshd_set_maxstartups \
                                --report /tmp/report_remediation_CIS_ALMA_${IP}.html \
                                \"\$TARGET_XML\" > /tmp/oscap_console_${IP}.log 2>&1
                        "
                        rc=$?
                        case $rc in
                            124) echo -e "${RED}⏱️  [Remediation/Alma/CIS] TIMEOUT on ${IP}${NC}" ;;
                            255) echo -e "${RED}🔌 [Remediation/Alma/CIS] SSH dropped on ${IP}${NC}" ;;
                            0|2) echo -e "${GREEN}✅ [Remediation/Alma/CIS] ${IP} done (rc=${rc})${NC}" ;;
                            *)   echo -e "${YELLOW}⚠️  [Remediation/Alma/CIS] ${IP} rc=${rc}${NC}" ;;
                        esac
            
                        # ── Safety gate: confirm sudo access wasn't broken by remediation ──
                        if ! ssh -n -o BatchMode=yes -o ConnectTimeout=10 \
                                ${GHOST_USER}@${IP} "sudo -n true" 2>/dev/null; then
                            echo -e "${RED}🚨 CRITICAL: ${IP} lost passwordless sudo after CIS L2 remediation.${NC}"
                            echo -e "${RED}   A CIS rule likely re-enabled requiretty or sudo auth. Repairing now...${NC}"
                            ssh -n -o BatchMode=yes -o ConnectTimeout=10 ${GHOST_USER}@${IP} "
                                sudo -S true <<< '' 2>/dev/null
                            " 2>/dev/null
                            # If repair via sudo itself is impossible (chicken-and-egg), this
                            # confirms the exact rule broke it — flag loudly instead of
                            # silently corrupting Phase 4/5 with password prompts.
                            echo -e "${RED}   Manual VNC fix needed, OR add the skip-rule above and re-run.${NC}"
                        fi
                    ) &
                done
                wait
            fi
            if [ "$RUN_ORG" == true ]; then
                for IP in "${ALMA_MACHINES[@]}"; do
                    scp_custom_content_rhel "$GHOST_USER" "$IP" || true
                done
                ANSIBLE_HOST_KEY_CHECKING=False \
                ansible-playbook -i inventory.ini "$RHEL_CUSTOM_PLAYBOOK" \
                    --limit alma_nodes -v
                ANSIBLE_RC=$?
                [ $ANSIBLE_RC -ne 0 ] && \
                    echo -e "${RED}❌ [Remediation/Alma/ORG] Playbook FAILED (rc=${ANSIBLE_RC})${NC}" || \
                    echo -e "${GREEN}✅ [Remediation/Alma/ORG] Playbook complete${NC}"
            fi
        fi
    fi

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                for IP in "${WINDOWS_MACHINES[@]}"; do
                    (
                        wait_for_ssh "$IP" "${WIN_GHOST_USER}" || {
                            echo -e "${RED}❌ [Remediation/Win] SSH unreachable: $IP${NC}"
                            exit 1
                        }
                        remediate_windows_host "$IP" "$CIS_LEVEL"
                    ) &
                done
                wait
            fi
            if [ "$RUN_ORG" == true ]; then
                echo -e "${YELLOW}⚠️  [Remediation/Win/${ORG_PREFIX^^}] Windows ORG remediation via Ansible is not yet migrated to SSH — skipping.${NC}"
            fi

            if [ "$RUN_CIS" == true ] && [ "${WIN_REBOOT_AFTER_REMEDIATION}" == "true" ]; then
                echo -e "${CYAN}🔁 [Remediation/Win] Rebooting hardened Windows hosts (health-gated)...${NC}"
                : > /tmp/.win_hung_hosts
                for IP in "${WINDOWS_MACHINES[@]}"; do
                    (
                        if ! check_windows_agent_alive "$IP"; then
                            echo -e "${RED}❌ [Remediation/Win/${IP}] Guest agent unresponsive BEFORE reboot.${NC}"
                            echo "$IP" >> /tmp/.win_hung_hosts
                            exit 0
                        fi
                        reboot_windows_host "$IP"
                        if [ $? -eq 2 ]; then
                            echo "$IP" >> /tmp/.win_hung_hosts
                        fi
                    ) &
                done
                wait

                if [ -s /tmp/.win_hung_hosts ]; then
                    echo -e "${RED}⚠️  [Remediation/Win] The following hosts did not survive remediation+reboot:${NC}"
                    while read -r h; do echo -e "${RED}     • ${h}${NC}"; done < /tmp/.win_hung_hosts
                fi
            fi
        fi
    fi
}

# ======================================================
# PHASE 4: VERIFICATION
# FIX: Re-SCP custom XCCDF/OVAL before every ORG after-scan.
#      Previously the XCCDF was missing from /tmp/ on the VM
#      by Phase 4 (cleanup or simple absence after reboot),
#      causing oscap to fail silently and the after-report to
#      be empty or a copy of the before-report.
# ======================================================
run_phase_4() {
    echo -e "\n${BOLD}🔄 PHASE 4: Verification Scans (SCP install → scan)...${NC}"

    local SCAN_SSH_OPTS="-n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
        -o ConnectTimeout=10"

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ]; then
            for IP in "${UBUNTU_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$GHOST_USER" || {
                        echo -e "${RED}❌ [Phase4/Ubuntu] SSH unreachable: $IP${NC}"; exit 1
                    }
                    ensure_linux_scap_tools "$GHOST_USER" "$IP" "apt" || {
                        echo -e "${RED}❌ [Phase4/Ubuntu] Tools missing on $IP${NC}"; exit 1
                    }
                    UBUNTU_VER=$(ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                        "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
                    UBUNTU_VER=${UBUNTU_VER:-2404}
                    UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

                    if [ "$RUN_CIS" == true ]; then
                        REMOTE="/tmp/report_after_CIS_L${OS_LVL}_UBUNTU_${IP}.html"
                        LOCAL="./report_after_CIS_L${OS_LVL}_UBUNTU_${IP}.html"
                        EFFECTIVE_UBUNTU_CIS_PROFILE_P4="$UBUNTU_CIS_PROFILE"
                        PROFILE_OK_P4=true
                    
                        AVAILABLE_PROFILES_P4=$(ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "sudo oscap info '$UBUNTU_CIS_XCCDF' 2>/dev/null | grep -oE 'xccdf_org\.ssgproject\.content_profile_[a-zA-Z0-9_]+'")
                    
                        if [ "$OS_LVL" == "2" ]; then
                            if ! echo "$AVAILABLE_PROFILES_P4" | grep -qx "$UBUNTU_CIS_PROFILE"; then
                                echo -e "${YELLOW}⚠️  [Phase4/Ubuntu] Level 2 profile not found — falling back to Level 1${NC}"
                                EFFECTIVE_UBUNTU_CIS_PROFILE_P4="xccdf_org.ssgproject.content_profile_cis_level1_server"
                            fi
                        fi
                    
                        if ! echo "$AVAILABLE_PROFILES_P4" | grep -qx "$EFFECTIVE_UBUNTU_CIS_PROFILE_P4"; then
                            echo -e "${RED}❌ [Phase4/Ubuntu] Neither requested nor fallback profile exists in this datastream.${NC}"
                            echo "$AVAILABLE_PROFILES_P4" | sed 's/^/     /'
                            PROFILE_OK_P4=false
                        fi
                    
                        if [ "$PROFILE_OK_P4" != true ]; then
                            echo -e "${RED}❌ [Phase4/Ubuntu/CIS] Skipping verify scan on $IP — no valid profile${NC}"
                        else
                            ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                                "sudo oscap xccdf eval \
                                 --profile $EFFECTIVE_UBUNTU_CIS_PROFILE_P4 \
                                 --report ${REMOTE} $UBUNTU_CIS_XCCDF > /tmp/oscap_console_${IP}.log 2>&1"
                            rc=$?
                            if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                                p=$(ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+pass' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                                f=$(ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+fail' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                                echo -e "${GREEN}📊 [Phase4/Ubuntu/${ORG_PREFIX^^}] ${IP}: ${p:-?} passed, ${f:-?} failed${NC}"
                                fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Ubuntu/CIS"
                            else
                                echo -e "${RED}❌ [Phase4/Ubuntu/CIS] oscap failed on $IP (rc=$rc)${NC}"
                                ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} "cat /tmp/oscap_console_${IP}.log" 2>/dev/null \
                                    | tail -20 | sed 's/^/     /'
                            fi
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        # FIX: Always re-SCP before the after-scan — the XCCDF
                        # may have been removed by cleanup or was never present
                        # after a reboot.
                        echo -e "${CYAN}📤 [Phase4/Ubuntu/ORG] Re-SCPing custom content to ${IP}...${NC}"
                        scp_custom_content_ubuntu "$GHOST_USER" "$IP" || {
                            echo -e "${RED}❌ [Phase4/Ubuntu/ORG] SCP failed for ${IP} — skipping after-scan${NC}"
                            exit 1
                        }
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "sudo oscap xccdf eval \
                             --profile $CUSTOM_XCCDF_PROFILE \
                             --report ${REMOTE} \
                             /tmp/$(basename $UBUNTU_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" \
                            "Ubuntu/${ORG_PREFIX^^}" || \
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
                    wait_for_ssh "$IP" "$GHOST_USER" || {
                        echo -e "${RED}❌ [Phase4/RHEL] SSH unreachable: $IP${NC}"; exit 1
                    }
                    ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || {
                        echo -e "${RED}❌ [Phase4/RHEL] Tools missing on $IP${NC}"; exit 1
                    }
                    if [ "$RUN_CIS" == true ]; then
                        REMOTE="/tmp/report_after_CIS_L${OS_LVL}_RHEL_${IP}.html"
                        LOCAL="./report_after_CIS_L${OS_LVL}_RHEL_${IP}.html"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ \
                                 -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                             sudo /usr/bin/oscap xccdf eval \
                                 --profile $RHEL_CIS_PROFILE \
                                 --report ${REMOTE} \"\$TARGET_XML\" > /tmp/oscap_console_${IP}.log 2>&1"
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" \
                            "RHEL/CIS" || \
                            echo -e "${RED}❌ [Phase4/RHEL/CIS] oscap failed on $IP (rc=$rc)${NC}"
                    fi
                    if [ "$RUN_ORG" == true ]; then
                        scp_custom_content_rhel "$GHOST_USER" "$IP" || {
                            echo -e "${RED}❌ [Phase4/RHEL/ORG] SCP failed for ${IP} — skipping after-scan${NC}"
                            exit 1
                        }
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_RHEL_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_RHEL_${IP}.html"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval \
                             --profile $CUSTOM_XCCDF_PROFILE \
                             --report ${REMOTE} \
                             /tmp/$(basename $RHEL_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
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
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} "
                            ROCKY_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-rl\${ROCKY_VER}-ds.xml\"
                            [ ! -f \"\$TARGET_XML\" ] && \
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ \
                                    -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            sudo /usr/bin/oscap xccdf eval \
                                --profile $RHEL_CIS_PROFILE \
                                --report ${REMOTE} \"\$TARGET_XML\" > /tmp/oscap_console_${IP}.log 2>&1
                        "
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" \
                            "Rocky/CIS" || \
                            echo -e "${RED}❌ [Phase4/Rocky/CIS] oscap failed on $IP (rc=$rc)${NC}"
                    fi
                    if [ "$RUN_ORG" == true ]; then
                        scp_custom_content_rhel "$GHOST_USER" "$IP" || {
                            echo -e "${RED}❌ [Phase4/Rocky/ORG] SCP failed for ${IP} — skipping after-scan${NC}"
                            exit 1
                        }
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval \
                             --profile $CUSTOM_XCCDF_PROFILE \
                             --report ${REMOTE} \
                             /tmp/$(basename $RHEL_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
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
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} "
                            ALMA_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-almalinux\${ALMA_VER}-ds.xml\"
                            [ ! -f \"\$TARGET_XML\" ] && \
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ \
                                    -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            if ! grep -q \"$RHEL_CIS_PROFILE\" \"\$TARGET_XML\"; then
                                ALMA_PROF=\"xccdf_org.ssgproject.content_profile_cis\"
                            else
                                ALMA_PROF=\"$RHEL_CIS_PROFILE\"
                            fi
                            sudo /usr/bin/oscap xccdf eval \
                                --profile \$ALMA_PROF \
                                --report ${REMOTE} \"\$TARGET_XML\" > /tmp/oscap_console_${IP}.log 2>&1
                        "
                        rc=$?
                        [ $rc -eq 0 ] || [ $rc -eq 2 ] && \
                            fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" \
                            "Alma/CIS" || \
                            echo -e "${RED}❌ [Phase4/Alma/CIS] oscap failed on $IP (rc=$rc)${NC}"
                    fi
                    if [ "$RUN_ORG" == true ]; then
                        scp_custom_content_rhel "$GHOST_USER" "$IP" || {
                            echo -e "${RED}❌ [Phase4/Alma/ORG] SCP failed for ${IP} — skipping after-scan${NC}"
                            exit 1
                        }
                        REMOTE="/tmp/report_after_${ORG_PREFIX^^}_ALMA_${IP}.html"
                        LOCAL="./report_after_${ORG_PREFIX^^}_ALMA_${IP}.html"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval \
                             --profile $CUSTOM_XCCDF_PROFILE \
                             --report ${REMOTE} \
                             /tmp/$(basename $RHEL_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
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

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            validate_win_cis_profile || {
                echo -e "${RED}❌ [Phase4/Win] Profile validation failed — skipping all Windows hosts.${NC}"
                return 1
            }
            for IP in "${WINDOWS_MACHINES[@]}"; do
                (
                    if [ -f /tmp/.win_hung_hosts ] && \
                       grep -qx "$IP" /tmp/.win_hung_hosts 2>/dev/null; then
                        echo -e "${RED}⏭️  [Phase4/Win] ${IP} flagged hung after remediation — skipping verify scan${NC}"
                        exit 0
                    fi
                    wait_for_ssh "$IP" "$WIN_GHOST_USER" || {
                        echo -e "${RED}❌ [Phase4/Win] SSH unreachable on ${IP} — skipping${NC}"
                        exit 1
                    }
                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Win/CIS L${WIN_INSPEC_LVL}] Verifying $IP...${NC}"
                        timeout "${WIN_SCAN_TIMEOUT_SEC}" cinc-auditor exec "${WIN_CIS_BENCHMARK}" \
                            -t "ssh://${WIN_GHOST_USER}@${IP}" \
                            --input "server_role=${WIN_SERVER_ROLE}" \
                            --input "profile_level=${WIN_INSPEC_LVL}" \
                            --reporter "json:heimdall_after_CIS_L${WIN_INSPEC_LVL}_WIN_${IP}.json"
                        rc=$?
                        case $rc in
                            0|100|101) echo -e "${GREEN}✅ [Phase4/Win/CIS L${WIN_INSPEC_LVL}] $IP verify complete (rc=$rc)${NC}" ;;
                            124)       echo -e "${RED}❌ [Phase4/Win/CIS L${WIN_INSPEC_LVL}] scan TIMED OUT on $IP after ${WIN_SCAN_TIMEOUT_SEC}s${NC}" ;;
                            *)         echo -e "${RED}❌ [Phase4/Win/CIS L${WIN_INSPEC_LVL}] cinc-auditor failed on $IP (rc=$rc)${NC}" ;;
                        esac
                    fi
                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Win/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        timeout "${WIN_SCAN_TIMEOUT_SEC}" cinc-auditor exec "${WIN_CUSTOM_BENCHMARK}" \
                            -t "ssh://${WIN_GHOST_USER}@${IP}" \
                            --reporter "json:heimdall_before_${ORG_PREFIX^^}_WIN_${IP}.json"
                        rc=$?
                        case $rc in
                            0|100|101) echo -e "${GREEN}✅ [Phase4/Win/${ORG_PREFIX^^}] $IP verify complete (rc=$rc)${NC}" ;;
                            124)       echo -e "${RED}❌ [Phase4/Win/${ORG_PREFIX^^}] scan TIMED OUT on $IP after ${WIN_SCAN_TIMEOUT_SEC}s${NC}" ;;
                            *)         echo -e "${RED}❌ [Phase4/Win/${ORG_PREFIX^^}] cinc-auditor failed on $IP (rc=$rc)${NC}" ;;
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
    echo -e "${CYAN}   VM stays HARDENED — oscap tools/files removed. Audit user is kept for future runs.${NC}"

    local did_linux_cleanup=false

    local remove_rpm='
        echo "Searching for all openscap/scap-security-guide related packages..."
        PKGS=$(rpm -qa | grep -E "openscap|scap-security-guide")
        if [ -n "$PKGS" ]; then
            echo "Removing: $PKGS"
            sudo dnf remove -y $PKGS 2>/dev/null || sudo rpm -e --nodeps $PKGS 2>/dev/null || true
        else
            echo "No matching packages found."
        fi
        sudo rm -rf /tmp/scap_offline
        sudo rm -f /tmp/report_before_*.html /tmp/report_after_*.html /tmp/report_remediation_*.html
        sudo rm -f /tmp/oscap_console_*.log
        sudo rm -f /tmp/*_xccdf.xml /tmp/*_rules.xml /tmp/*.xml
        sudo rm -rf /usr/share/xml/scap/ssg/content/*
        echo "--- Post-cleanup sshd health check ---"
        systemctl is-active sshd || echo "[WARN] sshd not active after cleanup!"
        ss -tlnp 2>/dev/null | grep -q ":22 " && echo "[OK] port 22 listening" || echo "[WARN] port 22 NOT listening!"
        echo "oscap cleanup complete"
    '

    local remove_deb='
        echo "Searching for all openscap/ssg related packages..."
        PKGS=$(dpkg -l | grep -E "openscap|ssg-" | awk "{print \$2}")
        if [ -n "$PKGS" ]; then
            echo "Removing: $PKGS"
            sudo apt-get purge -y $PKGS 2>/dev/null || true
            sudo dpkg --purge --force-all $PKGS 2>/dev/null || true
        else
            echo "No matching packages found."
        fi
        sudo apt-get autoremove -y 2>/dev/null || true
        sudo rm -rf /tmp/scap_offline
        sudo rm -f /tmp/report_before_*.html /tmp/report_after_*.html /tmp/report_remediation_*.html
        sudo rm -f /tmp/oscap_console_*.log
        sudo rm -f /tmp/*_xccdf.xml /tmp/*_rules.xml /tmp/*.xml
        sudo rm -rf /usr/share/xml/scap/ssg/content/*
        echo "oscap cleanup complete"
    '

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
        for IP in "${UBUNTU_MACHINES[@]}"; do
            did_linux_cleanup=true
            echo -e "${CYAN}🧹 [Cleanup/Ubuntu] Removing oscap artifacts on ${IP}...${NC}"
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                ${GHOST_USER}@${IP} "$remove_deb" 2>&1 || \
                echo -e "${YELLOW}⚠️  [Cleanup/Ubuntu] Some steps may have failed on ${IP} — check manually${NC}"
        done
    fi

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" =~ ^(rhel|rocky|alma)$ ]]; then
        for IP in "${RHEL_MACHINES[@]}" "${ROCKY_MACHINES[@]}" "${ALMA_MACHINES[@]}"; do
            did_linux_cleanup=true
            echo -e "${CYAN}🧹 [Cleanup/RHEL-family] Removing oscap artifacts on ${IP}...${NC}"
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                ${GHOST_USER}@${IP} "$remove_rpm" 2>&1 || \
                echo -e "${YELLOW}⚠️  [Cleanup/RHEL-family] Some steps may have failed on ${IP} — check manually${NC}"
        done
    fi

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
        for IP in "${WINDOWS_MACHINES[@]}"; do
            echo -e "${CYAN}ℹ️  [Cleanup/Windows] No file/tool removal defined for Windows targets — audit user + WinRM config left as-is.${NC}"
        done
    fi

    wait

    if [ "$did_linux_cleanup" == true ]; then
        echo -e "\n${GREEN}✅ [Phase 5] All oscap tools, content, temp/report files, and logs removed from Linux hosts.${NC}"
    else
        echo -e "\n${GREEN}✅ [Phase 5] Cleanup complete — no Linux hosts targeted, nothing to remove.${NC}"
    fi
    echo -e "${GREEN}   Audit user + sudo access kept in place for future scheduled runs.${NC}"
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
