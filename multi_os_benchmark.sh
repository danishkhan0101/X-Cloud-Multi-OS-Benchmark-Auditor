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

CLOUD_PROVIDER="${CLOUD_PROVIDER:-azure}"

HW_REGION="${HW_REGION:-ap-southeast-1}"
HW_PROJECT_ID="${HW_PROJECT_ID:-}"
HW_ECS_TAG_KEY="${HW_ECS_TAG_KEY:-Environment}"
HW_ECS_TAG_VAL="${HW_ECS_TAG_VAL:-}"
HW_CSMS_SECRET="${HW_CSMS_SECRET:-AuditPassword}"
HW_VPC_ID="${HW_VPC_ID:-}"
HW_ECS_ENDPOINT="${HW_ECS_ENDPOINT:-https://ecs.${HW_REGION}.alphaedge.tmone.com.my}"

WIN_SERVER_ROLE="${WIN_SERVER_ROLE:-member_server}"
WIN_REBOOT_AFTER_REMEDIATION="${WIN_REBOOT_AFTER_REMEDIATION:-true}"
WIN_REBOOT_SETTLE_SEC="${WIN_REBOOT_SETTLE_SEC:-45}"
WIN_AGENT_PROBE_SEC="${WIN_AGENT_PROBE_SEC:-180}"
WIN_REBOOT_HEALTH_WAIT_SEC="${WIN_REBOOT_HEALTH_WAIT_SEC:-360}"
WIN_SCAN_TIMEOUT_SEC="${WIN_SCAN_TIMEOUT_SEC:-1200}"

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
        # FIX 1: was missing && between rm and mkdir — rm was treating "mkdir" as an argument
        rm -rf "${SCAP_CACHE_DIR}/ubuntu2204/"* && mkdir -p "${SCAP_CACHE_DIR}/ubuntu2204/"
        echo -e "${CYAN}   Fetching Ubuntu 22.04 packages via Docker...${NC}"
        # FIX 4: ubuntu:22.04 Docker image only enables 'main' by default; ssg-base is in
        # 'universe'. Without explicitly adding universe, apt-get exits non-zero, the &&
        # chain breaks, cp never runs, and the cache directory stays empty.
        # Solution: add universe explicitly, then install packages with || true so the
        # cp always runs even if an optional package isn't found.
        # FIX 5: Run each package group as a separate download command.
        # When openscap-scanner and ssg-base were combined in one command, any
        # dependency conflict silently failed the whole command (2>/dev/null || true)
        # and neither ended up in the cache — so oscap was never installed on the VM.
        # Splitting them means a failure in one package group cannot block the others.
        # Also adding jammy-updates universe for the latest patched package versions.
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
        # FIX 1 (same): was `rm ... * mkdir -p ...` — missing && caused rm to treat mkdir as arg
        rm -rf "${SCAP_CACHE_DIR}/ubuntu2404/"* && mkdir -p "${SCAP_CACHE_DIR}/ubuntu2404/"
        echo -e "${CYAN}   Fetching Ubuntu 24.04 packages via Docker...${NC}"
        # ubuntu:24.04 ships with universe pre-enabled; using || true for consistency
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

  # FIX 9: GitHub release CDN (objects.githubusercontent.com) is blocked from
    # the runner network even though api.github.com is reachable. All previous
    # curl/tar approaches fail because the download redirect target is unreachable.
    #
    # Solution: download ssg-debderived from Ubuntu 24.04 noble's apt archive
    # (archive.ubuntu.com IS reachable). Noble's ssg-debderived (~v0.1.72) contains
    # BOTH ssg-ubuntu2204-ds.xml and ssg-ubuntu2404-ds.xml. We extract the xmls
    # from the deb on the runner and also carry the deb to the VM cache so the
    # air-gapped VM can dpkg-deb -x it without needing internet.
    # GitHub releases are still tried as a secondary fallback for cases where the
    # CDN IS reachable, but a failure there no longer aborts prefetch.
    if $need_ubuntu; then
        echo -e "${CYAN}   Fetching SCAP datastreams via ssg-debderived (Docker install)...${NC}"
        local ds_tmp
        ds_tmp=$(mktemp -d /tmp/ssg_ds_XXXXXX)
        chmod 777 "${ds_tmp}"

        # Install ssg-debderived properly (not download-only) so transitive
        # dependencies also install and all datastreams land in the expected path.
        # Then copy whatever ubuntu*-ds.xml files exist directly to output.
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

        # Distribute whatever datastreams were found to the right cache dirs
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

        # Also download the deb for air-gapped VM fallback
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

        # If ubuntu2404 still has no datastream, try jammy's ssg-debderived
        # (some versions shipped 2404 content backported to jammy repos)
        if ! ls "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" >/dev/null 2>&1; then
            echo -e "${YELLOW}   ⚠️  2404 datastream not in noble ssg-debderived — trying jammy...${NC}"
            local ds_tmp22
            ds_tmp22=$(mktemp -d /tmp/ssg_ds22_XXXXXX)
            chmod 777 "${ds_tmp22}"
            docker run --rm \
                -v "${ds_tmp22}:/output" \
                ubuntu:22.04 \
                bash -c "
                    export DEBIAN_FRONTEND=noninteractive
                    apt-get update -qq 2>/dev/null
                    echo 'deb http://archive.ubuntu.com/ubuntu jammy universe' \
                        >> /etc/apt/sources.list
                    echo 'deb http://archive.ubuntu.com/ubuntu jammy-updates universe' \
                        >> /etc/apt/sources.list
                    apt-get update -qq 2>/dev/null
                    apt-get install -y --no-install-recommends \
                        ssg-debderived ssg-base 2>/dev/null || true
                    find /usr/share/xml/scap/ssg/content/ \
                        -name 'ssg-ubuntu*-ds.xml' \
                        -exec cp -v {} /output/ \; 2>/dev/null || true
                " 2>/dev/null || true

            for _ds_file in "${ds_tmp22}"/ssg-ubuntu*-ds.xml; do
                [ -f "$_ds_file" ] || continue
                _fname=$(basename "$_ds_file")
                [[ "$_fname" == *"2404"* ]] && \
                    cp -f "$_ds_file" "${SCAP_CACHE_DIR}/ubuntu2404/" && \
                    echo -e "${GREEN}   ✅ ${_fname} from jammy → ubuntu2404 cache${NC}"
            done
            rm -rf "${ds_tmp22}"
        fi

        # Last resort: copy 2204 datastream as 2404 fallback.
        # The 2204 profile runs successfully against 22.04 VMs. For actual 24.04
        # VMs the scan will warn about profile mismatch but still complete.
        # This is only reached if no 2404 content exists in any Ubuntu package.
        if ! ls "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" >/dev/null 2>&1; then
            if ls "${SCAP_CACHE_DIR}/ubuntu2204/ssg-ubuntu2204-ds.xml" >/dev/null 2>&1; then
                echo -e "${YELLOW}   ⚠️  No 2404 datastream available — using 2204 as fallback for ubuntu2404 cache${NC}"
                cp -f "${SCAP_CACHE_DIR}/ubuntu2204/ssg-ubuntu2204-ds.xml" \
                    "${SCAP_CACHE_DIR}/ubuntu2404/" 2>/dev/null || true
            fi
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
        # FIX 8 (cont.): Ubuntu caches must contain the SCAP datastream xml.
        # Without this check, a Docker success + SSG download failure produces a
        # non-empty cache (deb files only) that passes the empty-dir check above
        # but leaves the VM without a datastream → exit 11 on the remote host.
        if [[ "${d}" == ubuntu* ]]; then
            if ! ls "${SCAP_CACHE_DIR}/${d}/ssg-"*.xml >/dev/null 2>&1; then
                # If the sibling cache has a datastream, warn but don't fail —
                # the last-resort copy above ensures at least one xml per cache dir.
                # A hard failure here would block all Ubuntu scans when 24.04 content
                # simply isn't packaged yet in the available apt repos.
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
        return 1
    fi

    local vm_name="${IP_TO_VM_NAME[$ip]:-}"
    if [ -z "$vm_name" ]; then
        echo -e "${RED}❌ [WinPS1] No VM name mapped for IP ${ip}${NC}"
        return 1
    fi

    local sections_arg=""
    if [ -n "$sections" ]; then
        local quoted
        quoted=$(echo "$sections" | tr ' ' '\n' | awk '{printf "\"%s\",",$0}' | sed 's/,$//')
        sections_arg="-Sections @(${quoted})"
    fi

    echo -e "${CYAN}📤 [WinPS1/${ip}] Uploading + running Invoke-CISRemediation-Combined.ps1${NC}"

    local encoded_main
    encoded_main=$(base64 -w0 < "$WIN_PS1_REMEDIATE")

    cloud_vm_run_powershell "$ip" "
\$ErrorActionPreference = 'Continue'
[IO.File]::WriteAllBytes('C:\Windows\Temp\Invoke-CISRemediation-Combined.ps1',
    [Convert]::FromBase64String('${encoded_main}'))
& 'C:\Windows\Temp\Invoke-CISRemediation-Combined.ps1' \`
    -ServerRole '${WIN_SERVER_ROLE}' \`
    ${sections_arg}
Remove-Item 'C:\Windows\Temp\Invoke-CISRemediation-Combined.ps1' \`
    -Force -ErrorAction SilentlyContinue
" 2>/dev/null

    local rc=$?
    if [ $rc -eq 0 ]; then
        echo -e "${GREEN}✅ [WinPS1/${ip}] PS1 remediation complete (role=${WIN_SERVER_ROLE})${NC}"
    elif [ $rc -eq 1 ] && [ "${CLOUD_PROVIDER}" == "huaweicloud" ]; then
        echo -e "${RED}❌ [WinPS1/${ip}] PS1 remediation via agent channel not available on Huawei Cloud.${NC}"
    else
        echo -e "${RED}❌ [WinPS1/${ip}] run-command failed (rc=${rc})${NC}"
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
        # FIX 6: The old `apt-get install -f -y` step removed our installed packages
        # when the VM had a newer/conflicting openscap (e.g. openscap-common 1.3.9 from
        # noble left over from a previous run). apt -f resolves conflicts by removing
        # the packages we just installed, leaving oscap missing.
        #
        # FIX 7 (cont.): On Ubuntu 22.04 there is no ssg-base/openscap-scanner package at
        # all, and the VM is air-gapped, so the previous apt fallbacks could never succeed.
        # We now:
        #   1. dpkg --force-overwrite the engine debs (no apt removal of our packages).
        #   2. dpkg --configure -a to finish configuring unpacked packages.
        #   3. If oscap is still missing, try openscap-scanner, then libopenscap8
        #      (jammy's engine package name) as a fallback — both are no-ops when offline
        #      but harmless and cover the online case.
        #   4. For content: if no ssg-*-ds.xml is present, FIRST copy the datastream that
        #      rode along in /tmp/scap_offline (downloaded from upstream on the runner) into
        #      /usr/share/xml/scap/ssg/content/. Only if that's somehow absent do we fall
        #      back to apt-get install ssg-base ssg-debderived (the datastreams live in
        #      ssg-debderived, not ssg-base) for distros where the packages do exist.
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
            if ! ls /usr/share/xml/scap/ssg/content/ssg-*-ds.xml >/dev/null 2>&1; then
                if ls /tmp/scap_offline/ssg-*-ds.xml >/dev/null 2>&1; then
                    # Direct xml files from GitHub CDN (when CDN is reachable)
                    sudo mkdir -p /usr/share/xml/scap/ssg/content
                    sudo cp -f /tmp/scap_offline/ssg-*-ds.xml \
                        /usr/share/xml/scap/ssg/content/ 2>/dev/null || true
                elif ls /tmp/scap_offline/ssg-debderived*.deb >/dev/null 2>&1; then
                    # ssg-debderived deb from noble apt — extract xmls without internet
                    _deb_extract=$(mktemp -d /tmp/ssg_deb_XXXXXX)
                    dpkg-deb -x /tmp/scap_offline/ssg-debderived*.deb \
                        "$_deb_extract" 2>/dev/null || true
                    sudo mkdir -p /usr/share/xml/scap/ssg/content
                    find "$_deb_extract" -name 'ssg-ubuntu*-ds.xml' \
                        -exec sudo cp -f {} /usr/share/xml/scap/ssg/content/ \;
                    rm -rf "$_deb_extract"
                else
                    # Air-gapped and no cached content — apt fallback (online VMs only)
                    sudo apt-get install -y --no-install-recommends \
                        ssg-base ssg-debderived 2>/dev/null || true
                fi
            fi
        '
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
# ======================================================
detect_windows_version() {
    local ip="$1"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"
    local caption=""

    caption=$(ansible -i inventory.ini "${ip}" -m ansible.windows.win_shell \
        -a '(Get-CimInstance Win32_OperatingSystem).Caption' \
        2>/dev/null | grep -oE 'Windows (Server (2019|2022|2025)|1[01])' | head -1)

    if [ -z "$caption" ] && [ -n "$vm_name" ]; then
        caption=$(cloud_vm_run_powershell "$ip" \
            '(Get-CimInstance Win32_OperatingSystem).Caption' 2>/dev/null \
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

WINRM_REOPEN_BASIC="${WINRM_REOPEN_BASIC:-true}"

# ======================================================
# HELPER: check_windows_agent_alive
# ======================================================
check_windows_agent_alive() {
    local ip="$1"
    local out
    out=$(cloud_vm_run_powershell "$ip" 'Write-Output "AGENT_ALIVE"' 2>/dev/null)
    local rc=$?
    [ $rc -ne 0 ] && return 1
    [[ "$out" == *"AGENT_ALIVE"* ]] && return 0 || return 1
}

# ======================================================
# HELPER: ensure_winrm_powershell
# ======================================================
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
    cloud_vm_run_powershell "$ip" "
\$ErrorActionPreference = 'Continue'
Set-Service WinRM -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service WinRM -ErrorAction SilentlyContinue
winrm quickconfig -quiet -force 2>&1 | Out-Null
try { Register-PSSessionConfiguration -Name 'Microsoft.PowerShell' -Force -ErrorAction Stop | Out-Null }
catch { Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction SilentlyContinue | Out-Null }
winrm set winrm/config/winrs '@{MaxShellsPerUser=\"30\"}'    2>&1 | Out-Null
winrm set winrm/config/winrs '@{MaxConcurrentUsers=\"10\"}'  2>&1 | Out-Null
winrm set winrm/config/winrs '@{MaxMemoryPerShellMB=\"1024\"}' 2>&1 | Out-Null
${reopen_block}
Set-NetFirewallRule -DisplayGroup 'Windows Remote Management' -Enabled True -Profile Any -ErrorAction SilentlyContinue
Restart-Service WinRM -Force -ErrorAction SilentlyContinue
Write-Output 'WinRM PowerShell provider re-initialized'
" >/dev/null 2>&1

    local rc=$?
    if [ $rc -eq 0 ]; then
        echo -e "${GREEN}✅ [WinRM-Heal/${ip}] provider re-registered${NC}"
    elif [ $rc -eq 124 ]; then
        echo -e "${RED}❌ [WinRM-Heal/${ip}] agent did not respond within ${WIN_AGENT_PROBE_SEC}s${NC}"
        return 1
    else
        echo -e "${YELLOW}⚠️  [WinRM-Heal/${ip}] az run-command rc=${rc} (continuing)${NC}"
    fi
    sleep 5
    return 0
}

# ======================================================
# HELPER: reboot_windows_host
# ======================================================
reboot_windows_host() {
    local ip="$1"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"
    [ -z "$vm_name" ] && { echo -e "${YELLOW}⚠️  [Reboot] No VM name for ${ip}${NC}"; return 0; }

    echo -e "${CYAN}🔧 [Reboot/${ip}] Re-opening WinRM via agent before reboot...${NC}"
    ensure_winrm_powershell "$ip"

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
    ensure_winrm_powershell "$ip"
    wait_for_winrm "$ip" || echo -e "${YELLOW}⚠️  [Reboot/${ip}] WinRM port not open yet (will retry at scan time)${NC}"
    return 0
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
    else
        tags="$tag_scope_l1"
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
# HELPER: fetch_remote_report
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
# CLOUD PROVIDER ABSTRACTION LAYER
# ======================================================

cloud_hcloud_check() {
    if ! python3 -c "import huaweicloudsdkecs" 2>/dev/null; then
        echo -e "${RED}❌ [HuaweiCloud] Python SDK not installed.${NC}"
        echo -e "${YELLOW}   Run: pip3 install huaweicloudsdkcore huaweicloudsdkecs${NC}"
        return 1
    fi
    if [ -z "${HUAWEICLOUD_ACCESS_KEY}" ] || [ -z "${HUAWEICLOUD_SECRET_KEY}" ] || [ -z "${HW_PROJECT_ID}" ]; then
        echo -e "${RED}❌ [HuaweiCloud] Missing credentials. Need HUAWEICLOUD_ACCESS_KEY, HUAWEICLOUD_SECRET_KEY, HW_PROJECT_ID.${NC}"
        return 1
    fi

    if ! timeout 20 env \
        HUAWEICLOUD_ACCESS_KEY="${HUAWEICLOUD_ACCESS_KEY}" \
        HUAWEICLOUD_SECRET_KEY="${HUAWEICLOUD_SECRET_KEY}" \
        HW_PROJECT_ID="${HW_PROJECT_ID}" \
        HW_ECS_ENDPOINT="${HW_ECS_ENDPOINT}" \
        HW_EPS_ID="${HW_EPS_ID}" \
        python3 "$(dirname "$0")/hw_ecs_discover.py" >/dev/null 2>/tmp/hw_check_err.log; then
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
        local sg_id
        sg_id=$(timeout 30 hcloud ECS ShowServer \
            --server-id "$vm_id" \
            --cli-region "${HW_REGION}" \
            --cli-output json 2>/dev/null \
            | python3 -c "
import json,sys
d=json.load(sys.stdin)
sgs=d.get('server',{}).get('security_groups',[])
print(sgs[0].get('id','') if sgs else '')
" 2>/dev/null)
        [ -z "$sg_id" ] && { echo -e "${YELLOW}⚠️  [HW] Could not find SG for ${ip}${NC}"; return 1; }
        timeout 30 hcloud VPC CreateSecurityGroupRule \
            --cli-region "${HW_REGION}" \
            --security-group-id "$sg_id" \
            --security-group-rule.direction "ingress" \
            --security-group-rule.protocol "tcp" \
            --security-group-rule.port-range-min "$port" \
            --security-group-rule.port-range-max "$port" \
            --security-group-rule.remote-ip-prefix "${runner_ip}/32" \
            --cli-output json >/dev/null 2>&1 || true
        ;;
    esac
}

cloud_vm_run_powershell() {
    local ip="$1"
    local script="$2"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"

    case "${CLOUD_PROVIDER}" in
    azure)
        [ -z "$vm_name" ] && return 1
        timeout "${WIN_AGENT_PROBE_SEC}" az vm run-command invoke \
            -g "$RG_NAME" -n "$vm_name" \
            --command-id RunPowerShellScript \
            --scripts "$script" \
            --query 'value[0].message' -o tsv 2>/dev/null
        return $?
        ;;
    huaweicloud)
        echo -e "${YELLOW}⚠️  [HW] Agent-channel PowerShell not available on Huawei Cloud.${NC}" >&2
        echo -e "${YELLOW}   WinRM must be reachable for Windows operations.${NC}" >&2
        return 1
        ;;
    esac
}

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
        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no "${LINUX_ADMIN_USER:-root}@${ip}" "$script" >/dev/null 2>&1
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

if [ -z "$AUDIT_PASS" ]; then
    case "${CLOUD_PROVIDER}" in
        azure)
            echo -e "${YELLOW}🔐 [Azure] Fetching credentials from KeyVault (${KV_NAME})...${NC}"
            az login --identity --allow-no-subscriptions > /dev/null 2>&1 || true
            AUDIT_PASS=$(az keyvault secret show \
                --name "$SECRET_NAME" \
                --vault-name "$KV_NAME" \
                --query value -o tsv 2>/dev/null | tr -d '\r\n')
            ;;
        huaweicloud)
            echo -e "${YELLOW}🔐 [HuaweiCloud] Fetching credentials from CSMS (${HW_CSMS_SECRET})...${NC}"
            AUDIT_PASS=$(hcloud CSMS ShowSecretVersion \
                --secret-name "${HW_CSMS_SECRET}" \
                --version-id "latest" \
                --cli-region "${HW_REGION}" \
                --cli-output json 2>/dev/null \
                | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('version',{}).get('secret_string',''))
" | tr -d '\r\n')
            if [ -z "$AUDIT_PASS" ]; then
                echo -e "${YELLOW}   CSMS fetch returned empty — expecting AUDIT_PASS env var${NC}"
            fi
            ;;
    esac
fi

if [ -z "$AUDIT_PASS" ]; then
    echo -e "${RED}❌ ERROR: Failed to retrieve password from KeyVault. Aborting.${NC}"
    exit 1
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
# ── AZURE ────────────────────────────────────────────────────────────
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
        IP_TO_VM_ID["$ip"]="$vm_name"
        _map_vm "$vm_name" "$ip" "$os" "$power" "$offer"
    done <<< "$VM_DATA"
    ;;

# ── HUAWEI CLOUD ─────────────────────────────────────────────────────
huaweicloud)
    echo -e "${CYAN}📡 [HuaweiCloud] Querying ECS instances via SDK [endpoint: ${HW_ECS_ENDPOINT}]...${NC}"
    # NOTE on HW_EPS_ID: when set, the API filters server-side; all instances
    # must belong to that enterprise project or they will be excluded.
    # Verify instance enterprise-project assignment in the console if 0 are returned.
    HW_RAW=$(
        HUAWEICLOUD_ACCESS_KEY="${HUAWEICLOUD_ACCESS_KEY}" \
        HUAWEICLOUD_SECRET_KEY="${HUAWEICLOUD_SECRET_KEY}" \
        HW_PROJECT_ID="${HW_PROJECT_ID}" \
        HW_ECS_ENDPOINT="${HW_ECS_ENDPOINT}" \
        HW_ECS_TAG_KEY="${HW_ECS_TAG_KEY}" \
        HW_ECS_TAG_VAL="${HW_ECS_TAG_VAL}" \
        HW_EPS_ID="${HW_EPS_ID}" \
        python3 "$(dirname "$0")/hw_ecs_discover.py"
    )
    _hw_rc=$?

    if [ $_hw_rc -ne 0 ] || [ -z "$HW_RAW" ]; then
        echo -e "${RED}❌ [HuaweiCloud] ECS list returned empty or failed.${NC}"
        # FIX 3: Warn if EPS ID filtering is active — the most common cause of 0 servers
        [ -n "${HW_EPS_ID}" ] && \
            echo -e "${YELLOW}   ⚠️  HW_EPS_ID='${HW_EPS_ID}' is set — verify instances belong to this enterprise project.${NC}"
    else
        # FIX 2: Write JSON to a temp file instead of piping into python3 - <<'PYEOF'.
        # Root cause: when both a pipe (|) and a heredoc (<<) target the same command,
        # bash uses the heredoc as stdin (to supply the Python script source), and the
        # piped data from echo "$HW_RAW" is silently discarded. sys.stdin.read() then
        # returns "" and json.loads("") raises "Expecting value: line 1 col 1 (char 0)".
        _hw_tmp=$(mktemp /tmp/hw_ecs_XXXXXX.json)
        echo "$HW_RAW" > "$_hw_tmp"

        while IFS=$'\t' read -r vm_name ip os_type power offer srv_id; do
            IP_TO_VM_ID["$ip"]="$srv_id"
            _map_vm "$vm_name" "$ip" "$os_type" "$power" "$offer"
        done < <(python3 -c "
import json, sys, os
with open(sys.argv[1]) as fh:
    data = json.load(fh)
os.unlink(sys.argv[1])

tag_key = os.environ.get('HW_ECS_TAG_KEY', '')
tag_val = os.environ.get('HW_ECS_TAG_VAL', '')

for s in data.get('servers', []):
    name       = s.get('name', '')
    srv_id     = s.get('id', '')
    status     = s.get('status', '')
    meta       = s.get('metadata') or {}
    os_type    = meta.get('os_type', 'Linux')
    image_name = (s.get('image') or {}).get('name', '').lower()

    if tag_key:
        tags = {t.get('key', ''): t.get('value', '') for t in (s.get('tags') or [])}
        if tag_val and tags.get(tag_key, '') != tag_val:
            continue

    public_ip = ''
    for addrs in (s.get('addresses') or {}).values():
        for a in addrs:
            if a.get('OS-EXT-IPS:type') == 'floating':
                public_ip = a.get('addr', '')
                break
        if public_ip:
            break

    if not public_ip:
        continue

    power = 'running' if status == 'ACTIVE' else status.lower()
    print(f'{name}\t{public_ip}\t{os_type}\t{power}\t{image_name}\t{srv_id}')
" "$_hw_tmp")
    fi
    ;;
esac

if [ "$H_TARGET_IP" != "all" ] && [ -n "$H_TARGET_IP" ]; then
    echo -e "${MAGENTA}🎯 MATRIX SHARDING: Isolating to node $H_TARGET_IP${NC}"
    UBUNTU_MACHINES=(); RHEL_MACHINES=(); ROCKY_MACHINES=()
    ALMA_MACHINES=();   WINDOWS_MACHINES=()
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
# ======================================================
echo -e "\n${CYAN}⚙️  PHASE 0.3: PARALLEL INFRASTRUCTURE BOOTSTRAPPING${NC}"
RUNNER_IP=$(curl -s https://api.ipify.org)

if [ "${CLOUD_PROVIDER}" == "huaweicloud" ]; then
    cloud_hcloud_check || exit 1
fi

declare -a WIN_BOOTSTRAP_PIDS=()

if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
    for ip in "${UBUNTU_MACHINES[@]}"; do
        (
            if [ "$(ssh -n -o BatchMode=yes -o ConnectTimeout=5 \
                    -o StrictHostKeyChecking=no ${UBUNTU_USER}@${ip} \
                    "echo SSH_OK" 2>/dev/null)" != "SSH_OK" ]; then
                VM_NAME="${IP_TO_VM_NAME[$ip]}"
                cloud_add_port_rule "$ip" 22 "Allow_SSH_Runner_Only"
                PUB_KEY=$(cat ~/.ssh/id_rsa.pub)
                cloud_vm_run_shell "$ip" "useradd -m -s /bin/bash ${UBUNTU_USER} || true
                               echo '${UBUNTU_USER} ALL=(ALL) NOPASSWD:ALL' \
                                   > /etc/sudoers.d/99-${UBUNTU_USER}
                               chmod 440 /etc/sudoers.d/99-${UBUNTU_USER}
                               mkdir -p /home/${UBUNTU_USER}/.ssh
                               echo '${PUB_KEY}' \
                                   > /home/${UBUNTU_USER}/.ssh/authorized_keys
                               chown -R ${UBUNTU_USER}:${UBUNTU_USER} \
                                   /home/${UBUNTU_USER}/.ssh
                               chmod 700 /home/${UBUNTU_USER}/.ssh
                               chmod 600 /home/${UBUNTU_USER}/.ssh/authorized_keys
                               systemctl restart sshd" || true
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
                cloud_add_port_rule "$ip" 22 "Allow_SSH_Runner_Only"
                PUB_KEY=$(cat ~/.ssh/id_rsa.pub)
                cloud_vm_run_shell "$ip" "useradd -m -s /bin/bash ${GHOST_USER} || true
                               echo '${GHOST_USER} ALL=(ALL) NOPASSWD:ALL' \
                                   > /etc/sudoers.d/99-${GHOST_USER}
                               chmod 440 /etc/sudoers.d/99-${GHOST_USER}
                               mkdir -p /home/${GHOST_USER}/.ssh
                               echo '${PUB_KEY}' \
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
                               systemctl restart sshd" || true
                sleep 15
            fi
        ) &
    done
fi

if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
    for ip in "${WINDOWS_MACHINES[@]}"; do
        (
            VM_NAME="${IP_TO_VM_NAME[$ip]}"
            cloud_add_port_rule "$ip" 5985 "Allow_WinRM_Runner_Only"
            cloud_vm_run_powershell "$ip" "
Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM' \
    -Recurse -Force -ErrorAction SilentlyContinue
net user ${AUDIT_USER} '${AUDIT_PASS}' /add /y 2>&1 | Out-Null
net user ${AUDIT_USER} '${AUDIT_PASS}' 2>&1 | Out-Null
net localgroup Administrators ${AUDIT_USER} /add 2>&1 | Out-Null
WMIC USERACCOUNT WHERE Name='${AUDIT_USER}' SET PasswordExpires=FALSE 2>&1 | Out-Null
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
Restart-Service WinRM -Force" || true
            sleep 20
        ) &
        WIN_BOOTSTRAP_PIDS+=($!)
    done
fi
wait

if [ ${#WIN_BOOTSTRAP_PIDS[@]} -gt 0 ]; then
    echo -e "${CYAN}⏳ [Phase 0.3] Waiting for Windows WinRM bootstrap to complete...${NC}"
    for pid in "${WIN_BOOTSTRAP_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    echo -e "${GREEN}✅ [Phase 0.3] Windows bootstrap done — proceeding to remediation${NC}"
    sleep 10
fi

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
                    ensure_winrm_powershell "$IP"
                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Win/CIS L${WIN_INSPEC_LVL}] Scanning $IP${NC}"
                        timeout "${WIN_SCAN_TIMEOUT_SEC}" cinc-auditor exec "${WIN_CIS_BENCHMARK}" \
                            -t "winrm://${IP}" \
                            --user="${AUDIT_USER}" \
                            --password="${AUDIT_PASS}" \
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
                            -t "winrm://${IP}" \
                            --user="${AUDIT_USER}" \
                            --password="${AUDIT_PASS}" \
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
# ======================================================
run_remediation() {
    echo -e "\n${BOLD}🛠️  PHASE 2 & 3: Executing Remediation (Hardened SSH)...${NC}"

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ] && [ "$RUN_CIS" == true ]; then
            for IP in "${UBUNTU_MACHINES[@]}"; do
                (
                    echo -e "${CYAN}🛠️  [Remediation/Ubuntu] Starting on ${IP}...${NC}"
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
                        255) echo -e "${RED}🔌 [Remediation/Ubuntu] SSH dropped on ${IP}${NC}" ;;
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
                    echo -e "${CYAN}🛠️  [Remediation/RHEL] Starting on ${IP}...${NC}"
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

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                for IP in "${WINDOWS_MACHINES[@]}"; do
                    (
                        local _saved_timeout=$WINRM_TIMEOUT_SEC
                        WINRM_TIMEOUT_SEC=300
                        wait_for_winrm "$IP" || {
                            echo -e "${RED}❌ [Remediation/Win] WinRM unreachable after 300s: $IP${NC}"
                            ensure_winrm_powershell "$IP"
                            WINRM_TIMEOUT_SEC=120
                            wait_for_winrm "$IP" || {
                                echo -e "${RED}❌ [Remediation/Win] WinRM still down after repair — skipping${NC}"
                                WINRM_TIMEOUT_SEC=$_saved_timeout
                                exit 1
                            }
                        }
                        WINRM_TIMEOUT_SEC=$_saved_timeout
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

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            validate_win_cis_profile || {
                echo -e "${RED}❌ [Phase4/Win] Profile validation failed — skipping all Windows hosts.${NC}"
                return 1
            }
            for IP in "${WINDOWS_MACHINES[@]}"; do
                (
                    if [ -f /tmp/.win_hung_hosts ] && grep -qx "$IP" /tmp/.win_hung_hosts 2>/dev/null; then
                        echo -e "${RED}⏭️  [Phase4/Win] ${IP} flagged hung after remediation — skipping verify scan${NC}"
                        exit 0
                    fi
                    wait_for_winrm "$IP" || {
                        echo -e "${YELLOW}⚠️  [Phase4/Win] WinRM port closed on ${IP} — probing guest agent...${NC}"
                        if check_windows_agent_alive "$IP"; then
                            ensure_winrm_powershell "$IP"
                            wait_for_winrm "$IP" || {
                                echo -e "${RED}❌ [Phase4/Win] WinRM still down after repair on ${IP} — skipping${NC}"
                                exit 1
                            }
                        else
                            echo -e "${RED}❌ [Phase4/Win] Guest agent dead — ${IP} is hung at boot. Skipping.${NC}"
                            exit 1
                        fi
                    }
                    ensure_winrm_powershell "$IP"
                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Win/CIS L${WIN_INSPEC_LVL}] Verifying $IP...${NC}"
                        timeout "${WIN_SCAN_TIMEOUT_SEC}" cinc-auditor exec "${WIN_CIS_BENCHMARK}" \
                            -t "winrm://${IP}" \
                            --user="${AUDIT_USER}" \
                            --password="${AUDIT_PASS}" \
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
                            -t "winrm://${IP}" \
                            --user="${AUDIT_USER}" \
                            --password="${AUDIT_PASS}" \
                            --reporter "json:heimdall_after_${ORG_PREFIX^^}_WIN_${IP}.json"
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
