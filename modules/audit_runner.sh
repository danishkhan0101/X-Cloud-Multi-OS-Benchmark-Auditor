#!/bin/bash
# ======================================================
# modules/audit_runner.sh
# Core scan / remediate / verify / cleanup logic for all
# supported OSes (Ubuntu, RHEL, Rocky, Alma, Windows).
#
# Depends on:
#   modules/utils.sh          (log_*, wait_for_ssh, fetch_remote_report)
#   Orchestrator-level globals (must be set before calling into this file):
#     GHOST_USER, WIN_GHOST_USER, SCAP_CACHE_DIR, SCRIPT_DIR
#     ORG_PREFIX, CUSTOM_XCCDF_PROFILE
#     UBUNTU_CUSTOM_XCCDF/_OVAL/_PLAYBOOK, RHEL_CUSTOM_XCCDF/_OVAL/_PLAYBOOK
#     WIN_CIS_BENCHMARK, WIN_PS1_REMEDIATE, WIN_CUSTOM_BENCHMARK, WIN_CUSTOM_PLAYBOOK
#     WIN_SERVER_ROLE, WIN_SCAN_TIMEOUT_SEC, WIN_REBOOT_*_SEC, WIN_REBOOT_AFTER_REMEDIATION
#     REMEDIATION_TIMEOUT_SEC, REMEDIATION_SSH_OPTS
#     UBUNTU_MACHINES / RHEL_MACHINES / ROCKY_MACHINES / ALMA_MACHINES / WINDOWS_MACHINES (arrays)
#     IP_TO_VM_NAME (assoc array)
#     RUN_CIS, RUN_ORG, OS_LVL, WIN_INSPEC_LVL, CIS_LEVEL, H_TARGET_OS
#   Orchestrator-level functions (thin cloud dispatchers):
#     reassert_ssh_rule_all_linux, reassert_ssh_rule_all_windows
#     cloud_vm_restart(ip), cloud_vm_get_power_state(ip)
# ======================================================

if [ -n "${__AUDIT_RUNNER_SH_LOADED:-}" ]; then
    return 0
fi
__AUDIT_RUNNER_SH_LOADED=1

# ======================================================
# SECTION 1: SCAP PACKAGE PRE-FETCH (runner-side cache)
# ======================================================

# ------------------------------------------------------
# prefetch_scap_packages
# Pre-downloads openscap/ssg packages + datastreams for
# every distro the current run needs, onto the RUNNER
# (not the target VMs), so later phases can push them via
# SCP without requiring internet access on the VM itself.
# ------------------------------------------------------
prefetch_scap_packages() {
    log_info "PHASE 0.2b: SCAP PACKAGE PRE-FETCH (runner has internet)"

    if [[ "${H_TARGET_OS,,}" == "windows" ]]; then
        log_ok "Windows-only run — cinc-auditor runs from runner via SSH. No SCAP packages needed. Skipping."
        return 0
    fi

    # Derive actual needs from the (post-reclassification) arrays rather than
    # trusting H_TARGET_OS alone — a host can be reclassified into a different
    # bucket than the CLI flag implied (e.g. --target-os rocky on a host that
    # turns out to be Alma), and prefetch must match reality, not the guess.
    local need_rhel=false need_alma=false need_rocky=false need_ubuntu=false

    [ ${#RHEL_MACHINES[@]}   -gt 0 ] && need_rhel=true
    [ ${#ALMA_MACHINES[@]}   -gt 0 ] && need_alma=true
    [ ${#ROCKY_MACHINES[@]}  -gt 0 ] && need_rocky=true
    [ ${#UBUNTU_MACHINES[@]} -gt 0 ] && need_ubuntu=true

    log_info "[Phase0.2b] Prefetch needs (derived from actual host buckets): rhel=${need_rhel} alma=${need_alma} rocky=${need_rocky} ubuntu=${need_ubuntu}"

    $need_rhel   && mkdir -p "${SCAP_CACHE_DIR}"/{rhel9,rhel10}
    $need_rocky  && mkdir -p "${SCAP_CACHE_DIR}"/{rocky9,rocky10}
    $need_alma   && mkdir -p "${SCAP_CACHE_DIR}"/{alma9,alma10}
    $need_ubuntu && mkdir -p "${SCAP_CACHE_DIR}"/{ubuntu2204,ubuntu2404}

    _prefetch_rhel_rocky_9   "$need_rhel" "$need_rocky"
    _prefetch_rhel_rocky_10  "$need_rhel" "$need_rocky"
    $need_alma && _prefetch_alma_ver 9
    $need_alma && _prefetch_alma_ver 10
    $need_ubuntu && _prefetch_ubuntu_ver 2204 jammy
    $need_ubuntu && _prefetch_ubuntu_ver 2404 noble
    $need_ubuntu && _prefetch_ubuntu_datastreams

    _prefetch_verify_caches "$need_rhel" "$need_rocky" "$need_alma" "$need_ubuntu"
}

_prefetch_rhel_rocky_9() {
    local need_rhel="$1" need_rocky="$2"
    ( $need_rhel || $need_rocky ) || return 0

    if [ ! "$(ls -A "${SCAP_CACHE_DIR}/rhel9/"*.rpm 2>/dev/null)" ]; then
        log_info "Fetching RHEL9 packages..."
        docker run --rm \
            -v "${SCAP_CACHE_DIR}/rhel9:/output" \
            rockylinux:9 \
            bash -c "dnf install -y --downloadonly --downloaddir=/output \
                     openscap-scanner scap-security-guide 2>/dev/null" \
            && log_ok "RHEL9 cached" \
            || log_error "RHEL9 fetch failed"
        $need_rocky && cp -f "${SCAP_CACHE_DIR}"/rhel9/*.rpm \
            "${SCAP_CACHE_DIR}/rocky9/" 2>/dev/null || true
    else
        log_ok "RHEL9/Rocky9 cache valid — skipping download"
    fi
}

_prefetch_rhel_rocky_10() {
    local need_rhel="$1" need_rocky="$2"
    ( $need_rhel || $need_rocky ) || return 0

    if [ ! "$(ls -A "${SCAP_CACHE_DIR}/rhel10/"*.rpm 2>/dev/null)" ]; then
        log_info "Fetching RHEL10 packages..."
        if docker pull rockylinux:10 >/dev/null 2>&1; then
            docker run --rm \
                -v "${SCAP_CACHE_DIR}/rhel10:/output" \
                rockylinux:10 \
                bash -c "dnf install -y --downloadonly --downloaddir=/output \
                         openscap-scanner scap-security-guide 2>/dev/null" \
                && log_ok "RHEL10 cached" \
                || log_error "RHEL10 fetch failed"
            $need_rocky && cp -f "${SCAP_CACHE_DIR}"/rhel10/*.rpm \
                "${SCAP_CACHE_DIR}/rocky10/" 2>/dev/null || true
        else
            log_warn "rockylinux:10 image not yet on Docker Hub — marking as skipped"
            touch "${SCAP_CACHE_DIR}/rhel10/.skipped"
            touch "${SCAP_CACHE_DIR}/rocky10/.skipped"
        fi
    else
        log_ok "RHEL10/Rocky10 cache valid — skipping download"
    fi
}

_prefetch_alma_ver() {
    local ver="$1"
    local dir="${SCAP_CACHE_DIR}/alma${ver}"

    if [ ! "$(ls -A "${dir}/"*.rpm 2>/dev/null)" ]; then
        log_info "Fetching Alma${ver} packages..."
        docker run --rm \
            -v "${dir}:/output" \
            "almalinux:${ver}" \
            bash -c "dnf install -y --downloadonly --downloaddir=/output \
                     openscap-scanner scap-security-guide 2>/dev/null" \
            && log_ok "Alma${ver} cached" \
            || log_error "Alma${ver} fetch failed"
    else
        log_ok "Alma${ver} cache valid — skipping download"
    fi
}

_prefetch_ubuntu_ver() {
    local ver="$1" codename="$2"
    local dir="${SCAP_CACHE_DIR}/ubuntu${ver}"

    rm -rf "${dir:?}/"* && mkdir -p "${dir}/"
    log_info "Fetching Ubuntu ${ver} packages via Docker..."

    local extra_repo=""
    if [ "$ver" == "2204" ]; then
        extra_repo="
                echo 'deb http://archive.ubuntu.com/ubuntu ${codename} universe' >> /etc/apt/sources.list
                echo 'deb http://archive.ubuntu.com/ubuntu ${codename}-updates universe' >> /etc/apt/sources.list
                apt-get update -qq 2>/dev/null"
    fi

    docker run --rm \
        -v "${dir}:/output" \
        "ubuntu:${ver:0:2}.${ver:2:2}" \
        bash -c "
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq 2>/dev/null
            ${extra_repo}
            apt-get install --download-only -y openscap-scanner 2>/dev/null || true
            apt-get install --download-only -y ssg-base 2>/dev/null || true
            apt-get install --download-only -y 'libopenscap*' 2>/dev/null || true
            apt-get install --download-only -y 'libopendbx*' 2>/dev/null || true
            cp /var/cache/apt/archives/*.deb /output/ 2>/dev/null || true
        " \
        && log_ok "Ubuntu${ver} cached" \
        || log_error "Ubuntu${ver} Docker step failed"
}

# ------------------------------------------------------
# _prefetch_ubuntu_datastreams
# Fetches ssg-ubuntu*-ds.xml via, in order: ssg-debderived
# package install, upstream ComplianceAsCode GitHub release,
# then a from-source Docker build, then (last resort) the
# 22.04 datastream copied over as a stand-in for 24.04.
# Every fallback is validated with `oscap info` before being
# trusted — a broken/incomplete copy is worse than none.
# ------------------------------------------------------
_prefetch_ubuntu_datastreams() {
    log_info "Fetching SCAP datastreams via ssg-debderived (Docker install)..."
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
        && log_ok "ssg-debderived installed in Docker" \
        || log_warn "Docker step exited non-zero (checking output anyway)"

    local ds_file fname
    for ds_file in "${ds_tmp}"/ssg-ubuntu*-ds.xml; do
        [ -f "$ds_file" ] || continue
        fname=$(basename "$ds_file")
        if [[ "$fname" == *"2204"* ]]; then
            cp -f "$ds_file" "${SCAP_CACHE_DIR}/ubuntu2204/"
            log_ok "${fname} -> ubuntu2204 cache"
        elif [[ "$fname" == *"2404"* ]]; then
            cp -f "$ds_file" "${SCAP_CACHE_DIR}/ubuntu2404/"
            log_ok "${fname} -> ubuntu2404 cache"
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

    local ssg_deb
    ssg_deb=$(find "${ds_tmp}" -name 'ssg-debderived*.deb' | head -1)
    if [ -n "$ssg_deb" ]; then
        cp -f "$ssg_deb" "${SCAP_CACHE_DIR}/ubuntu2204/" 2>/dev/null || true
        cp -f "$ssg_deb" "${SCAP_CACHE_DIR}/ubuntu2404/" 2>/dev/null || true
    fi
    rm -rf "${ds_tmp}"

    if ! ls "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" >/dev/null 2>&1; then
        _prefetch_ubuntu2404_from_upstream_release
    fi

    if ! ls "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" >/dev/null 2>&1; then
        _prefetch_ubuntu2404_from_source
    fi

    if ! ls "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" >/dev/null 2>&1; then
        _prefetch_ubuntu2404_last_resort_fallback
    fi
}

_prefetch_ubuntu2404_from_upstream_release() {
    log_info "Fetching ssg-ubuntu2404-ds.xml from upstream ComplianceAsCode release..."
    local ssg_ver
    ssg_ver="${SSG_VER:-$(curl -sL https://api.github.com/repos/ComplianceAsCode/content/releases/latest \
        | python3 -c "import json,sys; print(json.load(sys.stdin).get('tag_name','').lstrip('v'))" 2>/dev/null)}"

    [ -z "$ssg_ver" ] && return 0

    curl -sL -o /tmp/scap-security-guide.tar.bz2 \
        "https://github.com/ComplianceAsCode/content/releases/download/v${ssg_ver}/scap-security-guide-${ssg_ver}.tar.bz2"

    if [ -s /tmp/scap-security-guide.tar.bz2 ]; then
        tar -xjf /tmp/scap-security-guide.tar.bz2 -C /tmp 2>/dev/null
        local found
        found=$(find /tmp -name 'ssg-ubuntu2404-ds.xml' 2>/dev/null | head -1)
        if [ -n "$found" ]; then
            cp -f "$found" "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml"
            log_ok "Real ssg-ubuntu2404-ds.xml fetched from upstream release v${ssg_ver}"
        fi
    fi
    rm -f /tmp/scap-security-guide.tar.bz2
    rm -rf /tmp/scap-security-guide-*
}

_prefetch_ubuntu2404_from_source() {
    log_warn "Pre-built release lacks ubuntu2404 — building from source via Docker (this takes a few minutes)..."
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
    local rc=$?
    if [ $rc -eq 0 ] && ls "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" >/dev/null 2>&1; then
        log_ok "Built ssg-ubuntu2404-ds.xml from source"
    else
        log_error "Source build failed (docker rc=${rc}) — see output above for the real error"
        rm -f "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml"
    fi
}

_prefetch_ubuntu2404_last_resort_fallback() {
    if ! ls "${SCAP_CACHE_DIR}/ubuntu2204/ssg-ubuntu2204-ds.xml" >/dev/null 2>&1; then
        log_error "No 2204 datastream available either — ubuntu2404 cache will be empty"
        return 1
    fi

    log_warn "Upstream fetch failed too — using 2204 as last-resort fallback (results will be unreliable)"
    cp -f "${SCAP_CACHE_DIR}/ubuntu2204/ssg-ubuntu2204-ds.xml" \
        "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" 2>/dev/null || true

    if ! oscap info "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" 2>/dev/null \
            | grep -q 'xccdf_org.ssgproject.content_profile_cis_level1_server'; then
        log_error "2204 fallback copy has no valid CIS profile — removing broken file"
        rm -f "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml"
    fi
}

_prefetch_verify_caches() {
    local need_rhel="$1" need_rocky="$2" need_alma="$3" need_ubuntu="$4"
    local failed=0
    local check_dirs=()

    $need_rhel   && check_dirs+=(rhel9)
    $need_rocky  && check_dirs+=(rocky9)
    $need_alma   && check_dirs+=(alma9 alma10)

    if $need_ubuntu; then
        log_info "Diagnostic: ubuntu2404 cache contents:"
        ls -la "${SCAP_CACHE_DIR}/ubuntu2404/" 2>&1
        if [ -f "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" ]; then
            echo "   File size: $(stat -c%s "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" 2>/dev/null) bytes"
            oscap info "${SCAP_CACHE_DIR}/ubuntu2404/ssg-ubuntu2404-ds.xml" 2>&1 | head -20
        fi
        check_dirs+=(ubuntu2204 ubuntu2404)
    fi

    local d
    for d in "${check_dirs[@]}"; do
        if [ -f "${SCAP_CACHE_DIR}/${d}/.skipped" ]; then
            log_warn "[Phase 0.2b] ${d} skipped (image unavailable)"
            continue
        fi
        if [ ! "$(ls -A "${SCAP_CACHE_DIR}/${d}/" 2>/dev/null)" ]; then
            log_error "[Phase 0.2b] Cache still empty: ${d}"
            failed=1
        fi
        if [[ "${d}" == ubuntu* ]]; then
            if ! ls "${SCAP_CACHE_DIR}/${d}/ssg-"*.xml >/dev/null 2>&1; then
                if ls "${SCAP_CACHE_DIR}"/ubuntu*/ssg-*.xml >/dev/null 2>&1; then
                    log_warn "[Phase 0.2b] No SCAP xml in ${d} — will use available datastream at runtime"
                else
                    log_error "[Phase 0.2b] SCAP datastream xml missing from ${d} — no Ubuntu content at all"
                    failed=1
                fi
            fi
        fi
    done

    if [ $failed -eq 0 ]; then
        log_ok "[Phase 0.2b] All SCAP packages ready on runner. No VM internet needed."
    else
        log_error "[Phase 0.2b] Some caches failed — check errors above."
    fi
    return $failed
}

# ======================================================
# SECTION 2: LINUX TOOL/CONTENT PUSH HELPERS
# ======================================================

# ------------------------------------------------------
# ensure_linux_scap_tools
# Checks if oscap + a datastream already exist on the
# target; if not, pushes the pre-fetched cache for that
# distro/version via SCP and installs offline (no VM
# internet access required).
# Args: user ip pkg_mgr("apt"|"dnf")
# ------------------------------------------------------
ensure_linux_scap_tools() {
    local user="$1" ip="$2" pkg_mgr="$3"

    if ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
           -o ConnectTimeout=10 \
           "${user}@${ip}" \
           "command -v oscap >/dev/null 2>&1 && \
            ls /usr/share/xml/scap/ssg/content/ssg-*-ds.xml \
            >/dev/null 2>&1" 2>/dev/null; then
        log_ok "[Tool Guard] SCAP already present on ${ip} — skipping push"
        return 0
    fi

    local distro_id distro_ver cache_key distro_raw distro_err
    distro_raw="$(ssh -n \
        -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "${user}@${ip}" \
        '. /etc/os-release && echo "$ID ${VERSION_ID%%.*}"' 2>/dev/null)"
    distro_err=$?
    read -r distro_id distro_ver <<< "$distro_raw"

    if [ -z "$distro_id" ] || [ -z "$distro_ver" ]; then
        log_error "[Tool Guard] Could not determine distro on ${ip} (ssh rc=${distro_err}). Raw output: ${distro_raw}"
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
            log_warn "[Tool Guard] Unknown distro '${distro_id}${distro_ver}' — falling back to rhel9 cache"
            cache_key="rhel9"
            ;;
        *10)
            log_warn "[Tool Guard] Unknown distro '${distro_id}${distro_ver}' — falling back to alma10 cache"
            cache_key="alma10"
            ;;
        *)
            log_error "[Tool Guard] Unknown distro: '${distro_id}${distro_ver}' on ${ip} — cannot determine cache"
            return 1
            ;;
    esac

    local cache_dir="${SCAP_CACHE_DIR}/${cache_key}"
    if [ ! "$(ls -A "${cache_dir}" 2>/dev/null)" ]; then
        log_error "[Tool Guard] Cache empty: ${cache_dir}"
        return 1
    fi

    log_info "[Tool Guard] Pushing ${cache_key} packages -> ${ip} (SCP/port 22)"

    # Never let openssl/openssl-libs RPMs leave the runner's cache dir —
    # the rpm -Uvh fallback below has no --exclude of its own.
    find "${cache_dir}" -maxdepth 1 -name '*.rpm' \
        \( -iname 'openssl-[0-9]*' -o -iname 'openssl-libs-*' \) \
        -exec echo "   Excluding from push: {}" \; -exec rm -f {} \;

    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
        "${user}@${ip}" \
        "sudo mkdir -p /tmp/scap_offline && sudo chmod 777 /tmp/scap_offline" 2>/dev/null

    scp -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "${cache_dir}"/* "${user}@${ip}:/tmp/scap_offline/"
    if [ $? -ne 0 ]; then
        log_error "[Tool Guard] SCP push failed to ${ip}"
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

        if ! command -v oscap >/dev/null 2>&1; then
            if [ "${ALLOW_OPENSSL_AUTO_UPDATE:-false}" != "true" ]; then
                echo '[FATAL] oscap missing after offline install (likely openssl version mismatch — set ALLOW_OPENSSL_AUTO_UPDATE=true to enable auto-recovery)'
                exit 10
            fi

            echo '[WARN] oscap missing after offline install — attempting openssl auto-recovery (ALLOW_OPENSSL_AUTO_UPDATE=true)'
            INSTALLED_SSL=$(rpm -q --qf '%{VERSION}-%{RELEASE}' openssl 2>/dev/null)
            echo "[Recovery] Installed openssl: ${INSTALLED_SSL:-unknown}"
            echo "[Recovery] Attempting safe openssl/openssl-libs update from VM's own repos (not pushed RPMs)..."

            sudo dnf update -y openssl openssl-libs 2>&1
            UPDATE_RC=$?

            if [ $UPDATE_RC -ne 0 ]; then
                echo '[FATAL] openssl/openssl-libs update failed — aborting, not retrying oscap install'
                exit 14
            fi

            echo '[Recovery] Verifying sshd config integrity after openssl update...'
            if ! sudo sshd -t 2>&1; then
                echo '[FATAL] sshd -t failed after openssl update — refusing to restart sshd, manual intervention required'
                exit 15
            fi

            sudo systemctl restart sshd
            sleep 2
            if ! sudo sshd -T >/dev/null 2>&1; then
                echo '[FATAL] sshd did not come back healthy after restart — manual intervention required'
                exit 16
            fi
            echo '[Recovery] sshd verified healthy after openssl update'

            echo '[Recovery] Retrying SCAP tool install now that openssl is current...'
            ${install_cmd}

            command -v oscap >/dev/null 2>&1 \
                || { echo '[FATAL] oscap still missing after openssl recovery + retry'; exit 10; }
            echo '[Recovery] oscap now available after openssl update + retry'
        fi
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
        log_error "[Tool Guard] Offline install failed on ${ip} (rc=${rc})"
        return $rc
    fi

    log_ok "[Tool Guard] SCAP ready on ${ip} (offline SCP install — no VM internet used)"
    return 0
}

# ------------------------------------------------------
# scp_custom_content_ubuntu / scp_custom_content_rhel
# Centralised so Phase 1, remediation, and Phase 4 all use
# the same push logic and never forget to re-SCP before an
# oscap run that depends on the file being present.
# ------------------------------------------------------
scp_custom_content_ubuntu() {
    local user="$1" ip="$2"
    log_info "[SCP] Pushing custom XCCDF/OVAL to ${ip}..."
    scp -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "$UBUNTU_CUSTOM_OVAL" "$UBUNTU_CUSTOM_XCCDF" \
        "${user}@${ip}:/tmp/"
    local rc=$?
    if [ $rc -ne 0 ]; then
        log_error "[SCP] Failed to push custom content to ${ip} (rc=${rc})"
        return 1
    fi
    log_ok "[SCP] Custom content ready on ${ip}"
    return 0
}

scp_custom_content_rhel() {
    local user="$1" ip="$2"
    log_info "[SCP] Pushing custom RHEL XCCDF/OVAL to ${ip}..."
    scp -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" \
        "${user}@${ip}:/tmp/"
    local rc=$?
    if [ $rc -ne 0 ]; then
        log_error "[SCP] Failed to push custom RHEL content to ${ip} (rc=${rc})"
        return 1
    fi
    log_ok "[SCP] Custom RHEL content ready on ${ip}"
    return 0
}

# ======================================================
# SECTION 3: WINDOWS HELPERS
# ======================================================

# ------------------------------------------------------
# get_win_cis_controls_for_level
# Extracts control IDs matching the requested CIS level
# from the combined L1+L2 benchmark file, since
# profile_level is report metadata only — cinc-auditor
# doesn't filter controls by it natively.
#   level=1 -> only tag level: ['L1']
#   level=2 -> tag level: ['L1'] OR ['L2'] (superset)
# ------------------------------------------------------
get_win_cis_controls_for_level() {
    local rb_file="$1" level="$2"

    if [ "$level" == "1" ]; then
        awk '
            /^control / { cur = $2; gsub(/[\x27"]/, "", cur) }
            /tag level:/ && /\x27L1\x27/ { print cur }
        ' "$rb_file"
    else
        awk '
            /^control / { cur = $2; gsub(/[\x27"]/, "", cur) }
            /tag level:/ && (/\x27L1\x27/ || /\x27L2\x27/) { print cur }
        ' "$rb_file"
    fi
}

# ------------------------------------------------------
# validate_win_cis_profile
# Guard: confirms the Windows CIS benchmark files exist
# and reports control counts before any scan attempts to
# use them.
# ------------------------------------------------------
validate_win_cis_profile() {
    local ok=true
    local rb_file="${WIN_CIS_BENCHMARK}/controls/cis_ws2022_v5_0_0_benchmark.rb"
    local inspec_yml="${WIN_CIS_BENCHMARK}/inspec.yml"
    local ps1_file="${WIN_PS1_REMEDIATE}"

    [ -f "${inspec_yml}" ] || { log_error "[Profile Guard] ${inspec_yml} not found."; ok=false; }
    [ -f "${rb_file}" ]    || { log_error "[Profile Guard] ${rb_file} not found."; ok=false; }
    [ -f "${ps1_file}" ]   || log_warn "[Profile Guard] ${ps1_file} not found — PS1 remediation path unavailable."

    [ "$ok" == "false" ] && return 1

    local ctrl_count l1_count l2_count
    ctrl_count=$(grep -c "^control " "${rb_file}" 2>/dev/null || echo 0)
    l1_count=$(grep -c "tag level: \['L1'\]" "${rb_file}" 2>/dev/null || echo 0)
    l2_count=$(grep -c "tag level: \['L2'\]" "${rb_file}" 2>/dev/null || echo 0)
    log_ok "[Profile Guard] CIS WS2022 v5 profile OK — ${ctrl_count} controls (L1: ${l1_count}, L2: ${l2_count})."
    log_info "server_role=${WIN_SERVER_ROLE} | profile_level driven by CIS_LEVEL at scan time"
    return 0
}

# ------------------------------------------------------
# run_win_ps1_remediation
# Uploads and runs the combined CIS remediation PS1 script
# over SSH, then removes it from the target.
# Args: ip [cis_level("Level 1"|"Level 2")] [sections]
# ------------------------------------------------------
run_win_ps1_remediation() {
    local ip="$1" cis_level="${2:-Level 1}" sections="${3:-}"

    if [ ! -f "$WIN_PS1_REMEDIATE" ]; then
        log_error "[WinPS1] ${WIN_PS1_REMEDIATE} not found."
        return 1
    fi

    local ps1_level="L1"
    [ "$cis_level" == "Level 2" ] && ps1_level="L2"

    local sections_arg=""
    [ -n "$sections" ] && sections_arg=" -Sections ${sections}"

    log_info "[WinPS1/${ip}] Uploading + running via SSH (CIS ${ps1_level})"
    scp -o BatchMode=yes -o StrictHostKeyChecking=no \
        "$WIN_PS1_REMEDIATE" "$WIN_GHOST_USER@${ip}:C:/Windows/Temp/Invoke-CISRemediation-Combined.ps1"

    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no "$WIN_GHOST_USER@${ip}" \
        "powershell -NoProfile -File C:\\Windows\\Temp\\Invoke-CISRemediation-Combined.ps1 -ServerRole ${WIN_SERVER_ROLE} -CisLevel ${ps1_level}${sections_arg}"
    local rc=$?

    ssh -n "$WIN_GHOST_USER@${ip}" \
        "Remove-Item C:\\Windows\\Temp\\Invoke-CISRemediation-Combined.ps1 -Force -ErrorAction SilentlyContinue" 2>/dev/null

    if [ $rc -eq 0 ]; then
        log_ok "[WinPS1/${ip}] Remediation complete (${ps1_level})"
    else
        log_error "[WinPS1/${ip}] Remediation failed (rc=${rc})"
    fi
    return $rc
}

# ------------------------------------------------------
# detect_windows_version
# Prints "2019"|"2022"|"2025"|"10"|"11"; defaults to 2022
# with a warning if detection fails.
# ------------------------------------------------------
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
            log_warn "[Win] Version detection failed for ${ip} — assuming WS2022"
            echo "2022"
            ;;
    esac
}

# ------------------------------------------------------
# ensure_windows_ghost_user
# Provisions the dedicated audit-service local admin
# account on a Windows host, mirroring the Linux GHOST_USER
# pattern. Idempotent — checks SSH reachability first.
# ------------------------------------------------------
ensure_windows_ghost_user() {
    local ip="$1"

    if ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
           "${WIN_GHOST_USER}@${ip}" "echo SSH_OK" 2>/dev/null | grep -q SSH_OK; then
        log_ok "[WinGhost] ${WIN_GHOST_USER} already provisioned on ${ip}"
        return 0
    fi

    log_info "[WinGhost] Provisioning ${WIN_GHOST_USER} on ${ip} via ${WIN_SSH_USER}..."
    local pub_key
    pub_key=$(cat ~/.ssh/id_rsa.pub)

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

    local encoded_cmd
    encoded_cmd=$(iconv -f UTF-8 -t UTF-16LE "$ps_script" | base64 -w 0)
    rm -f "$ps_script"

    local ssh_output
    ssh_output=$(ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
        "${WIN_SSH_USER}@${ip}" "powershell -NoProfile -EncodedCommand ${encoded_cmd}" 2>&1)

    if ! echo "$ssh_output" | grep -q GHOST_USER_READY; then
        log_error "[WinGhost] Failed to provision ${WIN_GHOST_USER} on ${ip}: ${ssh_output}"
        return 1
    fi

    sleep 5
    if ! ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
             "${WIN_GHOST_USER}@${ip}" "echo SSH_OK" 2>/dev/null | grep -q SSH_OK; then
        log_error "[WinGhost] ${WIN_GHOST_USER} still not reachable after provisioning on ${ip}"
        return 1
    fi

    log_ok "[WinGhost] ${WIN_GHOST_USER} ready on ${ip}"
    return 0
}

# ------------------------------------------------------
# reboot_windows_host
# Restarts a Windows VM at the fabric level, waits for the
# power state to return to running, then waits for the
# guest agent (SSH) to answer. Returns 2 if the guest never
# comes back — signals a boot-breaking remediation.
# Requires: cloud_vm_restart, cloud_vm_get_power_state
# (orchestrator-level cloud dispatchers).
# ------------------------------------------------------
reboot_windows_host() {
    local ip="$1"
    local vm_name="${IP_TO_VM_NAME[$ip]:-}"
    [ -z "$vm_name" ] && { log_warn "[Reboot] No VM name for ${ip}"; return 0; }

    log_info "[Reboot/${ip}] Restarting ${vm_name} (non-blocking)..."
    cloud_vm_restart "$ip"
    sleep 20

    local deadline=$(( SECONDS + 480 ))
    log_info "[Reboot/${ip}] Waiting for VM to return to running state..."
    while [ $SECONDS -lt $deadline ]; do
        local ps
        ps=$(cloud_vm_get_power_state "$ip")
        if [[ "$ps" == "running" ]]; then
            log_ok "[Reboot/${ip}] VM back to 'running' (fabric level)"
            break
        fi
        log_info "[Reboot/${ip}] PowerState: ${ps:-unknown} — waiting..."
        sleep 15
    done

    sleep "${WIN_REBOOT_SETTLE_SEC}"

    log_info "[Reboot/${ip}] Probing guest agent (max ${WIN_REBOOT_HEALTH_WAIT_SEC}s)..."
    local hb_deadline=$(( SECONDS + WIN_REBOOT_HEALTH_WAIT_SEC ))
    local agent_ok=false
    while [ $SECONDS -lt $hb_deadline ]; do
        if check_windows_agent_alive "$ip"; then
            agent_ok=true
            break
        fi
        log_info "[Reboot/${ip}] Guest agent not answering yet — waiting..."
        sleep 20
    done

    if [ "$agent_ok" != "true" ]; then
        log_error "[Reboot/${ip}] Guest agent did NOT respond after reboot. The OS is hung at boot — a CIS control likely broke startup."
        return 2
    fi

    log_ok "[Reboot/${ip}] Guest agent alive — OS booted"
    wait_for_ssh "$ip" "$WIN_GHOST_USER" || log_warn "[Reboot/${ip}] SSH not open yet (will retry at scan time)"
    return 0
}

# ------------------------------------------------------
# remediate_windows_host
# Thin wrapper kept for call-site readability.
# ------------------------------------------------------
remediate_windows_host() {
    local ip="$1" cis_level="$2"
    log_info "[Win] Remediating ${ip} via SSH+PS1 (Level: ${cis_level})..."
    run_win_ps1_remediation "$ip" "$cis_level"
}

# ======================================================
# SECTION 4: PHASE 1 — INITIAL SCAN
# ======================================================
run_phase_1() {
    log_info "PHASE 1: Initial Baselines (SCP install -> scan)..."

    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]] && _phase1_ubuntu
    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rhel"   ]] && _phase1_rhel
    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rocky"  ]] && _phase1_rocky
    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "alma"   ]] && _phase1_alma
    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]] && _phase1_windows
}

_phase1_ubuntu() {
    [ ${#UBUNTU_MACHINES[@]} -eq 0 ] && return 0
    local IP
    for IP in "${UBUNTU_MACHINES[@]}"; do
        (
            if ! ensure_linux_scap_tools "$GHOST_USER" "$IP" "apt"; then
                log_error "[Phase1/Ubuntu] Skipping $IP — tools unavailable."
                exit 1
            fi

            local RAW_VER UBUNTU_VER UBUNTU_CIS_XCCDF
            RAW_VER=$(ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                ${GHOST_USER}@${IP} \
                "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
            UBUNTU_VER=${RAW_VER:-2404}
            UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

            if [ "$RUN_CIS" == true ]; then
                local EFFECTIVE_PROFILE="$UBUNTU_CIS_PROFILE" PROFILE_OK=true
                local AVAILABLE_PROFILES
                AVAILABLE_PROFILES=$(ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                    ${GHOST_USER}@${IP} \
                    "sudo oscap info '$UBUNTU_CIS_XCCDF' 2>/dev/null | grep -oE 'xccdf_org\.ssgproject\.content_profile_[a-zA-Z0-9_]+'")

                if [ "$OS_LVL" == "2" ] && ! echo "$AVAILABLE_PROFILES" | grep -qx "$UBUNTU_CIS_PROFILE"; then
                    log_warn "[Phase1/Ubuntu] Level 2 profile not found in ssg-ubuntu${UBUNTU_VER}-ds.xml — falling back to Level 1"
                    EFFECTIVE_PROFILE="xccdf_org.ssgproject.content_profile_cis_level1_server"
                fi

                if ! echo "$AVAILABLE_PROFILES" | grep -qx "$EFFECTIVE_PROFILE"; then
                    log_error "[Phase1/Ubuntu] Neither requested nor fallback profile exists in this datastream. Requested: $UBUNTU_CIS_PROFILE | Fallback: $EFFECTIVE_PROFILE"
                    echo "$AVAILABLE_PROFILES" | sed 's/^/     /'
                    PROFILE_OK=false
                fi

                if [ "$PROFILE_OK" != true ]; then
                    log_error "[Phase1/Ubuntu/CIS] Skipping scan on $IP — no valid profile in datastream"
                else
                    log_info "[Phase1/Ubuntu/CIS L${OS_LVL}] Scanning $IP..."
                    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                        ${GHOST_USER}@${IP} \
                        "sudo oscap xccdf eval --profile $EFFECTIVE_PROFILE \
                         --report /tmp/report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html \
                         $UBUNTU_CIS_XCCDF > /tmp/oscap_console_${IP}.log 2>&1"
                    local rc=$?
                    if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                        local p f
                        p=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+pass' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                        f=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+fail' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                        log_ok "[Phase1/Ubuntu/CIS] ${IP}: ${p:-?} passed, ${f:-?} failed"
                        fetch_remote_report "$GHOST_USER" "$IP" \
                            "/tmp/report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html" \
                            "./report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html" \
                            "Ubuntu/CIS-before"
                    else
                        log_error "[Phase1/Ubuntu/CIS] oscap failed on $IP (rc=$rc)"
                        fetch_remote_report "$GHOST_USER" "$IP" \
                            "/tmp/oscap_console_${IP}.log" \
                            "./oscap_console_UBUNTU_${IP}_FAILURE.log" \
                            "Ubuntu/CIS-failure-log"
                    fi
                fi
            fi

            if [ "$RUN_ORG" == true ]; then
                log_info "[Phase1/Ubuntu/${ORG_PREFIX^^}] Scanning $IP..."
                scp_custom_content_ubuntu "$GHOST_USER" "$IP" \
                    || { log_error "[Phase1] SCP failed for $IP"; exit 1; }
                ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                    ${GHOST_USER}@${IP} \
                    "sudo oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                     --report /tmp/report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html \
                     /tmp/$(basename $UBUNTU_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
                local rc=$?
                if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                    local p f
                    p=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+pass' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                    f=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+fail' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                    log_ok "[Phase1/Ubuntu/${ORG_PREFIX^^}] ${IP}: ${p:-?} passed, ${f:-?} failed"
                    fetch_remote_report "$GHOST_USER" "$IP" \
                        "/tmp/report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html" \
                        "./report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html" \
                        "Ubuntu/${ORG_PREFIX^^}-before"
                else
                    log_error "[Phase1/Ubuntu/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)"
                fi
            fi
        ) &
    done
    wait
}

_phase1_rhel() {
    [ ${#RHEL_MACHINES[@]} -eq 0 ] && return 0
    local IP
    for IP in "${RHEL_MACHINES[@]}"; do
        (
            if ! ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf"; then
                log_error "[Phase1/RHEL] Skipping $IP — tools unavailable."
                exit 1
            fi
            if [ "$RUN_CIS" == true ]; then
                log_info "[Phase1/RHEL/CIS L${OS_LVL}] Scanning $IP..."
                ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                    ${GHOST_USER}@${IP} \
                    "TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ \
                         -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                     sudo /usr/bin/oscap xccdf eval \
                         --profile $RHEL_CIS_PROFILE \
                         --report /tmp/report_before_CIS_L${OS_LVL}_RHEL_${IP}.html \
                         \"\$TARGET_XML\" > /tmp/oscap_console_${IP}.log 2>&1"
                local rc=$?
                if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                    local p f
                    p=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+pass' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                    f=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+fail' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                    log_ok "[Phase1/RHEL/CIS] ${IP}: ${p:-?} passed, ${f:-?} failed"
                    fetch_remote_report "$GHOST_USER" "$IP" \
                        "/tmp/report_before_CIS_L${OS_LVL}_RHEL_${IP}.html" \
                        "./report_before_CIS_L${OS_LVL}_RHEL_${IP}.html" \
                        "RHEL/CIS-before"
                else
                    log_error "[Phase1/RHEL/CIS] oscap failed on $IP (rc=$rc)"
                fi
            fi
            if [ "$RUN_ORG" == true ]; then
                log_info "[Phase1/RHEL/${ORG_PREFIX^^}] Scanning $IP..."
                scp_custom_content_rhel "$GHOST_USER" "$IP" \
                    || { log_error "[Phase1] SCP failed for $IP"; exit 1; }
                ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                    ${GHOST_USER}@${IP} \
                    "sudo env OSCAP_CPE_DICT_PATH=\$(find /usr/share/xml/scap/ssg/content/ \
                         -name 'ssg-rhel*-cpe-dictionary.xml' | sort -V | tail -n 1) \
                     /usr/bin/oscap xccdf eval \
                         --profile $CUSTOM_XCCDF_PROFILE \
                         --report /tmp/report_before_${ORG_PREFIX^^}_RHEL_${IP}.html \
                         /tmp/$(basename $RHEL_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
                local rc=$?
                if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                    local p f
                    p=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+pass' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                    f=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+fail' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                    log_ok "[Phase1/RHEL/${ORG_PREFIX^^}] ${IP}: ${p:-?} passed, ${f:-?} failed"
                    fetch_remote_report "$GHOST_USER" "$IP" \
                        "/tmp/report_before_${ORG_PREFIX^^}_RHEL_${IP}.html" \
                        "./report_before_${ORG_PREFIX^^}_RHEL_${IP}.html" \
                        "RHEL/${ORG_PREFIX^^}-before"
                else
                    log_error "[Phase1/RHEL/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)"
                fi
            fi
        ) &
    done
    wait
}

_phase1_rocky() {
    [ ${#ROCKY_MACHINES[@]} -eq 0 ] && return 0
    local IP
    for IP in "${ROCKY_MACHINES[@]}"; do
        (
            if ! ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf"; then
                log_error "[Phase1/Rocky] Skipping $IP — tools unavailable."
                exit 1
            fi
            if [ "$RUN_CIS" == true ]; then
                log_info "[Phase1/Rocky/CIS L${OS_LVL}] Scanning $IP..."
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
                local rc=$?
                if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                    fetch_remote_report "$GHOST_USER" "$IP" \
                        "/tmp/report_before_CIS_L${OS_LVL}_ROCKY_${IP}.html" \
                        "./report_before_CIS_L${OS_LVL}_ROCKY_${IP}.html" \
                        "Rocky/CIS-before"
                else
                    log_error "[Phase1/Rocky/CIS] oscap failed on $IP (rc=$rc)"
                fi
            fi
            if [ "$RUN_ORG" == true ]; then
                log_info "[Phase1/Rocky/${ORG_PREFIX^^}] Scanning $IP..."
                scp_custom_content_rhel "$GHOST_USER" "$IP" \
                    || { log_error "[Phase1] SCP failed for $IP"; exit 1; }
                ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                    ${GHOST_USER}@${IP} \
                    "sudo /usr/bin/oscap xccdf eval \
                         --profile $CUSTOM_XCCDF_PROFILE \
                         --report /tmp/report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html \
                         /tmp/$(basename $RHEL_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
                local rc=$?
                local p f
                p=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+pass' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                f=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+fail' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                log_ok "[Phase1/Rocky/${ORG_PREFIX^^}] ${IP}: ${p:-?} passed, ${f:-?} failed"
                if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                    fetch_remote_report "$GHOST_USER" "$IP" \
                        "/tmp/report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html" \
                        "./report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html" \
                        "Rocky/${ORG_PREFIX^^}-before"
                else
                    log_error "[Phase1/Rocky/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)"
                fi
            fi
        ) &
    done
    wait
}

_phase1_alma() {
    [ ${#ALMA_MACHINES[@]} -eq 0 ] && return 0
    local IP
    for IP in "${ALMA_MACHINES[@]}"; do
        (
            if ! ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf"; then
                log_error "[Phase1/Alma] Skipping $IP — tools unavailable."
                exit 1
            fi
            if [ "$RUN_CIS" == true ]; then
                log_info "[Phase1/Alma/CIS L${OS_LVL}] Scanning $IP..."
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
                local rc=$?
                if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                    fetch_remote_report "$GHOST_USER" "$IP" \
                        "/tmp/report_before_CIS_L${OS_LVL}_ALMA_${IP}.html" \
                        "./report_before_CIS_L${OS_LVL}_ALMA_${IP}.html" \
                        "Alma/CIS-before"
                else
                    log_error "[Phase1/Alma/CIS] oscap failed on $IP (rc=$rc)"
                    fetch_remote_report "$GHOST_USER" "$IP" \
                        "/tmp/oscap_console_${IP}.log" \
                        "./oscap_console_ALMA_${IP}_FAILURE.log" \
                        "Alma/CIS-failure-log"
                fi
            fi
            if [ "$RUN_ORG" == true ]; then
                log_info "[Phase1/Alma/${ORG_PREFIX^^}] Scanning $IP..."
                scp_custom_content_rhel "$GHOST_USER" "$IP" \
                    || { log_error "[Phase1] SCP failed for $IP"; exit 1; }
                ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                    ${GHOST_USER}@${IP} \
                    "sudo /usr/bin/oscap xccdf eval \
                         --profile $CUSTOM_XCCDF_PROFILE \
                         --report /tmp/report_before_${ORG_PREFIX^^}_ALMA_${IP}.html \
                         /tmp/$(basename $RHEL_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
                local rc=$?
                if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                    local p f
                    p=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+pass' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                    f=$(ssh -n ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+fail' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                    log_ok "[Phase1/Alma/${ORG_PREFIX^^}] ${IP}: ${p:-?} passed, ${f:-?} failed"
                    fetch_remote_report "$GHOST_USER" "$IP" \
                        "/tmp/report_before_${ORG_PREFIX^^}_ALMA_${IP}.html" \
                        "./report_before_${ORG_PREFIX^^}_ALMA_${IP}.html" \
                        "Alma/${ORG_PREFIX^^}-before"
                else
                    log_error "[Phase1/Alma/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)"
                    fetch_remote_report "$GHOST_USER" "$IP" \
                        "/tmp/oscap_console_${IP}.log" \
                        "./oscap_console_ALMA_${IP}_FAILURE.log" \
                        "Alma/${ORG_PREFIX^^}-failure-log"
                fi
            fi
        ) &
    done
    wait
}

_phase1_windows() {
    [ ${#WINDOWS_MACHINES[@]} -eq 0 ] && return 0
    local IP
    for IP in "${WINDOWS_MACHINES[@]}"; do
        (
            wait_for_ssh "$IP" "${WIN_GHOST_USER}" || {
                log_error "[Phase1/Win] SSH unreachable: $IP — skipping"
                exit 1
            }
            if [ "$RUN_CIS" == true ]; then
                log_info "[Phase1/Win/CIS L${WIN_INSPEC_LVL}] Scanning $IP"
                local WIN_RB_FILE="${WIN_CIS_BENCHMARK}/controls/cis_ws2022_v5_0_0_benchmark.rb"
                local WIN_LEVEL_CONTROLS=()
                mapfile -t WIN_LEVEL_CONTROLS < <(get_win_cis_controls_for_level "$WIN_RB_FILE" "$WIN_INSPEC_LVL")

                if [ ${#WIN_LEVEL_CONTROLS[@]} -eq 0 ]; then
                    log_error "[Phase1/Win/CIS] No controls matched level ${WIN_INSPEC_LVL} in ${WIN_RB_FILE} — aborting scan for ${IP}"
                else
                    log_info "${#WIN_LEVEL_CONTROLS[@]} controls selected for CIS L${WIN_INSPEC_LVL}"
                    timeout "${WIN_SCAN_TIMEOUT_SEC}" cinc-auditor exec "${WIN_CIS_BENCHMARK}" \
                        -t "ssh://${WIN_GHOST_USER}@${IP}" \
                        --input "server_role=${WIN_SERVER_ROLE}" \
                        --input "profile_level=${WIN_INSPEC_LVL}" \
                        --controls "${WIN_LEVEL_CONTROLS[@]}" \
                        --reporter "json:heimdall_before_CIS_L${WIN_INSPEC_LVL}_WIN_${IP}.json"
                    local rc=$?
                    case $rc in
                        0|100|101) log_ok "[Phase1/Win/CIS L${WIN_INSPEC_LVL}] $IP scan complete (rc=$rc)" ;;
                        124)       log_error "[Phase1/Win/CIS L${WIN_INSPEC_LVL}] scan TIMED OUT on $IP after ${WIN_SCAN_TIMEOUT_SEC}s" ;;
                        *)         log_error "[Phase1/Win/CIS L${WIN_INSPEC_LVL}] cinc-auditor failed on $IP (rc=$rc)" ;;
                    esac
                fi
            fi
            if [ "$RUN_ORG" == true ]; then
                log_info "[Phase1/Win/${ORG_PREFIX^^}] Scanning $IP..."
                timeout "${WIN_SCAN_TIMEOUT_SEC}" cinc-auditor exec "${WIN_CUSTOM_BENCHMARK}" \
                    -t "ssh://${WIN_GHOST_USER}@${IP}" \
                    --reporter "json:heimdall_before_${ORG_PREFIX^^}_WIN_${IP}.json"
                local rc=$?
                case $rc in
                    0|100|101) log_ok "[Phase1/Win/${ORG_PREFIX^^}] $IP scan complete (rc=$rc)" ;;
                    124)       log_error "[Phase1/Win/${ORG_PREFIX^^}] scan TIMED OUT on $IP after ${WIN_SCAN_TIMEOUT_SEC}s" ;;
                    *)         log_error "[Phase1/Win/${ORG_PREFIX^^}] cinc-auditor failed on $IP (rc=$rc)" ;;
                esac
            fi
        ) &
    done
    wait
}

# ======================================================
# SECTION 5: REMEDIATION (PHASE 2/3)
# ======================================================
run_remediation() {
    log_info "PHASE 2 & 3: Executing Remediation (Hardened SSH)..."

    reassert_ssh_rule_all_linux
    reassert_ssh_rule_all_windows

    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu"  ]] && _remediate_ubuntu
    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rhel"    ]] && _remediate_rhel
    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rocky"   ]] && _remediate_rocky
    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "alma"    ]] && _remediate_alma
    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]] && _remediate_windows
}

_remediate_ubuntu() {
    if [ ${#UBUNTU_MACHINES[@]} -gt 0 ] && [ "$RUN_CIS" == true ]; then
        local IP
        for IP in "${UBUNTU_MACHINES[@]}"; do
            (
                log_info "[Remediation/Ubuntu/CIS] Starting on ${IP}..."
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
                local rc=$?
                case $rc in
                    124) log_error "[Remediation/Ubuntu/CIS] TIMEOUT on ${IP}" ;;
                    255) log_error "[Remediation/Ubuntu/CIS] SSH dropped on ${IP}" ;;
                    0|2) log_ok "[Remediation/Ubuntu/CIS] ${IP} done (rc=${rc})" ;;
                    *)   log_warn "[Remediation/Ubuntu/CIS] ${IP} rc=${rc}" ;;
                esac
            ) &
        done
        wait
    fi

    if [ ${#UBUNTU_MACHINES[@]} -gt 0 ] && [ "$RUN_ORG" == true ]; then
        log_info "=== WORKSPACE CHECK ==="
        echo "  Script dir      : ${SCRIPT_DIR}"
        echo "  Playbook path   : ${UBUNTU_CUSTOM_PLAYBOOK}"
        echo "  XCCDF path      : ${UBUNTU_CUSTOM_XCCDF}"
        echo "  OVAL path       : ${UBUNTU_CUSTOM_OVAL}"
        ls -la "${SCRIPT_DIR}/ubuntu-custom/" 2>/dev/null \
            || log_error "ubuntu-custom/ MISSING from ${SCRIPT_DIR}"

        if [ ! -f "$UBUNTU_CUSTOM_PLAYBOOK" ]; then
            log_error "[Remediation/Ubuntu/ORG] Playbook not found: ${UBUNTU_CUSTOM_PLAYBOOK}"
            return 1
        fi
        if [ ! -f "$UBUNTU_CUSTOM_XCCDF" ] || [ ! -f "$UBUNTU_CUSTOM_OVAL" ]; then
            log_error "[Remediation/Ubuntu/ORG] XCCDF or OVAL file missing: XCCDF=${UBUNTU_CUSTOM_XCCDF} OVAL=${UBUNTU_CUSTOM_OVAL}"
            return 1
        fi

        local IP
        for IP in "${UBUNTU_MACHINES[@]}"; do
            log_info "[Remediation/Ubuntu/ORG] Fixing broken apt state on ${IP}..."
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                -o ControlMaster=no -o ControlPath=none \
                ${GHOST_USER}@${IP} \
                "sudo apt-get remove -y --purge openscap-common ssg-debderived 2>/dev/null || true
                 sudo dpkg --remove --force-remove-reinstreq openscap-common ssg-debderived 2>/dev/null || true
                 sudo apt-get install -f -y 2>/dev/null || true
                 echo 'APT state repaired'"
        done

        log_info "[Remediation/Ubuntu/ORG] Running Ansible playbook..."
        ANSIBLE_HOST_KEY_CHECKING=False \
        ansible-playbook \
            -i inventory.ini \
            "$UBUNTU_CUSTOM_PLAYBOOK" \
            --limit ubuntu_nodes \
            --ssh-extra-args="-o StrictHostKeyChecking=no -o BatchMode=yes" \
            -v
        local ANSIBLE_RC=$?

        if [ $ANSIBLE_RC -ne 0 ]; then
            log_error "[Remediation/Ubuntu/ORG] Playbook FAILED (rc=${ANSIBLE_RC})"
            return $ANSIBLE_RC
        fi
        log_ok "[Remediation/Ubuntu/ORG] Playbook complete (rc=${ANSIBLE_RC})"
    fi
}

_remediate_rhel() {
    if [ ${#RHEL_MACHINES[@]} -gt 0 ] && [ "$RUN_CIS" == true ]; then
        local IP
        for IP in "${RHEL_MACHINES[@]}"; do
            (
                log_info "[Remediation/RHEL/CIS] Starting on ${IP}..."
                timeout $REMEDIATION_TIMEOUT_SEC \
                    ssh $REMEDIATION_SSH_OPTS ${GHOST_USER}@${IP} \
                    "XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ \
                         -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                     sudo /usr/bin/oscap xccdf eval --remediate \
                         --profile $RHEL_CIS_PROFILE \
                         --report /tmp/report_remediation_CIS_${IP}.html \"\$XML_FILE\" > /tmp/oscap_console_${IP}.log 2>&1"
                local rc=$?
                case $rc in
                    124) log_error "[Remediation/RHEL/CIS] TIMEOUT on ${IP}" ;;
                    255) log_error "[Remediation/RHEL/CIS] SSH dropped on ${IP}" ;;
                    0|2) log_ok "[Remediation/RHEL/CIS] ${IP} done (rc=${rc})" ;;
                    *)   log_warn "[Remediation/RHEL/CIS] ${IP} rc=${rc}" ;;
                esac
            ) &
        done
        wait
    fi
    if [ ${#RHEL_MACHINES[@]} -gt 0 ] && [ "$RUN_ORG" == true ]; then
        local IP
        for IP in "${RHEL_MACHINES[@]}"; do
            scp_custom_content_rhel "$GHOST_USER" "$IP" || true
        done
        ANSIBLE_HOST_KEY_CHECKING=False \
        ansible-playbook -i inventory.ini "$RHEL_CUSTOM_PLAYBOOK" --limit rhel_nodes -v
        local ANSIBLE_RC=$?
        [ $ANSIBLE_RC -ne 0 ] \
            && log_error "[Remediation/RHEL/ORG] Playbook FAILED (rc=${ANSIBLE_RC})" \
            || log_ok "[Remediation/RHEL/ORG] Playbook complete"
    fi
}

_remediate_rocky() {
    [ ${#ROCKY_MACHINES[@]} -eq 0 ] && return 0

    if [ "$RUN_CIS" == true ]; then
        local IP
        for IP in "${ROCKY_MACHINES[@]}"; do
            (
                log_info "[Remediation/Rocky/CIS] Starting on ${IP}..."
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
                local rc=$?
                case $rc in
                    124) log_error "[Remediation/Rocky/CIS] TIMEOUT on ${IP}" ;;
                    255) log_error "[Remediation/Rocky/CIS] SSH dropped on ${IP}" ;;
                    0|2) log_ok "[Remediation/Rocky/CIS] ${IP} done (rc=${rc})" ;;
                    *)   log_warn "[Remediation/Rocky/CIS] ${IP} rc=${rc}" ;;
                esac
            ) &
        done
        wait
    fi
    if [ "$RUN_ORG" == true ]; then
        local IP
        for IP in "${ROCKY_MACHINES[@]}"; do
            scp_custom_content_rhel "$GHOST_USER" "$IP" || true
        done
        ANSIBLE_HOST_KEY_CHECKING=False \
        ansible-playbook -i inventory.ini "$RHEL_CUSTOM_PLAYBOOK" --limit rocky_nodes -v
        local ANSIBLE_RC=$?
        [ $ANSIBLE_RC -ne 0 ] \
            && log_error "[Remediation/Rocky/ORG] Playbook FAILED (rc=${ANSIBLE_RC})" \
            || log_ok "[Remediation/Rocky/ORG] Playbook complete"
    fi
}

_remediate_alma() {
    [ ${#ALMA_MACHINES[@]} -eq 0 ] && return 0

    if [ "$RUN_CIS" == true ]; then
        local IP
        for IP in "${ALMA_MACHINES[@]}"; do
            (
                log_info "[Remediation/Alma/CIS] Starting on ${IP}..."
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
                local rc=$?
                case $rc in
                    124) log_error "[Remediation/Alma/CIS] TIMEOUT on ${IP}" ;;
                    255) log_error "[Remediation/Alma/CIS] SSH dropped on ${IP}" ;;
                    0|2) log_ok "[Remediation/Alma/CIS] ${IP} done (rc=${rc})" ;;
                    *)   log_warn "[Remediation/Alma/CIS] ${IP} rc=${rc}" ;;
                esac

                # Safety gate: confirm sudo access wasn't broken by remediation
                if ! ssh -n -o BatchMode=yes -o ConnectTimeout=10 \
                        ${GHOST_USER}@${IP} "sudo -n true" 2>/dev/null; then
                    log_error "CRITICAL: ${IP} lost passwordless sudo after CIS L2 remediation. A CIS rule likely re-enabled requiretty or sudo auth."
                    ssh -n -o BatchMode=yes -o ConnectTimeout=10 ${GHOST_USER}@${IP} "sudo -S true <<< ''" 2>/dev/null
                    log_error "Manual VNC fix needed, OR add the skip-rule above and re-run."
                fi
            ) &
        done
        wait
    fi
    if [ "$RUN_ORG" == true ]; then
        local IP
        for IP in "${ALMA_MACHINES[@]}"; do
            scp_custom_content_rhel "$GHOST_USER" "$IP" || true
        done
        ANSIBLE_HOST_KEY_CHECKING=False \
        ansible-playbook -i inventory.ini "$RHEL_CUSTOM_PLAYBOOK" --limit alma_nodes -v
        local ANSIBLE_RC=$?
        [ $ANSIBLE_RC -ne 0 ] \
            && log_error "[Remediation/Alma/ORG] Playbook FAILED (rc=${ANSIBLE_RC})" \
            || log_ok "[Remediation/Alma/ORG] Playbook complete"
    fi
}

_remediate_windows() {
    [ ${#WINDOWS_MACHINES[@]} -eq 0 ] && return 0

    if [ "$RUN_CIS" == true ]; then
        local IP
        for IP in "${WINDOWS_MACHINES[@]}"; do
            (
                wait_for_ssh "$IP" "${WIN_GHOST_USER}" || {
                    log_error "[Remediation/Win] SSH unreachable: $IP"
                    exit 1
                }
                remediate_windows_host "$IP" "$CIS_LEVEL"
            ) &
        done
        wait
    fi

    if [ "$RUN_ORG" == true ]; then
        log_info "[Remediation/Win/${ORG_PREFIX^^}] Running ${WIN_CUSTOM_PLAYBOOK} over SSH..."
        if [ ! -f "$WIN_CUSTOM_PLAYBOOK" ]; then
            log_error "[Remediation/Win/${ORG_PREFIX^^}] Playbook not found: ${WIN_CUSTOM_PLAYBOOK}"
        else
            local IP
            for IP in "${WINDOWS_MACHINES[@]}"; do
                wait_for_ssh "$IP" "$WIN_GHOST_USER" || \
                    log_warn "[Remediation/Win/${ORG_PREFIX^^}] ${IP} not responding yet — Ansible will retry/timeout on it"
            done

            ANSIBLE_HOST_KEY_CHECKING=False \
            ansible-playbook \
                -i inventory.ini \
                "$WIN_CUSTOM_PLAYBOOK" \
                --limit windows_nodes \
                --ssh-extra-args="-o StrictHostKeyChecking=no -o BatchMode=yes" \
                -v
            local ANSIBLE_RC=$?

            if [ $ANSIBLE_RC -ne 0 ]; then
                log_error "[Remediation/Win/${ORG_PREFIX^^}] Playbook FAILED (rc=${ANSIBLE_RC})"
            else
                log_ok "[Remediation/Win/${ORG_PREFIX^^}] Playbook complete (rc=${ANSIBLE_RC})"
            fi
        fi
    fi

    if [ "$RUN_CIS" == true ] && [ "${WIN_REBOOT_AFTER_REMEDIATION}" == "true" ]; then
        log_info "[Remediation/Win] Rebooting hardened Windows hosts (health-gated)..."
        : > /tmp/.win_hung_hosts
        local IP
        for IP in "${WINDOWS_MACHINES[@]}"; do
            (
                if ! check_windows_agent_alive "$IP"; then
                    log_error "[Remediation/Win/${IP}] Guest agent unresponsive BEFORE reboot."
                    echo "$IP" >> /tmp/.win_hung_hosts
                    exit 0
                fi
                reboot_windows_host "$IP"
                [ $? -eq 2 ] && echo "$IP" >> /tmp/.win_hung_hosts
            ) &
        done
        wait

        if [ -s /tmp/.win_hung_hosts ]; then
            log_error "[Remediation/Win] The following hosts did not survive remediation+reboot:"
            while read -r h; do log_error "     - ${h}"; done < /tmp/.win_hung_hosts
        fi
    fi
}

# ======================================================
# SECTION 6: PHASE 4 — VERIFICATION
# ======================================================
run_phase_4() {
    log_info "PHASE 4: Verification Scans (SCP install -> scan)..."
    reassert_ssh_rule_all_windows

    SCAN_SSH_OPTS="-n -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
        -o ConnectTimeout=10"

    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu"  ]] && _verify_ubuntu
    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rhel"    ]] && _verify_rhel
    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "rocky"   ]] && _verify_rocky
    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "alma"    ]] && _verify_alma
    [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]] && _verify_windows
}

_verify_ubuntu() {
    [ ${#UBUNTU_MACHINES[@]} -eq 0 ] && return 0
    local IP
    for IP in "${UBUNTU_MACHINES[@]}"; do
        (
            wait_for_ssh "$IP" "$GHOST_USER" || { log_error "[Phase4/Ubuntu] SSH unreachable: $IP"; exit 1; }
            ensure_linux_scap_tools "$GHOST_USER" "$IP" "apt" || { log_error "[Phase4/Ubuntu] Tools missing on $IP"; exit 1; }

            local UBUNTU_VER UBUNTU_CIS_XCCDF
            UBUNTU_VER=$(ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
            UBUNTU_VER=${UBUNTU_VER:-2404}
            UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

            if [ "$RUN_CIS" == true ]; then
                local REMOTE="/tmp/report_after_CIS_L${OS_LVL}_UBUNTU_${IP}.html"
                local LOCAL="./report_after_CIS_L${OS_LVL}_UBUNTU_${IP}.html"
                local EFFECTIVE_PROFILE="$UBUNTU_CIS_PROFILE" PROFILE_OK=true
                local AVAILABLE_PROFILES
                AVAILABLE_PROFILES=$(ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                    "sudo oscap info '$UBUNTU_CIS_XCCDF' 2>/dev/null | grep -oE 'xccdf_org\.ssgproject\.content_profile_[a-zA-Z0-9_]+'")

                if [ "$OS_LVL" == "2" ] && ! echo "$AVAILABLE_PROFILES" | grep -qx "$UBUNTU_CIS_PROFILE"; then
                    log_warn "[Phase4/Ubuntu] Level 2 profile not found — falling back to Level 1"
                    EFFECTIVE_PROFILE="xccdf_org.ssgproject.content_profile_cis_level1_server"
                fi
                if ! echo "$AVAILABLE_PROFILES" | grep -qx "$EFFECTIVE_PROFILE"; then
                    log_error "[Phase4/Ubuntu] Neither requested nor fallback profile exists in this datastream."
                    echo "$AVAILABLE_PROFILES" | sed 's/^/     /'
                    PROFILE_OK=false
                fi

                if [ "$PROFILE_OK" != true ]; then
                    log_error "[Phase4/Ubuntu/CIS] Skipping verify scan on $IP — no valid profile"
                else
                    ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                        "sudo oscap xccdf eval \
                         --profile $EFFECTIVE_PROFILE \
                         --report ${REMOTE} $UBUNTU_CIS_XCCDF > /tmp/oscap_console_${IP}.log 2>&1"
                    local rc=$?
                    if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                        local p f
                        p=$(ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+pass' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                        f=$(ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} "grep -cE '^Result[[:space:]]+fail' /tmp/oscap_console_${IP}.log" 2>/dev/null)
                        log_ok "[Phase4/Ubuntu/${ORG_PREFIX^^}] ${IP}: ${p:-?} passed, ${f:-?} failed"
                        fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Ubuntu/CIS"
                    else
                        log_error "[Phase4/Ubuntu/CIS] oscap failed on $IP (rc=$rc)"
                        ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} "cat /tmp/oscap_console_${IP}.log" 2>/dev/null \
                            | tail -20 | sed 's/^/     /'
                    fi
                fi
            fi

            if [ "$RUN_ORG" == true ]; then
                log_info "[Phase4/Ubuntu/ORG] Re-SCPing custom content to ${IP}..."
                scp_custom_content_ubuntu "$GHOST_USER" "$IP" || {
                    log_error "[Phase4/Ubuntu/ORG] SCP failed for ${IP} — skipping after-scan"
                    exit 1
                }
                local REMOTE="/tmp/report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html"
                local LOCAL="./report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html"
                ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                    "sudo oscap xccdf eval \
                     --profile $CUSTOM_XCCDF_PROFILE \
                     --report ${REMOTE} \
                     /tmp/$(basename $UBUNTU_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
                local rc=$?
                if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                    fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Ubuntu/${ORG_PREFIX^^}"
                else
                    log_error "[Phase4/Ubuntu/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)"
                fi
            fi
        ) &
    done
    wait
}

_verify_rhel() {
    [ ${#RHEL_MACHINES[@]} -eq 0 ] && return 0
    local IP
    for IP in "${RHEL_MACHINES[@]}"; do
        (
            wait_for_ssh "$IP" "$GHOST_USER" || { log_error "[Phase4/RHEL] SSH unreachable: $IP"; exit 1; }
            ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || { log_error "[Phase4/RHEL] Tools missing on $IP"; exit 1; }

            if [ "$RUN_CIS" == true ]; then
                local REMOTE="/tmp/report_after_CIS_L${OS_LVL}_RHEL_${IP}.html"
                local LOCAL="./report_after_CIS_L${OS_LVL}_RHEL_${IP}.html"
                ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                    "TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ \
                         -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                     sudo /usr/bin/oscap xccdf eval \
                         --profile $RHEL_CIS_PROFILE \
                         --report ${REMOTE} \"\$TARGET_XML\" > /tmp/oscap_console_${IP}.log 2>&1"
                local rc=$?
                if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                    fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "RHEL/CIS"
                else
                    log_error "[Phase4/RHEL/CIS] oscap failed on $IP (rc=$rc)"
                fi
            fi
            if [ "$RUN_ORG" == true ]; then
                scp_custom_content_rhel "$GHOST_USER" "$IP" || {
                    log_error "[Phase4/RHEL/ORG] SCP failed for ${IP} — skipping after-scan"
                    exit 1
                }
                local REMOTE="/tmp/report_after_${ORG_PREFIX^^}_RHEL_${IP}.html"
                local LOCAL="./report_after_${ORG_PREFIX^^}_RHEL_${IP}.html"
                ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                    "sudo /usr/bin/oscap xccdf eval \
                     --profile $CUSTOM_XCCDF_PROFILE \
                     --report ${REMOTE} \
                     /tmp/$(basename $RHEL_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
                local rc=$?
                if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                    fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "RHEL/${ORG_PREFIX^^}"
                else
                    log_error "[Phase4/RHEL/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)"
                fi
            fi
        ) &
    done
    wait
}

_verify_rocky() {
    [ ${#ROCKY_MACHINES[@]} -eq 0 ] && return 0
    local IP
    for IP in "${ROCKY_MACHINES[@]}"; do
        (
            wait_for_ssh "$IP" "$GHOST_USER" || { log_error "[Phase4/Rocky] SSH unreachable: $IP"; exit 1; }
            ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || { log_error "[Phase4/Rocky] Tools missing on $IP"; exit 1; }

            if [ "$RUN_CIS" == true ]; then
                local REMOTE="/tmp/report_after_CIS_L${OS_LVL}_ROCKY_${IP}.html"
                local LOCAL="./report_after_CIS_L${OS_LVL}_ROCKY_${IP}.html"
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
                local rc=$?
                if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                    fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Rocky/CIS"
                else
                    log_error "[Phase4/Rocky/CIS] oscap failed on $IP (rc=$rc)"
                fi
            fi
            if [ "$RUN_ORG" == true ]; then
                scp_custom_content_rhel "$GHOST_USER" "$IP" || {
                    log_error "[Phase4/Rocky/ORG] SCP failed for ${IP} — skipping after-scan"
                    exit 1
                }
                local REMOTE="/tmp/report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html"
                local LOCAL="./report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html"
                ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                    "sudo /usr/bin/oscap xccdf eval \
                     --profile $CUSTOM_XCCDF_PROFILE \
                     --report ${REMOTE} \
                     /tmp/$(basename $RHEL_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
                local rc=$?
                if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                    fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Rocky/${ORG_PREFIX^^}"
                else
                    log_error "[Phase4/Rocky/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)"
                fi
            fi
        ) &
    done
    wait
}

_verify_alma() {
    [ ${#ALMA_MACHINES[@]} -eq 0 ] && return 0
    local IP
    for IP in "${ALMA_MACHINES[@]}"; do
        (
            wait_for_ssh "$IP" "$GHOST_USER" || { log_error "[Phase4/Alma] SSH unreachable: $IP"; exit 1; }
            ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || { log_error "[Phase4/Alma] Tools missing on $IP"; exit 1; }

            if [ "$RUN_CIS" == true ]; then
                local REMOTE="/tmp/report_after_CIS_L${OS_LVL}_ALMA_${IP}.html"
                local LOCAL="./report_after_CIS_L${OS_LVL}_ALMA_${IP}.html"
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
                local rc=$?
                if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                    fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Alma/CIS"
                else
                    log_error "[Phase4/Alma/CIS] oscap failed on $IP (rc=$rc)"
                fi
            fi
            if [ "$RUN_ORG" == true ]; then
                scp_custom_content_rhel "$GHOST_USER" "$IP" || {
                    log_error "[Phase4/Alma/ORG] SCP failed for ${IP} — skipping after-scan"
                    exit 1
                }
                local REMOTE="/tmp/report_after_${ORG_PREFIX^^}_ALMA_${IP}.html"
                local LOCAL="./report_after_${ORG_PREFIX^^}_ALMA_${IP}.html"
                ssh $SCAN_SSH_OPTS ${GHOST_USER}@${IP} \
                    "sudo /usr/bin/oscap xccdf eval \
                     --profile $CUSTOM_XCCDF_PROFILE \
                     --report ${REMOTE} \
                     /tmp/$(basename $RHEL_CUSTOM_XCCDF) > /tmp/oscap_console_${IP}.log 2>&1"
                local rc=$?
                if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                    fetch_remote_report "$GHOST_USER" "$IP" "$REMOTE" "$LOCAL" "Alma/${ORG_PREFIX^^}"
                else
                    log_error "[Phase4/Alma/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)"
                fi
            fi
        ) &
    done
    wait
}

_verify_windows() {
    [ ${#WINDOWS_MACHINES[@]} -eq 0 ] && return 0

    validate_win_cis_profile || {
        log_error "[Phase4/Win] Profile validation failed — skipping all Windows hosts."
        return 1
    }

    local IP
    for IP in "${WINDOWS_MACHINES[@]}"; do
        (
            if [ -f /tmp/.win_hung_hosts ] && grep -qx "$IP" /tmp/.win_hung_hosts 2>/dev/null; then
                log_error "[Phase4/Win] ${IP} flagged hung after remediation — skipping verify scan"
                exit 0
            fi
            wait_for_ssh "$IP" "$WIN_GHOST_USER" || {
                log_error "[Phase4/Win] SSH unreachable on ${IP} — skipping"
                exit 1
            }
            if [ "$RUN_CIS" == true ]; then
                log_ok "[Phase4/Win/CIS L${WIN_INSPEC_LVL}] Verifying $IP..."
                local WIN_RB_FILE="${WIN_CIS_BENCHMARK}/controls/cis_ws2022_v5_0_0_benchmark.rb"
                local WIN_LEVEL_CONTROLS=()
                mapfile -t WIN_LEVEL_CONTROLS < <(get_win_cis_controls_for_level "$WIN_RB_FILE" "$WIN_INSPEC_LVL")

                if [ ${#WIN_LEVEL_CONTROLS[@]} -eq 0 ]; then
                    log_error "[Phase4/Win/CIS] No controls matched level ${WIN_INSPEC_LVL} in ${WIN_RB_FILE} — aborting verify scan for ${IP}"
                else
                    log_info "${#WIN_LEVEL_CONTROLS[@]} controls selected for CIS L${WIN_INSPEC_LVL} verify scan"
                    timeout "${WIN_SCAN_TIMEOUT_SEC}" cinc-auditor exec "${WIN_CIS_BENCHMARK}" \
                        -t "ssh://${WIN_GHOST_USER}@${IP}" \
                        --input "server_role=${WIN_SERVER_ROLE}" \
                        --input "profile_level=${WIN_INSPEC_LVL}" \
                        --controls "${WIN_LEVEL_CONTROLS[@]}" \
                        --reporter "json:heimdall_after_CIS_L${WIN_INSPEC_LVL}_WIN_${IP}.json"
                    local rc=$?
                    case $rc in
                        0|100|101) log_ok "[Phase4/Win/CIS L${WIN_INSPEC_LVL}] $IP verify complete (rc=$rc)" ;;
                        124)       log_error "[Phase4/Win/CIS L${WIN_INSPEC_LVL}] scan TIMED OUT on $IP after ${WIN_SCAN_TIMEOUT_SEC}s" ;;
                        *)         log_error "[Phase4/Win/CIS L${WIN_INSPEC_LVL}] cinc-auditor failed on $IP (rc=$rc)" ;;
                    esac
                fi
            fi
            if [ "$RUN_ORG" == true ]; then
                log_ok "[Phase4/Win/${ORG_PREFIX^^}] Verifying $IP..."
                timeout "${WIN_SCAN_TIMEOUT_SEC}" cinc-auditor exec "${WIN_CUSTOM_BENCHMARK}" \
                    -t "ssh://${WIN_GHOST_USER}@${IP}" \
                    --reporter "json:heimdall_after_${ORG_PREFIX^^}_WIN_${IP}.json"
                local rc=$?
                case $rc in
                    0|100|101) log_ok "[Phase4/Win/${ORG_PREFIX^^}] $IP verify complete (rc=$rc)" ;;
                    124)       log_error "[Phase4/Win/${ORG_PREFIX^^}] scan TIMED OUT on $IP after ${WIN_SCAN_TIMEOUT_SEC}s" ;;
                    *)         log_error "[Phase4/Win/${ORG_PREFIX^^}] cinc-auditor failed on $IP (rc=$rc)" ;;
                esac
            fi
        ) &
    done
    wait
}

# ======================================================
# SECTION 7: PHASE 5 — CLEANUP
# ======================================================
run_cleanup() {
    log_info "PHASE 5: POST-AUDIT CLEANUP"
    log_info "VM stays HARDENED — oscap tools/files removed. Audit user is kept for future runs."

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
        local IP
        for IP in "${UBUNTU_MACHINES[@]}"; do
            did_linux_cleanup=true
            log_info "[Cleanup/Ubuntu] Removing oscap artifacts on ${IP}..."
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                ${GHOST_USER}@${IP} "$remove_deb" 2>&1 || \
                log_warn "[Cleanup/Ubuntu] Some steps may have failed on ${IP} — check manually"
        done
    fi

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" =~ ^(rhel|rocky|alma)$ ]]; then
        local IP
        for IP in "${RHEL_MACHINES[@]}" "${ROCKY_MACHINES[@]}" "${ALMA_MACHINES[@]}"; do
            did_linux_cleanup=true
            log_info "[Cleanup/RHEL-family] Removing oscap artifacts on ${IP}..."
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no \
                ${GHOST_USER}@${IP} "$remove_rpm" 2>&1 || \
                log_warn "[Cleanup/RHEL-family] Some steps may have failed on ${IP} — check manually"
        done
    fi

    if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
        local IP
        for IP in "${WINDOWS_MACHINES[@]}"; do
            log_info "[Cleanup/Windows] No file/tool removal defined for Windows targets — audit user + WinRM config left as-is."
        done
    fi

    wait

    if [ "$did_linux_cleanup" == true ]; then
        log_ok "[Phase 5] All oscap tools, content, temp/report files, and logs removed from Linux hosts."
    else
        log_ok "[Phase 5] Cleanup complete — no Linux hosts targeted, nothing to remove."
    fi
    log_ok "Audit user + sudo access kept in place for future scheduled runs."
}
