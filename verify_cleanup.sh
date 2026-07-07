#!/bin/bash
# verify_cleanup.sh — checks a Linux ECS target for leftover oscap artifacts
# Usage: ./verify_cleanup.sh <user> <ip>

set -euo pipefail

USER="$1"
IP="$2"

if [ -z "$USER" ] || [ -z "$IP" ]; then
    echo "Usage: $0 <ssh_user> <ip>"
    exit 1
fi

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}🔍 Verifying oscap cleanup on ${USER}@${IP}...${NC}"

REMOTE_CHECK='
FOUND=0

check_path() {
    local desc="$1"
    local pattern="$2"
    local matches
    matches=$(sudo bash -c "ls -la ${pattern} 2>/dev/null" || true)
    if [ -n "$matches" ]; then
        echo "❌ LEFTOVER: ${desc}"
        echo "$matches" | sed "s/^/     /"
        return 1
    else
        echo "✅ Clean: ${desc}"
        return 0
    fi
}

echo "--- Package check ---"
if command -v dpkg >/dev/null 2>&1; then
    PKGS=$(dpkg -l | grep -E "openscap|ssg-base|ssg-debderived" || true)
else
    PKGS=$(rpm -qa | grep -E "openscap|scap-security-guide" || true)
fi
if [ -n "$PKGS" ]; then
    echo "❌ LEFTOVER: SCAP packages still installed"
    echo "$PKGS" | sed "s/^/     /"
    FOUND=1
else
    echo "✅ Clean: no SCAP packages installed"
fi

echo "--- File/directory checks ---"
check_path "SCAP offline cache dir"          "/tmp/scap_offline"            || FOUND=1
check_path "oscap console logs"              "/tmp/oscap_console_*.log"     || FOUND=1
check_path "before-scan HTML reports"        "/tmp/report_before_*.html"    || FOUND=1
check_path "after-scan HTML reports"         "/tmp/report_after_*.html"     || FOUND=1
check_path "remediation HTML reports"        "/tmp/report_remediation_*.html" || FOUND=1
check_path "custom XCCDF/OVAL in /tmp"       "/tmp/*_xccdf.xml"             || FOUND=1
check_path "custom rules XML in /tmp"        "/tmp/*_rules.xml"             || FOUND=1
check_path "SCAP datastream content dir"     "/usr/share/xml/scap/ssg/content/*" || FOUND=1

echo "--- oscap binary check ---"
if command -v oscap >/dev/null 2>&1; then
    echo "❌ LEFTOVER: oscap binary still present at $(command -v oscap)"
    FOUND=1
else
    echo "✅ Clean: oscap binary not found"
fi

echo "---"
if [ "$FOUND" -eq 1 ]; then
    echo "RESULT: DIRTY — leftovers found"
    exit 1
else
    echo "RESULT: CLEAN — no oscap artifacts remain"
    exit 0
fi
'

if ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
    "${USER}@${IP}" "$REMOTE_CHECK"; then
    echo -e "${GREEN}✅ ${IP} is fully clean.${NC}"
    exit 0
else
    echo -e "${RED}❌ ${IP} still has leftover oscap artifacts. See output above.${NC}"
    exit 1
fi
