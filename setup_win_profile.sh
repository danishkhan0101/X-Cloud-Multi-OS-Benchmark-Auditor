#!/bin/bash
# =============================================================================
# setup_win_profile.sh
# =============================================================================
# Run this ONCE to place the files from files_2.zip into the correct folder
# layout expected by audit_main.sh:
#
#   window-default-cis/
#   └── window-baseline/
#       ├── inspec.yml
#       └── controls/
#           ├── section_01_account_policies.rb
#           ├── section_02_local_policies.rb
#           ├── section_09_windows_firewall.rb
#           ├── section_17_advanced_audit_policy.rb
#           ├── section_18_admin_templates_computer.rb
#           └── section_19_admin_templates_user.rb
#
# Usage:
#   chmod +x setup_win_profile.sh
#   ./setup_win_profile.sh /path/to/files_2.zip
#
# If no argument is given, looks for files_2.zip in the current directory.
# =============================================================================
set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'

ZIP_FILE="${1:-files_2.zip}"
PROFILE_DIR="window-default-cis/window-baseline"
CONTROLS_DIR="${PROFILE_DIR}/controls"

# ---- Validate zip exists ----
if [ ! -f "$ZIP_FILE" ]; then
    echo -e "${RED}❌ Zip not found: ${ZIP_FILE}${NC}"
    echo "   Usage: $0 [path/to/files_2.zip]"
    exit 1
fi

echo -e "${CYAN}${BOLD}🗂️  Setting up CIS WS2022 v5.0.0 InSpec profile...${NC}"
echo -e "${CYAN}   Source : ${ZIP_FILE}${NC}"
echo -e "${CYAN}   Target : ${PROFILE_DIR}/${NC}"

# ---- Create directory structure ----
mkdir -p "${CONTROLS_DIR}"

# ---- Extract to temp dir ----
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT
unzip -q "$ZIP_FILE" -d "$TMP"

# ---- Copy inspec.yml ----
if [ ! -f "$TMP/inspec.yml" ]; then
    echo -e "${RED}❌ inspec.yml not found inside ${ZIP_FILE}${NC}"
    exit 1
fi
cp "$TMP/inspec.yml" "${PROFILE_DIR}/inspec.yml"
echo -e "${GREEN}   ✅ inspec.yml${NC}"

# ---- Copy control .rb files ----
rb_count=0
for rb in "$TMP"/section_*.rb; do
    [ -f "$rb" ] || continue
    cp "$rb" "${CONTROLS_DIR}/$(basename $rb)"
    echo -e "${GREEN}   ✅ controls/$(basename $rb)${NC}"
    rb_count=$((rb_count + 1))
done

if [ $rb_count -eq 0 ]; then
    echo -e "${RED}❌ No section_*.rb files found inside ${ZIP_FILE}${NC}"
    exit 1
fi

# ---- Copy PowerShell remediation scripts (Invoke-CISRemediation.ps1 + helpers) ----
for ps1 in "$TMP"/*.ps1; do
    [ -f "$ps1" ] || continue
    cp "$ps1" "${PROFILE_DIR}/$(basename $ps1)"
    echo -e "${GREEN}   ✅ $(basename $ps1) (PowerShell remediation)${NC}"
done

# ---- Copy optional docs ----
for doc in README.md COVERAGE.md; do
    [ -f "$TMP/$doc" ] && cp "$TMP/$doc" "${PROFILE_DIR}/$doc" && \
        echo -e "${GREEN}   ✅ ${doc}${NC}" || true
done

# ---- Summary ----
echo ""
echo -e "${GREEN}${BOLD}✅ Profile layout ready:${NC}"
find "${PROFILE_DIR}" -type f | sort | while read f; do
    echo "   $f"
done

echo ""
echo -e "${CYAN}${BOLD}Profile inputs (override via --input or .env):${NC}"
echo -e "   server_role  = member_server | domain_controller  (default: member_server)"
echo -e "   profile_level= 1 | 2                              (default: 1 — set by CIS_LEVEL)"
echo ""
echo -e "${GREEN}Run audit_main.sh normally — validate_win_cis_profile() will confirm the layout.${NC}"
