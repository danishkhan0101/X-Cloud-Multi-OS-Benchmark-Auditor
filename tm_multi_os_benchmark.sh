#!/bin/bash

# ======================================================
# CONFIGURATION - DYNAMIC ENVIRONMENT VARIABLES
# ======================================================
# Load local .env file if it exists (for manual terminal runs)
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

# --- AZURE TARGET INFRASTRUCTURE ---
RG_NAME="${AZURE_RG_NAME:-Packer_RG}"
KV_NAME="${AZURE_KV_NAME:-TM-Vault-Danish}"
SECRET_NAME="${AZURE_KV_SECRET:-AuditPassword}"

# --- FLEET CREDENTIALS ---
UBUNTU_USER="${LINUX_ADMIN_USER:-ubuntu}"
AUDIT_USER="${WINDOWS_ADMIN_USER:-TM_Admin}"
AUDIT_HOST_NAME="${EXCLUDE_HOST_NAME:-Audit-Host}"

# --- DIRECTORY MAPPINGS (Static) ---
UBUNTU_DIR="ubuntu-custom"
XCCDF_FILE="${UBUNTU_DIR}/tm_xccdf.xml"
OVAL_RULES="${UBUNTU_DIR}/tm_ubuntu_rules.xml"
UBUNTU_PLAYBOOK="${UBUNTU_DIR}/ubuntu_custom_playbook.yml"
UBUNTU_DEF_DIR="ubuntu-default-cis"
XCCDF_DEF_FILE="${UBUNTU_DEF_DIR}/ssg-ubuntu2404-ds.xml"

WIN_DIR="window-custom"
WIN_BENCHMARK="${WIN_DIR}/tm_baseline.rb"
WIN_PLAYBOOK="${WIN_DIR}/tm_remediate.yml"
WIN_DEF_DIR="window-default-cis"
WIN_DEF_BENCHMARK="${WIN_DEF_DIR}/window-baseline"
WIN_DEF_PLAYBOOK="${WIN_DEF_DIR}/cis_remediate.yml"

# Global Settings
export CHEF_LICENSE="accept-silent"
export INSPEC_SSH_CONFIG_NO_SECURE=true
BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

clear

# ======================================================
# HEADLESS MODE PARSER (For CI/CD Automation)
# ======================================================
HEADLESS=false
H_PROFILE="tm"
H_MODE="scan"
H_TARGETS="all"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --headless) HEADLESS=true ;;
        --profile) H_PROFILE="$2"; shift ;;
        --mode) H_MODE="$2"; shift ;;
        --targets) H_TARGETS="$2"; shift ;;
        *) echo -e "${RED}Unknown parameter: $1${NC}"; exit 1 ;;
    esac
    shift
done

if [ "$HEADLESS" == true ]; then
    echo -e "${CYAN}${BOLD}🤖 HEADLESS CI/CD MODE ACTIVATED${NC}"
fi

# ======================================================
# PHASE 0: ZERO-TRUST DISCOVERY (TAG-AWARE)
# ======================================================
echo -e "${CYAN}📡 Querying Azure for VMs in [$RG_NAME]...${NC}"

# 1. Query Azure using an ORDERED ARRAY [ ] instead of a Dictionary { }
if [ "$H_TARGETS" == "all" ] || [ -z "$H_TARGETS" ]; then
    echo "🔍 Target Mode: ALL VMs"
    VM_DATA=$(az vm list -d -g "$RG_NAME" --query "[].[publicIps, storageProfile.osDisk.osType]" -o tsv)
else
    echo "🔍 Target Mode: Environment Tag -> $H_TARGETS"
    VM_DATA=$(az vm list -d -g "$RG_NAME" --query "[?tags.Environment=='$H_TARGETS'].[publicIps, storageProfile.osDisk.osType]" -o tsv)
fi

if [ -z "$VM_DATA" ]; then
    echo -e "${RED}❌ ERROR: No VMs found matching Environment tag '$H_TARGETS' in '$RG_NAME'.${NC}"
    exit 1
fi

UBUNTU_MACHINES=()
WINDOWS_MACHINES=()

while IFS=$'\t' read -r raw_ip raw_os; do
    # 2. Scrub invisible carriage returns (\r) and trailing spaces
    ip=$(echo "$raw_ip" | tr -d '\r' | xargs)
    os=$(echo "$raw_os" | tr -d '\r' | xargs)
    
    if [ -z "$ip" ] || [ "$ip" == "None" ]; then continue; fi
    
    # 3. Strict OS Routing
    if [[ "$os" == *"Linux"* ]] || [[ "$os" == *"Ubuntu"* ]]; then
        UBUNTU_MACHINES+=("$ip")
        echo -e "${GREEN}🐧 Mapped Ubuntu Node: $ip${NC}"
    elif [[ "$os" == *"Windows"* ]]; then
        WINDOWS_MACHINES+=("$ip")
        echo -e "${BLUE}🪟 Mapped Windows Node: $ip${NC}"
    else
        echo -e "${YELLOW}⚠️ Warning: Unrecognized OS ($os) for IP $ip. Skipping.${NC}"
    fi
done <<< "$VM_DATA"

echo -e "${GREEN}✅ Discovery Complete: Found ${#UBUNTU_MACHINES[@]} Linux and ${#WINDOWS_MACHINES[@]} Windows targets.${NC}"

# ======================================================
# INVENTORY BUILDER & AZURE KEYVAULT AUTH
# ======================================================
# Fetch Windows Password from Azure KeyVault if needed
if [ -z "$AUDIT_PASS" ] && [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
    # Try fetching via Managed Identity (if running on Azure VM)
    az login --identity --allow-no-subscriptions > /dev/null 2>&1 || true
    AUDIT_PASS=$(az keyvault secret show --name "$SECRET_NAME" --vault-name "$KV_NAME" --query value -o tsv 2>/dev/null | tr -d '\r\n')
fi

# BUILD THE FINAL ANSIBLE INVENTORY
echo "[ubuntu_nodes]" > inventory.ini
for ip in "${UBUNTU_MACHINES[@]}"; do echo "${ip} ansible_user=${UBUNTU_USER}" >> inventory.ini; done
echo "" >> inventory.ini
echo "[windows_nodes]" >> inventory.ini
for ip in "${WINDOWS_MACHINES[@]}"; do echo "${ip} ansible_user=${AUDIT_USER} ansible_password=\"${AUDIT_PASS}\" ansible_connection=ssh ansible_shell_type=powershell ansible_shell_executable=None" >> inventory.ini; done

# ======================================================
# PHASE 0.75: COMPLIANCE PROFILE SELECTION
# ======================================================
echo -e "\n${CYAN}${BOLD}======================================================"
echo -e "📋 PHASE 0.75: COMPLIANCE PROFILE"
echo -e "======================================================${NC}"

RUN_TM=false
RUN_CIS=false

if [ "$HEADLESS" == true ]; then
    if [ "$H_PROFILE" == "tm" ] || [ "$H_PROFILE" == "both" ]; then RUN_TM=true; fi
    if [ "$H_PROFILE" == "cis" ] || [ "$H_PROFILE" == "both" ]; then RUN_CIS=true; fi
    echo -e "${GREEN}✅ CI/CD Pipeline: Running profile -> $H_PROFILE${NC}"
else
    echo -e "1) ${BOLD}TM CUSTOM BASELINE${NC}   (Run custom playbooks/rules)"
    echo -e "2) ${BOLD}CIS DEFAULT BASELINE${NC} (Run standard CIS playbooks/rules)"
    echo -e "3) ${BOLD}RUN BOTH SECURELY${NC}    (Comprehensive Audit)"
    read -p "Choose profile mode [1-3]: " profile_choice

    if [ "$profile_choice" == "1" ] || [ "$profile_choice" == "3" ]; then RUN_TM=true; fi
    if [ "$profile_choice" == "2" ] || [ "$profile_choice" == "3" ]; then RUN_CIS=true; fi
fi

# ======================================================
# CORE FUNCTIONS (Execution)
# ======================================================

run_phase_1() {
    echo -e "\n${BOLD}🔍 PHASE 1: Running Initial Baselines...${NC}"
    for IP in "${UBUNTU_MACHINES[@]}"; do
        if [ "$RUN_CIS" == true ]; then
            echo -e "${GREEN}📦 [UBUNTU - CIS] Scanning $IP...${NC}"
            oscap-ssh --sudo ${UBUNTU_USER}@${IP} 22 xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_level1_server --report report_before_CIS_${IP}.html "$XCCDF_DEF_FILE"
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${GREEN}📦 [UBUNTU - TM] Scanning $IP...${NC}"
            scp "$OVAL_RULES" ${UBUNTU_USER}@${IP}:/tmp/tm_ubuntu_rules.xml >/dev/null 2>&1
            oscap-ssh --sudo ${UBUNTU_USER}@${IP} 22 xccdf eval --profile xccdf_com.tm_profile_lsb --report report_before_TM_${IP}.html "$XCCDF_FILE"
        fi
    done
    for IP in "${WINDOWS_MACHINES[@]}"; do
        if [ "$RUN_CIS" == true ]; then
            echo -e "${CYAN}🔍 [WINDOWS - CIS] Scanning $IP...${NC}"
            /usr/bin/inspec exec $WIN_DEF_BENCHMARK -t ssh://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter cli json:heimdall_before_CIS_${IP}.json --chef-license accept-silent
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${CYAN}🔍 [WINDOWS - TM] Scanning $IP...${NC}"
            /usr/bin/inspec exec $WIN_BENCHMARK -t ssh://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter cli json:heimdall_before_TM_${IP}.json --chef-license accept-silent
        fi
    done
}

run_remediation() {
    echo -e "\n${BOLD}🛠️  PHASE 2 & 3: Executing Remediation...${NC}"
    
    if [ ${#UBUNTU_MACHINES[@]} -gt 0 ]; then
        if [ "$RUN_CIS" == true ]; then
            echo -e "${GREEN}▶️ [CIS] Auto-Remediating Ubuntu via OpenSCAP Workspace...${NC}"
            for IP in "${UBUNTU_MACHINES[@]}"; do
                echo -e "   ${YELLOW}Fixing $IP...${NC}"
                ssh ${UBUNTU_USER}@${IP} "mkdir -p ~/tm_audit"
                scp "$XCCDF_DEF_FILE" ${UBUNTU_USER}@${IP}:~/tm_audit/ssg-ubuntu2404-ds.xml > /dev/null
                ssh -t ${UBUNTU_USER}@${IP} "sudo oscap xccdf eval --remediate --profile xccdf_org.ssgproject.content_profile_cis_level1_server --report ~/tm_audit/report_remediation.html ~/tm_audit/ssg-ubuntu2404-ds.xml"
                scp ${UBUNTU_USER}@${IP}:~/tm_audit/report_remediation.html ./report_remediation_CIS_${IP}.html > /dev/null
                ssh ${UBUNTU_USER}@${IP} "rm -rf ~/tm_audit"
            done
        fi   
        if [ "$RUN_TM" == true ]; then
            echo -e "${GREEN}▶️ [TM] Running Custom Ubuntu Playbook...${NC}"
            ansible-playbook -i inventory.ini $UBUNTU_PLAYBOOK --limit ubuntu_nodes
        fi
    fi

    if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
        if [ "$RUN_CIS" == true ]; then
            echo -e "${CYAN}▶️ [HARDENING - CIS] Applying Baseline as $AUDIT_USER...${NC}"
            ansible-playbook -i inventory.ini $WIN_DEF_PLAYBOOK --limit windows_nodes
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${CYAN}▶️ [HARDENING - TM] Applying Baseline as $AUDIT_USER...${NC}"
            ansible-playbook -i inventory.ini $WIN_PLAYBOOK --limit windows_nodes
        fi
    fi
}

run_phase_4() {
    echo -e "\n${BOLD}🔄 PHASE 4: Running Verification Scans...${NC}"
    for IP in "${UBUNTU_MACHINES[@]}"; do
        if [ "$RUN_CIS" == true ]; then
            echo -e "${GREEN}✅ [UBUNTU - CIS] Verifying $IP...${NC}"
            oscap-ssh --sudo ${UBUNTU_USER}@${IP} 22 xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_level1_server --report report_after_CIS_${IP}.html "$XCCDF_DEF_FILE"
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${GREEN}✅ [UBUNTU - TM] Verifying $IP...${NC}"
            oscap-ssh --sudo ${UBUNTU_USER}@${IP} 22 xccdf eval --profile xccdf_com.tm_profile_lsb --report report_after_TM_${IP}.html "$XCCDF_FILE"
        fi
    done
    for IP in "${WINDOWS_MACHINES[@]}"; do
        if [ "$RUN_CIS" == true ]; then
            echo -e "${CYAN}✅ [WINDOWS - CIS] Verifying $IP...${NC}"
            /usr/bin/inspec exec $WIN_DEF_BENCHMARK -t ssh://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter cli json:heimdall_after_CIS_${IP}.json --chef-license accept-silent
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${CYAN}✅ [WINDOWS - TM] Verifying $IP...${NC}"
            /usr/bin/inspec exec $WIN_BENCHMARK -t ssh://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter cli json:heimdall_after_TM_${IP}.json --chef-license accept-silent
        fi
    done
}

# ======================================================
# HEADLESS EXECUTION (Bypasses Interactive Menu)
# ======================================================
if [ "$HEADLESS" == true ]; then
    echo -e "\n${CYAN}${BOLD}======================================================"
    echo -e "🚀 EXECUTING CI/CD WORKFLOW: MODE -> $H_MODE"
    echo -e "======================================================${NC}"
    
    case $H_MODE in
        scan) run_phase_1 ;;
        remediate) run_remediation ;;
        full) run_phase_1; run_remediation; run_phase_4 ;;
        *) echo -e "${RED}Invalid headless mode specified. Use scan, remediate, or full.${NC}"; exit 1 ;;
    esac
    
    chmod 755 *.json *.html 2>/dev/null || true
    echo -e "\n${GREEN}✅ CI/CD Pipeline Execution Complete. All reports generated.${NC}"
    exit 0
fi

# ======================================================
# INTERACTIVE MENU (INFINITE LOOP)
# ======================================================
while true; do
    echo -e "\n${CYAN}------------------------------------------------------${NC}"
    echo -e "🎯 READY TO EXECUTE ON CHOSEN TARGETS"
    echo -e "${CYAN}------------------------------------------------------${NC}"
    echo -e "1) ${BOLD}SCAN ONLY${NC}      (Initial Baseline)"
    echo -e "2) ${BOLD}REMEDIATE ONLY${NC} (Ansible Fixes)"
    echo -e "3) ${BOLD}FULL PIPELINE${NC}  (Run all phases in order)"
    echo -e "4) ${BOLD}EXIT${NC}"
    echo -e "${CYAN}------------------------------------------------------${NC}"
    read -p "Choose an option [1-4]: " choice

    case $choice in
        1) run_phase_1 ;;
        2) run_remediation ;;
        3) run_phase_1; run_remediation; run_phase_4 ;;
        4) 
            chmod 755 *.json *.html 2>/dev/null || true
            echo -e "\n${GREEN}✅ Exiting Fleet Commander. All compliance reports safely stored.${NC}"
            exit 0 
            ;;
        *) 
            echo -e "${RED}Invalid option. Please try again.${NC}"; continue ;;
    esac

    echo -e "\n${YELLOW}------------------------------------------------------${NC}"
    read -n 1 -s -r -p "Press any key to return to the main menu..."
    echo ""
done
