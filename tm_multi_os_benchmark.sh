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
AUDIT_HOST_NAME="Audit-Host"
export CHEF_LICENSE="accept-silent"
export INSPEC_SSH_CONFIG_NO_SECURE=true
BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

clear

# ======================================================
# HEADLESS MODE PARSER (For CI/CD Automation)
# ======================================================
HEADLESS=false
H_PROFILE="both"
H_MODE="full"
H_TARGETS="all"  # <--- NEW DEFAULT

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --headless) HEADLESS=true ;;
        --profile) H_PROFILE="$2"; shift ;;
        --mode) H_MODE="$2"; shift ;;
        --targets) H_TARGETS="$2"; shift ;;  # <--- NEW FLAG
        *) echo -e "${RED}Unknown parameter: $1${NC}"; exit 1 ;;
    esac
    shift
done

if [ "$HEADLESS" == true ]; then
    echo -e "${CYAN}${BOLD}🤖 HEADLESS CI/CD MODE ACTIVATED${NC}"
fi

# ======================================================
# PHASE 0: AUTODISCOVERY & INTELLIGENT INJECTION
# ======================================================
echo -e "${CYAN}${BOLD}======================================================"
echo -e "🔍 PHASE 0: AZURE HEALTH, OS DISCOVERY & INJECTION"
echo -e "======================================================${NC}"

echo -n "🤖 Determining Audit-Host Identity... "
MY_IP=$(curl -s ifconfig.me)
echo -e "${YELLOW}$MY_IP${NC}"

echo -e "📡 Querying Azure for VMs and Identity Tags in [${BOLD}$RG_NAME${NC}]..."
VM_DATA=$(az vm list -d -g "$RG_NAME" --query "[?powerState=='VM running'].[name, publicIps]" -o tsv 2>/dev/null)
if [ -z "$VM_DATA" ]; then
    echo -e "${RED}❌ ERROR: No VMs found in '$RG_NAME'.${NC}"; exit 1
fi

declare -a MASTER_UBUNTU
declare -a MASTER_WINDOWS
COUNT=0
KV_FETCHED=false

TRACKING_FILE=".tm_injected_vms.log"
touch "$TRACKING_FILE"

echo -e "✅ Data retrieved. Processing nodes..."
while read -r VM_NAME IP; do
    
    if [ "$VM_NAME" == "$AUDIT_HOST_NAME" ] || [ "$IP" == "$MY_IP" ]; then 
        echo -e "   [-] ${YELLOW}Skipping $VM_NAME (Audit-Host Exception)${NC}"
        continue
    fi

    ((COUNT++))
    
    if ! grep -q "^${VM_NAME}$" "$TRACKING_FILE"; then
        echo -e "   ${YELLOW}[$COUNT] 🔐 Injecting TM_Admin into $VM_NAME...${NC}"
        
        if [ "$KV_FETCHED" == false ]; then
            az login --identity --allow-no-subscriptions > /dev/null 2>&1
            AUDIT_PASS=$(az keyvault secret show --name "$SECRET_NAME" --vault-name "$KV_NAME" --query value -o tsv | tr -d '\r\n')
            KV_FETCHED=true
        fi

        az vm user update -g "$RG_NAME" -n "$VM_NAME" -u "$AUDIT_USER" -p "$AUDIT_PASS" > /dev/null 2>&1
        echo "$VM_NAME" >> "$TRACKING_FILE"
    else
        echo -e "   ${GREEN}[$COUNT] ⚡ Identity already injected for $VM_NAME (Skipping).${NC}"
    fi

    echo -n "        Scanning OS for $IP... "
    IS_LINUX=$(ssh -o ConnectTimeout=5 -o BatchMode=yes ${UBUNTU_USER}@${IP} "uname" 2>/dev/null)
    if [ "$IS_LINUX" == "Linux" ]; then
        echo -e "${GREEN}🐧 Ubuntu${NC}"
        MASTER_UBUNTU+=("$IP")
    else
        echo -e "${CYAN}🪟 Windows${NC}"
        MASTER_WINDOWS+=("$IP")
    fi
done <<< "$VM_DATA"

# ======================================================
# PHASE 0.5: TARGET SCOPE SELECTION
# ======================================================
echo -e "\n${CYAN}${BOLD}======================================================"
echo -e "🎯 PHASE 0.5: TARGET SCOPE SELECTION"
echo -e "======================================================${NC}"

declare -a UBUNTU_MACHINES
declare -a WINDOWS_MACHINES

# Pre-build the map just in case we need custom targeting (Headless or Interactive)
idx=1; declare -A IP_MAP
for ip in "${MASTER_UBUNTU[@]}"; do IP_MAP[$idx]="$ip:U"; ((idx++)); done
for ip in "${MASTER_WINDOWS[@]}"; do IP_MAP[$idx]="$ip:W"; ((idx++)); done

if [ "$HEADLESS" == true ]; then
    if [ "$H_TARGETS" == "all" ]; then
        UBUNTU_MACHINES=("${MASTER_UBUNTU[@]}")
        WINDOWS_MACHINES=("${MASTER_WINDOWS[@]}")
        echo -e "${GREEN}✅ CI/CD Pipeline: Automatically targeting all discovered machines.${NC}"
    else
        # Process the custom targets passed from the CI/CD pipeline
        custom_nums="${H_TARGETS//,/ }"
        for n in $custom_nums; do
            entry="${IP_MAP[$n]}"
            if [ -n "$entry" ]; then
                ip="${entry%:*}"; os="${entry#*:}"
                if [ "$os" == "U" ]; then UBUNTU_MACHINES+=("$ip"); elif [ "$os" == "W" ]; then WINDOWS_MACHINES+=("$ip"); fi
            fi
        done
        echo -e "${GREEN}✅ CI/CD Pipeline: Custom targets injected -> [ $H_TARGETS ]${NC}"
    fi
else
    echo -e "1) ${BOLD}ALL MACHINES${NC} (Target all $COUNT discovered VMs)"
    echo -e "2) ${BOLD}CUSTOM SELECTION${NC} (Pick specific machines)"
    read -p "Choose target scope [1-2]: " scope_choice

    if [ "$scope_choice" == "1" ]; then
        UBUNTU_MACHINES=("${MASTER_UBUNTU[@]}")
        WINDOWS_MACHINES=("${MASTER_WINDOWS[@]}")
        echo -e "${GREEN}✅ Targeting all machines.${NC}"
    else
        echo -e "\n${YELLOW}Available Machines:${NC}"
        # Print the map for the human
        idx=1
        for ip in "${MASTER_UBUNTU[@]}"; do echo -e "   ${BOLD}[$idx]${NC} $ip ${GREEN}(Ubuntu)${NC}"; ((idx++)); done
        for ip in "${MASTER_WINDOWS[@]}"; do echo -e "   ${BOLD}[$idx]${NC} $ip ${CYAN}(Windows)${NC}"; ((idx++)); done
        
        read -p "Targets (e.g., '1,3,6' or '1 2 3'): " custom_nums
        
        # --- Input Sanitization ---
        custom_nums="${custom_nums//,/ }"
        
        for n in $custom_nums; do
            entry="${IP_MAP[$n]}"
            if [ -n "$entry" ]; then
                ip="${entry%:*}"; os="${entry#*:}"
                if [ "$os" == "U" ]; then UBUNTU_MACHINES+=("$ip"); elif [ "$os" == "W" ]; then WINDOWS_MACHINES+=("$ip"); fi
            fi
        done
        echo -e "${GREEN}✅ Custom scope set.${NC}"
    fi
fi

if [ "$KV_FETCHED" == false ] && [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
    az login --identity --allow-no-subscriptions > /dev/null 2>&1
    AUDIT_PASS=$(az keyvault secret show --name "$SECRET_NAME" --vault-name "$KV_NAME" --query value -o tsv | tr -d '\r\n')
fi

# BUILD THE FINAL INVENTORY
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
            inspec exec $WIN_DEF_BENCHMARK -t ssh://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter json:heimdall_before_CIS_${IP}.json
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${CYAN}🔍 [WINDOWS - TM] Scanning $IP...${NC}"
            inspec exec $WIN_BENCHMARK -t ssh://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter json:heimdall_before_TM_${IP}.json
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
            inspec exec $WIN_DEF_BENCHMARK -t ssh://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter json:heimdall_after_CIS_${IP}.json
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${CYAN}✅ [WINDOWS - TM] Verifying $IP...${NC}"
            inspec exec $WIN_BENCHMARK -t ssh://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter json:heimdall_after_TM_${IP}.json
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
        rescan) run_phase_4 ;;
        full) run_phase_1; run_remediation; run_phase_4 ;;
        *) echo -e "${RED}Invalid headless mode specified. Use scan, remediate, rescan, or full.${NC}"; exit 1 ;;
    esac
    
    chmod 755 *.json *.html 2>/dev/null
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
    echo -e "3) ${BOLD}RE-SCAN ONLY${NC}   (Verification/Handover)"
    echo -e "4) ${BOLD}FULL PIPELINE${NC}  (Run all phases in order)"
    echo -e "5) ${BOLD}EXIT${NC}"
    echo -e "${CYAN}------------------------------------------------------${NC}"
    read -p "Choose an option [1-5]: " choice

    case $choice in
        1) run_phase_1 ;;
        2) run_remediation ;;
        3) run_phase_4 ;;
        4) run_phase_1; run_remediation; run_phase_4 ;;
        5) 
            chmod 755 *.json *.html 2>/dev/null
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
