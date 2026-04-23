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

# ======================================================
# DIRECTORY MAPPINGS (Custom Rules Only!)
# ======================================================
# Note: CIS default XML files are NOT stored here! 
# They are dynamically mapped to native /usr/share/... paths in the execution loops.

# --- UBUNTU ---
UBUNTU_CUSTOM_DIR="ubuntu-custom"
UBUNTU_CUSTOM_XCCDF="${UBUNTU_CUSTOM_DIR}/tm_xccdf.xml"
UBUNTU_CUSTOM_OVAL="${UBUNTU_CUSTOM_DIR}/tm_ubuntu_rules.xml"
UBUNTU_CUSTOM_PLAYBOOK="${UBUNTU_CUSTOM_DIR}/ubuntu_custom_playbook.yml"

# --- RHEL ---
RHEL_CUSTOM_DIR="rhel-custom"
RHEL_CUSTOM_XCCDF="${RHEL_CUSTOM_DIR}/tm_rhel_xccdf.xml"
RHEL_CUSTOM_OVAL="${RHEL_CUSTOM_DIR}/tm_rhel_rules.xml"
RHEL_CUSTOM_PLAYBOOK="${RHEL_CUSTOM_DIR}/rhel_custom_playbook.yml"

# --- WINDOWS ---
WIN_CUSTOM_DIR="window-custom"
WIN_CUSTOM_BENCHMARK="${WIN_CUSTOM_DIR}/tm_baseline.rb"
WIN_CUSTOM_PLAYBOOK="${WIN_CUSTOM_DIR}/tm_remediate.yml"

WIN_CIS_DIR="window-default-cis"
WIN_CIS_BENCHMARK="${WIN_CIS_DIR}/window-baseline"
WIN_CIS_PLAYBOOK="${WIN_CIS_DIR}/cis_remediate.yml"

# ======================================================
# GLOBAL SETTINGS
# ======================================================
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
H_TICKET="None"
DEBUG_MODE=false
H_CLEANUP=false 

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --headless) HEADLESS=true ;;
        --profile) H_PROFILE="$2"; shift ;;
        --mode) H_MODE="$2"; shift ;;
        --targets) H_TARGETS="$2"; shift ;;
        --ticket) H_TICKET="$2"; shift ;;
        --debug) DEBUG_MODE="$2"; shift ;;
        *) echo -e "${RED}Unknown parameter: $1${NC}"; exit 1 ;;
    esac
    shift
done

# ======================================================
# ENTERPRISE GUARDRAILS (Audit & Debug)
# ======================================================
if [ "$HEADLESS" == true ]; then
    echo -e "${CYAN}${BOLD}🤖 HEADLESS CI/CD MODE ACTIVATED${NC}"
    
    if [ -n "$H_TICKET" ] && [ "$H_TICKET" != "None" ]; then
        echo -e "${GREEN}🎫 AUDIT AUTHORIZATION: Execution tracked under Change Request / Ticket ID: ${BOLD}$H_TICKET${NC}"
    else
        echo -e "${YELLOW}⚠️ WARNING: No Ticket ID provided. This execution will be flagged in audit logs as Unassociated.${NC}"
    fi

    if [ "$DEBUG_MODE" == "true" ]; then
        echo -e "${YELLOW}🐞 DEBUG MODE ENABLED: Activating verbose bash tracing...${NC}"
        set -x
    fi
fi

# ======================================================
# SECURE CREDENTIAL FETCH
# ======================================================
if [ -z "$AUDIT_PASS" ]; then
    echo -e "${YELLOW}🔐 Fetching TM Credentials from Azure KeyVault...${NC}"
    az login --identity --allow-no-subscriptions > /dev/null 2>&1 || true
    AUDIT_PASS=$(az keyvault secret show --name "$SECRET_NAME" --vault-name "$KV_NAME" --query value -o tsv 2>/dev/null | tr -d '\r\n')
fi

if [ -z "$AUDIT_PASS" ]; then
    echo -e "${RED}❌ ERROR: Failed to retrieve AuditPassword from KeyVault! Aborting to prevent SSH lockouts.${NC}"
    exit 1
fi

# ======================================================
# PHASE 0: ZERO-TRUST DISCOVERY (AUTO-HEALING)
# ======================================================
echo -e "${CYAN}📡 Querying Azure for VMs and Power States in [$RG_NAME]...${NC}"

if [ "$H_TARGETS" == "all" ] || [ -z "$H_TARGETS" ]; then
    echo "🔍 Target Mode: ALL VMs"
    VM_DATA=$(az vm list -d -g "$RG_NAME" --query "[].[name, publicIps, storageProfile.osDisk.osType, powerState, storageProfile.imageReference.offer]" -o tsv)
else
    echo "🔍 Target Mode: Environment Tag -> $H_TARGETS"
    VM_DATA=$(az vm list -d -g "$RG_NAME" --query "[?tags.Environment=='$H_TARGETS'].[name, publicIps, storageProfile.osDisk.osType, powerState, storageProfile.imageReference.offer]" -o tsv)
fi

if [ -z "$VM_DATA" ]; then
    echo -e "${RED}❌ ERROR: No VMs found matching Environment tag '$H_TARGETS' in '$RG_NAME'.${NC}"
    exit 1
fi

UBUNTU_MACHINES=()
RHEL_MACHINES=()
WINDOWS_MACHINES=()

while IFS=$'\t' read -r raw_name raw_ip raw_os raw_power raw_offer; do
    vm_name=$(echo "$raw_name" | tr -d '\r' | xargs)
    ip=$(echo "$raw_ip" | tr -d '\r' | xargs)
    os=$(echo "$raw_os" | tr -d '\r' | xargs)
    power=$(echo "$raw_power" | tr -d '\r' | xargs)
    offer=$(echo "$raw_offer" | tr -d '\r' | tr '[:upper:]' '[:lower:]' | xargs)
    
    if [ -z "$ip" ] || [ "$ip" == "None" ]; then 
        echo -e "${RED}🚫 Skipping Node: $vm_name (Error: Azure CLI cannot see the Public IP!)${NC}"
        continue
    fi
    
    if [[ "$power" != *"VM running"* ]]; then
        echo -e "${YELLOW}💤 Skipping Node: $ip (Status: OFF / $power)${NC}"
        continue
    fi
    
    if [[ "$os" == *"Linux"* ]] || [[ "$os" == *"Ubuntu"* ]]; then
        
        # --- DISTRO ROUTER ---
        if [[ "$offer" == *"rhel"* ]] || [[ "${vm_name,,}" == *"rhel"* ]]; then
            DISTRO="RHEL"
            LINUX_USER="azureuser"
        else
            DISTRO="Ubuntu"
            LINUX_USER="$UBUNTU_USER"
        fi

        # 🛡️ THE AUTO-HEALER (LINUX)
        if ! ssh -n -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no ${LINUX_USER}@${ip} "echo ok" > /dev/null 2>&1; then
            echo -e "${YELLOW}   ⚠️ Access denied for $DISTRO node $ip. Auto-injecting SSH key via Azure...${NC}"
            az vm user update -g "$RG_NAME" -n "$vm_name" -u "$LINUX_USER" --ssh-key-value "$(cat ~/.ssh/id_rsa.pub)" -o none
            echo -e "${GREEN}   ✅ Key injected!${NC}"
        fi
        
        if [ "$DISTRO" == "RHEL" ]; then
            RHEL_MACHINES+=("$ip")
            echo -e "${GREEN}🔴 Mapped RHEL Node: $ip (Status: ON)${NC}"
        else
            UBUNTU_MACHINES+=("$ip")
            echo -e "${GREEN}🟠 Mapped Ubuntu Node: $ip (Status: ON)${NC}"
        fi
        
    elif [[ "$os" == *"Windows"* ]]; then
        # 🛡️ THE AUTO-HEALER (WINDOWS)
        if ! nc -z -w 5 $ip 5985 2>/dev/null; then
            echo -e "${YELLOW}   ⚠️ WinRM offline for Windows node $ip.${NC}"
            
            echo -e "${YELLOW}   💉 1/2: Auto-injecting KeyVault Password via Azure...${NC}"
            az vm user update -g "$RG_NAME" -n "$vm_name" -u "$AUDIT_USER" --password "$AUDIT_PASS" -o none
            
            echo -e "${YELLOW}   🛠️ 2/2: Enabling WinRM (Native Windows Remote Management)...${NC}"
            az vm open-port --resource-group "$RG_NAME" --name "$vm_name" --port 5985 -o none > /dev/null 2>&1 || true
            
            az vm run-command invoke \
                --resource-group "$RG_NAME" \
                --name "$vm_name" \
                --command-id RunPowerShellScript \
                --scripts 'Enable-PSRemoting -SkipNetworkProfileCheck -Force; Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true -Force; Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force; New-ItemProperty -Name LocalAccountTokenFilterPolicy -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -PropertyType DWord -Value 1 -Force; Set-NetFirewallRule -DisplayGroup "Windows Remote Management" -Enabled True -Profile Any; Restart-Service WinRM' \
                -o none
                
            echo -e "${YELLOW}   ⏳ Waiting 30 seconds for WinRM to bind...${NC}"
            sleep 30
            echo -e "${GREEN}   ✅ Windows Node fully healed and ready for WinRM!${NC}"
        fi
        
        WINDOWS_MACHINES+=("$ip")
        echo -e "${CYAN}🪟 Mapped Windows Node: $ip (Status: ON)${NC}"
    else
        echo -e "${YELLOW}⚠️ Warning: Unrecognized OS ($os) for IP $ip. Skipping.${NC}"
    fi
done <<< "$VM_DATA"

echo -e "${GREEN}✅ Discovery Complete: Found ${#UBUNTU_MACHINES[@]} Ubuntu, ${#RHEL_MACHINES[@]} RHEL, and ${#WINDOWS_MACHINES[@]} Windows targets currently RUNNING.${NC}"

# ======================================================
# INVENTORY BUILDER & AZURE KEYVAULT AUTH
# ======================================================
echo "[ubuntu_nodes]" > inventory.ini
for ip in "${UBUNTU_MACHINES[@]}"; do echo "${ip} ansible_user=${UBUNTU_USER}" >> inventory.ini; done
echo "" >> inventory.ini

echo "[rhel_nodes]" >> inventory.ini
for ip in "${RHEL_MACHINES[@]}"; do echo "${ip} ansible_user=azureuser" >> inventory.ini; done
echo "" >> inventory.ini

echo "[windows_nodes]" >> inventory.ini
for ip in "${WINDOWS_MACHINES[@]}"; do echo "${ip} ansible_user=${AUDIT_USER} ansible_password=\"${AUDIT_PASS}\" ansible_connection=winrm ansible_winrm_transport=basic ansible_winrm_server_cert_validation=ignore" >> inventory.ini; done

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
# PHASE 0.8: FLEET BOOTSTRAPPING (DEPENDENCIES)
# ======================================================
if [ ${#UBUNTU_MACHINES[@]} -gt 0 ]; then
    echo -e "\n${CYAN}${BOLD}======================================================"
    echo -e "⚙️ PHASE 0.8a: UBUNTU BOOTSTRAPPING"
    echo -e "======================================================${NC}"
    for IP in "${UBUNTU_MACHINES[@]}"; do
        echo -e "   ${YELLOW}Installing OpenSCAP engine on Ubuntu Node: $IP...${NC}"
        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "sudo apt-get update -qq && sudo apt-get install -y openscap-scanner ssg-base ssg-debderivatives libopenscap25t64" > /dev/null 2>&1
    done
    echo -e "${GREEN}✅ All Ubuntu nodes bootstrapped and ready.${NC}"
fi

if [ ${#RHEL_MACHINES[@]} -gt 0 ]; then
    echo -e "\n${CYAN}${BOLD}======================================================"
    echo -e "⚙️ PHASE 0.8b: RHEL BOOTSTRAPPING"
    echo -e "======================================================${NC}"
    for IP in "${RHEL_MACHINES[@]}"; do
        echo -e "   ${YELLOW}Installing OpenSCAP & SSG Baselines on RHEL Node: $IP...${NC}"
        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no azureuser@${IP} "sudo dnf install -y openscap-scanner scap-security-guide" > /dev/null 2>&1
    done
    echo -e "${GREEN}✅ All RHEL nodes bootstrapped and ready.${NC}"
fi

# ======================================================
# CORE FUNCTIONS (Execution)
# ======================================================

run_phase_1() {
    echo -e "\n${BOLD}🔍 PHASE 1: Running Initial Baselines...${NC}"
    
    for IP in "${UBUNTU_MACHINES[@]}"; do
        UBUNTU_VER=$(ssh -n -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
        UBUNTU_VER=${UBUNTU_VER:-2404}
        UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

        if [ "$RUN_CIS" == true ]; then
            echo -e "${GREEN}📦 [UBUNTU $UBUNTU_VER - CIS] Scanning $IP...${NC}"
            oscap-ssh --sudo ${UBUNTU_USER}@${IP} 22 xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_level1_server --report report_before_CIS_${IP}.html "$UBUNTU_CIS_XCCDF"
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${GREEN}📦 [UBUNTU $UBUNTU_VER - TM] Scanning $IP...${NC}"
            scp "$UBUNTU_CUSTOM_OVAL" ${UBUNTU_USER}@${IP}:/tmp/tm_ubuntu_rules.xml >/dev/null 2>&1 || true
            oscap-ssh --sudo ${UBUNTU_USER}@${IP} 22 xccdf eval --profile xccdf_com.tm_profile_lsb --report report_before_TM_${IP}.html "$UBUNTU_CUSTOM_XCCDF"
        fi
    done
    
    for IP in "${RHEL_MACHINES[@]}"; do
        RHEL_VER=$(ssh -n -o StrictHostKeyChecking=no azureuser@${IP} "source /etc/os-release && echo \${VERSION_ID%%.*}" 2>/dev/null)
        RHEL_VER=${RHEL_VER:-9}
        RHEL_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-rhel${RHEL_VER}-ds.xml"

        if [ "$RUN_CIS" == true ]; then
            echo -e "${GREEN}🔴 [RHEL $RHEL_VER - CIS] Scanning $IP...${NC}"
            oscap-ssh --sudo azureuser@${IP} 22 xccdf eval --profile xccdf_org.ssgproject.content_profile_cis --report report_before_CIS_RHEL_${IP}.html "$RHEL_CIS_XCCDF"
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${GREEN}🔴 [RHEL $RHEL_VER - TM] Scanning $IP...${NC}"
            scp "$RHEL_CUSTOM_OVAL" azureuser@${IP}:/tmp/tm_rhel_rules.xml >/dev/null 2>&1 || true
            oscap-ssh --sudo azureuser@${IP} 22 xccdf eval --profile xccdf_com.tm_profile_lsb --report report_before_TM_RHEL_${IP}.html "$RHEL_CUSTOM_XCCDF"
        fi
    done
    
    for IP in "${WINDOWS_MACHINES[@]}"; do
        if [ "$RUN_CIS" == true ]; then
            echo -e "${CYAN}🔍 [WINDOWS - CIS] Scanning $IP...${NC}"
            CHEF_LICENSE="accept-silent" /usr/bin/inspec exec $WIN_CIS_BENCHMARK -t winrm://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter cli json:heimdall_before_CIS_${IP}.json
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${CYAN}🔍 [WINDOWS - TM] Scanning $IP...${NC}"
            CHEF_LICENSE="accept-silent" /usr/bin/inspec exec $WIN_CUSTOM_BENCHMARK -t winrm://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter cli json:heimdall_before_TM_${IP}.json
        fi
    done
}

run_remediation() {
    echo -e "\n${BOLD}🛠️  PHASE 2 & 3: Executing Remediation...${NC}"
    
    if [ ${#UBUNTU_MACHINES[@]} -gt 0 ]; then
        if [ "$RUN_CIS" == true ]; then
            echo -e "${GREEN}▶️ [CIS] Auto-Remediating Ubuntu via Native OpenSCAP...${NC}"
            for IP in "${UBUNTU_MACHINES[@]}"; do
                echo -e "   ${YELLOW}Fixing $IP...${NC}"
                UBUNTU_VER=$(ssh -n -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
                UBUNTU_VER=${UBUNTU_VER:-2404}
                UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

                # THE FIX: No scp upload required! We remediate using the native file on the server.
                ssh -t -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "sudo oscap xccdf eval --remediate --profile xccdf_org.ssgproject.content_profile_cis_level1_server --report ~/report_remediation_CIS_${IP}.html $UBUNTU_CIS_XCCDF"
                scp ${UBUNTU_USER}@${IP}:~/report_remediation_CIS_${IP}.html ./report_remediation_CIS_${IP}.html > /dev/null
                ssh -n -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "rm -f ~/report_remediation_CIS_${IP}.html"
            done
        fi   
        if [ "$RUN_TM" == true ]; then
            echo -e "${GREEN}▶️ [TM] Running Custom Ubuntu Playbook...${NC}"
            ansible-playbook -i inventory.ini $UBUNTU_CUSTOM_PLAYBOOK --limit ubuntu_nodes
        fi
    fi

    if [ ${#RHEL_MACHINES[@]} -gt 0 ]; then
        if [ "$RUN_TM" == true ]; then
            echo -e "${GREEN}▶️ [TM] Running Custom RHEL Playbook...${NC}"
            ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK --limit rhel_nodes
        fi
    fi

    if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
        if [ "$RUN_CIS" == true ]; then
            echo -e "${CYAN}▶️ [HARDENING - CIS] Applying Baseline as $AUDIT_USER...${NC}"
            ansible-playbook -i inventory.ini $WIN_CIS_PLAYBOOK --limit windows_nodes
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${CYAN}▶️ [HARDENING - TM] Applying Baseline as $AUDIT_USER...${NC}"
            ansible-playbook -i inventory.ini $WIN_CUSTOM_PLAYBOOK --limit windows_nodes
        fi
    fi
}

run_phase_4() {
    echo -e "\n${BOLD}🔄 PHASE 4: Running Verification Scans...${NC}"
    
    for IP in "${UBUNTU_MACHINES[@]}"; do
        UBUNTU_VER=$(ssh -n -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
        UBUNTU_VER=${UBUNTU_VER:-2404}
        UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

        if [ "$RUN_CIS" == true ]; then
            echo -e "${GREEN}✅ [UBUNTU $UBUNTU_VER - CIS] Verifying $IP...${NC}"
            oscap-ssh --sudo ${UBUNTU_USER}@${IP} 22 xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_level1_server --report report_after_CIS_${IP}.html "$UBUNTU_CIS_XCCDF"
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${GREEN}✅ [UBUNTU $UBUNTU_VER - TM] Verifying $IP...${NC}"
            oscap-ssh --sudo ${UBUNTU_USER}@${IP} 22 xccdf eval --profile xccdf_com.tm_profile_lsb --report report_after_TM_${IP}.html "$UBUNTU_CUSTOM_XCCDF"
        fi
    done
    
    for IP in "${RHEL_MACHINES[@]}"; do
        RHEL_VER=$(ssh -n -o StrictHostKeyChecking=no azureuser@${IP} "source /etc/os-release && echo \${VERSION_ID%%.*}" 2>/dev/null)
        RHEL_VER=${RHEL_VER:-9}
        RHEL_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-rhel${RHEL_VER}-ds.xml"

        if [ "$RUN_CIS" == true ]; then
            echo -e "${GREEN}🔴 [RHEL $RHEL_VER - CIS] Verifying $IP...${NC}"
            oscap-ssh --sudo azureuser@${IP} 22 xccdf eval --profile xccdf_org.ssgproject.content_profile_cis --report report_after_CIS_RHEL_${IP}.html "$RHEL_CIS_XCCDF"
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${GREEN}🔴 [RHEL $RHEL_VER - TM] Verifying $IP...${NC}"
            oscap-ssh --sudo azureuser@${IP} 22 xccdf eval --profile xccdf_com.tm_profile_lsb --report report_after_TM_RHEL_${IP}.html "$RHEL_CUSTOM_XCCDF"
        fi
    done
    
    for IP in "${WINDOWS_MACHINES[@]}"; do
        if [ "$RUN_CIS" == true ]; then
            echo -e "${CYAN}✅ [WINDOWS - CIS] Verifying $IP...${NC}"
            CHEF_LICENSE="accept-silent" /usr/bin/inspec exec $WIN_CIS_BENCHMARK -t winrm://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter cli json:heimdall_after_CIS_${IP}.json
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${CYAN}✅ [WINDOWS - TM] Verifying $IP...${NC}"
            CHEF_LICENSE="accept-silent" /usr/bin/inspec exec $WIN_CUSTOM_BENCHMARK -t winrm://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter cli json:heimdall_after_TM_${IP}.json
        fi
    done
}

run_cleanup() {
    echo -e "\n${BOLD}${RED}🧹 PHASE 5: POST-AUDIT CLEANUP (REMOVING TOOLS)${NC}"
    
    # Clean Ubuntu
    for IP in "${UBUNTU_MACHINES[@]}"; do
        echo -e "   ${YELLOW}Removing OpenSCAP from Ubuntu: $IP...${NC}"
        ssh -n -o BatchMode=yes ${UBUNTU_USER}@${IP} "sudo apt-get purge -y openscap-scanner ssg-base ssg-debderivatives && sudo apt-get autoremove -y" > /dev/null 2>&1
    done

    # Clean RHEL
    for IP in "${RHEL_MACHINES[@]}"; do
        echo -e "   ${YELLOW}Removing OpenSCAP from RHEL: $IP...${NC}"
        ssh -n -o BatchMode=yes azureuser@${IP} "sudo dnf remove -y openscap-scanner scap-security-guide" > /dev/null 2>&1
    done
    
    echo -e "${GREEN}✅ All Linux targets have been cleaned.${NC}"
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

    if [ "$H_CLEANUP" == "true" ]; then
        run_cleanup
    fi
    
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
