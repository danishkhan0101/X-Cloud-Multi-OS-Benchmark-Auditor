#!/bin/bash
set +H
# ======================================================
# CONFIGURATION - DYNAMIC ENVIRONMENT VARIABLES
# ======================================================
# Load local .env file if it exists (for manual terminal runs)
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

# --- ORGANIZATION VARIABLES (Public defaults, override in .env) ---
ORG_NAME="${ORG_NAME:-Custom}"
ORG_PREFIX="${ORG_PREFIX:-custom}"
GHOST_USER="${GHOST_USER:-audit_ghost}"
CUSTOM_XCCDF_PROFILE="${CUSTOM_XCCDF_PROFILE:-xccdf_com.org_profile_lsb}"

# --- AZURE TARGET INFRASTRUCTURE ---
RG_NAME="${AZURE_RG_NAME:-DEFAULT_RG}"
KV_NAME="${AZURE_KV_NAME:-YOUR-KEYVAULT-NAME}"
SECRET_NAME="${AZURE_KV_SECRET:-AuditPassword}"

# --- FLEET CREDENTIALS ---
UBUNTU_USER="${LINUX_ADMIN_USER:-ubuntu}"
AUDIT_USER="${WINDOWS_ADMIN_USER:-Windows_Admin}"
AUDIT_HOST_NAME="${EXCLUDE_HOST_NAME:-Audit-Host}"

# ======================================================
# DIRECTORY MAPPINGS (Custom Rules Only!)
# ======================================================
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
WIN_CIS_PLAYBOOK="${WIN_CIS_DIR}/cis_remediate.yml"

# ======================================================
# GLOBAL SETTINGS
# ======================================================
export INSPEC_SSH_CONFIG_NO_SECURE=true
BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

clear

# ======================================================
# HEADLESS MODE PARSER (For CI/CD Automation)
# ======================================================
HEADLESS=false
H_PROFILE="custom"
H_MODE="scan"
H_TARGETS="all"
H_TICKET="None"
DEBUG_MODE=false
H_CLEANUP=false 
H_TARGET_OS="all" # 🚨 NEW: Added Target OS filter for Matrix Parallelism

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --headless) HEADLESS=true ;;
        --profile) H_PROFILE="$2"; shift ;;
        --mode) H_MODE="$2"; shift ;;
        --targets) H_TARGETS="$2"; shift ;;
        --ticket) H_TICKET="$2"; shift ;;
        --debug) DEBUG_MODE="$2"; shift ;;
        --cleanup) H_CLEANUP="$2"; shift ;;
        --target-os) H_TARGET_OS="$2"; shift ;; # 🚨 NEW: Catch the OS argument
        *) echo -e "${RED}Unknown parameter: $1${NC}"; exit 1 ;;
    esac
    shift
done

CIS_LEVEL="${CIS_LEVEL:-Level 1}"

# Ensure cleanup runs on exit, terminal close, or script crash
if [ "$H_CLEANUP" == "true" ]; then
    trap run_cleanup EXIT ERR INT TERM
fi

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
    echo -e "${YELLOW}🔐 Fetching Credentials from Azure KeyVault...${NC}"
    az login --identity --allow-no-subscriptions > /dev/null 2>&1 || true
    AUDIT_PASS=$(az keyvault secret show --name "$SECRET_NAME" --vault-name "$KV_NAME" --query value -o tsv 2>/dev/null | tr -d '\r\n')
fi

if [ -z "$AUDIT_PASS" ]; then
    echo -e "${RED}❌ ERROR: Failed to retrieve password from KeyVault! Aborting to prevent SSH lockouts.${NC}"
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
ROCKY_MACHINES=() # 🚨 NEW: Dedicated Rocky Array
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
        
        # 🚨 NEW: Separated Rocky Linux Distro Router
        if [[ "$offer" == *"rocky"* ]] || [[ "${vm_name,,}" == *"rocky"* ]]; then
            DISTRO="Rocky"
            LINUX_USER="$GHOST_USER"
        elif [[ "$offer" == *"rhel"* ]] || [[ "${vm_name,,}" == *"rhel"* ]]; then
            DISTRO="RHEL"
            LINUX_USER="$GHOST_USER"   
        else
            DISTRO="Ubuntu"
            LINUX_USER="$UBUNTU_USER"
        fi

        # 🛡️ THE AUTO-HEALER (LINUX)
        if ! ssh -n -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no ${LINUX_USER}@${ip} "echo ok" > /dev/null 2>&1; then
            echo -e "${YELLOW}   ⚠️ Access denied or timeout for $DISTRO node $ip. Attempting Force-Injection...${NC}"
            
            echo -e "${YELLOW}   🛠️ 1/2: Opening Port 22 on Azure NSG for Runner...${NC}"
            RUNNER_IP=$(curl -s https://api.ipify.org)
            NIC_ID=$(az vm show -g "$RG_NAME" -n "$vm_name" --query "networkProfile.networkInterfaces[0].id" -o tsv)
            NSG_ID=$(az network nic show --ids "$NIC_ID" --query "networkSecurityGroup.id" -o tsv)
            NSG_NAME=$(basename "$NSG_ID")
            
            az network nsg rule create \
                --resource-group "$RG_NAME" \
                --nsg-name "$NSG_NAME" \
                --name "Allow_SSH_Runner_Only" \
                --priority 998 \
                --destination-port-ranges 22 \
                --source-address-prefixes "$RUNNER_IP" \
                --access Allow \
                --protocol Tcp \
                -o none > /dev/null 2>&1 || true

            echo -e "${YELLOW}   💉 2/2: Force-Injecting SSH key via Azure Run-Command...${NC}"
            PUB_KEY=$(cat ~/.ssh/id_rsa.pub)
            az vm run-command invoke -g "$RG_NAME" -n "$vm_name" --command-id RunShellScript --scripts "
                useradd -m -s /bin/bash $LINUX_USER || true
                echo '$LINUX_USER ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/99-${LINUX_USER}
                chmod 440 /etc/sudoers.d/99-${LINUX_USER}
                mkdir -p /home/$LINUX_USER/.ssh
                echo '$PUB_KEY' > /home/$LINUX_USER/.ssh/authorized_keys
                chown -R $LINUX_USER:$LINUX_USER /home/$LINUX_USER/.ssh
                chmod 700 /home/$LINUX_USER/.ssh
                chmod 600 /home/$LINUX_USER/.ssh/authorized_keys
                if command -v restorecon &> /dev/null; then restorecon -Rv /home/$LINUX_USER/.ssh >/dev/null 2>&1 || true; fi
                echo 'PubkeyAcceptedKeyTypes +ssh-rsa' > /etc/ssh/sshd_config.d/99-runner-key.conf 2>/dev/null || true
                systemctl restart sshd
            " -o none > /dev/null 2>&1 || true
            
            echo -e "${YELLOW}   ⏳ Waiting 15s for file system sync...${NC}"
            sleep 15
            echo -e "${GREEN}   ✅ Key injected via Guest Agent. SSH access should now be open!${NC}"
        fi

        # 🚨 NEW: Appending to the correct distinct arrays
        if [ "$DISTRO" == "Rocky" ]; then
            ROCKY_MACHINES+=("$ip")
            echo -e "${CYAN}🏔️ Mapped Rocky Node: $ip (Status: ON)${NC}"
        elif [ "$DISTRO" == "RHEL" ]; then
            RHEL_MACHINES+=("$ip")
            echo -e "${CYAN}🔴 Mapped RHEL Node: $ip (Status: ON)${NC}"
        else
            UBUNTU_MACHINES+=("$ip")
            echo -e "${CYAN}🟠 Mapped Ubuntu Node: $ip (Status: ON)${NC}"
        fi
        
    elif [[ "$os" == *"Windows"* ]]; then
        echo -e "${YELLOW}   ☢️ Forcing WinRM Unlock & Rebuilding User Inside VM for $ip...${NC}"
        
        RUNNER_IP=$(curl -s https://api.ipify.org)
        NIC_ID=$(az vm show -g "$RG_NAME" -n "$vm_name" --query "networkProfile.networkInterfaces[0].id" -o tsv)
        NSG_ID=$(az network nic show --ids "$NIC_ID" --query "networkSecurityGroup.id" -o tsv)
        
        if [ -n "$NSG_ID" ]; then
            NSG_NAME=$(basename "$NSG_ID")
            az network nsg rule create \
                --resource-group "$RG_NAME" \
                --nsg-name "$NSG_NAME" \
                --name "Allow_WinRM_Runner_Only" \
                --priority 999 \
                --destination-port-ranges 5985 \
                --source-address-prefixes "$RUNNER_IP" \
                --access Allow \
                --protocol Tcp \
                -o none > /dev/null 2>&1 || true
        fi
                    
        echo -e "${YELLOW}   🛠️ Bypassing CIS & Hard-Coding Permissions...${NC}"
        az vm run-command invoke \
            --resource-group "$RG_NAME" \
            --name "$vm_name" \
            --command-id RunPowerShellScript \
            --scripts "
                Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM' -Recurse -Force -ErrorAction SilentlyContinue; 
                net user ${AUDIT_USER} '${AUDIT_PASS}' /add /y 2>&1 | Out-Null;
                net user ${AUDIT_USER} '${AUDIT_PASS}' 2>&1 | Out-Null;
                net localgroup Administrators ${AUDIT_USER} /add 2>&1 | Out-Null;
                WMIC USERACCOUNT WHERE Name='${AUDIT_USER}' SET PasswordExpires=FALSE 2>&1 | Out-Null;
                Enable-PSRemoting -SkipNetworkProfileCheck -Force; 
                winrm set winrm/config/service/auth '@{Basic=\"true\"}'; 
                winrm set winrm/config/service '@{AllowUnencrypted=\"true\"}'; 
                New-ItemProperty -Name LocalAccountTokenFilterPolicy -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -PropertyType DWord -Value 1 -Force; 
                Set-NetFirewallRule -DisplayGroup 'Windows Remote Management' -Enabled True -Profile Any -ErrorAction SilentlyContinue;
                Restart-Service WinRM -Force;
            " -o none
            
        echo -e "${YELLOW}   ⏳ Waiting 20 seconds for WinRM to bind...${NC}"
        sleep 20
        echo -e "${GREEN}   ✅ Windows Node fully unlocked and ready for Phase 1!${NC}"
        
        WINDOWS_MACHINES+=("$ip")
        echo -e "${CYAN}🪟 Mapped Windows Node: $ip (Status: ON)${NC}"
    fi
done <<< "$VM_DATA"

echo -e "${GREEN}✅ Discovery Complete: Found ${#UBUNTU_MACHINES[@]} Ubuntu, ${#RHEL_MACHINES[@]} RHEL, ${#ROCKY_MACHINES[@]} Rocky, and ${#WINDOWS_MACHINES[@]} Windows targets RUNNING.${NC}"

# 🚨 THE EARLY EXIT FIX: If the target OS array is empty, kill the script instantly
if [ "$HEADLESS" == true ] && [ "$H_TARGET_OS" != "all" ]; then
    if [ "${H_TARGET_OS,,}" == "ubuntu" ] && [ ${#UBUNTU_MACHINES[@]} -eq 0 ]; then echo -e "${YELLOW}⚠️ No running Ubuntu VMs found. Aborting gracefully.${NC}"; exit 0; fi
    if [ "${H_TARGET_OS,,}" == "rhel" ] && [ ${#RHEL_MACHINES[@]} -eq 0 ]; then echo -e "${YELLOW}⚠️ No running RHEL VMs found. Aborting gracefully.${NC}"; exit 0; fi
    if [ "${H_TARGET_OS,,}" == "rocky" ] && [ ${#ROCKY_MACHINES[@]} -eq 0 ]; then echo -e "${YELLOW}⚠️ No running Rocky VMs found. Aborting gracefully.${NC}"; exit 0; fi
    if [ "${H_TARGET_OS,,}" == "windows" ] && [ ${#WINDOWS_MACHINES[@]} -eq 0 ]; then echo -e "${YELLOW}⚠️ No running Windows VMs found. Aborting gracefully.${NC}"; exit 0; fi
fi

# ======================================================
# INVENTORY BUILDER
# ======================================================
echo "[ubuntu_nodes]" > inventory.ini
for ip in "${UBUNTU_MACHINES[@]}"; do echo "${ip} ansible_user=${UBUNTU_USER}" >> inventory.ini; done
echo "" >> inventory.ini

echo "[rhel_nodes]" >> inventory.ini
for ip in "${RHEL_MACHINES[@]}"; do echo "${ip} ansible_user=${GHOST_USER}" >> inventory.ini; done
echo "" >> inventory.ini

# 🚨 NEW: Dedicated Rocky Inventory Group
echo "[rocky_nodes]" >> inventory.ini
for ip in "${ROCKY_MACHINES[@]}"; do echo "${ip} ansible_user=${GHOST_USER}" >> inventory.ini; done
echo "" >> inventory.ini

echo "[windows_nodes]" >> inventory.ini
for ip in "${WINDOWS_MACHINES[@]}"; do echo "${ip} ansible_user=${AUDIT_USER} ansible_password=\"${AUDIT_PASS}\" ansible_port=5985 ansible_winrm_scheme=http ansible_connection=winrm ansible_winrm_transport=basic ansible_winrm_server_cert_validation=ignore" >> inventory.ini; done

# ======================================================
# PHASE 0.75: COMPLIANCE PROFILE SELECTION
# ======================================================
RUN_ORG=false
RUN_CIS=false

if [ "$HEADLESS" == true ]; then
    if [ "$H_PROFILE" == "tm" ] || [ "$H_PROFILE" == "$ORG_PREFIX" ] || [ "$H_PROFILE" == "both" ]; then RUN_ORG=true; fi
    if [ "$H_PROFILE" == "cis" ] || [ "$H_PROFILE" == "both" ]; then RUN_CIS=true; fi
    echo -e "${GREEN}✅ CI/CD Pipeline: Running profile -> $H_PROFILE${NC}"
else
    echo -e "\n${CYAN}${BOLD}======================================================"
    echo -e "📋 PHASE 0.75: COMPLIANCE PROFILE"
    echo -e "======================================================${NC}"
    echo -e "1) ${BOLD}${ORG_NAME^^} CUSTOM BASELINE${NC}   (Run custom playbooks/rules)"
    echo -e "2) ${BOLD}CIS DEFAULT BASELINE${NC} (Run standard CIS playbooks/rules)"
    echo -e "3) ${BOLD}RUN BOTH SECURELY${NC}    (Comprehensive Audit)"
    read -p "Choose profile mode [1-3]: " profile_choice

    if [ "$profile_choice" == "1" ] || [ "$profile_choice" == "3" ]; then RUN_ORG=true; fi
    if [ "$profile_choice" == "2" ] || [ "$profile_choice" == "3" ]; then RUN_CIS=true; fi
fi

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

# ======================================================
# CORE FUNCTIONS (Execution)
# ======================================================

run_phase_1() {
    echo -e "\n${BOLD}🔍 PHASE 1: Running Initial Baselines...${NC}"
    
    # --- UBUNTU SCANNING ---
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "ubuntu" ]; then
        for IP in "${UBUNTU_MACHINES[@]}"; do
            RAW_VER=$(ssh -n -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
            UBUNTU_VER=${RAW_VER:-2404}
            UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

            if [ "$RUN_CIS" == true ]; then
                echo -e "${GREEN}📦 [UBUNTU $UBUNTU_VER - CIS L${OS_LVL}] Scanning $IP...${NC}"
                ssh -t -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "sudo oscap xccdf eval --profile $UBUNTU_CIS_PROFILE --report /tmp/report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html $UBUNTU_CIS_XCCDF" > /dev/null 2>&1 || true
                scp -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP}:/tmp/report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html ./report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html > /dev/null 2>&1 || true
            fi
            
            if [ "$RUN_ORG" == true ]; then
                echo -e "${GREEN}📦 [UBUNTU $UBUNTU_VER - $ORG_NAME] Scanning $IP...${NC}"
                scp -o StrictHostKeyChecking=no "$UBUNTU_CUSTOM_OVAL" "$UBUNTU_CUSTOM_XCCDF" ${UBUNTU_USER}@${IP}:/tmp/ > /dev/null 2>&1 || true
                ssh -t -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "sudo oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE --report /tmp/report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html /tmp/$(basename $UBUNTU_CUSTOM_XCCDF)" > /dev/null 2>&1 || true
                scp -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP}:/tmp/report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html ./report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html > /dev/null 2>&1 || true
            fi
        done
    fi
    
    # --- RHEL SCANNING ---
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rhel" ]; then
        for IP in "${RHEL_MACHINES[@]}"; do
            if [ "$RUN_CIS" == true ]; then
                echo -e "${GREEN}🔴 [RHEL - CIS L${OS_LVL}] Scanning $IP...${NC}"
                ssh -n -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1); sudo /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE --report /tmp/report_before_CIS_L${OS_LVL}_RHEL_${IP}.html \"\$TARGET_XML\"" > /dev/null 2>&1 || true
                scp -o StrictHostKeyChecking=no ${GHOST_USER}@${IP}:/tmp/report_before_CIS_L${OS_LVL}_RHEL_${IP}.html ./report_before_CIS_L${OS_LVL}_RHEL_${IP}.html > /dev/null 2>&1 || true
            fi
            if [ "$RUN_ORG" == true ]; then
                echo -e "${GREEN}🔴 [RHEL - $ORG_NAME] Scanning $IP...${NC}"
                scp -o StrictHostKeyChecking=no "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" ${GHOST_USER}@${IP}:/tmp/ > /dev/null 2>&1 || true
                ssh -n -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE --report /tmp/report_before_${ORG_PREFIX^^}_RHEL_${IP}.html /tmp/$(basename $RHEL_CUSTOM_XCCDF)" > /dev/null 2>&1 || true
                scp -o StrictHostKeyChecking=no ${GHOST_USER}@${IP}:/tmp/report_before_${ORG_PREFIX^^}_RHEL_${IP}.html ./report_before_${ORG_PREFIX^^}_RHEL_${IP}.html > /dev/null 2>&1 || true
            fi
        done
    fi

    # 🚨 --- ROCKY SCANNING ---
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rocky" ]; then
        for IP in "${ROCKY_MACHINES[@]}"; do
            if [ "$RUN_CIS" == true ]; then
                echo -e "${GREEN}🏔️ [Rocky - CIS L${OS_LVL}] Scanning $IP...${NC}"
                ssh -n -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "
                    TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                    CPE_DICT=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-cpe-dictionary.xml' | sort -V | tail -n 1)
                    
                    # Spoofing CPE to ensure Rocky applicability
                    sudo env OSCAP_CPE_DICT_PATH=\"\$CPE_DICT\" /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE --report /tmp/report_before_CIS_L${OS_LVL}_ROCKY_${IP}.html \"\$TARGET_XML\"
                " > /dev/null 2>&1 || true
                scp -o StrictHostKeyChecking=no ${GHOST_USER}@${IP}:/tmp/report_before_CIS_L${OS_LVL}_ROCKY_${IP}.html ./report_before_CIS_L${OS_LVL}_ROCKY_${IP}.html > /dev/null 2>&1 || true
            fi
            
            if [ "$RUN_ORG" == true ]; then
                echo -e "${GREEN}🏔️ [Rocky - $ORG_NAME] Scanning $IP...${NC}"
                scp -o StrictHostKeyChecking=no "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" ${GHOST_USER}@${IP}:/tmp/ > /dev/null 2>&1 || true
                ssh -n -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "
                    CPE_DICT=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-cpe-dictionary.xml' | sort -V | tail -n 1)
                    sudo env OSCAP_CPE_DICT_PATH=\"\$CPE_DICT\" /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE --report /tmp/report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html /tmp/$(basename $RHEL_CUSTOM_XCCDF)
                " > /dev/null 2>&1 || true
                scp -o StrictHostKeyChecking=no ${GHOST_USER}@${IP}:/tmp/report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html ./report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html > /dev/null 2>&1 || true
            fi
        done
    fi
    
    # --- WINDOWS SCANNING ---
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "windows" ]; then
        for IP in "${WINDOWS_MACHINES[@]}"; do
            export INSPEC_PASSWORD="${AUDIT_PASS}"
            if [ "$RUN_CIS" == true ]; then
                echo -e "${GREEN}📦 [WINDOWS - CIS L${WIN_INSPEC_LVL}] Scanning $IP...${NC}"
                cinc-auditor exec $WIN_CIS_BENCHMARK -t winrm://${IP} --user="${AUDIT_USER}" --input level_1_or_2=$WIN_INSPEC_LVL --reporter cli json:heimdall_before_CIS_L${WIN_INSPEC_LVL}_WIN_${IP}.json > /dev/null 2>&1 || true
            fi
            
            if [ "$RUN_ORG" == true ]; then
                echo -e "${CYAN}🔍 [WINDOWS - $ORG_NAME] Scanning $IP...${NC}"
                cinc-auditor exec $WIN_CUSTOM_BENCHMARK -t winrm://${IP} --user="${AUDIT_USER}" --reporter cli json:heimdall_before_${ORG_PREFIX^^}_WIN_${IP}.json > /dev/null 2>&1 || true
            fi
            unset INSPEC_PASSWORD
        done
    fi
}

run_remediation() {
    echo -e "\n${BOLD}🛠️  PHASE 2 & 3: Executing Remediation...${NC}"
    
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "ubuntu" ]; then
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                echo -e "${GREEN}▶️ [CIS] Auto-Remediating Ubuntu via Native OpenSCAP...${NC}"
                for IP in "${UBUNTU_MACHINES[@]}"; do
                    ssh -n -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "
                        XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-ubuntu*-ds.xml' | sort -V | tail -n 1)
                        sudo /usr/bin/oscap xccdf eval --remediate --profile $UBUNTU_CIS_PROFILE --report /tmp/report_remediation_CIS_${IP}.html \"\$XML_FILE\"
                    " > /dev/null 2>&1 || true
                    scp -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP}:/tmp/report_remediation_CIS_${IP}.html ./report_remediation_CIS_${IP}.html > /dev/null 2>&1 || true
                    ssh -n -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "rm -f /tmp/report_remediation_CIS_${IP}.html" > /dev/null 2>&1 || true
                done
            fi   
            if [ "$RUN_ORG" == true ]; then
                echo -e "${GREEN}▶️ [$ORG_NAME] Running Custom Ubuntu Playbook...${NC}"
                ansible-playbook -i inventory.ini $UBUNTU_CUSTOM_PLAYBOOK --limit ubuntu_nodes > /dev/null 2>&1 || true
            fi
        fi
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rhel" ]; then
        if [ ${#RHEL_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                echo -e "${GREEN}▶️ [CIS] Auto-Remediating RHEL via Native OpenSCAP...${NC}"
                for IP in "${RHEL_MACHINES[@]}"; do
                    ssh -n -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "
                        XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                        sudo /usr/bin/oscap xccdf eval --remediate --profile $RHEL_CIS_PROFILE --report /tmp/report_remediation_CIS_${IP}.html \"\$XML_FILE\"
                    " > /dev/null 2>&1 || true
                    scp -o StrictHostKeyChecking=no ${GHOST_USER}@${IP}:/tmp/report_remediation_CIS_${IP}.html ./report_remediation_CIS_${IP}.html > /dev/null 2>&1 || true
                    ssh -n -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "rm -f /tmp/report_remediation_CIS_${IP}.html" > /dev/null 2>&1 || true
                done
            fi
            if [ "$RUN_ORG" == true ]; then
                echo -e "${GREEN}▶️ [$ORG_NAME] Running Custom RHEL Playbook...${NC}"
                ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK --limit rhel_nodes > /dev/null 2>&1 || true
            fi
        fi
    fi

    # 🚨 ROCKY REMEDIATION
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rocky" ]; then
        if [ ${#ROCKY_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                echo -e "${GREEN}▶️ [CIS] Auto-Remediating Rocky via Native OpenSCAP...${NC}"
                for IP in "${ROCKY_MACHINES[@]}"; do
                    ssh -n -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "
                        XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                        CPE_DICT=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-cpe-dictionary.xml' | sort -V | tail -n 1)
                        sudo env OSCAP_CPE_DICT_PATH=\"\$CPE_DICT\" /usr/bin/oscap xccdf eval --remediate --profile $RHEL_CIS_PROFILE --report /tmp/report_remediation_CIS_ROCKY_${IP}.html \"\$XML_FILE\"
                    " > /dev/null 2>&1 || true
                    scp -o StrictHostKeyChecking=no ${GHOST_USER}@${IP}:/tmp/report_remediation_CIS_ROCKY_${IP}.html ./report_remediation_CIS_ROCKY_${IP}.html > /dev/null 2>&1 || true
                    ssh -n -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "rm -f /tmp/report_remediation_CIS_ROCKY_${IP}.html" > /dev/null 2>&1 || true
                done
            fi
            if [ "$RUN_ORG" == true ]; then
                echo -e "${GREEN}▶️ [$ORG_NAME] Running Custom RHEL Playbook on Rocky...${NC}"
                ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK --limit rocky_nodes > /dev/null 2>&1 || true
            fi
        fi
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "windows" ]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                echo -e "${CYAN}▶️ [HARDENING - CIS] Applying Baseline as $AUDIT_USER...${NC}"
                ansible-galaxy role install ansible-lockdown.windows_2022_cis > /dev/null 2>&1 || true
                EXTRA_VARS="-e win2022cis_level_1=true -e win2022cis_level_2=$([ "$CIS_LEVEL" == "Level 2" ] && echo true || echo false)"
                ansible-playbook -i inventory.ini $WIN_CIS_PLAYBOOK --limit windows_nodes $EXTRA_VARS > /dev/null 2>&1 || true
            fi
            if [ "$RUN_ORG" == true ]; then
                echo -e "${CYAN}▶️ [HARDENING - $ORG_NAME] Applying Baseline as $AUDIT_USER...${NC}"
                ansible-playbook -i inventory.ini $WIN_CUSTOM_PLAYBOOK --limit windows_nodes > /dev/null 2>&1 || true
            fi
        fi
    fi
}

run_phase_4() {
    echo -e "\n${BOLD}🔄 PHASE 4: Running Verification Scans...${NC}"
    
    # --- UBUNTU VERIFICATION ---
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "ubuntu" ]; then
        for IP in "${UBUNTU_MACHINES[@]}"; do
            RAW_VER=$(ssh -n -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
            UBUNTU_VER=${RAW_VER:-2404}
            UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

            if [ "$RUN_CIS" == true ]; then
                echo -e "${GREEN}✅ [UBUNTU $UBUNTU_VER - CIS L${OS_LVL}] Verifying $IP...${NC}"
                ssh -t -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "sudo oscap xccdf eval --profile $UBUNTU_CIS_PROFILE --report /tmp/report_after_CIS_L${OS_LVL}_UBUNTU_${IP}.html $UBUNTU_CIS_XCCDF" > /dev/null 2>&1 || true
                scp -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP}:/tmp/report_after_CIS_L${OS_LVL}_UBUNTU_${IP}.html ./report_after_CIS_L${OS_LVL}_UBUNTU_${IP}.html > /dev/null 2>&1 || true
            fi
            if [ "$RUN_ORG" == true ]; then
                echo -e "${GREEN}✅ [UBUNTU $UBUNTU_VER - $ORG_NAME] Verifying $IP...${NC}"
                scp -o StrictHostKeyChecking=no "$UBUNTU_CUSTOM_OVAL" "$UBUNTU_CUSTOM_XCCDF" ${UBUNTU_USER}@${IP}:/tmp/ > /dev/null 2>&1 || true
                ssh -t -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE --report /tmp/report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html /tmp/$(basename $UBUNTU_CUSTOM_XCCDF)" > /dev/null 2>&1 || true
                scp -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP}:/tmp/report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html ./report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html > /dev/null 2>&1 || true
            fi
        done
    fi
    
    # --- RHEL VERIFICATION ---
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rhel" ]; then
        for IP in "${RHEL_MACHINES[@]}"; do
            if [ "$RUN_CIS" == true ]; then
                echo -e "${GREEN}🔴 [RHEL - CIS L${OS_LVL}] Verifying $IP...${NC}"
                ssh -n -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1); sudo /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE --report /tmp/report_after_CIS_L${OS_LVL}_RHEL_${IP}.html \"\$XML_FILE\"" > /dev/null 2>&1 || true
                scp -o StrictHostKeyChecking=no ${GHOST_USER}@${IP}:/tmp/report_after_CIS_L${OS_LVL}_RHEL_${IP}.html ./report_after_CIS_L${OS_LVL}_RHEL_${IP}.html > /dev/null 2>&1 || true
            fi
            if [ "$RUN_ORG" == true ]; then
                echo -e "${GREEN}🔴 [RHEL - $ORG_NAME] Verifying $IP...${NC}"
                scp -o StrictHostKeyChecking=no "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" ${GHOST_USER}@${IP}:/tmp/ > /dev/null 2>&1 || true
                ssh -n -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE --report /tmp/report_after_${ORG_PREFIX^^}_RHEL_${IP}.html /tmp/$(basename $RHEL_CUSTOM_XCCDF)" > /dev/null 2>&1 || true
                scp -o StrictHostKeyChecking=no ${GHOST_USER}@${IP}:/tmp/report_after_${ORG_PREFIX^^}_RHEL_${IP}.html ./report_after_${ORG_PREFIX^^}_RHEL_${IP}.html > /dev/null 2>&1 || true
            fi
        done
    fi

    # 🚨 --- ROCKY VERIFICATION ---
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rocky" ]; then
        for IP in "${ROCKY_MACHINES[@]}"; do
            if [ "$RUN_CIS" == true ]; then
                echo -e "${GREEN}🏔️ [Rocky - CIS L${OS_LVL}] Verifying $IP...${NC}"
                ssh -n -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "
                    XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                    CPE_DICT=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-cpe-dictionary.xml' | sort -V | tail -n 1)
                    sudo env OSCAP_CPE_DICT_PATH=\"\$CPE_DICT\" /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE --report /tmp/report_after_CIS_L${OS_LVL}_ROCKY_${IP}.html \"\$XML_FILE\"
                " > /dev/null 2>&1 || true
                scp -o StrictHostKeyChecking=no ${GHOST_USER}@${IP}:/tmp/report_after_CIS_L${OS_LVL}_ROCKY_${IP}.html ./report_after_CIS_L${OS_LVL}_ROCKY_${IP}.html > /dev/null 2>&1 || true
            fi
            if [ "$RUN_ORG" == true ]; then
                echo -e "${GREEN}🏔️ [Rocky - $ORG_NAME] Verifying $IP...${NC}"
                scp -o StrictHostKeyChecking=no "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" ${GHOST_USER}@${IP}:/tmp/ > /dev/null 2>&1 || true
                ssh -n -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "
                    CPE_DICT=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-cpe-dictionary.xml' | sort -V | tail -n 1)
                    sudo env OSCAP_CPE_DICT_PATH=\"\$CPE_DICT\" /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE --report /tmp/report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html /tmp/$(basename $RHEL_CUSTOM_XCCDF)
                " > /dev/null 2>&1 || true
                scp -o StrictHostKeyChecking=no ${GHOST_USER}@${IP}:/tmp/report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html ./report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html > /dev/null 2>&1 || true
            fi
        done
    fi
    
    # --- WINDOWS VERIFICATION ---
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "windows" ]; then
        for IP in "${WINDOWS_MACHINES[@]}"; do
            export INSPEC_PASSWORD="${AUDIT_PASS}"
            if [ "$RUN_CIS" == true ]; then
                echo -e "${GREEN}✅ [WINDOWS - CIS L${WIN_INSPEC_LVL}] Verifying $IP...${NC}"
                cinc-auditor exec $WIN_CIS_BENCHMARK -t winrm://${IP} --user="${AUDIT_USER}" --input level_1_or_2=$WIN_INSPEC_LVL --reporter cli json:heimdall_after_CIS_L${WIN_INSPEC_LVL}_WIN_${IP}.json > /dev/null 2>&1 || true
            fi
            if [ "$RUN_ORG" == true ]; then
                echo -e "${CYAN}✅ [WINDOWS - $ORG_NAME] Verifying $IP...${NC}"
                cinc-auditor exec $WIN_CUSTOM_BENCHMARK -t winrm://${IP} --user="${AUDIT_USER}" --reporter cli json:heimdall_after_${ORG_PREFIX^^}_WIN_${IP}.json > /dev/null 2>&1 || true
            fi
            unset INSPEC_PASSWORD
        done
    fi
}

run_cleanup() {
    echo -e "\n${BOLD}${RED}🧹 PHASE 5: POST-AUDIT CLEANUP (THE GHOST METHOD)${NC}"
    
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "ubuntu" ]; then
        for IP in "${UBUNTU_MACHINES[@]}"; do
            echo -e "   ${YELLOW}Removing tools & nuking user from Ubuntu: $IP...${NC}"
            ssh -n -o BatchMode=yes ${UBUNTU_USER}@${IP} "sudo apt-get purge -y openscap-scanner ssg-base && sudo apt-get autoremove -y" > /dev/null 2>&1
            VM_NAME=$(az vm list-ip-addresses -g "$RG_NAME" --query "[?virtualMachine.network.publicIpAddresses[0].ipAddress=='$IP'].virtualMachine.name" -o tsv)
            if [ -n "$VM_NAME" ]; then
                az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunShellScript --scripts "userdel -r ${UBUNTU_USER}" -o none > /dev/null 2>&1 || true
            fi
        done
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rhel" ]; then
        for IP in "${RHEL_MACHINES[@]}"; do
            echo -e "   ${YELLOW}Removing tools from RHEL: $IP...${NC}"
            ssh -n -o BatchMode=yes ${GHOST_USER}@${IP} "sudo dnf remove -y openscap-scanner scap-security-guide -C --setopt=metadata_expire=never" > /dev/null 2>&1
        done
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rocky" ]; then
        for IP in "${ROCKY_MACHINES[@]}"; do
            echo -e "   ${YELLOW}Removing tools from Rocky: $IP...${NC}"
            ssh -n -o BatchMode=yes ${GHOST_USER}@${IP} "sudo dnf remove -y openscap-scanner scap-security-guide -C --setopt=metadata_expire=never" > /dev/null 2>&1
        done
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "windows" ]; then
        for IP in "${WINDOWS_MACHINES[@]}"; do
            echo -e "   ${CYAN}🧹 Reversing security changes & nuking user on Windows: $IP...${NC}"
            VM_NAME=$(az vm list-ip-addresses -g "$RG_NAME" --query "[?virtualMachine.network.publicIpAddresses[0].ipAddress=='$IP'].virtualMachine.name" -o tsv)
            if [ -n "$VM_NAME" ]; then
                NIC_ID=$(az vm show -g "$RG_NAME" -n "$VM_NAME" --query "networkProfile.networkInterfaces[0].id" -o tsv)
                NSG_ID=$(az network nic show --ids "$NIC_ID" --query "networkSecurityGroup.id" -o tsv)
                if [ -n "$NSG_ID" ]; then
                    NSG_NAME=$(basename "$NSG_ID")
                    az network nsg rule delete -g "$RG_NAME" --nsg-name "$NSG_NAME" --name "Allow_WinRM_Runner_Only" -o none > /dev/null 2>&1 || true
                fi
                az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunPowerShellScript --scripts "
                    Stop-Service WinRM -WarningAction SilentlyContinue; 
                    Set-Service WinRM -StartupType Disabled; 
                    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Force -ErrorAction SilentlyContinue;
                    Disable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue;
                    Remove-LocalUser -Name '$AUDIT_USER' -ErrorAction SilentlyContinue
                " -o none > /dev/null 2>&1 || true
            fi
        done
    fi
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

    # Cleanup is handled automatically by the trap now, but leaving this explicit call won't hurt
    # if it runs successfully (since the exit trap will also fire, ensure cleanups are idempotent)
    
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
