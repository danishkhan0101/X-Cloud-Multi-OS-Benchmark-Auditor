#!/bin/bash
set +H
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
        --cleanup) H_CLEANUP="$2"; shift ;;
        *) echo -e "${RED}Unknown parameter: $1${NC}"; exit 1 ;;
    esac
    shift
done

# Catch GitHub CIS_LEVEL or default to Level 1
CIS_LEVEL="${CIS_LEVEL:-Level 1}"

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
            echo -e "${YELLOW}   ⚠️ Access denied or timeout for $DISTRO node $ip.${NC}"
            
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

            echo -e "${YELLOW}   💉 2/2: Auto-injecting SSH key via Azure...${NC}"
            az vm user update -g "$RG_NAME" -n "$vm_name" -u "$LINUX_USER" --ssh-key-value "$(cat ~/.ssh/id_rsa.pub)" -o none
            echo -e "${GREEN}   ✅ Key injected and SSH connection secured!${NC}"
        fi
        
        if [ "$DISTRO" == "RHEL" ]; then
            RHEL_MACHINES+=("$ip")
            echo -e "${GREEN}🔴 Mapped RHEL Node: $ip (Status: ON)${NC}"
        else
            UBUNTU_MACHINES+=("$ip")
            echo -e "${GREEN}🟠 Mapped Ubuntu Node: $ip (Status: ON)${NC}"
        fi
        
    elif [[ "$os" == *"Windows"* ]]; then
        # 🛡️ THE AUTO-HEALER (NUCLEAR OVERRIDE V2)
        echo -e "${YELLOW}   ☢️ Forcing WinRM Unlock & Rebuilding User Inside VM for $ip...${NC}"
        
        # 1. Secure the Network Security Group
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
                    
        # 2. Indestructible PowerShell Payload (Native OS Execution)
        echo -e "${YELLOW}   🛠️ Bypassing CIS & Hard-Coding Permissions...${NC}"
        az vm run-command invoke \
            --resource-group "$RG_NAME" \
            --name "$vm_name" \
            --command-id RunPowerShellScript \
            --scripts "
                # Destroy CIS WinRM blocks
                Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM' -Recurse -Force -ErrorAction SilentlyContinue; 
                
                # Forcefully create/update the user locally (Bypasses Azure Agent failures)
                net user ${AUDIT_USER} '${AUDIT_PASS}' /add /y 2>&1 | Out-Null;
                net user ${AUDIT_USER} '${AUDIT_PASS}' 2>&1 | Out-Null;
                net localgroup Administrators ${AUDIT_USER} /add 2>&1 | Out-Null;
                WMIC USERACCOUNT WHERE Name='${AUDIT_USER}' SET PasswordExpires=FALSE 2>&1 | Out-Null;
                
                # Rebuild WinRM natively
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
for ip in "${WINDOWS_MACHINES[@]}"; do echo "${ip} ansible_user=${AUDIT_USER} ansible_password=\"${AUDIT_PASS}\" ansible_port=5985 ansible_winrm_scheme=http ansible_connection=winrm ansible_winrm_transport=basic ansible_winrm_server_cert_validation=ignore" >> inventory.ini; done

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
# DYNAMIC OSCAP PROFILE ROUTER (Linux Level 1 vs 2)
# ======================================================
if [ "$RUN_CIS" == true ]; then
    echo -e "${YELLOW}🛡️ CIS Level Selected: $CIS_LEVEL${NC}"
    if [ "$CIS_LEVEL" == "Level 1" ]; then
        UBUNTU_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis_level1_server"
        RHEL_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis_server_l1"
    else
        # Level 2 Profiles
        UBUNTU_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis_level2_server"
        RHEL_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis"
    fi
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
        
        # 🚨 THE FIX: The correct package names for Ubuntu 24.04 are ssg-debderived and ssg-debian
        ssh -t -o BatchMode=yes -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "
            sudo systemctl stop unattended-upgrades.service 2>/dev/null
            sudo fuser -kk /var/lib/dpkg/lock-frontend 2>/dev/null
            sudo apt-get update -qq
            sudo apt-get install -y openscap-scanner ssg-base ssg-debderived ssg-debian
        " 
        
        if ssh -n -o BatchMode=yes ${UBUNTU_USER}@${IP} "command -v oscap" > /dev/null 2>&1; then
            echo -e "   ${GREEN}✨ Success: oscap is verified on $IP${NC}"
        else
            echo -e "   ${RED}❌ FATAL: Installation failed on $IP.${NC}"
            exit 1
        fi
    done
fi

if [ ${#RHEL_MACHINES[@]} -gt 0 ]; then
    echo -e "\n${CYAN}${BOLD}======================================================"
    echo -e "⚙️ PHASE 0.8b: RHEL BOOTSTRAPPING"
    echo -e "======================================================${NC}"
    for IP in "${RHEL_MACHINES[@]}"; do
        echo -e "   ${YELLOW}Installing OpenSCAP & SSG Baselines on RHEL Node: $IP...${NC}"
        # 🚨 THE FIX: Removed > /dev/null and added -t so we can see the DNF error!
        ssh -t -o BatchMode=yes -o StrictHostKeyChecking=no azureuser@${IP} "sudo dnf install -y openscap-scanner scap-security-guide"
    done
fi

# ======================================================
# CORE FUNCTIONS (Execution)
# ======================================================

run_phase_1() {
    echo -e "\n${BOLD}🔍 PHASE 1: Running Initial Baselines...${NC}"
    
    # --- UBUNTU SCANNING ---
    for IP in "${UBUNTU_MACHINES[@]}"; do
        
        # 1. Ask the server exactly what version it is
        RAW_VER=$(ssh -n -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
        UBUNTU_VER=${RAW_VER:-2404}
        
        # 2. Build the strict file path
        UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

        # 3. THE AUTO-INJECTOR: Check if the file exists. If not, fetch it from GitHub!
        FILE_EXISTS=$(ssh -n -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "[ -f $UBUNTU_CIS_XCCDF ] && echo 'YES' || echo 'NO'" 2>/dev/null)
        
        if [ "$FILE_EXISTS" == "NO" ]; then
            echo -e "${YELLOW}   ⚠️ Missing official baseline for Ubuntu ${UBUNTU_VER}. Auto-injecting v0.1.80 via Python...${NC}"
            # Using -t -t to suppress the pseudo-terminal warning!
            ssh -t -t -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "
                cd /tmp && \
                wget -q https://github.com/ComplianceAsCode/content/releases/download/v0.1.80/scap-security-guide-0.1.80.zip && \
                python3 -m zipfile -e scap-security-guide-0.1.80.zip . && \
                sudo mkdir -p /usr/share/xml/scap/ssg/content/ && \
                sudo cp scap-security-guide-0.1.80/ssg-ubuntu${UBUNTU_VER}-ds.xml /usr/share/xml/scap/ssg/content/ 2>/dev/null || \
                sudo cp scap-security-guide-0.1.80/ssg-ubuntu2204-ds.xml /usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml && \
                rm -rf scap-security-guide-0.1.80*
            " > /dev/null 2>&1 || true
            echo -e "${GREEN}   ✅ Baseline injected successfully!${NC}"
        fi

        if [ "$RUN_CIS" == true ]; then
            echo -e "${GREEN}📦 [UBUNTU $UBUNTU_VER - CIS $CIS_LEVEL] Scanning $IP...${NC}"
            ssh -t -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "sudo oscap xccdf eval --profile $UBUNTU_CIS_PROFILE --report /tmp/report_before_CIS_UBUNTU_${IP}.html $UBUNTU_CIS_XCCDF"
            scp -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP}:/tmp/report_before_CIS_UBUNTU_${IP}.html ./report_before_CIS_UBUNTU_${IP}.html > /dev/null 2>&1 || true
        fi
        
        if [ "$RUN_TM" == true ]; then
            echo -e "${GREEN}📦 [UBUNTU $UBUNTU_VER - TM] Scanning $IP...${NC}"
            scp -o StrictHostKeyChecking=no "$UBUNTU_CUSTOM_OVAL" "$UBUNTU_CUSTOM_XCCDF" ${UBUNTU_USER}@${IP}:/tmp/ > /dev/null 2>&1 || true
            ssh -t -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "sudo oscap xccdf eval --profile xccdf_com.tm_profile_lsb --report /tmp/report_before_TM_UBUNTU_${IP}.html /tmp/$(basename $UBUNTU_CUSTOM_XCCDF)"
            scp -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP}:/tmp/report_before_TM_UBUNTU_${IP}.html ./report_before_TM_UBUNTU_${IP}.html > /dev/null 2>&1 || true
        fi
    done
    
    for IP in "${RHEL_MACHINES[@]}"; do
        if [ "$RUN_CIS" == true ]; then
            echo -e "${GREEN}🔴 [RHEL - CIS $CIS_LEVEL] Scanning $IP...${NC}"
            ssh -n -o StrictHostKeyChecking=no azureuser@${IP} "TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1); if [ -z \"\$TARGET_XML\" ]; then echo '❌ ERROR: SCAP XML missing! scap-security-guide failed to install.'; exit 1; fi; echo \"   ↳ Discovered Baseline: \$TARGET_XML\"; sudo /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE --report /tmp/report_before_CIS_RHEL_${IP}.html \"\$TARGET_XML\"" || true
            scp -o StrictHostKeyChecking=no azureuser@${IP}:/tmp/report_before_CIS_RHEL_${IP}.html ./report_before_CIS_RHEL_${IP}.html > /dev/null 2>&1 || true
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${GREEN}🔴 [RHEL - TM] Scanning $IP...${NC}"
            scp -o StrictHostKeyChecking=no "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" azureuser@${IP}:/tmp/ > /dev/null 2>&1 || true
            ssh -n -o StrictHostKeyChecking=no azureuser@${IP} "sudo /usr/bin/oscap xccdf eval --profile xccdf_com.tm_profile_lsb --report /tmp/report_before_TM_RHEL_${IP}.html /tmp/$(basename $RHEL_CUSTOM_XCCDF)" || true
            scp -o StrictHostKeyChecking=no azureuser@${IP}:/tmp/report_before_TM_RHEL_${IP}.html ./report_before_TM_RHEL_${IP}.html > /dev/null 2>&1 || true
        fi
    done
    
    # --- WINDOWS SCANNING ---
    for IP in "${WINDOWS_MACHINES[@]}"; do
        if [ "$RUN_CIS" == true ]; then
            echo -e "${CYAN}🔍 [WINDOWS - CIS $CIS_LEVEL] Scanning $IP...${NC}"
            
            # 1. Translate string to integer
            if [ "$CIS_LEVEL" == "Level 1" ]; then INSPEC_LVL="1"; else INSPEC_LVL="2"; fi
            
            # 2. 🚨 THE FIX: Create a YAML file to safely pass the input!
            echo "cis_level: $INSPEC_LVL" > inspec_inputs.yml
            
            # 3. Execute using the perfectly working credential syntax + input-file
            CHEF_LICENSE="accept-silent" /usr/bin/inspec exec $WIN_CIS_BENCHMARK -t winrm://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --input-file inspec_inputs.yml --reporter cli json:heimdall_before_CIS_WIN_${IP}.json
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${CYAN}🔍 [WINDOWS - TM] Scanning $IP...${NC}"
            CHEF_LICENSE="accept-silent" /usr/bin/inspec exec $WIN_CUSTOM_BENCHMARK -t winrm://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter cli json:heimdall_before_TM_WIN_${IP}.json
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
                ssh -n -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "
                    XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-ubuntu*-ds.xml' | sort -V | tail -n 1)
                    sudo /usr/bin/oscap xccdf eval --remediate --profile $UBUNTU_CIS_PROFILE --report /tmp/report_remediation_CIS_${IP}.html \"\$XML_FILE\"
                " || true
                scp -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP}:/tmp/report_remediation_CIS_${IP}.html ./report_remediation_CIS_${IP}.html > /dev/null 2>&1 || true
                ssh -n -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "rm -f /tmp/report_remediation_CIS_${IP}.html"
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
        EXTRA_VARS=""
        if [ "$RUN_CIS" == true ]; then
            echo -e "${CYAN}▶️ [HARDENING - CIS] Applying Baseline as $AUDIT_USER...${NC}"
            ansible-galaxy role install ansible-lockdown.windows_2022_cis > /dev/null 2>&1 || true
            if [ "$CIS_LEVEL" == "Level 1" ]; then
                EXTRA_VARS="-e win2022cis_level_1=true -e win2022cis_level_2=false"
            elif [ "$CIS_LEVEL" == "Level 2" ]; then
                EXTRA_VARS="-e win2022cis_level_1=true -e win2022cis_level_2=true"
            fi
            ansible-playbook -i inventory.ini $WIN_CIS_PLAYBOOK --limit windows_nodes $EXTRA_VARS
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${CYAN}▶️ [HARDENING - TM] Applying Baseline as $AUDIT_USER...${NC}"
            ansible-playbook -i inventory.ini $WIN_CUSTOM_PLAYBOOK --limit windows_nodes
        fi
    fi
}

run_phase_4() {
    echo -e "\n${BOLD}🔄 PHASE 4: Running Verification Scans...${NC}"
    
    # --- UBUNTU VERIFICATION ---
    for IP in "${UBUNTU_MACHINES[@]}"; do
        
        # 1. Ask the server exactly what version it is
        RAW_VER=$(ssh -n -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
        UBUNTU_VER=${RAW_VER:-2404}
        
        # 2. Build the strict file path
        UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

        # 3. THE AUTO-INJECTOR: Check if the file exists. If not, fetch it from GitHub!
        FILE_EXISTS=$(ssh -n -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "[ -f $UBUNTU_CIS_XCCDF ] && echo 'YES' || echo 'NO'" 2>/dev/null)
        
        if [ "$FILE_EXISTS" == "NO" ]; then
            echo -e "${YELLOW}   ⚠️ Missing official baseline for Ubuntu ${UBUNTU_VER}. Auto-injecting v0.1.80 via Python...${NC}"
            # Using -t -t to suppress the pseudo-terminal warning!
            ssh -t -t -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "
                cd /tmp && \
                wget -q https://github.com/ComplianceAsCode/content/releases/download/v0.1.80/scap-security-guide-0.1.80.zip && \
                python3 -m zipfile -e scap-security-guide-0.1.80.zip . && \
                sudo mkdir -p /usr/share/xml/scap/ssg/content/ && \
                sudo cp scap-security-guide-0.1.80/ssg-ubuntu${UBUNTU_VER}-ds.xml /usr/share/xml/scap/ssg/content/ 2>/dev/null || \
                sudo cp scap-security-guide-0.1.80/ssg-ubuntu2204-ds.xml /usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml && \
                rm -rf scap-security-guide-0.1.80*
            " > /dev/null 2>&1 || true
            echo -e "${GREEN}   ✅ Baseline injected successfully!${NC}"
        fi

        if [ "$RUN_CIS" == true ]; then
            echo -e "${GREEN}✅ [UBUNTU $UBUNTU_VER - CIS $CIS_LEVEL] Verifying $IP...${NC}"
            ssh -t -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "sudo /usr/bin/oscap xccdf eval --profile $UBUNTU_CIS_PROFILE --report /tmp/report_after_CIS_UBUNTU_${IP}.html $UBUNTU_CIS_XCCDF" > /dev/null 2>&1 || true
            scp -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP}:/tmp/report_after_CIS_UBUNTU_${IP}.html ./report_after_CIS_UBUNTU_${IP}.html > /dev/null 2>&1 || true
        fi
        
        if [ "$RUN_TM" == true ]; then
            echo -e "${GREEN}✅ [UBUNTU $UBUNTU_VER - TM] Verifying $IP...${NC}"
            scp -o StrictHostKeyChecking=no "$UBUNTU_CUSTOM_OVAL" "$UBUNTU_CUSTOM_XCCDF" ${UBUNTU_USER}@${IP}:/tmp/ > /dev/null 2>&1 || true
            ssh -t -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "sudo /usr/bin/oscap xccdf eval --profile xccdf_com.tm_profile_lsb --report /tmp/report_after_TM_UBUNTU_${IP}.html /tmp/$(basename $UBUNTU_CUSTOM_XCCDF)" > /dev/null 2>&1 || true
            scp -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP}:/tmp/report_after_TM_UBUNTU_${IP}.html ./report_after_TM_UBUNTU_${IP}.html > /dev/null 2>&1 || true
        fi
    done
    
    for IP in "${RHEL_MACHINES[@]}"; do
        if [ "$RUN_CIS" == true ]; then
            echo -e "${GREEN}🔴 [RHEL - CIS $CIS_LEVEL] Verifying $IP...${NC}"
            ssh -n -o StrictHostKeyChecking=no azureuser@${IP} "
                XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                sudo /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE --report /tmp/report_after_CIS_RHEL_${IP}.html \"\$XML_FILE\"
            " || true
            scp -o StrictHostKeyChecking=no azureuser@${IP}:/tmp/report_after_CIS_RHEL_${IP}.html ./report_after_CIS_RHEL_${IP}.html > /dev/null 2>&1 || true
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${GREEN}🔴 [RHEL - TM] Verifying $IP...${NC}"
            scp -o StrictHostKeyChecking=no "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" azureuser@${IP}:/tmp/ > /dev/null 2>&1 || true
            ssh -n -o StrictHostKeyChecking=no azureuser@${IP} "sudo /usr/bin/oscap xccdf eval --profile xccdf_com.tm_profile_lsb --report /tmp/report_after_TM_RHEL_${IP}.html /tmp/$(basename $RHEL_CUSTOM_XCCDF)" || true
            scp -o StrictHostKeyChecking=no azureuser@${IP}:/tmp/report_after_TM_RHEL_${IP}.html ./report_after_TM_RHEL_${IP}.html > /dev/null 2>&1 || true
        fi
    done
    
    # --- WINDOWS VERIFICATION ---
    for IP in "${WINDOWS_MACHINES[@]}"; do
        if [ "$RUN_CIS" == true ]; then
            echo -e "${CYAN}✅ [WINDOWS - CIS $CIS_LEVEL] Verifying $IP...${NC}"
            
            if [ "$CIS_LEVEL" == "Level 1" ]; then INSPEC_LVL="1"; else INSPEC_LVL="2"; fi
            
            # 🚨 THE FIX: Create a YAML file to safely pass the input!
            echo "cis_level: $INSPEC_LVL" > inspec_inputs.yml
            
            CHEF_LICENSE="accept-silent" /usr/bin/inspec exec $WIN_CIS_BENCHMARK -t winrm://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --input-file inspec_inputs.yml --reporter cli json:heimdall_after_CIS_WIN_${IP}.json
        fi
        if [ "$RUN_TM" == true ]; then
            echo -e "${CYAN}✅ [WINDOWS - TM] Verifying $IP...${NC}"
            CHEF_LICENSE="accept-silent" /usr/bin/inspec exec $WIN_CUSTOM_BENCHMARK -t winrm://${IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter cli json:heimdall_after_TM_WIN_${IP}.json
        fi
    done
}


run_cleanup() {
    echo -e "\n${BOLD}${RED}🧹 PHASE 5: POST-AUDIT CLEANUP (THE GHOST METHOD)${NC}"
    
    # --- Clean Ubuntu ---
    if [ ${#UBUNTU_MACHINES[@]} -gt 0 ]; then
        for IP in "${UBUNTU_MACHINES[@]}"; do
            echo -e "   ${YELLOW}Removing tools & nuking user from Ubuntu: $IP...${NC}"
            
            # 1. Uninstall tools normally over SSH
            ssh -n -o BatchMode=yes ${UBUNTU_USER}@${IP} "
                sudo apt-get purge -y openscap-scanner ssg-base && \
                sudo apt-get autoremove -y
            " > /dev/null 2>&1
            
            # 2. Out-of-band assassination: Use Azure to delete the user we just logged out of
            VM_NAME=$(az vm list-ip-addresses -g "$RG_NAME" --query "[?virtualMachine.network.publicIpAddresses[0].ipAddress=='$IP'].virtualMachine.name" -o tsv)
            if [ -n "$VM_NAME" ]; then
                az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunShellScript --scripts "userdel -r ${UBUNTU_USER}" -o none > /dev/null 2>&1 || true
            fi
        done
        echo -e "${GREEN}✅ Ubuntu targets have been scrubbed.${NC}"
    fi

    # --- Clean RHEL ---
    if [ ${#RHEL_MACHINES[@]} -gt 0 ]; then
        for IP in "${RHEL_MACHINES[@]}"; do
            echo -e "   ${YELLOW}Removing tools & nuking user from RHEL: $IP...${NC}"
            
            # 1. Uninstall tools normally over SSH
            ssh -n -o BatchMode=yes azureuser@${IP} "
                sudo dnf remove -y openscap-scanner scap-security-guide -C --setopt=metadata_expire=never
            " > /dev/null 2>&1
            
        done
        echo -e "${GREEN}✅ RHEL targets have been scrubbed.${NC}"
    fi

    # --- Clean Windows ---
    if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
        for IP in "${WINDOWS_MACHINES[@]}"; do
            echo -e "   ${CYAN}🧹 Reversing security changes & nuking user on Windows: $IP...${NC}"
            
            VM_NAME=$(az vm list-ip-addresses -g "$RG_NAME" --query "[?virtualMachine.network.publicIpAddresses[0].ipAddress=='$IP'].virtualMachine.name" -o tsv)
            
            if [ -n "$VM_NAME" ]; then
                NIC_ID=$(az vm show -g "$RG_NAME" -n "$VM_NAME" --query "networkProfile.networkInterfaces[0].id" -o tsv)
                NSG_ID=$(az network nic show --ids "$NIC_ID" --query "networkSecurityGroup.id" -o tsv)
                
                if [ -n "$NSG_ID" ]; then
                    NSG_NAME=$(basename "$NSG_ID")
                    echo -e "      🔒 Removing DevSecOps WinRM Firewall Rule from NSG..."
                    az network nsg rule delete -g "$RG_NAME" --nsg-name "$NSG_NAME" --name "Allow_WinRM_Runner_Only" -o none > /dev/null 2>&1 || true
                fi

                echo -e "      🔌 Disabling WinRM & Deleting TM_Admin..."
                az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunPowerShellScript --scripts "
                    Stop-Service WinRM -WarningAction SilentlyContinue; 
                    Set-Service WinRM -StartupType Disabled; 
                    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Force -ErrorAction SilentlyContinue;
                    Disable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue;
                    Remove-LocalUser -Name '$AUDIT_USER' -ErrorAction SilentlyContinue
                " -o none > /dev/null 2>&1 || true
            else
                echo -e "      ${RED}⚠️ Could not resolve VM name for IP $IP. Skipping.${NC}"
            fi
        done
        echo -e "${GREEN}✅ Windows targets have been reset to secure state.${NC}"
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

    if [ "$H_CLEANUP" == "true" ]; then
        run_cleanup
    fi
    
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
