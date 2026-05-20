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

export INSPEC_SSH_CONFIG_NO_SECURE=true
BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; MAGENTA='\033[0;35m'; NC='\033[0m'
clear

# ======================================================
# TOOL GUARD: Ensure SCAP tooling exists on Linux node
# ======================================================
ensure_linux_scap_tools() {
    local user="$1"
    local ip="$2"
    local pkg_mgr="$3"

    local install_cmd
    if [ "$pkg_mgr" == "apt" ]; then
        install_cmd="sudo apt-get update -qq && sudo apt-get install -y openscap-scanner ssg-base"
    else
        install_cmd="sudo dnf install -y openscap-scanner scap-security-guide"
    fi

    ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no "${user}@${ip}" "
        set -e
        if ! command -v oscap >/dev/null 2>&1 \
           || [ ! -d /usr/share/xml/scap/ssg/content ] \
           || [ -z \"\$(ls -A /usr/share/xml/scap/ssg/content 2>/dev/null)\" ]; then
            echo '[INSTALL] SCAP tools missing — installing...' | sudo tee /tmp/install_${ip}.log
            ${install_cmd} 2>&1 | sudo tee -a /tmp/install_${ip}.log
        fi
        command -v oscap >/dev/null 2>&1 || { echo '[FATAL] oscap still missing after install'; exit 10; }
        [ -d /usr/share/xml/scap/ssg/content ]   || { echo '[FATAL] SCAP content dir missing'; exit 11; }
        ls /usr/share/xml/scap/ssg/content/ssg-*-ds.xml >/dev/null 2>&1 || { echo '[FATAL] No SCAP datastreams found'; exit 12; }
    "
    local rc=$?
    if [ $rc -ne 0 ]; then
        echo -e "${RED}❌ [Tool Guard] SCAP tooling unavailable on ${ip} (rc=$rc). See /tmp/install_${ip}.log on the host.${NC}"
        return $rc
    fi
    return 0
}

# ======================================================
# AUTO-HEAL HELPER (Prevents SSH Lockout)
# ======================================================
wait_for_ssh() {
    local ip=$1
    local user=$2
    echo "🔍 Waiting for $user@$ip to be responsive..."
    local count=0
    until ssh -n -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no ${user}@${ip} "exit" >/dev/null 2>&1; do
        count=$((count+1))
        if [ $count -ge 12 ]; then echo "❌ Timeout waiting for $ip"; return 1; fi
        sleep 10
    done
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

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --headless) HEADLESS=true ;;
        --profile) H_PROFILE="$2"; shift ;;
        --mode) H_MODE="$2"; shift ;;
        --targets) H_TARGETS="$2"; shift ;;
        --ticket) H_TICKET="$2"; shift ;;
        --debug) DEBUG_MODE="$2"; shift ;;
        --cleanup) H_CLEANUP="$2"; shift ;;
        --target-os) H_TARGET_OS="$2"; shift ;;
        --target-ip) H_TARGET_IP="$2"; shift ;;
        *) echo -e "${RED}Unknown parameter: $1${NC}"; exit 1 ;;
    esac
    shift
done

CIS_LEVEL="${CIS_LEVEL:-Level 1}"

# ======================================================
# ENTERPRISE GUARDRAILS
# ======================================================
if [ "$HEADLESS" == true ]; then
    echo -e "${CYAN}${BOLD}🤖 HEADLESS CI/CD MODE ACTIVATED${NC}"
    if [ -n "$H_TICKET" ] && [ "$H_TICKET" != "None" ]; then
        echo -e "${GREEN}🎫 AUDIT AUTHORIZATION: Execution tracked under Ticket ID: ${BOLD}$H_TICKET${NC}"
    fi
    if [ "$DEBUG_MODE" == "true" ]; then set -x; fi
fi

if [ -z "$AUDIT_PASS" ]; then
    echo -e "${YELLOW}🔐 Fetching Credentials from Azure KeyVault...${NC}"
    az login --identity --allow-no-subscriptions > /dev/null 2>&1 || true
    AUDIT_PASS=$(az keyvault secret show --name "$SECRET_NAME" --vault-name "$KV_NAME" --query value -o tsv 2>/dev/null | tr -d '\r\n')
fi

if [ -z "$AUDIT_PASS" ]; then
    echo -e "${RED}❌ ERROR: Failed to retrieve password from KeyVault! Aborting.${NC}"
    exit 1
fi

# ======================================================
# ⚡ ACCELERATION: SSH MULTIPLEXING
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
# PHASE 0.1: ZERO-TRUST DISCOVERY (MAP ONLY)
# ======================================================
echo -e "${CYAN}📡 Querying Azure for VMs in [$RG_NAME]...${NC}"

if [ "$H_TARGETS" == "all" ] || [ -z "$H_TARGETS" ]; then
    VM_DATA=$(az vm list -d -g "$RG_NAME" --query "[].[name, publicIps, storageProfile.osDisk.osType, powerState, storageProfile.imageReference.offer]" -o tsv)
else
    VM_DATA=$(az vm list -d -g "$RG_NAME" --query "[?tags.Environment=='$H_TARGETS'].[name, publicIps, storageProfile.osDisk.osType, powerState, storageProfile.imageReference.offer]" -o tsv)
fi

UBUNTU_MACHINES=()
RHEL_MACHINES=()
ROCKY_MACHINES=()
ALMA_MACHINES=()
WINDOWS_MACHINES=()

declare -A IP_TO_VM_NAME

while IFS=$'\t' read -r raw_name raw_ip raw_os raw_power raw_offer; do
    vm_name=$(echo "$raw_name" | tr -d '\r' | xargs); ip=$(echo "$raw_ip" | tr -d '\r' | xargs); os=$(echo "$raw_os" | tr -d '\r' | xargs); power=$(echo "$raw_power" | tr -d '\r' | xargs); offer=$(echo "$raw_offer" | tr -d '\r' | tr '[:upper:]' '[:lower:]' | xargs)
    
    if [ -z "$ip" ] || [ "$ip" == "None" ] || [[ "$power" != *"VM running"* ]]; then continue; fi
    IP_TO_VM_NAME["$ip"]="$vm_name"
    
    if [[ "$os" == *"Linux"* ]] || [[ "$os" == *"Ubuntu"* ]]; then
        if [[ "${offer,,}" == *"rocky"* ]] || [[ "${vm_name,,}" == *"rocky"* ]]; then ROCKY_MACHINES+=("$ip"); echo -e "${CYAN}🏔️ Mapped Rocky Node: $ip${NC}"
        elif [[ "${offer,,}" == *"alma"* ]] || [[ "${vm_name,,}" == *"alma"* ]]; then ALMA_MACHINES+=("$ip"); echo -e "${CYAN}🦙 Mapped AlmaLinux Node: $ip${NC}"
        elif [[ "${offer,,}" == *"rhel"* ]] || [[ "${vm_name,,}" == *"rhel"* ]]; then RHEL_MACHINES+=("$ip"); echo -e "${CYAN}🔴 Mapped RHEL Node: $ip${NC}"
        else UBUNTU_MACHINES+=("$ip"); echo -e "${CYAN}🟠 Mapped Ubuntu Node: $ip${NC}"; fi
    elif [[ "$os" == *"Windows"* ]]; then 
        WINDOWS_MACHINES+=("$ip"); echo -e "${CYAN}🪟 Mapped Windows Node: $ip${NC}"
    fi
done <<< "$VM_DATA"

# 🚨 MATRIX SHARDING: Force target to single IP if requested
if [ "$H_TARGET_IP" != "all" ] && [ -n "$H_TARGET_IP" ]; then
    echo -e "${MAGENTA}🎯 MATRIX SHARDING: Isolating execution to node $H_TARGET_IP${NC}"
    UBUNTU_MACHINES=(); RHEL_MACHINES=(); ROCKY_MACHINES=(); ALMA_MACHINES=(); WINDOWS_MACHINES=()
    if [ "${H_TARGET_OS,,}" == "ubuntu" ]; then UBUNTU_MACHINES=("$H_TARGET_IP"); fi
    if [ "${H_TARGET_OS,,}" == "rhel" ]; then RHEL_MACHINES=("$H_TARGET_IP"); fi
    if [ "${H_TARGET_OS,,}" == "rocky" ]; then ROCKY_MACHINES=("$H_TARGET_IP"); fi
    if [ "${H_TARGET_OS,,}" == "alma" ]; then ALMA_MACHINES=("$H_TARGET_IP"); fi
    if [ "${H_TARGET_OS,,}" == "windows" ]; then WINDOWS_MACHINES=("$H_TARGET_IP"); fi
fi

# ======================================================
# 🚨 PHASE 0.2: EARLY EXIT
# ======================================================
if [ "$HEADLESS" == true ] && [ "$H_TARGET_OS" != "all" ]; then
    if [ "${H_TARGET_OS,,}" == "ubuntu" ] && [ ${#UBUNTU_MACHINES[@]} -eq 0 ]; then exit 0; fi
    if [ "${H_TARGET_OS,,}" == "rhel" ] && [ ${#RHEL_MACHINES[@]} -eq 0 ]; then exit 0; fi
    if [ "${H_TARGET_OS,,}" == "rocky" ] && [ ${#ROCKY_MACHINES[@]} -eq 0 ]; then exit 0; fi
    if [ "${H_TARGET_OS,,}" == "alma" ] && [ ${#ALMA_MACHINES[@]} -eq 0 ]; then exit 0; fi
    if [ "${H_TARGET_OS,,}" == "windows" ] && [ ${#WINDOWS_MACHINES[@]} -eq 0 ]; then exit 0; fi
fi

# ======================================================
# 🛡️ PHASE 0.3: AUTO-HEALER
# ======================================================
echo -e "\n${CYAN}⚙️ PHASE 0.3: PARALLEL INFRASTRUCTURE BOOTSTRAPPING${NC}"
RUNNER_IP=$(curl -s https://api.ipify.org)

if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "ubuntu" ]]; then
    for ip in "${UBUNTU_MACHINES[@]}"; do
        (
            if [ "$(ssh -n -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no ${UBUNTU_USER}@${ip} "echo SSH_OK" 2>/dev/null)" != "SSH_OK" ]; then
                VM_NAME="${IP_TO_VM_NAME[$ip]}"
                NIC_ID=$(az vm show -g "$RG_NAME" -n "$VM_NAME" --query "networkProfile.networkInterfaces[0].id" -o tsv); NSG_ID=$(az network nic show --ids "$NIC_ID" --query "networkSecurityGroup.id" -o tsv); NSG_NAME=$(basename "$NSG_ID")
                az network nsg rule create -g "$RG_NAME" --nsg-name "$NSG_NAME" --name "Allow_SSH_Runner_Only" --priority 998 --destination-port-ranges 22 --source-address-prefixes "$RUNNER_IP" --access Allow --protocol Tcp -o none > /dev/null 2>&1 || true
                PUB_KEY=$(cat ~/.ssh/id_rsa.pub)
                az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunShellScript --scripts "useradd -m -s /bin/bash ${UBUNTU_USER} || true; echo '${UBUNTU_USER} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/99-${UBUNTU_USER}; chmod 440 /etc/sudoers.d/99-${UBUNTU_USER}; mkdir -p /home/${UBUNTU_USER}/.ssh; echo '$PUB_KEY' > /home/${UBUNTU_USER}/.ssh/authorized_keys; chown -R ${UBUNTU_USER}:${UBUNTU_USER} /home/${UBUNTU_USER}/.ssh; chmod 700 /home/${UBUNTU_USER}/.ssh; chmod 600 /home/${UBUNTU_USER}/.ssh/authorized_keys; systemctl restart sshd" -o none > /dev/null 2>&1 || true
                sleep 15
            fi
        ) &
    done
fi

if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" =~ ^(rhel|rocky|alma)$ ]]; then
    for ip in "${RHEL_MACHINES[@]}" "${ROCKY_MACHINES[@]}" "${ALMA_MACHINES[@]}"; do
        (
            if [ "$(ssh -n -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no ${GHOST_USER}@${ip} "echo SSH_OK" 2>/dev/null)" != "SSH_OK" ]; then
                VM_NAME="${IP_TO_VM_NAME[$ip]}"
                NIC_ID=$(az vm show -g "$RG_NAME" -n "$VM_NAME" --query "networkProfile.networkInterfaces[0].id" -o tsv); NSG_ID=$(az network nic show --ids "$NIC_ID" --query "networkSecurityGroup.id" -o tsv); NSG_NAME=$(basename "$NSG_ID")
                az network nsg rule create -g "$RG_NAME" --nsg-name "$NSG_NAME" --name "Allow_SSH_Runner_Only" --priority 998 --destination-port-ranges 22 --source-address-prefixes "$RUNNER_IP" --access Allow --protocol Tcp -o none > /dev/null 2>&1 || true
                PUB_KEY=$(cat ~/.ssh/id_rsa.pub)
                az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunShellScript --scripts "useradd -m -s /bin/bash ${GHOST_USER} || true; echo '${GHOST_USER} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/99-${GHOST_USER}; chmod 440 /etc/sudoers.d/99-${GHOST_USER}; mkdir -p /home/${GHOST_USER}/.ssh; echo '$PUB_KEY' > /home/${GHOST_USER}/.ssh/authorized_keys; chown -R ${GHOST_USER}:${GHOST_USER} /home/${GHOST_USER}/.ssh; chmod 700 /home/${GHOST_USER}/.ssh; chmod 600 /home/${GHOST_USER}/.ssh/authorized_keys; if command -v restorecon &> /dev/null; then restorecon -Rv /home/${GHOST_USER}/.ssh >/dev/null 2>&1 || true; fi; echo 'PubkeyAcceptedKeyTypes +ssh-rsa' > /etc/ssh/sshd_config.d/99-runner-key.conf 2>/dev/null || true; systemctl restart sshd" -o none > /dev/null 2>&1 || true
                sleep 15
            fi
        ) &
    done
fi

if [[ "$H_TARGET_OS" == "all" || "${H_TARGET_OS,,}" == "windows" ]]; then
    for ip in "${WINDOWS_MACHINES[@]}"; do
        (
            VM_NAME="${IP_TO_VM_NAME[$ip]}"
            NIC_ID=$(az vm show -g "$RG_NAME" -n "$VM_NAME" --query "networkProfile.networkInterfaces[0].id" -o tsv); NSG_ID=$(az network nic show --ids "$NIC_ID" --query "networkSecurityGroup.id" -o tsv)
            if [ -n "$NSG_ID" ]; then
                NSG_NAME=$(basename "$NSG_ID")
                az network nsg rule create -g "$RG_NAME" --nsg-name "$NSG_NAME" --name "Allow_WinRM_Runner_Only" --priority 999 --destination-port-ranges 5985 --source-address-prefixes "$RUNNER_IP" --access Allow --protocol Tcp -o none > /dev/null 2>&1 || true
            fi
            az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunPowerShellScript --scripts "Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM' -Recurse -Force -ErrorAction SilentlyContinue; net user ${AUDIT_USER} '${AUDIT_PASS}' /add /y 2>&1 | Out-Null; net user ${AUDIT_USER} '${AUDIT_PASS}' 2>&1 | Out-Null; net localgroup Administrators ${AUDIT_USER} /add 2>&1 | Out-Null; WMIC USERACCOUNT WHERE Name='${AUDIT_USER}' SET PasswordExpires=FALSE 2>&1 | Out-Null; Enable-PSRemoting -SkipNetworkProfileCheck -Force; winrm set winrm/config/service/auth '@{Basic=\"true\"}'; winrm set winrm/config/service '@{AllowUnencrypted=\"true\"}'; New-ItemProperty -Name LocalAccountTokenFilterPolicy -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -PropertyType DWord -Value 1 -Force; Set-NetFirewallRule -DisplayGroup 'Windows Remote Management' -Enabled True -Profile Any -ErrorAction SilentlyContinue; Restart-Service WinRM -Force;" -o none > /dev/null 2>&1 || true
            sleep 20
        ) &
    done
fi
wait

# ======================================================
# INVENTORY BUILDER
# ======================================================
echo "[ubuntu_nodes]" > inventory.ini
for ip in "${UBUNTU_MACHINES[@]}"; do echo "${ip} ansible_user=${UBUNTU_USER}" >> inventory.ini; done
echo -e "\n[rhel_nodes]" >> inventory.ini
for ip in "${RHEL_MACHINES[@]}"; do echo "${ip} ansible_user=${GHOST_USER}" >> inventory.ini; done
echo -e "\n[rocky_nodes]" >> inventory.ini
for ip in "${ROCKY_MACHINES[@]}"; do echo "${ip} ansible_user=${GHOST_USER}" >> inventory.ini; done
echo -e "\n[alma_nodes]" >> inventory.ini
for ip in "${ALMA_MACHINES[@]}"; do echo "${ip} ansible_user=${GHOST_USER}" >> inventory.ini; done
echo -e "\n[windows_nodes]" >> inventory.ini
for ip in "${WINDOWS_MACHINES[@]}"; do echo "${ip} ansible_user=${AUDIT_USER} ansible_password=\"${AUDIT_PASS}\" ansible_port=5985 ansible_winrm_scheme=http ansible_connection=winrm ansible_winrm_transport=basic ansible_winrm_server_cert_validation=ignore" >> inventory.ini; done

RUN_ORG=false; RUN_CIS=false
if [ "$HEADLESS" == true ]; then
    if [[ "${H_PROFILE,,}" == "tm" ]] || [[ "${H_PROFILE,,}" == "${ORG_PREFIX,,}" ]] || [[ "${H_PROFILE,,}" == "both" ]]; then RUN_ORG=true; fi
    if [[ "${H_PROFILE,,}" == "cis" ]] || [[ "${H_PROFILE,,}" == "both" ]]; then RUN_CIS=true; fi
else
    echo -e "\n1) CUSTOM BASELINE\n2) CIS BASELINE\n3) BOTH"
    read -p "Choose profile [1-3]: " pc
    if [ "$pc" == "1" ] || [ "$pc" == "3" ]; then RUN_ORG=true; fi
    if [ "$pc" == "2" ] || [ "$pc" == "3" ]; then RUN_CIS=true; fi
fi

update_profile_vars() {
    if [ "$RUN_CIS" == true ]; then
        if [ "$CIS_LEVEL" == "Level 1" ]; then
            UBUNTU_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis_level1_server"
            RHEL_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis_server_l1"
            OS_LVL="1"; WIN_INSPEC_LVL="1"
        else
            UBUNTU_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis_level2_server"
            RHEL_CIS_PROFILE="xccdf_org.ssgproject.content_profile_cis"
            OS_LVL="2"; WIN_INSPEC_LVL="2"
        fi
    fi
}

# ======================================================
# PHASE 1: SCAN
# ======================================================
run_phase_1() {
    echo -e "\n${BOLD}🔍 PHASE 1: Running Initial Baselines (Asynchronous)...${NC}"

    # -------------------- UBUNTU --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "ubuntu" ]; then
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ]; then
            for IP in "${UBUNTU_MACHINES[@]}"; do
                (
                    if ! ensure_linux_scap_tools "$UBUNTU_USER" "$IP" "apt"; then
                        echo -e "${RED}❌ [Phase1/Ubuntu] Skipping $IP — tools unavailable.${NC}"
                        exit 1
                    fi

                    RAW_VER=$(ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} \
                        "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
                    UBUNTU_VER=${RAW_VER:-2404}
                    UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Ubuntu/CIS L${OS_LVL}] Scanning $IP...${NC}"
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} \
                            "sudo oscap xccdf eval --profile $UBUNTU_CIS_PROFILE \
                             --report /tmp/report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html \
                             $UBUNTU_CIS_XCCDF"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${UBUNTU_USER}@${IP}:/tmp/report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html \
                                ./report_before_CIS_L${OS_LVL}_UBUNTU_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-CIS report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/Ubuntu/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Ubuntu/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                            "$UBUNTU_CUSTOM_OVAL" "$UBUNTU_CUSTOM_XCCDF" ${UBUNTU_USER}@${IP}:/tmp/ \
                            || { echo -e "${RED}❌ [Phase1] SCP of custom content failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} \
                            "sudo oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report /tmp/report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html \
                             /tmp/$(basename $UBUNTU_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${UBUNTU_USER}@${IP}:/tmp/report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html \
                                ./report_before_${ORG_PREFIX^^}_UBUNTU_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-${ORG_PREFIX^^} report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/Ubuntu/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- RHEL --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rhel" ]; then
        if [ ${#RHEL_MACHINES[@]} -gt 0 ]; then
            for IP in "${RHEL_MACHINES[@]}"; do
                (
                    if ! ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf"; then
                        echo -e "${RED}❌ [Phase1/RHEL] Skipping $IP — tools unavailable.${NC}"
                        exit 1
                    fi

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/RHEL/CIS L${OS_LVL}] Scanning $IP...${NC}"
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} \
                            "TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1); \
                             sudo /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE \
                             --report /tmp/report_before_CIS_L${OS_LVL}_RHEL_${IP}.html \"\$TARGET_XML\""
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${GHOST_USER}@${IP}:/tmp/report_before_CIS_L${OS_LVL}_RHEL_${IP}.html \
                                ./report_before_CIS_L${OS_LVL}_RHEL_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-CIS report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/RHEL/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/RHEL/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                            "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" ${GHOST_USER}@${IP}:/tmp/ \
                            || { echo -e "${RED}❌ [Phase1] SCP of custom content failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} \
                            "sudo env OSCAP_CPE_DICT_PATH=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-cpe-dictionary.xml' | sort -V | tail -n 1) \
                             /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report /tmp/report_before_${ORG_PREFIX^^}_RHEL_${IP}.html \
                             /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${GHOST_USER}@${IP}:/tmp/report_before_${ORG_PREFIX^^}_RHEL_${IP}.html \
                                ./report_before_${ORG_PREFIX^^}_RHEL_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-${ORG_PREFIX^^} report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/RHEL/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- ROCKY --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rocky" ]; then
        if [ ${#ROCKY_MACHINES[@]} -gt 0 ]; then
            for IP in "${ROCKY_MACHINES[@]}"; do
                (
                    if ! ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf"; then
                        echo -e "${RED}❌ [Phase1/Rocky] Skipping $IP — tools unavailable.${NC}"
                        exit 1
                    fi

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Rocky/CIS L${OS_LVL}] Scanning $IP...${NC}"
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "
                            ROCKY_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-rl\${ROCKY_VER}-ds.xml\"
                            if [ ! -f \"\$TARGET_XML\" ]; then
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            fi
                            if [ -z \"\$TARGET_XML\" ] || [ ! -f \"\$TARGET_XML\" ]; then echo 'NO_SCAP_CONTENT'; exit 99; fi
                            sudo /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE \
                                --report /tmp/report_before_CIS_L${OS_LVL}_ROCKY_${IP}.html \"\$TARGET_XML\"
                        "
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${GHOST_USER}@${IP}:/tmp/report_before_CIS_L${OS_LVL}_ROCKY_${IP}.html \
                                ./report_before_CIS_L${OS_LVL}_ROCKY_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-CIS report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/Rocky/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Rocky/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                            "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" ${GHOST_USER}@${IP}:/tmp/ \
                            || { echo -e "${RED}❌ [Phase1] SCP of custom content failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report /tmp/report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html \
                             /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${GHOST_USER}@${IP}:/tmp/report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html \
                                ./report_before_${ORG_PREFIX^^}_ROCKY_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-${ORG_PREFIX^^} report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/Rocky/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- ALMA --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "alma" ]; then
        if [ ${#ALMA_MACHINES[@]} -gt 0 ]; then
            for IP in "${ALMA_MACHINES[@]}"; do
                (
                    if ! ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf"; then
                        echo -e "${RED}❌ [Phase1/Alma] Skipping $IP — tools unavailable.${NC}"
                        exit 1
                    fi

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Alma/CIS L${OS_LVL}] Scanning $IP...${NC}"
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "
                            ALMA_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-almalinux\${ALMA_VER}-ds.xml\"
                            if [ ! -f \"\$TARGET_XML\" ]; then
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            fi
                            if [ -z \"\$TARGET_XML\" ] || [ ! -f \"\$TARGET_XML\" ]; then echo 'NO_SCAP_CONTENT'; exit 99; fi
                            if ! grep -q \"$RHEL_CIS_PROFILE\" \"\$TARGET_XML\"; then
                                ALMA_PROF=\"xccdf_org.ssgproject.content_profile_cis\"
                            else
                                ALMA_PROF=\"$RHEL_CIS_PROFILE\"
                            fi
                            sudo /usr/bin/oscap xccdf eval --profile \$ALMA_PROF \
                                --report /tmp/report_before_CIS_L${OS_LVL}_ALMA_${IP}.html \"\$TARGET_XML\"
                        "
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${GHOST_USER}@${IP}:/tmp/report_before_CIS_L${OS_LVL}_ALMA_${IP}.html \
                                ./report_before_CIS_L${OS_LVL}_ALMA_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-CIS report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/Alma/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}🔎 [Phase1/Alma/${ORG_PREFIX^^}] Scanning $IP...${NC}"
                        scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                            "$RHEL_CUSTOM_OVAL" "$RHEL_CUSTOM_XCCDF" ${GHOST_USER}@${IP}:/tmp/ \
                            || { echo -e "${RED}❌ [Phase1] SCP of custom content failed for $IP${NC}"; exit 1; }
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report /tmp/report_before_${ORG_PREFIX^^}_ALMA_${IP}.html \
                             /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes -o StrictHostKeyChecking=no \
                                ${GHOST_USER}@${IP}:/tmp/report_before_${ORG_PREFIX^^}_ALMA_${IP}.html \
                                ./report_before_${ORG_PREFIX^^}_ALMA_${IP}.html \
                                || echo -e "${RED}❌ [Phase1] SCP failed for before-${ORG_PREFIX^^} report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase1/Alma/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- WINDOWS --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "windows" ]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            for IP in "${WINDOWS_MACHINES[@]}"; do
                (
                    export INSPEC_PASSWORD="${AUDIT_PASS}"
                    if [ "$RUN_CIS" == true ]; then
                        cinc-auditor exec "$WIN_CIS_BENCHMARK" -t winrm://${IP} \
                            --user="${AUDIT_USER}" --input level_1_or_2=$WIN_INSPEC_LVL \
                            --reporter json:heimdall_before_CIS_L${WIN_INSPEC_LVL}_WIN_${IP}.json \
                            > /dev/null 2>&1 || \
                            echo -e "${RED}❌ [Phase1/Win/CIS] cinc-auditor failed on $IP${NC}"
                    fi
                    if [ "$RUN_ORG" == true ]; then
                        cinc-auditor exec "$WIN_CUSTOM_BENCHMARK" -t winrm://${IP} \
                            --user="${AUDIT_USER}" \
                            --reporter json:heimdall_before_${ORG_PREFIX^^}_WIN_${IP}.json \
                            > /dev/null 2>&1 || \
                            echo -e "${RED}❌ [Phase1/Win/${ORG_PREFIX^^}] cinc-auditor failed on $IP${NC}"
                    fi
                    unset INSPEC_PASSWORD
                ) &
            done
            wait
        fi
    fi
}

# ======================================================
# PHASE 2/3: REMEDIATION (NO SCP DOWNLOADS)
# ======================================================
run_remediation() {
    echo -e "\n${BOLD}🛠️  PHASE 2 & 3: Executing Remediation (Asynchronous)...${NC}"
    
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "ubuntu" ]; then
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ] && [ "$RUN_CIS" == true ]; then
            for IP in "${UBUNTU_MACHINES[@]}"; do
                ( ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-ubuntu*-ds.xml' | sort -V | tail -n 1); sudo /usr/bin/oscap xccdf eval --remediate --profile $UBUNTU_CIS_PROFILE --report /tmp/report_remediation_CIS_${IP}.html \"\$XML_FILE\"" > /dev/null 2>&1 || true ) &
            done
            wait
        fi
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ] && [ "$RUN_ORG" == true ]; then ansible-playbook -i inventory.ini $UBUNTU_CUSTOM_PLAYBOOK --limit ubuntu_nodes > /dev/null 2>&1 || true; fi
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rhel" ]; then
        if [ ${#RHEL_MACHINES[@]} -gt 0 ] && [ "$RUN_CIS" == true ]; then
            for IP in "${RHEL_MACHINES[@]}"; do
                ( ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "XML_FILE=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1); sudo /usr/bin/oscap xccdf eval --remediate --profile $RHEL_CIS_PROFILE --report /tmp/report_remediation_CIS_${IP}.html \"\$XML_FILE\"" > /dev/null 2>&1 || true ) &
            done
            wait
        fi
        if [ ${#RHEL_MACHINES[@]} -gt 0 ] && [ "$RUN_ORG" == true ]; then ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK --limit rhel_nodes > /dev/null 2>&1 || true; fi
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rocky" ]; then
        if [ ${#ROCKY_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                for IP in "${ROCKY_MACHINES[@]}"; do
                    ( ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "ROCKY_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*}); TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-rl\${ROCKY_VER}-ds.xml\"; if [ ! -f \"\$TARGET_XML\" ]; then exit 1; fi; sudo /usr/bin/oscap xccdf eval --remediate --profile $RHEL_CIS_PROFILE --report /tmp/report_remediation_CIS_ROCKY_${IP}.html \"\$TARGET_XML\"" > /dev/null 2>&1 || true ) &
                done
                wait
            fi
            if [ "$RUN_ORG" == true ]; then ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK --limit rocky_nodes > /dev/null 2>&1 || true; fi
        fi
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "alma" ]; then
        if [ ${#ALMA_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                for IP in "${ALMA_MACHINES[@]}"; do
                    (
                        ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "
                            ALMA_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-almalinux\${ALMA_VER}-ds.xml\"
                            if [ ! -f \"\$TARGET_XML\" ]; then TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1); fi
                            if [ ! -f \"\$TARGET_XML\" ]; then exit 1; fi
                            if ! grep -q \"$RHEL_CIS_PROFILE\" \"\$TARGET_XML\"; then ALMA_PROF=\"xccdf_org.ssgproject.content_profile_cis\"; else ALMA_PROF=\"$RHEL_CIS_PROFILE\"; fi
                            sudo /usr/bin/oscap xccdf eval --remediate --profile \$ALMA_PROF --report /tmp/report_remediation_CIS_ALMA_${IP}.html \"\$TARGET_XML\"
                        " > /dev/null 2>&1 || true
                    ) &
                done
                wait
            fi
            if [ "$RUN_ORG" == true ]; then ansible-playbook -i inventory.ini $RHEL_CUSTOM_PLAYBOOK --limit alma_nodes > /dev/null 2>&1 || true; fi
        fi
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "windows" ]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            if [ "$RUN_CIS" == true ]; then
                ansible-galaxy role install ansible-lockdown.windows_2022_cis > /dev/null 2>&1 || true
                EXTRA_VARS="-e win2022cis_level_1=true -e win2022cis_level_2=$([ "$CIS_LEVEL" == "Level 2" ] && echo true || echo false)"
                ansible-playbook -i inventory.ini $WIN_CIS_PLAYBOOK --limit windows_nodes $EXTRA_VARS > /dev/null 2>&1 || true
            fi
            if [ "$RUN_ORG" == true ]; then ansible-playbook -i inventory.ini $WIN_CUSTOM_PLAYBOOK --limit windows_nodes > /dev/null 2>&1 || true; fi
        fi
    fi
}

# ======================================================
# PHASE 4: VERIFICATION
# ======================================================
run_phase_4() {
    echo -e "\n${BOLD}🔄 PHASE 4: Running Verification Scans (Asynchronous)...${NC}"

    # -------------------- UBUNTU VERIFY --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "ubuntu" ]; then
        if [ ${#UBUNTU_MACHINES[@]} -gt 0 ]; then
            for IP in "${UBUNTU_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$UBUNTU_USER" || { echo -e "${RED}❌ [Phase4/Ubuntu] SSH unreachable: $IP${NC}"; exit 1; }
                    ensure_linux_scap_tools "$UBUNTU_USER" "$IP" "apt" || { echo -e "${RED}❌ [Phase4/Ubuntu] Tools missing on $IP${NC}"; exit 1; }

                    UBUNTU_VER=$(ssh -n -o BatchMode=yes ${UBUNTU_USER}@${IP} \
                        "source /etc/os-release && echo \${VERSION_ID//./}" 2>/dev/null)
                    UBUNTU_VER=${UBUNTU_VER:-2404}
                    UBUNTU_CIS_XCCDF="/usr/share/xml/scap/ssg/content/ssg-ubuntu${UBUNTU_VER}-ds.xml"

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Ubuntu/CIS L${OS_LVL}] Verifying $IP...${NC}"
                        ssh -n -o BatchMode=yes ${UBUNTU_USER}@${IP} \
                            "sudo oscap xccdf eval --profile $UBUNTU_CIS_PROFILE \
                             --report /tmp/report_after_CIS_L${OS_LVL}_UBUNTU_${IP}.html \
                             $UBUNTU_CIS_XCCDF"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes ${UBUNTU_USER}@${IP}:/tmp/report_after_CIS_L${OS_LVL}_UBUNTU_${IP}.html \
                                ./report_after_CIS_L${OS_LVL}_UBUNTU_${IP}.html \
                                || echo -e "${RED}❌ [Phase4] SCP failed for after-CIS report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase4/Ubuntu/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Ubuntu/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        ssh -n -o BatchMode=yes ${UBUNTU_USER}@${IP} \
                            "sudo oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report /tmp/report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html \
                             /tmp/$(basename $UBUNTU_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes ${UBUNTU_USER}@${IP}:/tmp/report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html \
                                ./report_after_${ORG_PREFIX^^}_UBUNTU_${IP}.html \
                                || echo -e "${RED}❌ [Phase4] SCP failed for after-${ORG_PREFIX^^} report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase4/Ubuntu/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- RHEL VERIFY --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rhel" ]; then
        if [ ${#RHEL_MACHINES[@]} -gt 0 ]; then
            for IP in "${RHEL_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$GHOST_USER" || { echo -e "${RED}❌ [Phase4/RHEL] SSH unreachable: $IP${NC}"; exit 1; }
                    ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || { echo -e "${RED}❌ [Phase4/RHEL] Tools missing on $IP${NC}"; exit 1; }

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/RHEL/CIS L${OS_LVL}] Verifying $IP...${NC}"
                        ssh -n -o BatchMode=yes ${GHOST_USER}@${IP} \
                            "TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1); \
                             sudo /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE \
                             --report /tmp/report_after_CIS_L${OS_LVL}_RHEL_${IP}.html \"\$TARGET_XML\""
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes ${GHOST_USER}@${IP}:/tmp/report_after_CIS_L${OS_LVL}_RHEL_${IP}.html \
                                ./report_after_CIS_L${OS_LVL}_RHEL_${IP}.html \
                                || echo -e "${RED}❌ [Phase4] SCP failed for after-CIS report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase4/RHEL/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/RHEL/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        ssh -n -o BatchMode=yes ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report /tmp/report_after_${ORG_PREFIX^^}_RHEL_${IP}.html \
                             /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes ${GHOST_USER}@${IP}:/tmp/report_after_${ORG_PREFIX^^}_RHEL_${IP}.html \
                                ./report_after_${ORG_PREFIX^^}_RHEL_${IP}.html \
                                || echo -e "${RED}❌ [Phase4] SCP failed for after-${ORG_PREFIX^^} report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase4/RHEL/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- ROCKY VERIFY --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rocky" ]; then
        if [ ${#ROCKY_MACHINES[@]} -gt 0 ]; then
            for IP in "${ROCKY_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$GHOST_USER" || { echo -e "${RED}❌ [Phase4/Rocky] SSH unreachable: $IP${NC}"; exit 1; }
                    ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || { echo -e "${RED}❌ [Phase4/Rocky] Tools missing on $IP${NC}"; exit 1; }

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Rocky/CIS L${OS_LVL}] Verifying $IP...${NC}"
                        ssh -n -o BatchMode=yes ${GHOST_USER}@${IP} "
                            ROCKY_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-rl\${ROCKY_VER}-ds.xml\"
                            if [ ! -f \"\$TARGET_XML\" ]; then
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            fi
                            if [ -z \"\$TARGET_XML\" ] || [ ! -f \"\$TARGET_XML\" ]; then echo 'NO_SCAP_CONTENT'; exit 99; fi
                            sudo /usr/bin/oscap xccdf eval --profile $RHEL_CIS_PROFILE \
                                --report /tmp/report_after_CIS_L${OS_LVL}_ROCKY_${IP}.html \"\$TARGET_XML\"
                        "
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes ${GHOST_USER}@${IP}:/tmp/report_after_CIS_L${OS_LVL}_ROCKY_${IP}.html \
                                ./report_after_CIS_L${OS_LVL}_ROCKY_${IP}.html \
                                || echo -e "${RED}❌ [Phase4] SCP failed for after-CIS report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase4/Rocky/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Rocky/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        ssh -n -o BatchMode=yes ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report /tmp/report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html \
                             /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes ${GHOST_USER}@${IP}:/tmp/report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html \
                                ./report_after_${ORG_PREFIX^^}_ROCKY_${IP}.html \
                                || echo -e "${RED}❌ [Phase4] SCP failed for after-${ORG_PREFIX^^} report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase4/Rocky/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- ALMA VERIFY --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "alma" ]; then
        if [ ${#ALMA_MACHINES[@]} -gt 0 ]; then
            for IP in "${ALMA_MACHINES[@]}"; do
                (
                    wait_for_ssh "$IP" "$GHOST_USER" || { echo -e "${RED}❌ [Phase4/Alma] SSH unreachable: $IP${NC}"; exit 1; }
                    ensure_linux_scap_tools "$GHOST_USER" "$IP" "dnf" || { echo -e "${RED}❌ [Phase4/Alma] Tools missing on $IP${NC}"; exit 1; }

                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Alma/CIS L${OS_LVL}] Verifying $IP...${NC}"
                        ssh -n -o BatchMode=yes ${GHOST_USER}@${IP} "
                            ALMA_VER=\$(source /etc/os-release && echo \${VERSION_ID%%.*})
                            TARGET_XML=\"/usr/share/xml/scap/ssg/content/ssg-almalinux\${ALMA_VER}-ds.xml\"
                            if [ ! -f \"\$TARGET_XML\" ]; then
                                TARGET_XML=\$(find /usr/share/xml/scap/ssg/content/ -name 'ssg-rhel*-ds.xml' | sort -V | tail -n 1)
                            fi
                            if [ -z \"\$TARGET_XML\" ] || [ ! -f \"\$TARGET_XML\" ]; then echo 'NO_SCAP_CONTENT'; exit 99; fi
                            if ! grep -q \"$RHEL_CIS_PROFILE\" \"\$TARGET_XML\"; then
                                ALMA_PROF=\"xccdf_org.ssgproject.content_profile_cis\"
                            else
                                ALMA_PROF=\"$RHEL_CIS_PROFILE\"
                            fi
                            sudo /usr/bin/oscap xccdf eval --profile \$ALMA_PROF \
                                --report /tmp/report_after_CIS_L${OS_LVL}_ALMA_${IP}.html \"\$TARGET_XML\"
                        "
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes ${GHOST_USER}@${IP}:/tmp/report_after_CIS_L${OS_LVL}_ALMA_${IP}.html \
                                ./report_after_CIS_L${OS_LVL}_ALMA_${IP}.html \
                                || echo -e "${RED}❌ [Phase4] SCP failed for after-CIS report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase4/Alma/CIS] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi

                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Alma/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        ssh -n -o BatchMode=yes ${GHOST_USER}@${IP} \
                            "sudo /usr/bin/oscap xccdf eval --profile $CUSTOM_XCCDF_PROFILE \
                             --report /tmp/report_after_${ORG_PREFIX^^}_ALMA_${IP}.html \
                             /tmp/$(basename $RHEL_CUSTOM_XCCDF)"
                        rc=$?
                        if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
                            scp -o BatchMode=yes ${GHOST_USER}@${IP}:/tmp/report_after_${ORG_PREFIX^^}_ALMA_${IP}.html \
                                ./report_after_${ORG_PREFIX^^}_ALMA_${IP}.html \
                                || echo -e "${RED}❌ [Phase4] SCP failed for after-${ORG_PREFIX^^} report on $IP${NC}"
                        else
                            echo -e "${RED}❌ [Phase4/Alma/${ORG_PREFIX^^}] oscap failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                ) &
            done
            wait
        fi
    fi

    # -------------------- WINDOWS VERIFY --------------------
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "windows" ]; then
        if [ ${#WINDOWS_MACHINES[@]} -gt 0 ]; then
            for IP in "${WINDOWS_MACHINES[@]}"; do
                (
                    if [ "$RUN_CIS" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Win/CIS L${WIN_INSPEC_LVL}] Verifying $IP...${NC}"
                        cinc-auditor exec "$WIN_CIS_BENCHMARK" -t winrm://${IP} \
                            --user="${AUDIT_USER}" --password="${AUDIT_PASS}" \
                            --input level_1_or_2=$WIN_INSPEC_LVL \
                            --reporter json:heimdall_after_CIS_L${WIN_INSPEC_LVL}_WIN_${IP}.json
                        rc=$?
                        if [ $rc -ne 0 ] && [ $rc -ne 100 ] && [ $rc -ne 101 ]; then
                            echo -e "${RED}❌ [Phase4/Win/CIS] cinc-auditor failed on $IP (rc=$rc)${NC}"
                        fi
                    fi
                    if [ "$RUN_ORG" == true ]; then
                        echo -e "${GREEN}✅ [Phase4/Win/${ORG_PREFIX^^}] Verifying $IP...${NC}"
                        cinc-auditor exec "$WIN_CUSTOM_BENCHMARK" -t winrm://${IP} \
                            --user="${AUDIT_USER}" --password="${AUDIT_PASS}" \
                            --reporter json:heimdall_after_${ORG_PREFIX^^}_WIN_${IP}.json
                        rc=$?
                        if [ $rc -ne 0 ] && [ $rc -ne 100 ] && [ $rc -ne 101 ]; then
                            echo -e "${RED}❌ [Phase4/Win/${ORG_PREFIX^^}] cinc-auditor failed on $IP (rc=$rc)${NC}"
                        fi
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
    echo -e "\n${BOLD}${RED}🧹 PHASE 5: POST-AUDIT CLEANUP (THE GHOST METHOD)${NC}"
    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "ubuntu" ]; then
        for IP in "${UBUNTU_MACHINES[@]}"; do
            echo -e "   ${YELLOW}Removing tools & nuking user from Ubuntu: $IP...${NC}"
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${UBUNTU_USER}@${IP} "sudo apt-get purge -y openscap-scanner ssg-base && sudo apt-get autoremove -y" > /dev/null 2>&1
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            if [ -n "$VM_NAME" ]; then az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunShellScript --scripts "userdel -r ${UBUNTU_USER}" -o none > /dev/null 2>&1 || true; fi
        done
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rhel" ]; then
        for IP in "${RHEL_MACHINES[@]}"; do
            echo -e "   ${YELLOW}Removing tools & nuking user from RHEL: $IP...${NC}"
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "sudo dnf remove -y openscap-scanner scap-security-guide -C --setopt=metadata_expire=never" > /dev/null 2>&1
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            if [ -n "$VM_NAME" ]; then az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunShellScript --scripts "userdel -r ${GHOST_USER}" -o none > /dev/null 2>&1 || true; fi
        done
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "rocky" ]; then
        for IP in "${ROCKY_MACHINES[@]}"; do
            echo -e "   ${YELLOW}Removing tools & nuking user from Rocky: $IP...${NC}"
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "sudo dnf remove -y openscap-scanner scap-security-guide -C --setopt=metadata_expire=never" > /dev/null 2>&1
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            if [ -n "$VM_NAME" ]; then az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunShellScript --scripts "userdel -r ${GHOST_USER}" -o none > /dev/null 2>&1 || true; fi
        done
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "alma" ]; then
        for IP in "${ALMA_MACHINES[@]}"; do
            echo -e "   ${YELLOW}Removing tools & nuking user from AlmaLinux: $IP...${NC}"
            ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no ${GHOST_USER}@${IP} "sudo dnf remove -y openscap-scanner scap-security-guide -C --setopt=metadata_expire=never" > /dev/null 2>&1
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            if [ -n "$VM_NAME" ]; then az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunShellScript --scripts "userdel -r ${GHOST_USER}" -o none > /dev/null 2>&1 || true; fi
        done
    fi

    if [ "$H_TARGET_OS" == "all" ] || [ "${H_TARGET_OS,,}" == "windows" ]; then
        for IP in "${WINDOWS_MACHINES[@]}"; do
            echo -e "   ${CYAN}🧹 Reversing security changes & nuking user on Windows: $IP...${NC}"
            VM_NAME="${IP_TO_VM_NAME[$IP]}"
            if [ -n "$VM_NAME" ]; then
                NIC_ID=$(az vm show -g "$RG_NAME" -n "$VM_NAME" --query "networkProfile.networkInterfaces[0].id" -o tsv)
                NSG_ID=$(az network nic show --ids "$NIC_ID" --query "networkSecurityGroup.id" -o tsv)
                if [ -n "$NSG_ID" ]; then
                    NSG_NAME=$(basename "$NSG_ID")
                    az network nsg rule delete -g "$RG_NAME" --nsg-name "$NSG_NAME" --name "Allow_WinRM_Runner_Only" -o none > /dev/null 2>&1 || true
                fi
                az vm run-command invoke -g "$RG_NAME" -n "$VM_NAME" --command-id RunPowerShellScript --scripts "Stop-Service WinRM -WarningAction SilentlyContinue; Set-Service WinRM -StartupType Disabled; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Force -ErrorAction SilentlyContinue; Disable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue; Remove-LocalUser -Name '$AUDIT_USER' -ErrorAction SilentlyContinue" -o none > /dev/null 2>&1 || true
            fi
        done
    fi
}

# ======================================================
# EXECUTION ENGINE
# ======================================================
execute_phases() {
    case $H_MODE in
        scan) run_phase_1 ;;
        remediate) run_remediation ;;
        full) run_phase_1; run_remediation; run_phase_4 ;;
    esac
}

if [ "$HEADLESS" == true ]; then
    echo -e "\n${CYAN}${BOLD}======================================================"
    echo -e "🚀 EXECUTING CI/CD WORKFLOW: MODE -> $H_MODE"
    echo -e "======================================================${NC}"
    
    if [ "${H_PROFILE,,}" == "all" ]; then
        echo -e "\n${MAGENTA}======================================================${NC}"
        echo -e "${MAGENTA} 🔄 INITIATING FULL FLEET AUDIT (L1, L2, TM)...${NC}"
        echo -e "${MAGENTA}======================================================${NC}"

        export CIS_LEVEL="Level 1"; export RUN_CIS=true; export RUN_ORG=false
        update_profile_vars
        echo -e "\n${CYAN}▶️ STEP 1/3: EXECUTING CIS LEVEL 1${NC}"
        execute_phases

        export CIS_LEVEL="Level 2"; export RUN_CIS=true; export RUN_ORG=false
        update_profile_vars
        echo -e "\n${CYAN}▶️ STEP 2/3: EXECUTING CIS LEVEL 2${NC}"
        execute_phases

        export RUN_CIS=false; export RUN_ORG=true
        update_profile_vars
        echo -e "\n${CYAN}▶️ STEP 3/3: EXECUTING TM BASELINE${NC}"
        execute_phases
    else
        update_profile_vars
        execute_phases
    fi

    if [ "$H_CLEANUP" == "true" ]; then run_cleanup; fi

    chmod 755 *.json *.html 2>/dev/null || true
    echo -e "\n${GREEN}✅ CI/CD Pipeline Execution Complete. All reports generated.${NC}"
    exit 0
fi

# INTERACTIVE MODE
while true; do
    update_profile_vars
    echo -e "\n${CYAN}------------------------------------------------------${NC}"
    echo -e "1) ${BOLD}SCAN ONLY${NC}      (Initial Baseline)"
    echo -e "2) ${BOLD}REMEDIATE ONLY${NC} (Ansible Fixes)"
    echo -e "3) ${BOLD}FULL PIPELINE${NC}  (Run all phases in order)"
    echo -e "4) ${BOLD}EXIT${NC}"
    read -p "Choose an option [1-4]: " choice
    case $choice in
        1) run_phase_1 ;;
        2) run_remediation ;;
        3) run_phase_1; run_remediation; run_phase_4 ;;
        4) exit 0 ;;
    esac
done
