#!/bin/bash

# --- CONFIGURATION ---
SERVER_IP="20.212.133.93"
INIT_USER="window"
INIT_PASS="window#12345"
AUDIT_USER="TM_Admin"
AUDIT_PASS="TM_Secure_P@ssw0rd!"

# Global Settings
export CHEF_LICENSE="accept-silent"
export CHEF_LICENSE_KEY="free-e13ce9a4-c7a5-4132-8ee4-8ffe54c0011d-7485"
export INSPEC_SSH_CONFIG_NO_SECURE=true

# Formatting
BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo -e "${CYAN}${BOLD}======================================================"
echo -e "🛡️  TM INTERACTIVE SECURITY TOOL"
echo -e "======================================================${NC}"
echo -e "Target: ${BOLD}$SERVER_IP${NC}"
echo -e "1) ${BOLD}SCAN ONLY${NC}      (Phase 1: Initial Baseline)"
echo -e "2) ${BOLD}REMEDIATE ONLY${NC} (Phase 2 & 3: Ansible Fixes)"
echo -e "3) ${BOLD}RE-SCAN ONLY${NC}   (Phase 4: Using $AUDIT_USER)"
echo -e "4) ${BOLD}FULL PIPELINE${NC}  (Run all phases in order)"
echo -e "5) ${BOLD}EXIT${NC}"
echo -e "${CYAN}------------------------------------------------------${NC}"
read -p "Choose an option [1-5]: " choice

case $choice in
    1)
        echo -e "\n🔍 ${BOLD}Running Initial Scan...${NC}"
        inspec exec tm_baseline.rb -t ssh://${SERVER_IP} --user="${INIT_USER}" --password="${INIT_PASS}" --reporter json:heimdall_before.json
        ;;
    2)
        echo -e "\n🛠️  ${BOLD}Starting Remediation...${NC}"
        ansible-playbook -i inventory.ini tm_remediate.yml -u "${INIT_USER}" -e "ansible_password=${INIT_PASS}"
        ;;
    3)
        echo -e "\n🔄 ${BOLD}Running Re-Scan (Handover Account)...${NC}"
        inspec exec tm_baseline.rb -t ssh://${SERVER_IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter json:heimdall_after.json
        ;;
    4)
        echo -e "\n🚀 ${BOLD}Executing Full DevSecOps Pipeline...${NC}"
        # Phase 1
        inspec exec tm_baseline.rb -t ssh://${SERVER_IP} --user="${INIT_USER}" --password="${INIT_PASS}" --reporter json:heimdall_before.json
        # Phase 2/3
        ansible-playbook -i inventory.ini tm_remediate.yml -u "${INIT_USER}" -e "ansible_password=${INIT_PASS}"
        # Phase 4
        inspec exec tm_baseline.rb -t ssh://${SERVER_IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter json:heimdall_after.json
        ;;
    5)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid option.${NC}"
        exit 1
        ;;
esac

chmod 755 *.json
echo -e "\n${GREEN}✅ Task Complete!${NC}"
