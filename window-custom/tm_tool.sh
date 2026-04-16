#!/bin/bash

# ======================================================
# CONFIGURATION - TM ANALYTICS SECURE PIPELINE
# ======================================================
SERVER_IP="20.212.133.93"
INIT_USER="window"
INIT_PASS="window#12345"

# The "Bridge" account created during remediation
AUDIT_USER="TM_Admin"

# 🔐 AZURE KEY VAULT CONFIGURATION
KV_NAME="TM-Vault-Danish"
SECRET_NAME="AuditPassword"

# Global Settings
export CHEF_LICENSE="accept-silent"
export CHEF_LICENSE_KEY="free-e13ce9a4-c7a5-4132-8ee4-8ffe54c0011d-7485"
export INSPEC_SSH_CONFIG_NO_SECURE=true

# Formatting Helpers
BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

clear
echo -e "${CYAN}${BOLD}======================================================"
echo -e "🛡️  TM SMART DEVSECOPS PIPELINE - INTERACTIVE MODE"
echo -e "======================================================${NC}"
echo -e "Target: ${BOLD}$SERVER_IP${NC}"
echo -e "1) ${BOLD}SCAN ONLY${NC}      (Phase 1: Initial Baseline)"
echo -e "2) ${BOLD}REMEDIATE ONLY${NC} (Phase 2 & 3: Ansible Fixes)"
echo -e "3) ${BOLD}RE-SCAN ONLY${NC}   (Phase 4: Key Vault Handover)"
echo -e "4) ${BOLD}FULL PIPELINE${NC}  (Run all phases sequentially)"
echo -e "5) ${BOLD}EXIT${NC}"
echo -e "${CYAN}------------------------------------------------------${NC}"
read -p "Choose an execution mode [1-5]: " choice

case $choice in
    1)
        echo -e "\n${BOLD}🔍 PHASE 1:${NC} Running Initial Security Audit (InSpec)..."
        inspec exec tm_baseline.rb -t ssh://${SERVER_IP} --user="${INIT_USER}" --password="${INIT_PASS}" --reporter json:heimdall_before.json
        ;;
    2)
        echo -e "\n${BOLD}🛠️  PHASE 2 & 3:${NC} Executing Ansible Hardening..."
        ansible-playbook -i inventory.ini tm_remediate.yml -u "${INIT_USER}" -e "ansible_password=${INIT_PASS}"
        ;;
    3)
        echo -e "\n${CYAN}🔄 HANDOVER:${NC} Fetching Secondary Credentials from Azure Key Vault..."
        az login --identity --allow-no-subscriptions > /dev/null 2>&1
        AUDIT_PASS=$(az keyvault secret show --name "$SECRET_NAME" --vault-name "$KV_NAME" --query value -o tsv | tr -d '\r\n')

        if [ -z "$AUDIT_PASS" ]; then
            echo -e "${RED}❌ ERROR: Could not retrieve secret. Check IAM permissions.${NC}"
            exit 1
        fi
        echo -e "${GREEN}✅ Identity Verified. Vault Unlocked.${NC}"
        
        echo -e "\n${BOLD}✅ PHASE 4:${NC} Running Verification Audit as $AUDIT_USER..."
        inspec exec tm_baseline.rb -t ssh://${SERVER_IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter json:heimdall_after.json
        ;;
    4)
        # --- FULL PIPELINE LOGIC ---
        echo -e "\n${BOLD}🔍 PHASE 1:${NC} Running Initial Baseline..."
        inspec exec tm_baseline.rb -t ssh://${SERVER_IP} --user="${INIT_USER}" --password="${INIT_PASS}" --reporter json:heimdall_before.json
        
        echo -e "\n${BOLD}🛠️  PHASE 2 & 3:${NC} Executing Ansible Hardening..."
        ansible-playbook -i inventory.ini tm_remediate.yml -u "${INIT_USER}" -e "ansible_password=${INIT_PASS}"
        
        echo -e "\n${CYAN}🔄 HANDOVER:${NC} Fetching Secondary Credentials from Azure Key Vault..."
        az login --identity --allow-no-subscriptions > /dev/null 2>&1
        AUDIT_PASS=$(az keyvault secret show --name "$SECRET_NAME" --vault-name "$KV_NAME" --query value -o tsv)
        
        if [ -z "$AUDIT_PASS" ]; then
            echo -e "${RED}❌ ERROR: Could not retrieve secret. Pipeline halting.${NC}"
            exit 1
        fi
        echo -e "${GREEN}✅ Identity Verified. Vault Unlocked.${NC}"

        echo -e "\n${BOLD}✅ PHASE 4:${NC} Running Verification Audit..."
        inspec exec tm_baseline.rb -t ssh://${SERVER_IP} --user="${AUDIT_USER}" --password="${AUDIT_PASS}" --reporter json:heimdall_after.json
        ;;
    5)
        echo -e "\n${GREEN}Exiting pipeline safely.${NC}"
        exit 0
        ;;
    *)
        echo -e "\n${RED}Invalid option selected. Exiting.${NC}"
        exit 1
        ;;
esac

chmod 755 *.json 2>/dev/null
echo -e "\n${CYAN}======================================================"
echo -e "🎉 TASK COMPLETE! Analysis files ready for Heimdall."
echo -e "======================================================${NC}"
