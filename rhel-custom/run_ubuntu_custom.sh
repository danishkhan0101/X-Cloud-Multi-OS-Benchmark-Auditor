#!/bin/bash

# ======================================================
# 🛡️ TELEKOM MALAYSIA (TM) UNIFIED SECURITY PIPELINE
# ======================================================
SERVER_IP="52.237.80.6"
SSH_USER="ubuntu"

XCCDF_FILE="tm_xccdf.xml"
OVAL_RULES="tm_ubuntu_rules.xml"
PLAYBOOK="ubuntu_custom_playbook.yml"
INVENTORY="inventory.ini"

echo "======================================================"
echo "🚀 INITIATING TM XCCDF COMPLIANCE AUDIT"
echo "======================================================"

for file in "$XCCDF_FILE" "$OVAL_RULES" "$PLAYBOOK" "$INVENTORY"; do
    if [ ! -f "$file" ]; then
        echo "❌ ERROR: $file not found in the current directory!"
        exit 1
    fi
done

# --- THE FIX: Manually upload the OVAL file to the remote /tmp directory ---
echo "📦 Uploading custom OVAL rules to remote server..."
scp "$OVAL_RULES" ${SSH_USER}@${SERVER_IP}:/tmp/tm_ubuntu_rules.xml

echo "🔍 PHASE 1: Running Custom XCCDF Audit..."
oscap-ssh --sudo ${SSH_USER}@${SERVER_IP} 22 xccdf eval \
    --profile xccdf_com.tm_profile_lsb \
    --report report_before.html \
    "$XCCDF_FILE"

AUDIT_EXIT=$?
chmod 755 *.html
echo "======================================================"

if [ $AUDIT_EXIT -ne 0 ]; then
    echo "⚠️  TM COMPLIANCE GAPS DETECTED!"
    echo "------------------------------------------------------"
    read -p "🤔 Run the TM Custom Ansible remediation? (y/n): " choice
    
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        echo "🛠️  PHASE 2: Executing Ansible Hardening (LSB 13-41)..."
        ansible-playbook -i "$INVENTORY" "$PLAYBOOK"
        
        echo "======================================================"
        echo "✅ PHASE 3: Verifying Final TM Compliance..."
        oscap-ssh --sudo ${SSH_USER}@${SERVER_IP} 22 xccdf eval \
            --profile xccdf_com.tm_profile_lsb \
            --report report_after.html \
            "$XCCDF_FILE"
            
        echo "🎉 Final Reports generated: report_before.html & report_after.html"
    else
        echo "🛑 Remediation cancelled by user."
    fi
else
    echo "✅ SERVER IS 100% COMPLIANT WITH TM LSB!"
fi

echo "======================================================"
chmod 755 *.html
