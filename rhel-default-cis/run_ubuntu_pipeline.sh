#!/bin/bash

# ==========================================
# 🛡️ INTERACTIVE UBUNTU 24.04 CIS PIPELINE
# ==========================================
SERVER_IP="52.237.80.6"
SSH_USER="ubuntu"
SCAP_FILE="/usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml"
PROFILE="xccdf_org.ssgproject.content_profile_cis_level1_server"

echo "======================================================"
echo "🚀 INITIATING UBUNTU SMART CIS PIPELINE"
echo "======================================================"

# Step 1: Initial Audit
echo "🔍 PHASE 1: Running NIST-Certified Audit (OpenSCAP)..."
oscap-ssh ${SSH_USER}@${SERVER_IP} 22 xccdf eval \
    --profile $PROFILE \
    --results results_before.xml \
    --report report_before.html \
    $SCAP_FILE

AUDIT_EXIT=$?

echo "======================================================"
echo "📊 AUDIT COMPLETE: report_before.html generated."
chmod 755 *.html

if [ $AUDIT_EXIT -eq 0 ]; then
    echo "✅ SERVER IS 100% CIS COMPLIANT!"
    cp report_before.html report_after.html
else
    echo "⚠️ VULNERABILITIES DETECTED!"
    echo "------------------------------------------------------"
    
    # --- THE INTERACTIVE PROMPT ---
    read -p "🤔 Do you want to start the Ansible remediation? (y/n): " choice
    
    case "$choice" in 
      y|Y ) 
        echo "🛠️  Proceeding to Automated Remediation..."
        echo "======================================================"
        
        # Phase 2: Ansible Remediation
        ansible-playbook -i inventory.ini ubuntu_cis.yml
        
        # Phase 3: Final Verification
        echo "======================================================"
        echo "✅ PHASE 3: Verifying Final CIS Compliance..."
        oscap-ssh ${SSH_USER}@${SERVER_IP} 22 xccdf eval \
            --profile $PROFILE \
            --results results_after.xml \
            --report report_after.html \
            $SCAP_FILE
        ;;
      * ) 
        echo "🛑 Remediation skipped by user."
        echo "Exiting pipeline..."
        exit 0
        ;;
    esac
fi
chmod 755 *.html
echo "======================================================"
echo "🎉 PIPELINE FINISHED"
echo "======================================================"
