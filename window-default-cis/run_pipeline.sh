#!/bin/bash

# ==========================================
# 🛡️ GLOBAL CIS DEVSECOPS CONFIGURATION
# ==========================================
SERVER_IP="20.212.133.93"
SSH_USER="window"
SSH_PASS="window#12345"

# --- Chef License Injection (The "Fast" Fix) ---
export CHEF_LICENSE_KEY="free-e13ce9a4-c7a5-4132-8ee4-8ffe54c0011d-7485"
export CHEF_LICENSE="accept-silent"
# ------------------------------------------

echo "======================================================"
echo "🚀 INITIATING GLOBAL CIS SMART PIPELINE"
echo "======================================================"

# Step 1: Initial Audit against Global CIS Benchmarks
echo "🔍 PHASE 1: Auditing Server against CIS Benchmarks..."
# We use the official industry-standard baseline for Windows
inspec exec ./window-baseline \
    -t ssh://${SERVER_IP} \
    --user="${SSH_USER}" \
    --password="${SSH_PASS}" \
    --reporter json:heimdall_before.json

# Capture InSpec Exit Code (0=Secure, 100=Vulnerabilities)
SCAN_RESULT=$?

echo "======================================================"
if [ $SCAN_RESULT -eq 0 ]; then
    echo "✅ SERVER IS ALREADY 100% CIS COMPLIANT!"
    echo "⏭️  Skipping Remediation to save resources."
    cp heimdall_before.json heimdall_after.json
else
    echo "⚠️ CIS NON-COMPLIANCE DETECTED! Proceeding to Fix..."
    echo "======================================================"

    # Phase 2: Simulation (Dry Run)
    echo "⚠️ PHASE 2: Simulating CIS Remediation (Dry Run)..."
    ansible-playbook -i inventory.ini cis_remediate.yml --check --diff

    # Phase 3: Human Safety Catch
    echo "======================================================"
    read -p "🛑 Review the CIS changes above. Proceed with LIVE remediation? (y/n): " confirm
    if [[ $confirm != [yY] ]]; then
        echo "❌ Remediation aborted. Exiting safely."
        exit 1
    fi

    # Phase 4: Live Remediation
    echo "🛠️ PHASE 3: Executing Official CIS Hardening..."
    ansible-playbook -i inventory.ini cis_remediate.yml

    # Phase 5: Verification Audit
    echo "✅ PHASE 4: Verifying Final CIS Compliance..."
    inspec exec ./window-baseline \
        -t ssh://${SERVER_IP} \
        --user="${SSH_USER}" \
        --password="${SSH_PASS}" \
        --reporter json:heimdall_after.json
fi

echo "======================================================"
echo "🎉 CIS PIPELINE COMPLETE! View results in Heimdall."
echo "======================================================"
