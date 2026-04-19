# 🛡️ Unified Compliance Pipeline (Multi-OS)

An automated, Zero-Trust DevSecOps pipeline for cross-platform Azure infrastructure. This tool discovers, audits, and remediates both Ubuntu and Windows Virtual Machines against Default CIS Benchmarks and Custom Corporate (TM) Baselines.

## 🚀 Features

* **Zero-Trust Identity Injection:** Bypasses default OS credentials by automatically injecting secure Audit Admin identities via the Azure Hypervisor *before* SSH/WinRM connections are established.
* **Intelligent Auto-Discovery:** Dynamically queries Azure Resource Groups to detect running nodes, map IP addresses, and identify operating systems (Linux vs. Windows) on the fly.
* **Stateful Execution:** Utilizes local cache tracking (`.tm_injected_vms.log`) to remember previously injected nodes, reducing pipeline execution time on subsequent runs.
* **Multi-Protocol Scanning:** * **Ubuntu:** Agentless scanning via `oscap-ssh` with Passwordless Sudo.
  * **Windows:** Remote compliance validation using Chef InSpec.
* **Automated Remediation:** Seamlessly deploys Ansible Playbooks to auto-remediate failing controls.

## 🏗️ Architecture & Phases

The pipeline (`tm_fleet_commander.sh`) operates in a strict, modular phase execution:

1. **Phase 0 (Discovery & Identity):** Azure CLI queries the fabric, injects Key Vault credentials, and builds a dynamic `inventory.ini` file.
2. **Phase 1 (Initial Baseline):** OpenSCAP and InSpec perform non-destructive security scans against CIS Level 1 and Custom Baselines.
3. **Phase 2 & 3 (Remediation):** Ansible playbooks are deployed to harden the operating systems based on the Phase 1 findings.
4. **Phase 4 (Verification):** A final post-remediation scan is executed to prove compliance, generating HTML and JSON artifacts.

## 📋 Prerequisites

To run this pipeline from your Audit-Host, the following tools must be installed:

* `azure-cli` (Authenticated with Contributor/User Access Admin roles)
* `ansible`
* `openscap-utils` (oscap-ssh)
* `inspec` (Chef InSpec)

## ⚙️ Configuration & Setup

This pipeline is fully parameter-driven. You must provide your own Azure infrastructure details. Do not hardcode your values into the bash script.

### For Local Execution (Linux Audit-Host)
1. Copy the template: `cp .env.example .env`
2. Edit `.env` with your specific Azure Resource Group, Key Vault, and Users.
3. Run the script: `./tm_fleet_commander.sh`

### For CI/CD Execution (GitHub Actions)
If you fork this repository to run in your own environment, you must configure both **Variables** and **Secrets** in your GitHub repository.

#### 1. Repository Variables (Non-Sensitive)
Go to **Settings -> Secrets and variables -> Actions -> Variables** and add the following:
* `AZURE_RG_NAME` (e.g., Prod_Servers_RG)
* `AZURE_KV_NAME` (e.g., Corp-Security-Vault)
* `AZURE_KV_SECRET` (e.g., WindowsAdminPass)
* `WINDOWS_ADMIN_USER` (e.g., svc_audit_admin)

#### 2. Repository Secrets (Authentication)
Go to **Settings -> Secrets and variables -> Actions -> Secrets** and add the following:
* `AZURE_CREDENTIALS`: Your Azure Service Principal JSON block (used by the pipeline to authenticate with your Azure Cloud).
* `UBUNTU_SSH_KEY`: Your private SSH key (e.g., the contents of your `~/.ssh/id_rsa` or `id_ed25519` file).
  > **⚠️ Linux Authentication Note:** This pipeline adheres to Zero-Trust principles and does not use plain-text passwords for Linux nodes. The GitHub runner uses this private `UBUNTU_SSH_KEY` for agentless OpenSCAP and Ansible connections. You must ensure the corresponding **public key** is already present in the `~/.ssh/authorized_keys` file on all target Ubuntu VMs before running the pipeline.
