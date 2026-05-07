🛡️ Fleet Commander: Multi-OS DevSecOps Compliance Auditor
Fleet Commander is an enterprise-grade, zero-trust DevSecOps orchestrator designed to automatically discover, audit, and remediate multi-OS fleets (Ubuntu, RHEL, Windows) hosted in Microsoft Azure.

Built for seamless CI/CD integration, it utilizes a unique "Ghost User" auto-healing architecture to bypass locked-down SSH/WinRM configurations, dynamically injects credentials, runs Center for Internet Security (CIS) or custom organizational baselines, and completely covers its tracks post-execution.

✨ Core Capabilities
🧠 Dynamic Azure Discovery: Automatically queries Azure Resource Groups by Environment Tags to build real-time inventory lists of running VMs.

💉 "Ghost User" Auto-Healing: Bypasses broken cloud-init or locked default users by temporarily injecting a JIT (Just-In-Time) privileged user (audit_ghost), fixing SELinux/Crypto policies on the fly.

📊 Multi-OS Scanning: Natively routes Ubuntu/RHEL targets to OpenSCAP and Windows targets to Cinc Auditor (InSpec).

🛠️ Automated Remediation: Deploys Ansible playbooks and OpenSCAP remediation routines to fix failing compliance controls.

🧹 Post-Audit Scrubbing: Safely removes temporary NSG firewall rules, uninstalls scanner dependencies, and deletes the injected Ghost Users to return the environment to a secure state.

🤖 Headless CI/CD Mode: Fully parameterized execution for GitHub Actions, GitLab CI, or Jenkins.

🏗️ Project Structure
To use this orchestrator, populate the corresponding directories with your organization's custom SCAP (XCCDF/OVAL) XML files, InSpec Ruby benchmarks, and Ansible Playbooks:

Plaintext
├── multi_os_benchmark.sh        # The Core Orchestrator
├── .env.example                 # Template for local environment variables
├── ubuntu-custom/               # Custom Ubuntu Rules
│   ├── custom_xccdf.xml
│   ├── custom_ubuntu_rules.xml
│   └── ubuntu_custom_playbook.yml
├── rhel-custom/                 # Custom RHEL Rules
│   ├── custom_rhel_xccdf.xml
│   ├── custom_rhel_rules.xml
│   └── rhel_custom_playbook.yml
├── window-custom/               # Custom Windows Rules
│   ├── custom_baseline.rb
│   └── custom_remediate.yml
└── window-default-cis/          # Standard Windows CIS Rules
    ├── window-baseline/
    └── cis_remediate.yml
(Note: Standard Linux CIS profiles are downloaded and mapped dynamically from scap-security-guide during execution).

⚙️ Configuration & Secrets
Fleet Commander is 100% dynamic and relies on Environment Variables.

For Local Execution (Terminal)
Create a .env file in the root directory (ensure .env is in your .gitignore!):

Code snippet
# --- Azure Infrastructure ---
AZURE_RG_NAME="YOUR_RESOURCE_GROUP"
AZURE_KV_NAME="YOUR_KEYVAULT_NAME"
AZURE_KV_SECRET="WindowsAdminPasswordSecretName"

# --- Organization Customization ---
ORG_NAME="MyCorp"
ORG_PREFIX="custom"
GHOST_USER="audit_ghost"
CUSTOM_XCCDF_PROFILE="xccdf_com.mycorp_profile_lsb"

# --- Default Fallback Admins ---
LINUX_ADMIN_USER="ubuntu"
WINDOWS_ADMIN_USER="Windows_Admin"
For CI/CD Execution (GitHub Actions)
Map the above variables into your GitHub Repository settings under Settings > Secrets and variables > Actions.

🚀 Usage
Option A: Interactive Mode (Local)
Run the script without arguments to launch the interactive terminal menu. Ideal for local testing and manual execution.

Bash
chmod +x multi_os_benchmark.sh
./multi_os_benchmark.sh
Option B: Headless Mode (CI/CD Pipeline)
Pass arguments to fully automate the pipeline.

Syntax:

Bash
./multi_os_benchmark.sh --headless --profile <custom|cis|both> --mode <scan|remediate|full> --targets <Tag|all>
Examples:

Full Audit on 'Prod' Tag:

Bash
./multi_os_benchmark.sh --headless --profile both --mode scan --targets Prod
CIS Level 1 Scan & Fix on All VMs (with cleanup):

Bash
export CIS_LEVEL="Level 1"
./multi_os_benchmark.sh --headless --profile cis --mode full --targets all --cleanup true
🛠️ Prerequisites (Runner / Local Machine)
Ensure the machine running this orchestrator has the following tools installed:

az (Azure CLI) - Authenticated with az login

ansible - For remediation routing

cinc-auditor (or Chef InSpec) - For Windows scanning

python3 - For extracting legacy SCAP packages

ssh-agent - With your private key loaded (~/.ssh/id_rsa)

Note: The target Azure VMs do not need anything pre-installed. The orchestrator automatically bootstraps them with OpenSCAP and required dependencies during Phase 0.
