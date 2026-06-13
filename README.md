<div align="center">

# 🛡️ Fleet Commander
**Enterprise Multi-OS DevSecOps Compliance Orchestrator**

[![Bash](https://img.shields.io/badge/Scripting-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)](#)
[![Microsoft Azure](https://img.shields.io/badge/Cloud-Azure-0089D6?style=flat-square&logo=microsoft-azure&logoColor=white)](#)
[![Huawei Cloud](https://img.shields.io/badge/Cloud-Huawei_Cloud-FF0000?style=flat-square&logo=huawei&logoColor=white)](#)
[![Ansible](https://img.shields.io/badge/Automation-Ansible-EE0000?style=flat-square&logo=ansible&logoColor=white)](#)
[![OpenSCAP](https://img.shields.io/badge/Auditing-OpenSCAP-323330?style=flat-square)](#)
[![InSpec](https://img.shields.io/badge/Auditing-Cinc_Auditor-00A698?style=flat-square)](#)
[![GitHub Actions](https://img.shields.io/badge/CI-GitHub_Actions-2088FF?style=flat-square&logo=github-actions&logoColor=white)](#)

> A zero-trust CI/CD pipeline that automatically discovers, audits, remediates, verifies, and reports on virtual machine fleets (Ubuntu, RHEL, Rocky, AlmaLinux, Windows Server) running in Microsoft Azure and Huawei Cloud.

</div>

---

## 📖 Overview

**Fleet Commander** closes the gap between infrastructure management and continuous compliance. It is built for dynamic cloud environments and uses a **"Ghost User" auto-healing architecture** to reach hosts even when SSH is locked down or Windows Remote Management is broken. In a single run it discovers the fleet, injects Just-In-Time (JIT) credentials only when access recovery is needed, scans against Center for Internet Security (CIS) or custom organisational baselines, applies remediation, runs a verification scan to prove the result, builds a Heimdall report, and then removes every temporary change so the environment returns to a clean state.

The same pipeline runs on **Azure** and **Huawei Cloud** through a small provider abstraction layer, so the cloud is selected at run time without changing the logic.

## ✨ Core Features

* 🧠 **Dynamic Discovery:** Queries the cloud by Environment Tag to build a real-time inventory of running nodes, with no manual target lists.
* ☁️ **Multi-Cloud:** Runs on Microsoft Azure or Huawei Cloud through a provider abstraction layer, selected with a single flag.
* 💉 **JIT Auto-Healing:** Temporarily injects a privileged "Ghost User" through the cloud command channel to bypass broken cloud-init locks and fix SELinux or crypto policy on the fly.
* 📊 **Multi-OS Scanning:** Routes Linux targets to **OpenSCAP** and Windows targets to **Cinc Auditor** automatically.
* 🪟 **Full Windows CIS Profile:** Ships the CIS Windows Server 2022 v5.0.0 benchmark as a single InSpec profile (Level 1 and Level 2), with role-aware controls for member servers and domain controllers.
* 🛠️ **Dual Remediation:** Applies the ansible-lockdown CIS roles as the primary path, with a self-contained PowerShell script as a Windows fallback when the remote connection cannot be made.
* ✅ **Verification Re-Scan:** Re-scans after remediation so the before and after scores can be compared, not just asserted.
* 📈 **Heimdall Reporting:** Converts OpenSCAP and Cinc Auditor results into the MITRE SAF format so Linux and Windows results read side by side on one dashboard.
* 🧷 **Built-In Safety:** Opens firewall rules only from the runner address, checks host health before any reboot, bounds every remote call with a timeout so a single bad host cannot stall the run, and keeps the hardening while removing all temporary access.
* 🧹 **Zero-Trust Cleanup:** Removes temporary firewall rules, uninstalls scanner dependencies, and deletes the injected user after the audit.

---

## 🗺️ Pipeline Architecture

```mermaid
graph TD
    A[Trigger Pipeline<br/>Schedule or Manual] --> P{Cloud Provider}
    P -->|Azure| B(Resource Discovery)
    P -->|Huawei Cloud| B
    B -->|Query by Environment Tag| C{Target OS}

    C -->|Linux Fleets| D[SSH Access Check]
    C -->|Windows| E[WinRM Access Check]

    D -- Locked --> F[Inject Ghost User<br/>Fix SELinux / Crypto Policy]
    D -- Open --> G[Bootstrap OpenSCAP]
    F --> G

    E -- Broken --> H[Agent Channel<br/>Repair WinRM Provider]
    E -- Open --> I[Bootstrap Cinc Auditor]
    H --> I

    G --> J[Run XCCDF Baselines<br/>tm / cis / both]
    I --> K[Run Ruby Baselines<br/>CIS WS2022 L1 / L2]

    J --> L{Remediation Mode?}
    K --> L

    L -- Yes --> M[Ansible Playbooks<br/>PowerShell Fallback]
    M --> V[Verification Re-Scan]
    L -- No --> N[Generate Heimdall Report]
    V --> N

    N --> O((Phase 5<br/>Zero-Trust Cleanup))

    style O fill:#ff4d4d,stroke:#333,stroke-width:2px,color:#fff
    style F fill:#ffd24d,stroke:#333,color:#000
    style H fill:#ffd24d,stroke:#333,color:#000
    style M fill:#4da96b,stroke:#333,color:#fff
```

---

## 🧭 Compliance Profiles

Fleet Commander supports three profile selections through the `--profile` flag.

| Profile | Meaning |
| :--- | :--- |
| `tm` | Custom TM organisational baseline only. |
| `cis` | Standard CIS benchmark only. |
| `both` | Custom TM baseline followed by the standard CIS benchmark. |

For Windows, the CIS profile is the full **CIS Windows Server 2022 v5.0.0** benchmark held in one InSpec profile. Two inputs change its behaviour at scan time.

* **`profile_level`** selects Level 1 (the default baseline) or Level 2 (stricter, defence in depth). Set the level with the `CIS_LEVEL` environment variable, for example `Level 1` or `Level 2`.
* **`server_role`** selects `member_server` or `domain_controller`, so role-scoped controls skip on a host they do not apply to.

---

## 🚀 Quick Start Guide

### 1️⃣ Prerequisites

Make sure your runner or local machine has the following toolchain.

* ☁️ **`az`** Azure CLI, authenticated with your service principal (used when the provider is Azure).
* ☁️ **`hcloud`** Huawei Cloud CLI (KooCLI), configured with your access keys (used when the provider is Huawei Cloud).
* ⚙️ **`ansible`** for routing remediation playbooks.
* 🔍 **`cinc-auditor`** or Chef InSpec for Windows compliance scanning.
* 📈 **`saf`** the MITRE SAF CLI for converting results into the Heimdall format.
* 🐍 **`python3`** for unpacking SCAP packages dynamically.

**Bootstrap Ansible dependencies.** Before running the orchestrator, install the third-party roles and collections from the requirements file.

```bash
ansible-galaxy collection install -r requirements.yml
ansible-galaxy role install -r requirements.yml
```

### 2️⃣ Configuration (`.env`)

Fleet Commander is **100% dynamic**. For local testing, copy `.env.example` to `.env` and set your infrastructure variables.

> ⚠️ **SECURITY WARNING:** Never commit your `.env` file to version control. In GitHub Actions, provide these through **Repository Secrets and Variables** instead.

```env
# --- Cloud Provider (azure | huaweicloud) ---
CLOUD_PROVIDER="azure"

# --- Azure Infrastructure ---
AZURE_RG_NAME="YOUR_RESOURCE_GROUP"
AZURE_KV_NAME="YOUR_KEYVAULT_NAME"
AZURE_KV_SECRET="WindowsAdminPasswordSecretName"

# --- Huawei Cloud (used when CLOUD_PROVIDER=huaweicloud) ---
HW_REGION="ap-southeast-1"
HW_PROJECT_ID="YOUR_PROJECT_ID"
HW_ECS_TAG_KEY="Environment"
HW_VPC_ID="YOUR_VPC_ID"
HW_CSMS_SECRET="WindowsAdminPasswordSecretName"

# --- Organization Customization ---
ORG_NAME="TM"
ORG_PREFIX="tm"
GHOST_USER="audit_ghost"
CUSTOM_XCCDF_PROFILE="xccdf_tm_profile_lsb"

# --- Default Fallback Admins ---
LINUX_ADMIN_USER="ubuntu"
WINDOWS_ADMIN_USER="Windows_Admin"
```

### 3️⃣ Directory Structure

The repository keeps organisational rules separate from the standard CIS content.

```text
📦 Fleet-Commander
├── 📂 .github/workflows/                            # CI/CD pipeline (Fleet Commander Pipeline)
├── 📂 rhel-custom/                                  # Custom TM RHEL rules and playbooks
├── 📂 ubuntu-custom/                                # Custom TM Ubuntu rules and playbooks
├── 📂 window-custom/                                # Custom TM Windows rules and playbooks
├── 📂 window-default-cis/                           # Standard CIS Windows content
│   └── 📂 window-baseline/
│       ├── 📜 inspec.yml                            # Profile metadata and inputs
│       ├── 📂 controls/
│       │   └── 📜 cis_ws2022_v5_0_0_benchmark.rb    # CIS WS2022 v5.0.0, 433 controls (L1 and L2)
│       └── 📜 Invoke-CISRemediation-Combined.ps1    # PowerShell remediation fallback
├── 📜 azure_rm.yml                                  # Dynamic Ansible inventory (Azure)
├── 📜 universal_remediate.yml                       # Shared remediation playbook
├── 📜 multi_os_benchmark.sh                         # Core Bash orchestrator
├── 📜 requirements.yml                              # Ansible collections and roles
└── 📜 .env.example                                  # Configuration template
```

---

## 💻 Execution Methods

### 🕹️ Option A: Interactive Mode (Local)

Run the script without arguments to launch the interactive terminal menu. This is ideal for local testing and for running a single phase at a time.

```bash
chmod +x multi_os_benchmark.sh
./multi_os_benchmark.sh
```

### 🤖 Option B: Headless Mode (CI/CD Pipeline)

Pass parameters to automate the pipeline in GitHub Actions, GitLab CI, or Jenkins.

**Base syntax**
```bash
./multi_os_benchmark.sh --headless --cloud <azure|huaweicloud> --profile <tm|cis|both> --mode <scan|remediate|full> --targets <Tag|all>
```

**🎯 Example 1: Full audit on the Prod tag (Azure)**
```bash
./multi_os_benchmark.sh --headless --cloud azure --profile both --mode scan --targets Prod
```

**🎯 Example 2: CIS Level 1 scan and auto-fix with cleanup (Azure)**
```bash
export CIS_LEVEL="Level 1"
./multi_os_benchmark.sh --headless --cloud azure --profile cis --mode full --targets all --cleanup true
```

**🎯 Example 3: Scan a single Windows host on Huawei Cloud**
```bash
./multi_os_benchmark.sh --headless --cloud huaweicloud --profile cis --mode scan --target-os windows --targets Dev
```

---

## ⚙️ Command-Line Options

| Flag | Values | Description |
| :--- | :--- | :--- |
| `--headless` | none | Run without prompts, taking settings from the flags. |
| `--cloud` | `azure`, `huaweicloud` | Select the cloud provider (Azure is the default). |
| `--profile` | `tm`, `cis`, `both` | Select the baseline to apply. |
| `--mode` | `scan`, `remediate`, `full` | Select the action. `full` scans, fixes, then verifies. |
| `--targets` | `<Tag>`, `all` | Select the environment tag or the whole fleet. |
| `--target-os` | `ubuntu`, `rhel`, `rocky`, `alma`, `windows` | Limit the run to one operating system family. |
| `--target-ip` | `<address>` | Limit the run to a single host. |
| `--cleanup` | `true`, `false` | Remove temporary access and scanner tools after the run. |
| `--ticket` | `<id>` | Record a change request identifier with the run. |
| `--debug` | none | Produce verbose logs for troubleshooting. |

---

## 📈 Reporting

Every scan result is converted into the MITRE Security Automation Framework (SAF) format and can be opened in the **Heimdall** viewer. Because both the OpenSCAP and the Cinc Auditor output are converted to the same format, Linux and Windows results share the same severity colours, pass and fail counts, and control descriptions. The before and after result files are kept for each run, so the verification scan can be compared against the first scan. In a pipeline run, the result files and reports are gathered into a single release so the evidence for a run can be found later by its run identifier.

---

## 🌐 Multi-Cloud Support

The provider is chosen with `--cloud`. Each provider specific action sits behind a small wrapper, so the rest of the pipeline does not change between clouds.

* **Azure** uses the `az` CLI for discovery, firewall rules, and the run-command agent channel that powers the Ghost User access recovery.
* **Huawei Cloud** uses the `hcloud` CLI (KooCLI) for the same discovery and firewall operations, with the Windows audit password read from the Cloud Secret Management Service.

> **Note on Huawei Cloud and Windows.** Huawei Cloud does not offer a command channel for Windows equivalent to the Azure run-command agent. The Ghost User PowerShell repair and the post-remediation reboot recovery for Windows are therefore Azure features. On Huawei Cloud the Windows scan depends on the remote management service already being reachable, and the post-remediation reboot should be left disabled for Windows on that provider. The Linux path behaves the same on both clouds, because it uses SSH in either case.

---

## 🔒 Safety and Zero-Trust Cleanup

Because the pipeline can change live servers, safety is built into it rather than added later.

* **Runner-scoped access.** Temporary firewall rules are opened only from the runner address, so the opening cannot be used from anywhere else while the audit runs.
* **Health-gated reboot.** The pipeline confirms a host is alive through the cloud agent before it reboots, so it never reboots a server that is already in trouble.
* **Bounded waits.** Every remote call is wrapped in a timeout, so a single slow or broken host cannot stall the whole run. A host that times out is recorded and skipped rather than retried forever.
* **Mass-change guard.** The CI workflow blocks wide remediation when every profile is selected at once, so a broad selection cannot trigger a broad change.
* **Always-on cleanup.** The cleanup phase runs even after a failure. It deletes the Ghost User, removes the temporary firewall rule, and uninstalls scanner dependencies, while keeping the hardening that was applied.

---

## 🔑 CI/CD Secrets and Variables

When running in GitHub Actions, provide the following through repository settings rather than the `.env` file.

**Secrets**

| Secret | Purpose |
| :--- | :--- |
| `AZURE_CREDENTIALS` | Azure service principal used to authenticate the runner. |
| `AUDIT_PASS` | Windows audit account password (when not read from a vault). |
| `HW_ACCESS_KEY` | Huawei Cloud access key. |
| `HW_SECRET_KEY` | Huawei Cloud secret key. |

**Variables**

| Variable | Purpose |
| :--- | :--- |
| `AZURE_RG_NAME` | Target Azure resource group. |
| `AZURE_KV_NAME` | Azure Key Vault holding the audit password. |
| `AZURE_KV_SECRET` | Name of the secret in the Key Vault. |
| `HW_REGION` | Huawei Cloud region (default `ap-southeast-1`). |
| `HW_PROJECT_ID` | Huawei Cloud project identifier. |
| `HW_CSMS_SECRET` | Name of the secret in the Cloud Secret Management Service. |
| `HW_ECS_TAG_KEY` | Tag key used to discover Huawei ECS instances. |
| `HW_VPC_ID` | Huawei Cloud VPC used for the firewall rules. |
| `ORG_NAME`, `ORG_PREFIX` | Organisation name and prefix for custom content. |

---

<div align="center">

*Engineered for continuous compliance and zero-trust automation across a multi-cloud, multi-OS fleet.*

</div>

---

> 📝 **Nota.** Jika anda menyunting menggunakan UI GitHub atau editor seperti VSCode, cipta fail baharu bernama `README.md`, salin keseluruhan teks ini bermula daripada `<div align="center">` di bahagian atas sehingga ke penghujung fail, dan tampalkannya. Ia akan dipaparkan dengan sempurna sebagai dokumen Markdown, termasuk gambar rajah Mermaid dan jadual.
