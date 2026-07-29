# 🛡️ Cloud Compliance Auditor

**Enterprise Multi-OS DevSecOps Compliance Orchestrator**

> A zero-trust CI/CD pipeline that automatically discovers, audits, remediates, verifies, and reports on virtual machine fleets (Ubuntu, RHEL, Rocky, AlmaLinux, Windows Server) running in Microsoft Azure and Huawei Cloud.

---

## 📖 Overview

**Cloud Compliance Auditor** closes the gap between infrastructure management and continuous compliance. It is built for dynamic cloud environments and uses a **"Ghost User" auto-healing architecture** to reach hosts even when SSH is locked down or Windows Remote Management is broken. In a single run it discovers the fleet, injects Just-In-Time (JIT) credentials only when access recovery is needed, scans against Center for Internet Security (CIS) or custom organisational baselines, applies remediation, runs a verification scan to prove the result, builds a Heimdall report, and then removes every temporary change so the environment returns to a clean state.

The same pipeline runs on **Azure** and **Huawei Cloud** through a small provider abstraction layer, so the cloud is selected at run time without changing the logic.

## ✨ Core Features

* 🧠 **Dynamic Discovery:** Queries the cloud by Environment Tag to build a real-time inventory of running nodes, with no manual target lists.
* ☁️ **Cross-Cloud:** Runs on Microsoft Azure or Huawei Cloud through a provider abstraction layer, selected with a single flag.
* 💉 **JIT Auto-Healing:** Temporarily injects a privileged "Ghost User" through the cloud command channel to bypass broken cloud-init locks and fix SELinux or crypto policy on the fly.
* 📊 **Multi-OS Scanning:** Routes Linux targets to **OpenSCAP** and Windows targets to **Cinc Auditor** automatically.
* 🪟 **Full Windows CIS Profile:** Ships the CIS Windows Server 2022 v5.0.0 benchmark as a single InSpec profile (Level 1 and Level 2), with role-aware controls for member servers and domain controllers.
* 🛠️ **Dual Remediation:** Applies the ansible-lockdown CIS roles as the primary path, with a self-contained PowerShell script as a Windows fallback when the remote connection cannot be made.
* ✅ **Verification Re-Scan:** Re-scans after remediation so the before and after scores can be compared, not just asserted.
* 📈 **Heimdall Reporting:** Converts OpenSCAP and Cinc Auditor results into the MITRE SAF format so Linux and Windows results read side by side on one dashboard.
* 🧷 **Built-In Safety:** Opens firewall/NSG rules only from the runner address, checks host health before any reboot, bounds every remote call with a timeout so a single bad host cannot stall the run, and keeps the hardening while removing all temporary access.
* 🧹 **Zero-Trust Cleanup:** Removes temporary firewall rules, uninstalls scanner dependencies, and deletes the injected user after the audit.

---

## 🗺️ Pipeline Architecture

```mermaid
graph TD
    A[Trigger Pipeline] --> B[Discover VMs by Tag<br/>Azure or Huawei Cloud]

    B -->|Linux Fleet| D[Check Ghost User SSH<br/>GHOST_USER@host]
    B -->|Windows Fleet| E[Check svc_audit SSH<br/>WIN_GHOST_USER@host]

    D -- Not Reachable --> F[Open SSH Rule<br/>Inject Ghost User]
    D -- Reachable --> G[Ready for OpenSCAP]
    F --> G

    E -- Not Reachable --> H[Fall Back to<br/>Administrator via SSH]
    E -- Reachable --> I[Ready for Cinc Auditor]
    H -- Still Unreachable --> H2[Azure Run-Command<br/>Repairs SSH]
    H2 --> I

    G --> J[Build Ansible Inventory]
    I --> J

    J --> K[Select Profile<br/>tm / cis / all]

    K --> L{Profile = all?}
    L -- Yes --> M1[Step 1/3: CIS Level 1<br/>scan/remediate/verify]
    M1 --> M2[Step 2/3: CIS Level 2<br/>stricter profile]
    M2 --> M3[Step 3/3: Org Baseline<br/>TM custom XCCDF/Ruby]
    L -- No --> M4[Run Once<br/>tm or cis only]

    M3 --> N[Execute Phase&#40;s&#41;<br/>scan / remediate+verify / full]
    M4 --> N

    N --> O[Generate Reports<br/>HTML Linux, Heimdall JSON Windows]
    O --> P((Zero-Trust Cleanup<br/>if --cleanup true))

    style B fill:#5b4fc4,stroke:#333,color:#fff
    style D fill:#1a5f8f,stroke:#333,color:#fff
    style E fill:#1a5f8f,stroke:#333,color:#fff
    style F fill:#b8860b,stroke:#333,color:#fff
    style H fill:#b8860b,stroke:#333,color:#fff
    style H2 fill:#8b2020,stroke:#333,color:#fff
    style G fill:#0f6b5c,stroke:#333,color:#fff
    style I fill:#0f6b5c,stroke:#333,color:#fff
    style K fill:#5b4fc4,stroke:#333,color:#fff
    style M1 fill:#7a3010,stroke:#333,color:#fff
    style M2 fill:#7a3010,stroke:#333,color:#fff
    style M3 fill:#7a3010,stroke:#333,color:#fff
    style M4 fill:#7a3010,stroke:#333,color:#fff
    style N fill:#3d7a1f,stroke:#333,color:#fff
    style O fill:#0f6b5c,stroke:#333,color:#fff
    style P fill:#8b2020,stroke:#333,color:#fff
```

---

## 🧭 Compliance Profiles

Cloud Compliance Auditor supports three profile selections through the `--profile` flag.

| Profile | Meaning |
| --- | --- |
| `tm` | Custom TM organisational baseline only. |
| `cis` | Standard CIS benchmark only. |
| `all` | Custom TM baseline **and** the standard CIS benchmark, run together. |

> ⚠️ **Safety gate:** the CI workflow automatically forces `mode: scan` whenever `profile: all` is selected, regardless of what mode was requested. Mass remediation is never allowed to run against every profile at once — this is enforced in the pipeline, not just documented here.

For Windows, the CIS profile is the full **CIS Windows Server 2022 v5.0.0** benchmark held in one InSpec profile. Two inputs change its behaviour at scan time.

* **`profile_level`** selects Level 1 (the default baseline) or Level 2 (stricter, defence in depth). Set the level with the `CIS_LEVEL` environment variable, for example `Level 1` or `Level 2`.

---

## 🚀 Quick Start Guide

### 1️⃣ Prerequisites

Make sure your runner or local machine has the following toolchain.

* ☁️ **`az`** Azure CLI, authenticated with your service principal (used when the provider is Azure).
* ☁️ **Huawei Cloud Python SDK** (`huaweicloudsdkcore`, `huaweicloudsdkecs`, `huaweicloudsdkvpc`), authenticated with an IAM AK/SK pair (used when the provider is Huawei Cloud). AK/SK signs each request locally against a private ECS endpoint — the `hcloud` CLI (KooCLI) is **not** used, since it resolves endpoints from its own public-region catalogue and cannot reach a private endpoint.
* ⚙️ **`ansible`** for routing remediation playbooks.
* 🔍 **`cinc-auditor`** or Chef InSpec for Windows compliance scanning.
* 📈 **`saf`** the MITRE SAF CLI for converting results into the Heimdall format.
* 🐍 **`python3`** for unpacking SCAP packages dynamically and for the Huawei Cloud SDK calls.

### 2️⃣ Configuration (`.env`)

Cloud Compliance Auditor is **100% dynamic**. For local testing, copy `.env.example` to `.env` and set your infrastructure variables.

> ⚠️ **SECURITY WARNING:** Never commit your `.env` file to version control. In GitHub Actions, provide these through **Repository Secrets and Variables** instead.

```env
# --- Cloud Provider (azure | huaweicloud) ---
CLOUD_PROVIDER="azure"

# --- Azure Infrastructure ---
AZURE_RG_NAME="YOUR_RESOURCE_GROUP"

# --- Huawei Cloud (used when CLOUD_PROVIDER=huaweicloud) ---
HW_REGION="my-kualalumpur-1"
HW_PROJECT_ID="YOUR_PROJECT_ID"
HW_ECS_ENDPOINT="https://ecs.my-kualalumpur-1.alphaedge.tmone.com.my"
HW_ECS_TAG_KEY="Environment"
HW_VPC_ID="YOUR_VPC_ID"
HW_EPS_ID=""

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

The repository maintains strict separation of logic, baselines, and cloud-specific handlers:

```text
📦 Cloud-Compliance-Auditor
├── 📂 .github/workflows/                                # CI/CD pipelines
│   ├── 📜 cloud-compliance-auditor.yml                  # Main orchestrator workflow
│   ├── 📜 verify.yml                                    # Verification tasks
│   └── 📜 verifyClean.yml                               # Verification cleanup workflow
├── 📂 modules/                                          # Sourced by the orchestrator at runtime
│   ├── 📜 audit_runner.sh                               # Per-host audit execution
│   ├── 📜 discovery_azure.sh                            # Azure VM discovery, NSG rules, run-command helpers
│   ├── 📜 discovery_cae.sh                              # Huawei Cloud (CAE) discovery, SG rules, power state
│   └── 📜 utils.sh                                      # Shared logging, SSH helpers
├── 📂 rhel-custom/                                      # Custom TM RHEL rules and playbooks
│   ├── 📜 rhel_custom_playbook.yml                      # RHEL remediation playbook
│   ├── 📜 tm_rhel_rules.xml                             # Custom TM RHEL rules
│   └── 📜 tm_rhel_xccdf.xml                             # Custom TM RHEL XCCDF baseline
├── 📂 scripts/                                          # Python helpers invoked by modules
│   ├── 📜 hw_ecs_discover.py                            # Huawei ECS discovery via SDK
│   ├── 📜 hw_sg_rule_manage.py                          # Huawei SG rule management
│   └── 📜 hw_verify_auth.py                             # Huawei SDK auth check
├── 📂 ubuntu-custom/                                    # Custom TM Ubuntu rules and playbooks
│   ├── 📜 tm_ubuntu_rules.xml                           # Custom TM Ubuntu rules
│   ├── 📜 tm_xccdf.xml                                  # Custom TM Ubuntu XCCDF baseline
│   └── 📜 ubuntu_custom_playbook.yml                    # Ubuntu remediation playbook
├── 📂 windows-custom/                                   # Custom TM Windows rules and playbooks
│   ├── 📜 tm_baseline.rb                                # Windows custom baseline
│   └── 📜 tm_remediate.yml                              # Windows custom remediation
├── 📂 windows-default-cis/                              # Standard CIS Windows content
│   └── 📂 windows-baseline/                             # Windows baseline configuration
│       ├── 📂 controls/                                 # Control profiles
│       │   └── 📜 cis_ws2022_v5_0_0_benchmark.rb        # CIS WS2022 v5.0.0 benchmark
│       ├── 📜 Invoke-CISRemediation-Combined.ps1        # PowerShell remediation fallback
│       └── 📜 inspec.yml                                # Profile metadata and inputs
├── 📜 .env.example                                      # Configuration template
├── 📜 .gitignore                                        # Git ignore definitions
├── 📜 .gitleaks.toml                                    # Secret scanning configuration
├── 📜 README.md                                         # Project documentation
├── 📜 multi_os_benchmark.sh                             # Core Bash orchestrator
└── 📜 verify_cleanup.sh                                 # Zero-trust cleanup script
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
./multi_os_benchmark.sh --headless --cloud <azure|huaweicloud> --profile <tm|cis|all> --mode <scan|remediate|full> --targets <Tag|all>
```

**🎯 Example 1: Full audit on the Prod tag (Azure)**

```bash
./multi_os_benchmark.sh --headless --cloud azure --profile all --mode scan --targets Prod
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
| --- | --- | --- |
| `--headless` | none | Run without prompts, taking settings from the flags. |
| `--cloud` | `azure`, `huaweicloud` | Select the cloud provider (Azure is the default). |
| `--profile` | `tm`, `cis`, `all` | Select the baseline to apply. |
| `--mode` | `scan`, `remediate`, `full` | Select the action. `full` scans, fixes, then verifies. |
| `--targets` | `<Tag>`, `all` | Select the environment tag or the whole fleet. |
| `--target-os` | `ubuntu`, `rhel`, `rocky`, `alma`, `windows` | Limit the run to one operating system family. |
| `--target-ip` | `<address>` | Limit the run to a single host. |
| `--cleanup` | `true`, `false` | Remove temporary access and scanner tools after the run. |
| `--ticket` | `<id>` | Record a change request identifier with the run. |
| `--debug` | none | Produce verbose logs for troubleshooting. |

---

## 📈 Reporting

Linux and Windows results are kept in their own native formats rather than forced into one shared format:

| OS family | Scanner | Report format | How it's produced |
| --- | --- | --- | --- |
| Ubuntu, RHEL, Rocky, Alma | OpenSCAP | `.html` | OpenSCAP's built-in HTML report generator (`oscap xccdf generate report`) — no conversion step |
| Windows | Cinc Auditor | `.json` | Converted into the MITRE Heimdall/SAF format via `saf convert`, viewable in the **Heimdall** viewer |

Because Linux keeps OpenSCAP's own HTML report, it can be opened directly in a browser with no extra tooling. Because Windows results go through Heimdall, they get the same severity colours, pass/fail counts, and control-level detail that Heimdall provides for InSpec output. The before and after result files are kept for each run, so the verification scan can be compared against the first scan. In a pipeline run, the `.html` (Linux) and `.json` (Windows) artifacts are gathered into a single release, organised by host IP, so the evidence for a run can be found later by its run identifier regardless of which OS produced it.

---

## 🌐 Cross-Cloud Support

The provider is chosen with `--cloud`. Each provider-specific action sits behind a small wrapper (`modules/discovery_azure.sh`, `modules/discovery_cae.sh`), so the rest of the pipeline does not change between clouds.

* **Azure** uses the `az` CLI for discovery and NSG rules. SSH is now the primary access path for Windows as well as Linux, so both OS families are reached the same way on Azure.
* **Huawei Cloud** uses the official Python SDK (`huaweicloudsdkcore` + `huaweicloudsdkecs`) for discovery and security-group operations, signing requests locally with an AK/SK pair against a private ECS endpoint.

> **Windows access model.** Both clouds now use SSH as the primary path for Windows, matching the Linux flow. The difference is what happens when SSH is unreachable:
> * **Azure** falls back to `az vm run-command invoke` (`azure_vm_bootstrap_ssh`) — an out-of-band control-plane call that installs/starts OpenSSH Server and trusts the runner's key, without needing any existing remote-access session. This repair path only runs after `wait_for_ssh` has already failed; it is not used for routine scan/remediate calls.
> * **Huawei Cloud** has no equivalent out-of-band channel for Windows, so if SSH is unreachable there is no automated recovery — the runner's public key must already be trusted (baked into the image at creation time, same as Linux), and a broken SSH config requires manual intervention.
>
> This means Azure keeps a self-healing advantage over Huawei Cloud for Windows, even though day-to-day operation is identical (SSH) on both.

---

## 🔒 Safety and Zero-Trust Cleanup

Because the pipeline can change live servers, safety is built into it rather than added later.

* **Runner-scoped access.** Temporary firewall/NSG rules are opened only from the runner address, so the opening cannot be used from anywhere else while the audit runs.
* **Health-gated reboot.** The pipeline confirms a host is alive through the cloud agent before it reboots, so it never reboots a server that is already in trouble.
* **Bounded waits.** Every remote call is wrapped in a timeout, so a single slow or broken host cannot stall the whole run. A host that times out is recorded and skipped rather than retried forever.
* **Mass-change guard.** The CI workflow blocks wide remediation when every profile is selected at once, so a broad selection cannot trigger a broad change.
* **Always-on cleanup.** The cleanup phase runs even after a failure. It deletes the Ghost User, removes the temporary firewall rule, and uninstalls scanner dependencies, while keeping the hardening that was applied.

---

## 🔑 CI/CD Secrets and Variables

When running in GitHub Actions, provide the following through repository settings rather than the `.env` file.

**Secrets**

| Secret | Purpose |
| --- | --- |
| `AZURE_CLIENT_ID` | Azure service principal client ID. |
| `AZURE_CLIENT_SECRET` | Azure service principal client secret. |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID. |
| `AZURE_TENANT_ID` | Azure tenant ID. |
| `HW_ACCESS_KEY` | Huawei Cloud IAM access key. |
| `HW_SECRET_KEY` | Huawei Cloud IAM secret key. |
| `SSH_KEY` | Private SSH key used for Linux hosts (both clouds) and the Windows agent channel. |

**Variables**

| Variable | Purpose |
| --- | --- |
| `AZURE_RG_NAME` | Target Azure resource group. |
| `HW_REGION` | Huawei Cloud region (e.g. `my-kualalumpur-1`). |
| `HW_PROJECT_ID` | Huawei Cloud project identifier. |
| `HW_ECS_TAG_KEY` / `HW_ECS_TAG_VAL` | Optional tag key/value used to filter ECS discovery. |
| `HW_VPC_ID` | Huawei Cloud VPC used for security-group rules. |
| `HW_EPS_ID` | Optional Huawei Cloud enterprise project ID. |
| `HW_VPC_ENDPOINT` | Huawei Cloud VPC API endpoint (auto-derived from `HW_REGION` if unset). |
| `LINUX_SSH_USER` | SSH user for Linux targets. |
| `WIN_SSH_USER` | SSH user for Windows targets (default `Administrator`). |
| `WIN_SERVER_ROLE` | `member_server`. |
| `ORG_NAME`, `ORG_PREFIX` | Organisation name and prefix for custom content. |
| `GHOST_USER` | Name of the temporary JIT access-recovery account. |
| `CUSTOM_XCCDF_PROFILE` | XCCDF profile ID for the custom TM baseline. |

---

*Engineered for continuous compliance and zero-trust automation across a cross-cloud, multi-OS fleet.*
