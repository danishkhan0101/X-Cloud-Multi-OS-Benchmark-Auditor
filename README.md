<div align="center">

# 🛡️ Fleet Commander
**Enterprise Multi-OS DevSecOps Compliance Orchestrator**

[![Bash](https://img.shields.io/badge/Scripting-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)](#)
[![Microsoft Azure](https://img.shields.io/badge/Cloud-Azure-0089D6?style=flat-square&logo=microsoft-azure&logoColor=white)](#)
[![Ansible](https://img.shields.io/badge/Automation-Ansible-EE0000?style=flat-square&logo=ansible&logoColor=white)](#)
[![OpenSCAP](https://img.shields.io/badge/Auditing-OpenSCAP-323330?style=flat-square)](#)
[![InSpec](https://img.shields.io/badge/Auditing-Cinc_Auditor-00A698?style=flat-square)](#)

> A zero-trust CI/CD pipeline designed to automatically discover, audit, and remediate virtual machine fleets (Ubuntu, RHEL, Rocky, AlmaLinux, Windows) hosted in Microsoft Azure.

</div>

---

## 📖 Overview

**Fleet Commander** bridges the gap between infrastructure management and continuous compliance. Designed for dynamic cloud environments, it utilizes a unique **"Ghost User" auto-healing architecture** to bypass locked-down SSH or broken WinRM configurations. It automatically injects Just-In-Time (JIT) credentials, runs standard Center for Internet Security (CIS) or custom organizational baselines, applies Ansible remediations, and permanently covers its tracks.

## ✨ Core Features

* 🧠 **Dynamic Azure Discovery:** Automatically queries Azure Resource Groups by Environment Tags to build real-time inventory lists of running nodes.
* 💉 **JIT Auto-Healing:** Temporarily injects a privileged "Ghost User" to bypass broken cloud-init locks, fixing SELinux/Crypto policies on the fly.
* 📊 **Multi-OS Scanning:** Natively routes Linux targets to **OpenSCAP** and Windows targets to **Cinc Auditor**.
* 🛠️ **Automated Remediation:** Deploys targeted Ansible playbooks and OpenSCAP routines to instantly fix failing compliance controls.
* 🧹 **Zero-Trust Cleanup:** Safely removes temporary NSG firewall rules, uninstalls scanner dependencies, and completely deletes injected users to secure the environment post-audit.

---

## 🗺️ Pipeline Architecture

```mermaid
graph TD
    A[Trigger CI/CD Pipeline] --> B(Azure Resource Discovery)
    B -->|Query VMs| C{Target OS}
    
    C -->|Linux Fleets| D[SSH Access Check]
    C -->|Windows| E[WinRM Access Check]
    
    D -- Fails --> F[Force-Inject Ghost User Backdoor]
    D -- Passes --> G[Bootstrap OpenSCAP]
    F --> G
    
    E -- Locked --> H[Azure Run-Command: Unlock WinRM]
    H --> I[Bootstrap Cinc Auditor]
    E -- Open --> I
    
    G --> J[Execute CIS / Custom XCCDF Baselines]
    I --> K[Execute CIS / Custom Ruby Baselines]
    
    J --> L{Remediation Mode?}
    K --> L
    
    L -- Yes --> M[Execute Ansible Playbooks]
    L -- No --> N[Generate Heimdall Dashboard]
    
    M --> N
    N --> O((Phase 5: The Ghost Method Cleanup))
    
    style O fill:#ff4d4d,stroke:#333,stroke-width:2px,color:#fff
