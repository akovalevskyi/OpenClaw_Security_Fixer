<div align="center">

# 🦀 OpenClaw Security Toolkit v1.3 🛡️

```text
       ___     🛡️      ___
      /   \  [====]  /   \
     |  |  |  \__/  |  |  |
      \  \ \__/__\__/ /  /
       \__\  (o o)  /__/
          | /_++_\ |
         /  |____|  \
        / /        \ \
       / /          \ \
      "-"            "-"
```
**The Production-Ready Guardian of Your AI Agent**

[![Security: Hardened](https://img.shields.io/badge/Security-Hardened-success?style=for-the-badge&logo=shield)](https://github.com/akovalevskyi/OpenClaw_Security_Fixer)
[![Version: 1.3](https://img.shields.io/badge/Version-1.3_Production-blue?style=for-the-badge)](https://github.com/akovalevskyi/OpenClaw_Security_Fixer)

</div>

## 🛡️ v1.3 Production Updates (New!)

We've synchronized the toolkit with the latest live configurations from our Hostinger VPS environment:

*   **Host Infrastructure Audit:** Now checks for SSH hardening (Port 2244, disabled passwords) directly on the host.
*   **Live Docker Environment Audit:** Automatically inspects running OpenClaw containers for leaked API keys in ENV variables.
*   **Production Environment Awareness:** Fine-tuned logic for container names and actual directory structures used in production.
*   **Comprehensive Secret Scanning:** Improved entropy-based detection and regex patterns for even more secret types.

---

## 🚀 Quick Start

1. **Install:**
   ```bash
   git clone https://github.com/akovalevskyi/OpenClaw_Security_Fixer.git security-toolkit
   cd security-toolkit
   pip install -r requirements.txt
   ```

2. **Run Interactive Menu:**
   ```bash
   ./openclaw-secure.sh
   ```

---

## 🛡️ Key Security Features

### 1. Agentic Guardrails
*   **Egress Control:** Blocks unauthorized network calls from the sandbox.
*   **Autonomy Bounds:** Limits recursion, steps, and session timeouts.
*   **Output Scrubbing:** Prevents leakage of prompts and secrets back to the user.

### 2. Container & Host Hardening
*   **Isolation Audit:** Checks for root execution and dangerous Docker socket mounts.
*   **Infrastructure:** Integrates with UFW, Fail2ban, and encrypted Vaults.

---

## 🔍 Audit & Fixer Modules

*   `scripts/security_audit.py`: The Scanner (with JSON & Entropy support).
*   `scripts/security_fixer.py`: The Repairman (with atomic writes & auto-backups).

---
*Developed by akovalevskyi (2026)*
