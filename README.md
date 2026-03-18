<div align="center">

# 🦀 OpenClaw Security Toolkit v1.2 🛡️

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
**The Enterprise-Grade Guardian of Your AI Agent**

[![Security: Hardened](https://img.shields.io/badge/Security-Hardened-success?style=for-the-badge&logo=shield)](https://github.com/akovalevskyi/OpenClaw_Security_Fixer)
[![CI: Passing](https://img.shields.io/badge/CI-Passing-brightgreen?style=for-the-badge&logo=github-actions)](https://github.com/akovalevskyi/OpenClaw_Security_Fixer)
[![Version: 1.2](https://img.shields.io/badge/Version-1.2_Enterprise-blue?style=for-the-badge)](https://github.com/akovalevskyi/OpenClaw_Security_Fixer)

</div>

## 🛡️ v1.2 Enterprise Updates (New!)

We've elevated the toolkit to professional standards:

*   **Machine-Readable Output:** Support for `--json` flag in audit, allowing for easy integration with CI/CD and SOC monitoring.
*   **Entropy-Based Secret Scanning:** Beyond simple regex, we now use **Shannon Entropy** to detect unknown high-entropy strings (potential API keys) that don't match known patterns.
*   **Formal Threat Modeling:** Added `docs/THREAT_MODEL.md` to map attack vectors and mitigations.
*   **Automated Test Suite:** Initialized `tests/` with `pytest` support to ensure audit logic remains reliable.
*   **Versioned Backups:** Enhanced configuration management with persistent, timestamped rollback points.

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
