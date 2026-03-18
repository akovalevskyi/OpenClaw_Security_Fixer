<div align="center">

# 🦀 OpenClaw Security Toolkit 🛡️

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
**A practical hardening and audit toolkit for OpenClaw deployments**

[![Security: Hardened](https://img.shields.io/badge/Security-Hardened-success?style=for-the-badge&logo=shield)](https://github.com/akovalevskyi/OpenClaw_Security_Fixer)
[![Environment: Linux/Docker](https://img.shields.io/badge/Environment-Linux_Docker-blue?style=for-the-badge&logo=linux)](https://github.com/akovalevskyi/OpenClaw_Security_Fixer)
[![Version: 1.5](https://img.shields.io/badge/Version-1.5_Hardened-orange?style=for-the-badge)](https://github.com/akovalevskyi/OpenClaw_Security_Fixer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

</div>

> [!IMPORTANT]
> **Production Readiness:** This toolkit provides automated hardening and audit capabilities. However, security is a process. Always review the [Manual Checklist](docs/openclaw_security_checklist.md) and understand the changes being applied.

---

## ✅ Implemented in the Current Version (v1.5)

*   **Output Sanitization (Scrubbing):** Automatically detects and can configure output filters to block PII and secret leaks.
*   **Indirect Prompt Injection Protection:** Audits data-ingesting tools and enforces Human-in-the-Loop (HITL) approval gates.
*   **Monitoring & Auditing:** Checks for system logging status and can enable it for forensic trail.
*   **Reliable Host Audit:** Evaluates effective SSH configuration using `sshd -T`.
*   **Dynamic Container Discovery:** Automatically detects OpenClaw/Gateway containers and inspects their runtime environment.
*   **Safe Hardening (Atomic Writes):** All configuration changes are written atomically via temp files to prevent corruption.
*   **Automatic Backups:** Creates timestamped `.bak` files before any modification.
*   **Interactive Fixer:** A guided mode to review and approve every security improvement before it's applied.
*   **Profile Support:** Choose between `minimal`, `recommended`, and `paranoid` security levels.
*   **Workspace Protection:** Scans and can redact secrets (OpenAI, GitHub, JWT, etc.) in workspace files.
*   **Standardized JSON Output:** Machine-readable audit reports ready for CI/CD integration.

---

## 🚀 Quick Start

1. **Install:**
   ```bash
   git clone https://github.com/akovalevskyi/OpenClaw_Security_Fixer.git security-toolkit
   cd security-toolkit
   pip install -r requirements.txt
   ```

2. **Interactive Menu:**
   The recommended way to use the toolkit.
   ```bash
   ./openclaw-secure.sh
   ```

3. **CLI Usage:**
   ```bash
   # Run audit and output JSON
   python3 scripts/security_audit.py --json
   
   # Run fixer in dry-run mode
   python3 scripts/security_fixer.py --dry-run
   
   # Run fixer in interactive mode with paranoid profile
   python3 scripts/security_fixer.py --interactive --profile=paranoid
   ```

---

## 🛡️ Key Security Features

### 1. Agentic Security & Guardrails
- **Sandboxing Audit:** Verifies that agents are restricted to their workspace and have no direct network access.
- **Execution Limits:** Audits and enforces `maxSteps`, `timeoutMs`, and history limits.
- **Tool Policy:** Checks for denylists of dangerous tools (`exec`, `bash`, `cron`) on public-facing channels.

### 2. Secret Management
- **ENV Inspection:** Checks if sensitive API keys are exposed in container environment variables.
- **Pattern & Entropy Scanning:** Heuristic detection of secrets in workspaces using both known patterns and Shannon Entropy.

### 3. Container & Host Hardening
- **Infrastructure Audit:** Verifies SSH port, password auth status, and root login settings.
- **Runtime Security:** Checks for privileged mode, writable rootfs, and missing `no-new-privileges` flags.

---

## 🔌 Compatibility & External Tools
The toolkit is compatible with and complements:
- **Promptfoo:** For prompt compliance and regression testing.
- **Garak:** For LLM vulnerability scanning.
- **PyRIT:** For adversarial red-teaming.

---

## 🔍 Audit & Fixer Modules

*   `scripts/security_audit.py`: The Scanner (Infrastructure, Container, and Configuration).
*   `scripts/security_fixer.py`: The Repairman (Backups, Atomic Writes, and Profiles).

---
*Developed by akovalevskyi (2026)*
