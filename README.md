<div align="center">

# 🦀 OpenClaw Security Toolkit v1.1 🛡️

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
**The Unyielding Guardian of Your AI Agent**

[![Security: Hardened](https://img.shields.io/badge/Security-Hardened-success?style=for-the-badge&logo=shield)](https://github.com/akovalevskyi/OpenClaw_Security_Fixer)
[![Environment: Hostinger VPS](https://img.shields.io/badge/Environment-Hostinger_VPS-blue?style=for-the-badge&logo=linux)](https://github.com/akovalevskyi/OpenClaw_Security_Fixer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

</div>

> [!IMPORTANT]
> **Note on Compatibility:** This toolkit was developed on **Hostinger VPS**. It is designed to be compatible with **99% of standard Linux VPS environments** (Ubuntu/Debian) using Docker.

---

## 🚀 Quick Start (OpenClaw Integration)

To use this toolkit as a skill within your OpenClaw environment:

1. **Clone to your Skills directory:**
   ```bash
   git clone https://github.com/akovalevskyi/OpenClaw_Security_Fixer.git security-toolkit
   cd security-toolkit
   pip install -r requirements.txt
   ```

2. **Interactive Menu (v1.1 Hardened):**
   ```bash
   ./openclaw-secure.sh
   ```
   *Now supports **Dry-Run** mode and **Auto-Backups**!*

---

## 🛡️ v1.1 Hardened Features (New!)

We've improved the toolkit based on professional security audits:

*   **Atomic Fixer with Auto-Backup:** Every time you apply a fix, the toolkit creates a timestamped backup of your `openclaw.json`. Writing is now atomic (prevents config corruption).
*   **Dry-Run Mode:** Test your security changes without actually modifying any files.
*   **Deep Container Hardening:** Checks for `privileged` mode, `root` execution, and dangerous `docker.sock` mounts.
*   **Enhanced Secret Detection:** Now detects **AWS Keys, JWT Tokens, and Private Keys (PEM)** in your workspaces.
*   **Improved Logic:** Fixed bugs in `telegramBot` tools audit and `history` limit validation.

## 🛡️ Live Runtime Guardrails

1. **Tool & Network Restrictions:** Disables network egress in sandbox.
2. **Execution Limits:** Enforces `maxSteps` and timeouts.
3. **Approval Gates:** Ensures human-in-the-loop for `exec/shell`.
4. **Output Filtering:** Prevents leaking system prompts or keys back to the user.

---

## 🛡️ Non-Technical User Guidelines

### 1. Choose a "Hardened" AI Model
*   **Recommendation:** Use established models like **Google Gemini 2.5/3.0+** or **OpenAI GPT-4o**.
### 2. Never Share Your Agent Publicly
*   **Recommendation:** Set `dmPolicy` and `groupPolicy` to `allowlist`.
### 3. Treat Your Prompt Like a Password
*   **Recommendation:** Never instruct your AI to "share your system prompt".
### 4. Enforce the Digital Cage (Sandboxing)
*   **Recommendation:** Ensure **Sandbox** is `on` and `workspaceOnly` is `true`.
### 5. Never Hardcode API Keys
*   **Recommendation:** Use environment variables or a secure secret manager.

---

## 🔍 Audit & Fixer Modules (Python)

*   `scripts/security_audit.py`: Deep system & agent scanner.
*   `scripts/security_fixer.py`: Automated hardening with rollback safety.

---
*Developed by akovalevskyi (2026)*
