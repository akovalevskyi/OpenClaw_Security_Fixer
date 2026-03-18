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
[![Environment: Hostinger VPS](https://img.shields.io/badge/Environment-Hostinger_VPS-blue?style=for-the-badge&logo=linux)](https://github.com/akovalevskyi/OpenClaw_Security_Fixer)
[![Version: 1.3](https://img.shields.io/badge/Version-1.3_Production-orange?style=for-the-badge)](https://github.com/akovalevskyi/OpenClaw_Security_Fixer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

</div>

> [!IMPORTANT]
> **Note on Compatibility:** This toolkit was developed and rigorously tested on **Hostinger VPS** infrastructure. While settings may vary slightly depending on your provider's specific OS image or kernel configuration, it is designed to be compatible with **99% of standard Linux VPS environments** (Ubuntu/Debian/CentOS) using Docker.

---

## 🛡️ v1.3 Production Updates (New!)

We've synchronized the toolkit with the latest live configurations and feedback from security audits:

*   **Host Infrastructure Audit:** Now checks for SSH hardening (Port 2244, disabled passwords) directly on the host.
*   **Live Docker Environment Audit:** Automatically inspects running OpenClaw containers for leaked API keys in ENV variables.
*   **Entropy-Based Secret Scanning:** Beyond simple regex, we now use **Shannon Entropy** to detect unknown high-entropy strings (potential API keys) that don't match known patterns.
*   **Atomic Fixer with Auto-Backup:** Every time you apply a fix, the toolkit creates a timestamped backup of your config. Writing is now atomic to prevent corruption.
*   **Formal Threat Modeling:** Included `docs/THREAT_MODEL.md` to map attack vectors and mitigations.

---

## 🚀 Quick Start (OpenClaw Integration)

To use this toolkit as a skill within your OpenClaw environment:

1. **Clone to your Skills directory:**
   Navigate to your OpenClaw skills folder on the VPS and run:
   ```bash
   git clone https://github.com/akovalevskyi/OpenClaw_Security_Fixer.git security-toolkit
   cd security-toolkit
   pip install -r requirements.txt
   ```

2. **Interactive Menu (v1.3 Production):**
   We have included a beautiful, color-coded interactive wrapper for easy use via SSH. It now supports **Dry-Run** mode and **Auto-Backups**!
   ```bash
   ./openclaw-secure.sh
   ```

3. **Run via Agent:**
   Register the path to this folder in your `openclaw.json` under the `skills` section. You can now ask your OpenClaw agent:
   - *"Run a security audit using the security toolkit"*
   - *"Apply security fixes to my VPS"*

---

## 🛡️ Key Security Features

### 1. Live Runtime Guardrails (Agentic Security)
This toolkit enforces strict runtime boundaries directly on the AI agent to prevent autonomous exploitation:
- **Egress Control:** Automatically disables unauthorized network calls from the sandbox.
- **Execution Limits:** Enforces strict bounds on `maxSteps` and session timeouts to prevent financial DoS.
- **Approval Gates:** Audits for "human-in-the-loop" confirmation for dangerous tools (`exec`, `shell`).
- **Output Scrubbing:** Prevents leakage of system prompts or discovered secrets back to the user.

### 2. Advanced AI & LLM Security Integration
The toolkit is designed to work alongside industry-standard frameworks for auditing the AI layer:
- **Promptfoo (Compliance):** Automated evaluation of prompts to ensure they follow safety guidelines.
- **Garak (Vulnerability Scanner):** Specialized Nmap-style scanner for LLMs to find injection vectors.
- **PyRIT (Red-Teaming):** Microsoft's framework for multi-turn adversarial attacks (e.g., "Crescendo").

### 3. Container & Host Hardening
- **Isolation Audit:** Checks for non-root execution and blocks dangerous `docker.sock` mounts.
- **Infrastructure Infrastructure:** Integrates with UFW firewall, Fail2ban protection, and encrypted Vaults for secret management.

---

## 🛡️ Non-Technical User Guidelines (How to not get hacked)

If you are not deeply technical, follow these **5 Golden Rules** to keep your agent (and your wallet) safe:

### 1. Choose a "Hardened" AI Model
Use the latest established models from trusted providers like **OpenAI (GPT-4o/5)**, **Google Gemini (1.5 Pro/2.0/3.0+)**, or **Anthropic Claude (3.5 Sonnet/3.7/4)**. These top-tier providers invest millions in "red-teaming" to resist prompt injections. **Warning:** Using unverified or experimental models puts your agent's security at significant risk, as they often lack the robust safety guardrails needed to prevent manipulation.

### 2. Never Share Your Agent Publicly
In your OpenClaw settings, ensure your Telegram or Signal `dmPolicy` and `groupPolicy` are set to `allowlist`. Never let unknown users chat with your bot.

### 3. Treat Your Prompt Like a Password
Instructions in your `SOUL.md` are sensitive. Never instruct your AI to "share your system prompt" with users.

### 4. Enforce the Digital Cage (Sandboxing)
Always ensure the **Sandbox** is turned `on` and `workspaceOnly` is set to `true`. Our automatic fixer script does this for you!

### 5. Never Hardcode API Keys
Never type your `sk-...` keys directly into text files or your prompt. Use environment variables or a secure secret manager like our `vault.sh` integration.

---

## 🔍 Audit & Fixer Modules (Python)

*   `scripts/security_audit.py`: The Scanner (with JSON, SSH, and Entropy support).
*   `scripts/security_fixer.py`: The Repairman (with atomic writes and auto-backups).

---
*Developed by akovalevskyi (2026)*
