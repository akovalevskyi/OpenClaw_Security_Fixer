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
**The Unyielding Guardian of Your AI Agent**

[![Security: Hardened](https://img.shields.io/badge/Security-Hardened-success?style=for-the-badge&logo=shield)](https://github.com/akovalevskyi/termuxtest)
[![Environment: Hostinger VPS](https://img.shields.io/badge/Environment-Hostinger_VPS-blue?style=for-the-badge&logo=linux)](https://github.com/akovalevskyi/termuxtest)
[![Agent: OpenClaw](https://img.shields.io/badge/Agent-OpenClaw-orange?style=for-the-badge)](https://github.com/akovalevskyi/termuxtest)

</div>

> [!IMPORTANT]
> **Note on Compatibility:** This toolkit was developed and rigorously tested on **Hostinger VPS** infrastructure. While settings may vary slightly depending on your provider's specific OS image or kernel configuration, it is designed to be compatible with **99% of standard Linux VPS environments** (Ubuntu/Debian/CentOS) using Docker.

---

## 🚀 Quick Start (OpenClaw Integration)

To use this toolkit as a skill within your OpenClaw environment:

1. **Clone to your Skills directory:**
   Navigate to your OpenClaw skills folder on the VPS and run:
   ```bash
   git clone https://github.com/akovalevskyi/termuxtest.git security-toolkit
   cd security-toolkit
   pip install -r requirements.txt
   ```

2. **Interactive Menu (Recommended for Humans):**
   We have included a beautiful, color-coded interactive wrapper for easy use via SSH. Just run:
   ```bash
   ./openclaw-secure.sh
   ```
   
   ![Interactive Menu Demo](https://img.shields.io/badge/Terminal-Interactive_Menu-black?style=flat-square&logo=gnu-bash)

3. **Run via Agent:**
   Register the path to this folder in your `openclaw.json` under the `skills` section. You can now ask your OpenClaw agent:
   - *"Run a security audit using the security toolkit"*
   - *"Apply security fixes to my VPS"*

---

## Overview & Architecture

**OpenClaw Security Toolkit** is a comprehensive suite of scripts and protocols designed for deep security auditing and automated hardening of the OpenClaw AI agent environment.

**Key Testing Environment:**
This toolkit was primarily developed, optimized, and tested on **VPS (Virtual Private Server)** environments running Linux and Docker. It assumes a standard OpenClaw directory structure (e.g., `/data/.openclaw/`) but is adaptable to other Linux-based setups.

---

## 🛡️ Core Security Infrastructure

Our security architecture extends beyond the agent itself, integrating three critical external services to protect the host:

1. **UFW (Uncomplicated Firewall):**
   - **Purpose:** Restricts network access to the server at the OS level.
   - **Importance:** Protects against port scanning and unauthorized access to internal services (Docker, DBs). Only essential ports (e.g., custom SSH port 2244) are exposed.

2. **Fail2ban:**
   - **Purpose:** Protects against brute-force attacks by monitoring system logs.
   - **Importance:** Automatically bans IP addresses that show malicious behavior (e.g., multiple failed SSH logins), acting as the first line of defense against botnets.

3. **Vault.sh (Secure Secret Manager):**
   - **Purpose:** Isolates and encrypts sensitive API keys and tokens using AES-256-CBC.
   - **Importance:** Prevents secrets from being hardcoded in `openclaw.json` or leaked through logs. Secrets are only accessible via an interactive password-protected bridge (`vault_bridge.py`), isolating them from public messaging platforms like Telegram.

---

## 🤖 Advanced AI & LLM Security Services

This toolkit integrates three industry-standard frameworks for auditing the **AI/LLM layer** itself. These tools automatically download and update large databases of security probes and jailbreak patterns:

1. **Promptfoo (Prompt Evaluation & Compliance):**
   - **What it does:** Runs automated evaluations of the agent's prompts to ensure they follow safety guidelines and do not leak system instructions.
   - **Database:** Uses extensive sets of compliance and quality test cases.
   - **Importance:** Ensures the agent doesn't "hallucinate" or bypass its core instructions (e.g., the "Rule of Dot").

2. **Garak (LLM Vulnerability Scanner):**
   - **What it does:** A specialized scanner for LLMs (similar to Nmap for networks). It probes for prompt injections, hallucination risks, and data leakage.
   - **Database:** Downloads hundreds of probes specifically designed to break LLM safety filters.
   - **Importance:** Identifies if the chosen model (e.g., GPT-4o-mini, Claude-3.5-Sonnet) is inherently vulnerable to specific attack vectors in your current configuration.

3. **PyRIT (Python Risk Identification Tool):**
   - **What it does:** A red-teaming framework by Microsoft for multi-turn adversarial attacks.
   - **Database:** Utilizes sophisticated strategies like "Crescendo" to bypass AI safety guardrails through gradual persuasion.
   - **Importance:** Simulates a real human attacker trying to manipulate the AI over a long conversation, allowing us to find and patch deep logical vulnerabilities.

---


## 🛡️ Live Runtime Guardrails (Agentic Security)

To move beyond basic server hardening, this toolkit enforces strict runtime boundaries directly on the AI agent to prevent autonomous exploitation:

1. **Tool & Network Restrictions (Egress Control):**
   - Automatically disables network egress within the agent's sandbox (`network: "none"`). Prevents the AI from phoning home or downloading arbitrary payloads if compromised.
2. **Execution Limits & Timeouts:**
   - Enforces strict bounds on agent autonomy (e.g., maximum recursion steps, tool-call caps, and overall session timeouts) to prevent infinite loops and financial DoS.
3. **Approval Gates:**
   - Audits for the presence of "human-in-the-loop" confirmation gates for destructive or highly privileged tools (e.g., `exec`, `shell`).
4. **Live Output Filtering:**
   - Checks for active middleware designed to intercept and scrub outbound messages, ensuring the agent cannot leak its system prompt or discovered secrets back to a user.

---

## 🔍 Audit & Fixer Modules (Python)

### `security_audit.py` (The Scanner)
Performs a recursive audit of the entire system:
- **Gateway Config:** Checks for `GW_INSECURE_AUTH` and `GW_NO_DEVICE_AUTH`.
- **Sandboxing:** Validates if `sandbox: on` and `workspaceOnly: true` are enforced (Critical to prevent RCE).
- **Messaging Security:** Ensures `dmPolicy: allowlist` is active to prevent public token abuse.
- **Data Leaks:** Scans all workspaces and configs for hardcoded API keys.
- **Permissions:** Validates Linux file permissions (ensures `600`/`700` on sensitive files).

### `security_fixer.py` (The Repairman)
Automatically applies hardening measures based on the audit findings:
- Resets dangerous configuration flags to secure defaults.
- Automatically `chmod` files and directories to recommended modes.
- Redacts/masks plaintext secrets found in workspaces.
- *Note: May trigger a Gateway restart to apply changes.*

---

## Getting Started

1. **Run a full system audit:**
   ```bash
   python3 scripts/security_audit.py
   ```

2. **Apply automated security fixes:**
   ```bash
   python3 scripts/security_fixer.py
   ```

3. **Review the Host Checklist:**
   See `docs/openclaw_security_checklist.md` for manual VPS-level hardening steps.

---

## 🛡️ Non-Technical User Guidelines (How to not get hacked)

Protecting your AI agent isn't just about running scripts; it's about how you set it up and use it daily. If you are not deeply technical, follow these **5 Golden Rules** to keep your agent (and your wallet) safe:

### 1. Choose a "Hardened" AI Model (Prevent Prompt Injection)
Not all AI models are created equal when it comes to resisting hacks (like "Prompt Injection," where attackers trick the AI into ignoring your rules). 
*   **Recommendation:** Use established, highly secure, and tested models for your main agent, such as **Google Gemini 2.5/3.0+** or **OpenAI GPT-4o**.
*   **Why?** These top-tier providers invest millions in "red-teaming" (testing their own models against attacks). Smaller, open-source, or unverified models are much easier to manipulate into giving up your secrets or ignoring safety instructions.

### 2. Never Share Your Agent Publicly
Your agent costs money (API tokens) and has access to your private workspace.
*   **Recommendation:** In your OpenClaw settings, ensure your Telegram or Signal `dmPolicy` and `groupPolicy` are set to `allowlist`.
*   **Why?** If set to `public`, anyone on the internet can chat with your bot, run up a massive API bill, or try to trick it into deleting your files. Only add your own personal User ID to the allowlist.

### 3. Treat Your Prompt Like a Password
The instructions you give your agent (your `SOUL.md` or System Prompt) often contain sensitive logic about how your business or personal systems work.
*   **Recommendation:** Never instruct your AI to "share your system prompt" with users. Be wary of using third-party prompts without reading them.
*   **Why?** Attackers use a technique called "System Prompt Extraction." If they know exactly how your AI is instructed, they can find loopholes to break it.

### 4. Enforce the Digital Cage (Sandboxing)
*   **Recommendation:** Always ensure the **Sandbox** is turned `on` and `workspaceOnly` is set to `true`. *(Note: Our automatic fixer script does this for you!)*
*   **Why?** If the AI somehow goes rogue (or is tricked by an attacker), sandboxing acts as a digital cage. It prevents the AI from reaching out and deleting your server's core operating system files.

### 5. Never Hardcode API Keys
*   **Recommendation:** Never type your `sk-1234...` API keys directly into text files, your `openclaw.json`, or your prompt. Use environment variables or a secure secret manager (like our `vault.sh` integration).
*   **Why?** If you accidentally share a screenshot, or if the AI accidentally quotes a file in a chat, your keys can be stolen and used by others within minutes, leading to thousands of dollars in charges.
