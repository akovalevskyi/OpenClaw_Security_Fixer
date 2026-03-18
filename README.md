# OpenClaw Security Toolkit (Advanced)

```text
            ________
        ---/  ____  \---
          /  /    \  \
   ---   |  | ^  ^ |  |   ---
  /   \  |  |  __  |  |  /   \
 |  |  |  \  \____/  /  |  |  |
  \   /    \________/    \   /
   ---      /      \      ---
           / [SHIELD] \
          /____________\
             /|    |\
            / |____| \
```

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
