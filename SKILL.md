# System Security Skill

## Overview
This skill provides OpenClaw agents with the ability to run system security audits and automatic fixers on their own host environment (primarily designed for Linux/VPS). It uses Python scripts (`security_audit.py` and `security_fixer.py`) to scan configurations, permissions, and potential data leaks.

## Capabilities
- **Audit:** Analyze `openclaw.json`, workspace directories, and Docker environments for vulnerabilities.
- **Fix:** Automatically harden permissions, apply secure config flags, and redact plaintext secrets.

## Usage Instructions for the Agent
1. **Running an Audit:**
   Execute the audit script using the `run_shell_command` tool:
   ```bash
   python3 scripts/security_audit.py
   ```
   Analyze the JSON/Text output to identify `CRITICAL` or `HIGH` severity issues.

2. **Applying Fixes:**
   If the user requests to secure the system or fix issues found in the audit, execute:
   ```bash
   python3 scripts/security_fixer.py
   ```
   **Important:** This may restart the OpenClaw Gateway. Warn the user before executing.

3. **Checklist Review:**
   Refer to `docs/openclaw_security_checklist.md` for manual Host/VPS security checks (UFW, Fail2ban, Vault) that cannot be fully automated from within the container.
