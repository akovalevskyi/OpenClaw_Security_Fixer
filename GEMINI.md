# OpenClaw Security Fixer - AI Environment Rules

## GitHub Publishing & Access
- **Authentication:** This repository is configured to use **SSH** for GitHub access.
- **SSH Key:** The authorized key is located at `~/.ssh/id_ed25519`.
- **Remote URL:** Always use `git@github.com:akovalevskyi/OpenClaw_Security_Fixer.git`.
- **Skill Usage:** Use the `github-publisher` logic for any push operations. Do NOT ask for passwords or tokens; if a push fails, check the SSH connectivity with `ssh -T git@github.com`.

## Project Context
- This is a security auditing and hardening toolkit for OpenClaw.
- The environment is a production VPS (Hostinger).
- Always maintain the professional, hardened status of the scripts.
