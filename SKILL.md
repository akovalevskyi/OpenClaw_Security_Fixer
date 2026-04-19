# OpenClaw Security Fixer Skill

Use this skill to automatically audit and fix security vulnerabilities in OpenClaw infrastructure.

## Commands
- **Security Checkup**: \`./openclaw-secure.sh\` - Runs interactive menu for audit and automated remediation.

## Automated Fixes:
1. **Host Hardening**: 
   - Lock 'ubuntu' user, remove from sudo/adm.
   - SSH hardening (Port 2244, AllowUsers root).
2. **Container Isolation**: 
   - Apply PidsLimit, Memory, and CPU limits.
   - Remove privileged mode.
3. **Firewall Integrity**: 
   - Apply DOCKER-USER chain isolation.
   - Install persistent systemd firewall service.
4. **Data Protection**: 
   - Setup GPG-encrypted backups.
   - Integrate rclone for offsite B2 storage.

## Best Practices
- Always run an **Audit** (Option 1) before applying **Fixes** (Option 5).
- Ensure a backup of \`openclaw.json\` exists before live remediation.
