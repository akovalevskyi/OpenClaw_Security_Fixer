# OpenClaw Advanced Security Fixer

Automated infrastructure hardening and security remediation for OpenClaw.

## Features
- **Ubuntu Lockdown:** Automatically removes 'ubuntu' user from privileged groups and locks the account.
- **SSH Hardening:** Port 2244, Key-only auth, restricted AllowUsers.
- **Docker Isolation:** Sets PidsLimit, removes privileged mode, and enforces memory/CPU limits.
- **Persistent Firewall:** Implements DOCKER-USER chain isolation with LOG target and systemd service.
- **Secure Backups:** GPG-encrypted AES256 archives with Offsite B2 support.
- **Config Hardening:** Sandbox 'all', trustedProxies, and rate limiting enforcement.

## Included Checks (28 Vectors)

| Check Name | Why it's needed |
|---|---|
| SSH Port (2244) | Prevents automated brute-force attacks. |
| SSH Password Auth | Forces use of cryptographic keys. |
| SSH AllowUsers root | Prevents entry via non-root system accounts. |
| Fail2ban Jails | Automatically bans malicious IPs. |
| DOCKER-USER Isolation | Prevents Docker from bypassing host firewall. |
| Bubblewrap (bwrap) | unprivileged sandboxing for agents. |
| Ubuntu User Locked | Removes a common entry point for attackers. |
| GPG Backup Encryption | Protects archives with AES256 encryption. |
| Offsite rclone B2 | Cloud replication for disaster recovery. |

## Usage

\`\`\`bash
# Run interactive audit and fix
./openclaw-secure.sh
\`\`\`

## Installation
1. Config \`rclone\` remote named \`b2-backup\`.
2. Generate GPG passphrase in \`/root/.backup_passphrase\`.
3. Run \`systemctl enable docker-security-rules.service\`.

---
*Updated: April 19, 2026*
