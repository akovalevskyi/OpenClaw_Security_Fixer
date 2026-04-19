# OpenClaw Security Fixer Skill

The OpenClaw Security Fixer is an automated remediation toolkit designed to resolve critical vulnerabilities in both the host infrastructure (Ubuntu VPS) and the OpenClaw application container.

This skill equips agents with the ability to autonomously enforce the `OpenClaw Security Baseline` and remediate deviations.

## 🛠️ Automated Fixes & Threat Mitigation

The fixer targets specific threats by applying the following architectural changes:

| Component | Automated Fix Applied | Threat Mitigated |
| :--- | :--- | :--- |
| **OS Accounts** | Removes `ubuntu` user from `sudo`, `adm`, `lxd` groups and locks the account (`usermod -L`, `nologin`). Deletes cloud-init sudoers file. | **Privilege Escalation:** Prevents lateral movement if the default user is compromised. |
| **SSH Config** | Changes port to `2244`, disables `PasswordAuthentication`, enforces `AllowUsers root`, limits `MaxAuthTries` to 3, sets `ClientAliveInterval`, disables X11/TCP forwarding. | **Brute-Force & Unauthorized Access:** Eliminates password guessing and restricts entry points. |
| **Firewall** | Installs persistent `DOCKER-USER` iptables rules (DROP by default) with `LOG` targets via a custom systemd service. | **UFW Bypass & Exfiltration:** Stops Docker from exposing ports directly to the internet. |
| **Docker Engine** | Implements `PidsLimit: 512`, `Memory: 4g`, and `CPUs: 2.0` on the OpenClaw container. Removes `privileged: true`. | **DoS & Container Escape:** Prevents fork-bombs from crashing the host and limits escape vectors. |
| **Data Protection** | Replaces plaintext backup scripts with an AES256 GPG-encrypted architecture. Generates random passphrases (`400` root-only). | **Data Breach:** Ensures stolen backup archives cannot be read by attackers. |
| **Disaster Recovery** | Automates offsite replication to Backblaze B2 or Cloudflare R2 using `rclone`. | **Ransomware:** Ensures encrypted backups are safely stored in immutable cloud storage. |
| **App: Sandbox** | Enforces `agents.defaults.sandbox.mode = "all"` in `openclaw.json`. | **RCE (Remote Code Execution):** Forces all AI agents to run inside a restricted `bubblewrap` sandbox. |
| **App: Tools** | Adds `exec` and `bash` to global `tools.deny`. | **Arbitrary Command Execution:** Prevents public-facing agents from executing system commands. |
| **App: Networking** | Enforces `gateway.trustedProxies` and `gateway.auth.rateLimit`. Disables mDNS. | **DDoS & Spoofing:** Prevents spoofing of local IPs and limits API abuse. |

## 🚀 Execution

Execute the fixer script to begin remediation:

```bash
cd ~/OpenClaw_Security_Fixer
./openclaw-secure.sh
```

### Operational Modes

*   **Option 1 & 2 (Audit):** Use these to perform a non-destructive state assessment.
*   **Option 3 & 4 (Dry-Run / Interactive):** Use these to preview or approve individual remediation steps.
*   **Option 5 (Automated):** Use this to rapidly apply the complete security baseline.

## ⚠️ Important Considerations
*   **Backup:** Option 5 creates a backup of `openclaw.json` prior to mutation.
*   **Service Restarts:** The fixer will restart the `sshd` and `docker` services to apply network rules.
*   **Cloud Config:** The offsite backup functionality requires a pre-existing `rclone` remote named `b2-backup`.
