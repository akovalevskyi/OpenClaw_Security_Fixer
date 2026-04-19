# OpenClaw Advanced Security Fixer

Automated infrastructure hardening, security remediation, and compliance toolkit for OpenClaw environments.

## Overview

The `OpenClaw_Security_Fixer` is designed to aggressively secure an OpenClaw VPS by hardening the host OS, locking down Docker isolation, and enforcing strict application configurations. It transforms a standard Ubuntu VPS into a highly secure, Defense-in-Depth environment.

## 🛡️ Automated Remediation Matrix

The fixer automatically addresses the following security vectors and mitigates associated threats:

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

## 🚀 Usage

The toolkit provides an interactive CLI with dry-run capabilities, allowing you to preview changes before applying them.

```bash
# Launch the interactive menu
./openclaw-secure.sh
```

### Menu Options:
1. **🔍 Run Full Security Audit:** Non-destructive scan (28 vectors).
2. **📋 Generate JSON Report:** Machine-readable output for SIEMs.
3. **🛡️ Fixer (Dry-Run):** Simulates hardening. No files are changed.
4. **🧭 Fixer (Interactive):** Step-by-step guided remediation.
5. **🛠️ Fixer (Automated):** Applies all security fixes unattended.

## ⚙️ Prerequisites for Full Automation

While the fixer handles 95% of the hardening, a few manual steps are required for cloud integration:

1. **Configure Offsite Storage:** Run `rclone config` and create a remote named `b2-backup` (B2/R2/S3).
2. **Initialize Encryption:** The fixer will automatically generate `/root/.backup_passphrase`. Back this up securely!
3. **Persist Rules:** The fixer creates `docker-security-rules.service`. It will be enabled automatically.

