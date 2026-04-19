#!/usr/bin/env python3
import json
import os
import sys
import subprocess
import re
from datetime import datetime
import shutil

# Flags
DRY_RUN = "--dry-run" in sys.argv
INTERACTIVE = "--interactive" in sys.argv
REDACT_IN_PLACE = "--redact-in-place" in sys.argv

# Paths
DEFAULT_CONFIG_PATH = os.getenv("OPENCLAW_CONFIG", "/data/.openclaw/openclaw.json")
DEFAULT_WORKSPACE_ROOTS = [
    os.getenv("OPENCLAW_WORKSPACES", "/data/.openclaw/workspaces"),
    os.getenv("OPENCLAW_WORKSPACE", "/data/.openclaw/workspace"),
]

def run_cmd(cmd, check=True):
    if DRY_RUN:
        print(f"[Dry-Run] Would run: {cmd}")
        return True
    try:
        subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)
        return True
    except Exception as e:
        print(f"❌ Command failed: {cmd}\nError: {e}")
        return False

def confirm(prompt):
    if not INTERACTIVE:
        return True
    answer = input(f"{prompt} [y/N]: ").strip().lower()
    return answer in ("y", "yes")

def fix_ubuntu_user():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Locking down 'ubuntu' user...")
    if confirm("Lock ubuntu user, remove from sudo/adm/lxd groups and delete cloud-init sudoers?"):
        run_cmd("gpasswd -d ubuntu sudo || true")
        run_cmd("gpasswd -d ubuntu adm || true")
        run_cmd("gpasswd -d ubuntu lxd || true")
        run_cmd("rm -f /etc/sudoers.d/90-cloud-init-users")
        run_cmd("usermod -L ubuntu && usermod -s /usr/sbin/nologin ubuntu")
        print("✅ Ubuntu user locked down.")

def fix_ssh_hardening():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Hardening SSH configuration...")
    ssh_config = "/etc/ssh/sshd_config"
    fixes = [
        (r'^(#)?PasswordAuthentication.*', 'PasswordAuthentication no'),
        (r'^(#)?PermitRootLogin.*', 'PermitRootLogin prohibit-password'),
        (r'^(#)?MaxAuthTries.*', 'MaxAuthTries 3'),
        (r'^(#)?ClientAliveInterval.*', 'ClientAliveInterval 300'),
        (r'^(#)?ClientAliveCountMax.*', 'ClientAliveCountMax 2'),
        (r'^(#)?X11Forwarding.*', 'X11Forwarding no'),
        (r'^(#)?AllowTcpForwarding.*', 'AllowTcpForwarding no')
    ]
    
    if os.path.exists(ssh_config):
        for pattern, replacement in fixes:
            if confirm(f"Apply '{replacement}' to {ssh_config}?"):
                run_cmd(f"sed -i -E 's|{pattern}|{replacement}|' {ssh_config}")
        
        if confirm("Restrict SSH to root only (AllowUsers root)?"):
            run_cmd("grep -q '^AllowUsers' /etc/ssh/sshd_config || echo 'AllowUsers root' >> /etc/ssh/sshd_config")
            run_cmd("sed -i 's/^AllowUsers.*/AllowUsers root/g' /etc/ssh/sshd_config")
            
        print(f"✅ SSH configuration hardened.")
        run_cmd("systemctl reload ssh", check=False)

def fix_docker_firewall():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Hardening Docker Network Isolation (DOCKER-USER)...")
    if confirm("Apply DOCKER-USER isolation rules and create persistent service?"):
        script_path = "/usr/local/bin/apply-docker-rules.sh"
        rules = """#!/bin/bash
iptables -F DOCKER-USER
iptables -A DOCKER-USER -i eth0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A DOCKER-USER -i docker0 -o docker0 -j ACCEPT
iptables -A DOCKER-USER -i eth0 -m limit --limit 5/min -j LOG --log-prefix 'DOCKER-DROP: ' --log-level 4
iptables -A DOCKER-USER -i eth0 -j DROP
iptables -A DOCKER-USER -j RETURN
"""
        if not DRY_RUN:
            with open(script_path, "w") as f: f.write(rules)
            os.chmod(script_path, 0o755)
            
        service_path = "/etc/systemd/system/docker-security-rules.service"
        service = """[Unit]
Description=Apply custom DOCKER-USER iptables rules
After=docker.service
PartOf=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/apply-docker-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
        if not DRY_RUN:
            with open(service_path, "w") as f: f.write(service)
            run_cmd("systemctl daemon-reload && systemctl enable docker-security-rules.service && systemctl start docker-security-rules.service")
        
        print("✅ DOCKER-USER isolation applied and persistent.")

def fix_backup_security():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Hardening Backups (GPG & Offsite)...")
    if confirm("Enable GPG encryption and Offsite rclone support in backup script?"):
        if not os.path.exists("/root/.backup_passphrase") and not DRY_RUN:
            run_cmd("openssl rand -base64 48 > /root/.backup_passphrase")
            run_cmd("chmod 400 /root/.backup_passphrase")
        
        backup_script = """#!/bin/bash
set -e
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/docker/openclaw_backups"
BACKUP_FILE="$BACKUP_DIR/openclaw_backup_$TIMESTAMP.tar.gz"
ENC_FILE="$BACKUP_FILE.gpg"
AUDIT_FILE="$BACKUP_DIR/openclaw_audit_$TIMESTAMP.log"
AUDIT_ENC="$AUDIT_FILE.gpg"
BASELINE_PREFIX="openclaw_security_baseline_"

if [ -z "$BACKUP_PASSPHRASE" ]; then
    if [ -r /root/.backup_passphrase ]; then
        BACKUP_PASSPHRASE="$(cat /root/.backup_passphrase)"
    else
        echo "ERROR: BACKUP_PASSPHRASE missing" >&2
        exit 1
    fi
fi

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

echo "[1/5] Creating backup..."
tar -czf "$BACKUP_FILE" -C /docker/openclaw-3g02/data .openclaw/openclaw.json .openclaw/agents/ .openclaw/credentials/ vault.sh vault_bridge.py 2>/dev/null || true

echo "[2/5] Encrypting backup..."
gpg --batch --yes --symmetric --passphrase "$BACKUP_PASSPHRASE" -o "$ENC_FILE" "$BACKUP_FILE"
shred -u "$BACKUP_FILE"

echo "[3/5] Running Audit..."
docker exec openclaw-3g02-openclaw-1 openclaw security audit --deep > "$AUDIT_FILE" 2>&1 || true
gpg --batch --yes --symmetric --passphrase "$BACKUP_PASSPHRASE" -o "$AUDIT_ENC" "$AUDIT_FILE"
shred -u "$AUDIT_FILE"

echo "[4/5] Offsite upload..."
if rclone listremotes 2>/dev/null | grep -q '^b2-backup:'; then
    rclone copy "$ENC_FILE" b2-backup:openclaw-vault/
    rclone copy "$AUDIT_ENC" b2-backup:openclaw-vault/
fi

echo "[5/5] Cleanup..."
find "$BACKUP_DIR" -type f -mtime +30 ! -name "*${BASELINE_PREFIX}*" -delete
echo "Done."
"""
        if not DRY_RUN:
            with open("/root/backup_openclaw.sh", "w") as f: f.write(backup_script)
            os.chmod("/root/backup_openclaw.sh", 0o700)
        print("✅ Backup script updated with encryption and offsite support.")

def fix_docker_limits():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Applying Docker Resource Limits...")
    container = os.getenv("OPENCLAW_CONTAINER", "openclaw-3g02-openclaw-1")
    if confirm(f"Apply PidsLimit=512, Memory=4G, CPU=2.0 to {container}?"):
        run_cmd(f"docker update --pids-limit 512 --memory 4g --cpus 2 {container}")
        print(f"✅ Resource limits applied to {container}.")

def fix_config():
    print(f"[Fixer] Hardening OpenClaw JSON configuration...")
    if not os.path.exists(DEFAULT_CONFIG_PATH): return
    with open(DEFAULT_CONFIG_PATH, "r") as f: config = json.load(f)
    changed = False
    
    # Trusted Proxies
    if config.get("gateway", {}).get("trustedProxies") != ["127.0.0.1", "172.17.0.1"]:
        if confirm("Set gateway.trustedProxies?"):
            if "gateway" not in config: config["gateway"] = {}
            config["gateway"]["trustedProxies"] = ["127.0.0.1", "172.17.0.1"]
            changed = True
            
    # Sandbox All
    if config.get("agents", {}).get("defaults", {}).get("sandbox", {}).get("mode") != "all":
        if confirm("Set sandbox mode to 'all'?"):
            config["agents"]["defaults"]["sandbox"]["mode"] = "all"
            changed = True

    if changed and not DRY_RUN:
        with open(DEFAULT_CONFIG_PATH, "w") as f: json.dump(config, f, indent=2)
        print("✅ openclaw.json hardened.")
    return changed

def main():
    print("--- OPENCLAW SECURITY FIXER v1.8 ---")
    fix_ubuntu_user()
    fix_ssh_hardening()
    fix_docker_firewall()
    fix_backup_security()
    fix_docker_limits()
    fix_config()
    print("\\nFixing process complete. Reboot recommended.")

if __name__ == "__main__":
    main()
