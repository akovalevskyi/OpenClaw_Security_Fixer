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

# Profiles
PROFILES = {
    "minimal": {"maxMessages": 100, "maxSteps": 50, "timeoutMs": 180000},
    "recommended": {"maxMessages": 50, "maxSteps": 30, "timeoutMs": 120000},
    "paranoid": {"maxMessages": 20, "maxSteps": 15, "timeoutMs": 60000},
}

PROFILE_NAME = "recommended"
for arg in sys.argv:
    if arg.startswith("--profile="):
        PROFILE_NAME = arg.split("=", 1)[1].strip()

SELECTED_PROFILE = PROFILES.get(PROFILE_NAME, PROFILES["recommended"])

MANUAL_ONLY_NOTES = [
    "Approval gates must be reviewed manually because exact schema may vary by OpenClaw version.",
    "Output filtering presence is audited heuristically and is not auto-remediated.",
    "Docker runtime settings (privileged, network_mode, etc.) must be fixed in docker-compose.yml manually.",
]

def fix_ssh_hardening():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Hardening SSH configuration...")
    # 1. Main config
    ssh_config = "/etc/ssh/sshd_config"
    fixes = [
        (r'^(#)?PasswordAuthentication.*', 'PasswordAuthentication no'),
        (r'^(#)?PermitRootLogin.*', 'PermitRootLogin prohibit-password')
    ]
    
    changed_ssh = False
    if os.path.exists(ssh_config):
        for pattern, replacement in fixes:
            if not DRY_RUN:
                try:
                    subprocess.run(["sed", "-i", "-E", f"s|{pattern}|{replacement}|", ssh_config], check=True)
                    changed_ssh = True
                except: pass
        print(f"✅ {'Would harden' if DRY_RUN else 'Hardened'} {ssh_config}")

    # 2. config.d directory
    config_d = "/etc/ssh/sshd_config.d"
    if os.path.isdir(config_d):
        for f in os.listdir(config_d):
            if f.endswith(".conf"):
                f_path = os.path.join(config_d, f)
                for pattern, replacement in fixes:
                    if not DRY_RUN:
                        try:
                            subprocess.run(["sed", "-i", "-E", f"s|{pattern}|{replacement}|", f_path], check=True)
                            changed_ssh = True
                        except: pass
                print(f"✅ {'Would harden' if DRY_RUN else 'Hardened'} override {f_path}")

    if changed_ssh and not DRY_RUN:
        subprocess.run(["systemctl", "restart", "sshd"], check=False)

def fix_docker_firewall():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Enforcing Docker Network Isolation (iptables)...")
    if DRY_RUN:
        print("[Dry-Run] Would run iptables -I DOCKER-USER -i eth0 -j DROP ...")
        return
    
    try:
        # Check if rules already exist to avoid duplicates (heuristic)
        check = subprocess.run("iptables -L DOCKER-USER -n", shell=True, capture_output=True, text=True)
        if "DROP" not in check.stdout:
            subprocess.run("iptables -I DOCKER-USER -i eth0 -j DROP", shell=True, check=True)
            subprocess.run("iptables -I DOCKER-USER -i eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", shell=True, check=True)
            print("✅ DOCKER-USER rules applied to eth0")
        else:
            print("ℹ️ DOCKER-USER rules appear to be already present.")
    except Exception as e:
        print(f"❌ Failed to apply iptables rules: {e}")

def confirm(prompt):
    if not INTERACTIVE:
        return True
    answer = input(f"{prompt} [y/N]: ").strip().lower()
    return answer in ("y", "yes")

def backup_file(path):
    if DRY_RUN:
        print(f"[Dry-Run] Would create backup for {path}")
        return None
    if os.path.exists(path):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{path}.{timestamp}.bak"
        shutil.copy2(path, backup_path)
        print(f"[Backup] Created backup at {backup_path}")
        return backup_path
    return None

def atomic_write_text(path, content):
    if DRY_RUN:
        print(f"[Dry-Run] Would write updated file to {path}")
        return
    temp_path = f"{path}.tmp"
    with open(temp_path, "w") as f:
        f.write(content)
    os.replace(temp_path, path)

def atomic_write_json(path, data):
    if DRY_RUN:
        print(f"[Dry-Run] Would write updated config to {path}")
        return
    temp_path = f"{path}.tmp"
    with open(temp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(temp_path, path)

def validate_json_config(path):
    if DRY_RUN: return True
    try:
        with open(path, "r") as f:
            json.load(f)
        return True
    except Exception as e:
        print(f"❌ JSON Validation failed for {path}: {e}")
        return False

def fix_permissions():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Hardening file permissions...")
    data_dir = os.path.dirname(DEFAULT_CONFIG_PATH)
    paths_to_fix = [
        (DEFAULT_CONFIG_PATH, '600'),
        (os.path.join(data_dir, 'credentials'), '700'),
        ('/data', '700'),
        (data_dir, '700'),
        (os.path.join(data_dir, '.signal-data'), '700')
    ]
    for path, mode in paths_to_fix:
        if os.path.exists(path):
            if not confirm(f"Set {mode} for {path}?"):
                continue
            try:
                if not DRY_RUN:
                    subprocess.run(["chmod", mode, path], check=True)
                print(f"✅ {'Would set' if DRY_RUN else 'Set'} {mode} for {path}")
            except Exception as e:
                print(f"❌ Failed to fix {path}: {e}")

def fix_config():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Hardening OpenClaw configuration (Profile: {PROFILE_NAME})...")
    if not os.path.exists(DEFAULT_CONFIG_PATH):
        print(f"❌ Config file not found at {DEFAULT_CONFIG_PATH}")
        return False

    with open(DEFAULT_CONFIG_PATH, "r") as f:
        config = json.load(f)

    changed = False
    
    # 1. Gateway Hardening
    if "gateway" not in config: config["gateway"] = {}
    if "controlUi" not in config["gateway"]: config["gateway"]["controlUi"] = {}
    
    for key in ["allowInsecureAuth", "dangerouslyDisableDeviceAuth", "dangerouslyAllowHostHeaderOriginFallback"]:
        if config["gateway"]["controlUi"].get(key) is not False:
            if confirm(f"Set gateway.controlUi.{key} to False?"):
                config["gateway"]["controlUi"][key] = False
                changed = True
                print(f"✅ {'Would set' if DRY_RUN else 'Set'} {key} to False")

    # NEW: Rate Limiting
    if "auth" not in config["gateway"]: config["gateway"]["auth"] = {}
    if config["gateway"]["auth"].get("rateLimit") is None or config["gateway"]["auth"].get("rateLimit") is False:
        if confirm("Enable gateway.auth.rateLimit (brute-force protection)?"):
            config["gateway"]["auth"]["rateLimit"] = {}
            changed = True
            print(f"✅ {'Would enable' if DRY_RUN else 'Enabled'} gateway rate limiting")

    # NEW: Trusted Proxies
    if config["gateway"].get("trustedProxies") != ["127.0.0.1"]:
        if confirm("Set gateway.trustedProxies to [\"127.0.0.1\"]?"):
            config["gateway"]["trustedProxies"] = ["127.0.0.1"]
            changed = True
            print(f"✅ {'Would set' if DRY_RUN else 'Set'} trustedProxies to [\"127.0.0.1\"]")

    # NEW: Allowed Origins
    default_origins = ["http://127.0.0.1", "http://localhost"]
    current_origins = config["gateway"]["controlUi"].get("allowedOrigins", [])
    if not any(o in current_origins for o in default_origins):
        if confirm(f"Add {default_origins} to allowedOrigins?"):
            config["gateway"]["controlUi"]["allowedOrigins"] = list(set(current_origins + default_origins))
            changed = True
            print(f"✅ {'Would add' if DRY_RUN else 'Added'} default allowed origins")

    # 2. Filesystem Isolation
    if "tools" not in config: config["tools"] = {}
    if "fs" not in config["tools"]: config["tools"]["fs"] = {}
    if config["tools"]["fs"].get("workspaceOnly") is not True:
        if confirm("Enable tools.fs.workspaceOnly?"):
            config["tools"]["fs"]["workspaceOnly"] = True
            changed = True
            print(f"✅ {'Would enable' if DRY_RUN else 'Enabled'} filesystem workspaceOnly")

    # 3. Agent Sandboxing (Updated to 'all')
    if "agents" not in config: config["agents"] = {}
    if "defaults" not in config["agents"]: config["agents"]["defaults"] = {}
    if "sandbox" not in config["agents"]["defaults"]: config["agents"]["defaults"]["sandbox"] = {}
    if config["agents"]["defaults"]["sandbox"].get("mode") != "all":
        if confirm("Enable agent sandboxing (mode: all)?"):
            config["agents"]["defaults"]["sandbox"]["mode"] = "all"
            changed = True
            print(f"✅ {'Would set' if DRY_RUN else 'Set'} agent sandboxing to 'all'")

    # 4. Channel Policies (Allowlist)
    if "channels" not in config: config["channels"] = {}
    for channel_name in ['telegram', 'signal']:
        if channel_name not in config["channels"]: config["channels"][channel_name] = {}
        for policy in ['dmPolicy', 'groupPolicy']:
            if config["channels"][channel_name].get(policy) != 'allowlist':
                if confirm(f"Set channels.{channel_name}.{policy} to allowlist?"):
                    config["channels"][channel_name][policy] = 'allowlist'
                    changed = True
                    print(f"✅ {'Would set' if DRY_RUN else 'Set'} channels.{channel_name}.{policy} to allowlist")

    # NEW: Dynamic Secret Injection
    if "telegram" in config["channels"]:
        token = config["channels"]["telegram"].get("botToken", "")
        if token and "${" not in token:
            if confirm("Inject environment variable for Telegram botToken?"):
                config["channels"]["telegram"]["botToken"] = "${TELEGRAM_BOT_TOKEN}"
                changed = True
                print(f"✅ {'Would inject' if DRY_RUN else 'Injected'} variable for Telegram token")

    # 5. Dangerous Tools (Global + Telegram)
    dangerous_tools = ["exec", "process", "nodes", "gateway", "cron", "bash", "shell"]
    
    if "tools" not in config: config["tools"] = {}
    if "deny" not in config["tools"]: config["tools"]["deny"] = []
    for tool in dangerous_tools:
        if tool not in config["tools"]["deny"]:
            if confirm(f"Add \"{tool}\" to global tools.deny?"):
                config["tools"]["deny"].append(tool)
                changed = True
                print(f"✅ {'Would add' if DRY_RUN else 'Added'} \"{tool}\" to global tools.deny")

    if "telegramBot" not in config: config["telegramBot"] = {}
    if "tools" not in config["telegramBot"]: config["telegramBot"]["tools"] = {}
    if "deny" not in config["telegramBot"]["tools"]: config["telegramBot"]["tools"]["deny"] = []
    
    for tool in dangerous_tools:
        if tool not in config["telegramBot"]["tools"]["deny"]:
            if confirm(f"Add \"{tool}\" to telegramBot.tools.deny?"):
                config["telegramBot"]["tools"]["deny"].append(tool)
                changed = True
                print(f"✅ {'Would add' if DRY_RUN else 'Added'} \"{tool}\" to telegramBot.tools.deny")

    # 6. Default Limits & History (Profile-based)
    if "history" not in config["agents"]["defaults"]: config["agents"]["defaults"]["history"] = {}
    if config["agents"]["defaults"]["history"].get("maxMessages") != SELECTED_PROFILE["maxMessages"]:
        if confirm(f"Set agents.defaults.history.maxMessages to {SELECTED_PROFILE['maxMessages']}?"):
            config["agents"]["defaults"]["history"]["maxMessages"] = SELECTED_PROFILE["maxMessages"]
            changed = True
            print(f"✅ {'Would set' if DRY_RUN else 'Set'} History Limit (maxMessages: {SELECTED_PROFILE['maxMessages']})")

    if "limits" not in config["agents"]["defaults"]: config["agents"]["defaults"]["limits"] = {}
    for key in ["maxSteps", "timeoutMs"]:
        if config["agents"]["defaults"]["limits"].get(key) != SELECTED_PROFILE[key]:
            if confirm(f"Set agents.defaults.limits.{key} to {SELECTED_PROFILE[key]}?"):
                config["agents"]["defaults"]["limits"][key] = SELECTED_PROFILE[key]
                changed = True
                print(f"✅ {'Would set' if DRY_RUN else 'Set'} agents.defaults.limits.{key} to {SELECTED_PROFILE[key]}")

    # 7. Output Filtering (v1.5)
    if "plugins" not in config: config["plugins"] = {}
    if "output_filter" not in config["plugins"]:
        if confirm("Enable output_filter plugin with default patterns?"):
            config["plugins"]["output_filter"] = {
                "enabled": True,
                "patterns": [
                    { "regex": "sk-[a-zA-Z0-9]{20,}", "replacement": "[SECRET REDACTED]" },
                    { "regex": "ghp_[a-zA-Z0-9]{20,}", "replacement": "[TOKEN REDACTED]" },
                    { "regex": "gsk_[a-zA-Z0-9]{20,}", "replacement": "[SECRET REDACTED]" },
                    { "regex": "eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9._-]{10,}\\.[A-Za-z0-9._-]{10,}", "replacement": "[JWT REDACTED]" }
                ]
            }
            changed = True
            print(f"✅ {'Would add' if DRY_RUN else 'Added'} default output_filter configuration")

    # 8. Logging & Discovery (NEW)
    if "discovery" not in config: config["discovery"] = {}
    if "mdns" not in config["discovery"]: config["discovery"]["mdns"] = {}
    if config["discovery"]["mdns"].get("mode") != "off":
        if confirm("Disable mDNS network discovery?"):
            config["discovery"]["mdns"]["mode"] = "off"
            changed = True
            print(f"✅ {'Would disable' if DRY_RUN else 'Disabled'} mDNS discovery")

    if "logging" not in config: config["logging"] = {}
    if config["logging"].get("redactSensitive") != "tools":
        if confirm("Enable sensitive log redaction (redactSensitive: tools)?"):
            config["logging"]["redactSensitive"] = "tools"
            changed = True
            print(f"✅ {'Would enable' if DRY_RUN else 'Enabled'} sensitive log redaction")

    if not config.get("logging") and not config.get("logs"):
        if confirm("Enable system logging?"):
            config["logging"] = { "level": "info", "file": "openclaw.log" }
            changed = True
            print(f"✅ {'Would enable' if DRY_RUN else 'Enabled'} system logging")

    # 9. Approval Gates for Data Ingestion (v1.5)
    untrusted_tools = ["web_search", "fetch", "read_url"]
    if PROFILE_NAME in ["recommended", "paranoid"]:
        if "approval_gates" not in config: config["approval_gates"] = []
        for tool in untrusted_tools:
            if tool not in str(config.get("approval_gates")):
                if confirm(f"Add approval_gate for tool '{tool}'?"):
                    if isinstance(config["approval_gates"], list):
                        config["approval_gates"].append(tool)
                        changed = True
                        print(f"✅ {'Would add' if DRY_RUN else 'Added'} approval_gate for {tool}")

    if changed:
        backup_file(DEFAULT_CONFIG_PATH)
        atomic_write_json(DEFAULT_CONFIG_PATH, config)
        if validate_json_config(DEFAULT_CONFIG_PATH):
            print(f"✅ Configuration {'checked (no changes)' if DRY_RUN else 'updated and re-validated'}.")
            return True
        else:
            print("⚠️ Configuration updated but FAILED validation! Manual check required.")
            return False
    return False

def fix_workspace_leaks():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Scanning workspace secrets...")
    
    if not REDACT_IN_PLACE and not DRY_RUN:
        print("ℹ️ In-place workspace redaction is disabled by default. Use --redact-in-place to enable it.")
        return

    patterns = [
        (re.compile(r'sk-[a-zA-Z0-9]{30,}'), 'sk-****'),
        (re.compile(r'gsk_[a-zA-Z0-9]{30,}'), 'gsk_****'),
        (re.compile(r'ghp_[A-Za-z0-9]{20,}'), 'ghp_****'),
        (re.compile(r'(PASSWORD\s*[:=]\s*)\S+', re.IGNORECASE), r'\1****'),
        (re.compile(r'((?:API_KEY|SECRET|TOKEN|PASSWORD)\s*[:=]\s*)\S+', re.IGNORECASE), r'\1[REDACTED]'),
    ]
    
    text_extensions = ('.md', '.json', '.env', '.credentials', '.txt', '.yaml', '.yml', '.toml', '.ini', '.conf', '.py', '.js', '.ts', '.sh', '.log')
    
    for root in DEFAULT_WORKSPACE_ROOTS:
        if not os.path.exists(root): continue
        for base, dirs, files in os.walk(root):
            if '.git' in base: continue
            for f_name in files:
                if f_name.endswith(text_extensions):
                    f_path = os.path.join(base, f_name)
                    try:
                        with open(f_path, 'r', errors='ignore') as f:
                            content = f.read()
                        
                        new_content = content
                        for pattern, replacement in patterns:
                            new_content = pattern.sub(replacement, new_content)
                        
                        if new_content != content:
                            if confirm(f"Redact secrets in {f_path}?"):
                                backup_file(f_path)
                                atomic_write_text(f_path, new_content)
                                print(f"✅ {'Would redact' if DRY_RUN else 'Redacted'} secrets in {f_path}")
                    except Exception as e:
                        print(f"❌ Failed to process workspace file {f_path}: {e}")

def fix_docker_compose():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Hardening docker-compose.yml...")
    possible_paths = ["docker-compose.yml", "../docker-compose.yml", "./docker-compose.yaml"]
    compose_path = None
    for p in possible_paths:
        if os.path.exists(p):
            compose_path = p
            break
    
    if not compose_path:
        print("ℹ️ docker-compose.yml not found. Skipping.")
        return

    try:
        with open(compose_path, "r") as f:
            lines = f.readlines()
        
        changed = False
        new_lines = []
        for line in lines:
            new_lines.append(line)
            # Simple heuristic: add security options after service name or image
            if "image:" in line and "openclaw" in line.lower():
                # Note: This is a very basic injector. Real YAML parsing is preferred.
                pass 

        # For v1.6, we will mostly report or do very safe string replacements
        # To avoid breaking YAML, we'll just check and warn for now, or do exact line replacement if missing
        content = "".join(lines)
        if "security_opt:" not in content:
            if confirm(f"Add security_opt to {compose_path}?"):
                # This is risky without a real parser, so we'll just print a recommendation for now
                # unless we want to implement a simple line injector.
                print(f"👉 Recommendation: Add 'security_opt: [\"no-new-privileges:true\"]' to {compose_path}")
        
        if "read_only:" not in content:
            if confirm(f"Enable read_only in {compose_path}?"):
                print(f"👉 Recommendation: Add 'read_only: true' to {compose_path}")

    except Exception as e:
        print(f"❌ Failed to process docker-compose.yml: {e}")

def restart_service():
    restart_cmd = os.getenv("OPENCLAW_RESTART_CMD")
    container = os.getenv("OPENCLAW_CONTAINER")

    if DRY_RUN:
        print("[Dry-Run] Would attempt service restart.")
        return

    if restart_cmd:
        print(f"[Restart] Using OPENCLAW_RESTART_CMD: {restart_cmd}")
        subprocess.run(restart_cmd, shell=True, check=False)
        return

    if container:
        print(f"[Restart] Restarting container: {container}")
        subprocess.run(["docker", "restart", container], check=False)
        return

    print("⚠️ No restart strategy configured. Manual restart may be required.")

def fix_host_services():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Ensuring critical host services are active...")
    services = ["ufw", "fail2ban"]
    for svc in services:
        if confirm(f"Ensure {svc} is enabled and started?"):
            if not DRY_RUN:
                try:
                    subprocess.run(["systemctl", "enable", svc], check=True)
                    subprocess.run(["systemctl", "start", svc], check=True)
                    if svc == "ufw":
                        subprocess.run("echo 'y' | ufw enable", shell=True, check=True)
                    print(f"✅ Enabled and started {svc}")
                except Exception as e:
                    print(f"❌ Failed to fix {svc}: {e}")

def main():
    print(f"--- OPENCLAW SECURITY FIXER v1.7 {'(DRY-RUN MODE)' if DRY_RUN else ''} ---")
    fix_permissions()
    config_changed = fix_config()
    fix_ssh_hardening()
    fix_docker_firewall()
    fix_host_services()
    fix_workspace_leaks()
    fix_docker_compose()
    
    print("\nManual-only remediation notes:")
    for note in MANUAL_ONLY_NOTES:
        print(f" - {note}")

    if config_changed and not DRY_RUN:
        print("\nAttempting service restart...")
        restart_service()

if __name__ == "__main__":
    main()
