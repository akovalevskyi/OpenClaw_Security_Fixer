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
    "SSH hardening is not auto-remediated by this fixer.",
    "Docker runtime settings (privileged, network_mode, etc.) must be fixed in docker-compose.yml manually.",
]

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

    # 2. Filesystem Isolation
    if "tools" not in config: config["tools"] = {}
    if "fs" not in config["tools"]: config["tools"]["fs"] = {}
    if config["tools"]["fs"].get("workspaceOnly") is not True:
        if confirm("Enable tools.fs.workspaceOnly?"):
            config["tools"]["fs"]["workspaceOnly"] = True
            changed = True
            print(f"✅ {'Would enable' if DRY_RUN else 'Enabled'} filesystem workspaceOnly")

    # 3. Agent Sandboxing
    if "agents" not in config: config["agents"] = {}
    if "defaults" not in config["agents"]: config["agents"]["defaults"] = {}
    if "sandbox" not in config["agents"]["defaults"]: config["agents"]["defaults"]["sandbox"] = {}
    if config["agents"]["defaults"]["sandbox"].get("mode") != "on":
        if confirm("Enable agent sandboxing (mode: on)?"):
            config["agents"]["defaults"]["sandbox"]["mode"] = "on"
            changed = True
            print(f"✅ {'Would enable' if DRY_RUN else 'Enabled'} agent sandboxing (mode: on)")

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

    # 5. Telegram Dangerous Tools
    if "telegramBot" not in config: config["telegramBot"] = {}
    if "tools" not in config["telegramBot"]: config["telegramBot"]["tools"] = {}
    if "deny" not in config["telegramBot"]["tools"]: config["telegramBot"]["tools"]["deny"] = []
    
    dangerous_tools = ["exec", "process", "nodes", "gateway", "cron", "bash", "shell"]
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

    # 8. Logging (v1.5)
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
        (re.compile(r'(PASSWORD:\s*)\S+'), r'\1****'),
        (re.compile(r'(?:API_KEY|SECRET|TOKEN|PASSWORD)\s*[:=]\s*\S+', re.IGNORECASE), "REDACTED_SECRET"),
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

def main():
    print(f"--- OPENCLAW SECURITY FIXER v1.5 {'(DRY-RUN MODE)' if DRY_RUN else ''} ---")
    fix_permissions()
    config_changed = fix_config()
    fix_workspace_leaks()
    
    print("\nManual-only remediation notes:")
    for note in MANUAL_ONLY_NOTES:
        print(f" - {note}")

    if config_changed and not DRY_RUN:
        print("\nAttempting service restart...")
        restart_service()

if __name__ == "__main__":
    main()
