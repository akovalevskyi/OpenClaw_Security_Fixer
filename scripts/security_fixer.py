#!/usr/bin/env python3
import json
import os
import sys
import subprocess
import re
from datetime import datetime
import shutil

# Global flag for dry-run
DRY_RUN = "--dry-run" in sys.argv

def backup_config(path):
    if DRY_RUN: return
    if os.path.exists(path):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{path}.{timestamp}.bak"
        shutil.copy2(path, backup_path)
        print(f"[Backup] Created backup at {backup_path}")

def atomic_write_json(path, data):
    if DRY_RUN:
        print(f"[Dry-Run] Would write updated config to {path}")
        return
    temp_path = f"{path}.tmp"
    with open(temp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(temp_path, path)

def fix_permissions():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Hardening file permissions...")
    paths_to_fix = [('/data/.openclaw/openclaw.json', '600'), ('/data/.openclaw/credentials', '700'), ('/data', '700'), ('/data/.openclaw', '700'), ('/data/.signal-data', '700')]
    for path, mode in paths_to_fix:
        if os.path.exists(path):
            try:
                if not DRY_RUN:
                    subprocess.run(["chmod", mode, path], check=True)
                print(f"✅ {'Would set' if DRY_RUN else 'Set'} {mode} for {path}")
            except Exception as e:
                print(f"❌ Failed to fix {path}: {e}")

def fix_config():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Hardening openclaw.json configuration...")
    config_path = "/data/.openclaw/openclaw.json"
    if not os.path.exists(config_path):
        print("❌ Config file not found.")
        return False

    with open(config_path, "r") as f:
        config = json.load(f)

    changed = False
    
    # 1. Gateway Hardening
    if "gateway" not in config: config["gateway"] = {}
    if "controlUi" not in config["gateway"]: config["gateway"]["controlUi"] = {}
    
    for key in ["allowInsecureAuth", "dangerouslyDisableDeviceAuth", "dangerouslyAllowHostHeaderOriginFallback"]:
        if config["gateway"]["controlUi"].get(key) is not False:
            config["gateway"]["controlUi"][key] = False
            changed = True
            print(f"✅ {'Would set' if DRY_RUN else 'Set'} {key} to False")

    # 2. Filesystem Isolation
    if "tools" not in config: config["tools"] = {}
    if "fs" not in config["tools"]: config["tools"]["fs"] = {}
    if config["tools"]["fs"].get("workspaceOnly") is not True:
        config["tools"]["fs"]["workspaceOnly"] = True
        changed = True
        print(f"✅ {'Would enable' if DRY_RUN else 'Enabled'} filesystem workspaceOnly")

    # 3. Agent Sandboxing
    if "agents" not in config: config["agents"] = {}
    if "defaults" not in config["agents"]: config["agents"]["defaults"] = {}
    if "sandbox" not in config["agents"]["defaults"]: config["agents"]["defaults"]["sandbox"] = {}
    if config["agents"]["defaults"]["sandbox"].get("mode") != "on":
        config["agents"]["defaults"]["sandbox"]["mode"] = "on"
        changed = True
        print(f"✅ {'Would enable' if DRY_RUN else 'Enabled'} agent sandboxing (mode: on)")

    # 4. Channel Policies (Allowlist)
    if "channels" not in config: config["channels"] = {}
    for channel_name in ['telegram', 'signal']:
        if channel_name not in config["channels"]: config["channels"][channel_name] = {}
        for policy in ['dmPolicy', 'groupPolicy']:
            if config["channels"][channel_name].get(policy) != 'allowlist':
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
            config["telegramBot"]["tools"]["deny"].append(tool)
            changed = True
            print(f"✅ {'Would add' if DRY_RUN else 'Added'} \"{tool}\" to telegramBot.tools.deny")

    # 6. Default Limits & History
    if "history" not in config["agents"]["defaults"]: config["agents"]["defaults"]["history"] = {}
    if not config["agents"]["defaults"]["history"].get("maxMessages"):
        config["agents"]["defaults"]["history"]["maxMessages"] = 50
        changed = True
        print(f"✅ {'Would add' if DRY_RUN else 'Added'} default History Limit (maxMessages: 50)")

    if "limits" not in config["agents"]["defaults"]:
        config["agents"]["defaults"]["limits"] = {"maxSteps": 30, "timeoutMs": 120000}
        changed = True
        print(f"✅ {'Would add' if DRY_RUN else 'Added'} default Agent Execution Limits")

    if changed:
        backup_config(config_path)
        atomic_write_json(config_path, config)
        print(f"✅ Configuration {'checked (no changes)' if DRY_RUN else 'updated'}.")
        return True
    return False

def fix_workspace_leaks():
    print(f"[Fixer] {'(Dry-Run) ' if DRY_RUN else ''}Scanning and redacting secrets in workspaces...")
    patterns = [
        (re.compile(r'sk-[a-zA-Z0-9]{30,}'), 'sk-****'),
        (re.compile(r'gsk_[a-zA-Z0-9]{30,}'), 'gsk_****'),
        (re.compile(r'(PASSWORD:\s*)\S+'), r'\1****'),
    ]
    
    workspace_roots = ['/data/.openclaw/workspaces', '/data/.openclaw/workspace']
    for root in workspace_roots:
        if not os.path.exists(root): continue
        for base, dirs, files in os.walk(root):
            if '.git' in base: continue
            for f_name in files:
                if f_name.endswith(('.md', '.json', '.env', '.credentials', '.txt')):
                    f_path = os.path.join(base, f_name)
                    try:
                        with open(f_path, 'r', errors='ignore') as f:
                            content = f.read()
                        
                        new_content = content
                        for pattern, replacement in patterns:
                            new_content = pattern.sub(replacement, new_content)
                        
                        if new_content != content:
                            if not DRY_RUN:
                                with open(f_path, 'w') as f:
                                    f.write(new_content)
                            print(f"✅ {'Would redact' if DRY_RUN else 'Redacted'} secrets in {f_path}")
                    except: pass

def main():
    print(f"--- OPENCLAW SECURITY FIXER v1.1 {'(DRY-RUN MODE)' if DRY_RUN else ''} ---")
    fix_permissions()
    config_changed = fix_config()
    fix_workspace_leaks()
    
    if config_changed and not DRY_RUN:
        print("\n⚠️ Restarting Gateway via docker (if available)...")
        # Attempt common restart methods
        try:
            subprocess.run(["docker", "restart", "openclaw-3g02-openclaw-1"], check=False)
            print("✅ Docker restart command sent.")
        except:
            print("❌ Manual restart required: 'openclaw gateway restart'")

if __name__ == "__main__":
    main()
