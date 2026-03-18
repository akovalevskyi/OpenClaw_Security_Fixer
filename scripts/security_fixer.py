#!/usr/bin/env python3
import json
import os
import sys
import subprocess
import re

def fix_permissions():
    print("[Fixer] Hardening file permissions...")
    paths_to_fix = [('/data/.openclaw/openclaw.json', '600'), ('/data/.openclaw/credentials', '700'), ('/data', '700'), ('/data/.openclaw', '700'), ('/data/.signal-data', '700')]
    for path, mode in paths_to_fix:
        if os.path.exists(path):
            try:
                subprocess.run(["chmod", mode, path], check=True)
                print(f"✅ Set {mode} for {path}")
            except Exception as e:
                print(f"❌ Failed to fix {path}: {e}")

def fix_config():
    print("[Fixer] Hardening openclaw.json configuration...")
    config_path = "/data/.openclaw/openclaw.json"
    if not os.path.exists(config_path):
        print("❌ Config file not found.")
        return False

    with open(config_path, "r") as f:
        config = json.load(f)

    changed = False
    
    # Standard Hardening
    if "gateway" not in config: config["gateway"] = {}
    if "controlUi" not in config["gateway"]: config["gateway"]["controlUi"] = {}
    
    for key in ["allowInsecureAuth", "dangerouslyDisableDeviceAuth", "dangerouslyAllowHostHeaderOriginFallback"]:
        if config["gateway"]["controlUi"].get(key) is not False:
            config["gateway"]["controlUi"][key] = False
            changed = True
            print(f"✅ Set {key} to False")

    if "tools" not in config: config["tools"] = {}
    if "fs" not in config["tools"]: config["tools"]["fs"] = {}
    if config["tools"]["fs"].get("workspaceOnly") is not True:
        config["tools"]["fs"]["workspaceOnly"] = True
        changed = True
        print("✅ Enabled filesystem workspaceOnly")

    # START_CUSTOM_CONFIG_FIXES
    if "agents" not in config: config["agents"] = {}
    if "defaults" not in config["agents"]: config["agents"]["defaults"] = {}
    if "sandbox" not in config["agents"]["defaults"]: config["agents"]["defaults"]["sandbox"] = {}
    if config["agents"]["defaults"]["sandbox"].get("mode") != "on":
        config["agents"]["defaults"]["sandbox"]["mode"] = "on"
        changed = True
        print("✅ Enabled agent sandboxing (mode: on)")
    # Fix for allowlist policy in channels
    if "channels" not in config: config["channels"] = {}
    for channel_name in ['telegram', 'signal']:
        if channel_name not in config["channels"]: config["channels"][channel_name] = {}
        if config["channels"][channel_name].get('dmPolicy') != 'allowlist':
            config["channels"][channel_name]['dmPolicy'] = 'allowlist'
            changed = True
            print(f"✅ Set channels.{channel_name}.dmPolicy to allowlist")
        if config["channels"][channel_name].get('groupPolicy') != 'allowlist':
            config["channels"][channel_name]['groupPolicy'] = 'allowlist'
            changed = True
            print(f"✅ Set channels.{channel_name}.groupPolicy to allowlist")

    # Fix for dangerous tools in telegram bot tools.deny
    if "telegramBot" not in config: config["telegramBot"] = {}
    if "tools" not in config["telegramBot"]: config["telegramBot"]["tools"] = {}
    if "deny" not in config["telegramBot"]["tools"]: config["telegramBot"]["tools"]["deny"] = []
    
    dangerous_tools = ["exec", "process", "nodes", "gateway", "cron"]
    for tool in dangerous_tools:
        if tool not in config["telegramBot"]["tools"]["deny"]:
            config["telegramBot"]["tools"]["deny"].append(tool)
            changed = True
            print(f"✅ Added \"{tool}\" to telegramBot.tools.deny")

    # ADVANCED AI SECURITY FIXES
    # 1. Add Default Rate Limiting if none exists
    if "gateway" not in config: config["gateway"] = {}
    if not config["gateway"].get("rateLimit"):
        config["gateway"]["rateLimit"] = {"max": 100, "timeWindow": 60000}
        changed = True
        print("✅ Added default Gateway Rate Limit (100 req/min)")
        
    # 2. Add History Boundary (Context Window limit)
    if "agents" not in config: config["agents"] = {}
    if "defaults" not in config["agents"]: config["agents"]["defaults"] = {}
    if "history" not in config["agents"]["defaults"]: config["agents"]["defaults"]["history"] = {}
    
    # Check if a limit already exists in defaults or any agent
    limit_exists = False
    if config["agents"]["defaults"]["history"].get("maxMessages"): limit_exists = True
    for a in config.get("agents", {}).get("list", []):
        if a.get("history", {}).get("maxMessages"): limit_exists = True
        
    if not limit_exists:
        config["agents"]["defaults"]["history"]["maxMessages"] = 50
        changed = True
        print("✅ Added default Agent History Limit (maxMessages: 50)")

    
    # 3. Add Execution Limits & Timeouts
    if "limits" not in config["agents"]["defaults"]:
        config["agents"]["defaults"]["limits"] = {
            "maxSteps": 30,
            "timeoutMs": 120000
        }
        changed = True
        print("✅ Added default Agent Execution Limits (maxSteps: 30, timeout: 2m)")
        
    # 4. Disable Sandbox Network Egress (if applicable)
    if config["agents"]["defaults"].get("sandbox"):
        if config["agents"]["defaults"]["sandbox"].get("network") != "none":
            config["agents"]["defaults"]["sandbox"]["network"] = "none"
            changed = True
            print("✅ Disabled network egress in Agent Sandbox")

    # END_CUSTOM_CONFIG_FIXES

    if changed:
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        print("✅ Configuration updated.")
        return True
    return False

def fix_workspace_leaks():
    print("[Fixer] Scanning and redacting secrets in workspaces...")
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
                            with open(f_path, 'w') as f:
                                f.write(new_content)
                            print(f"✅ Redacted secrets in {f_path}")
                    except: pass

def main():
    print("--- OPENCLAW SECURITY FIXER ---")
    fix_permissions()
    config_changed = fix_config()
    fix_workspace_leaks()
    
    # START_CUSTOM_SYSTEM_FIXES
    # END_CUSTOM_SYSTEM_FIXES

    if config_changed:
        print("\n⚠️ Restarting Gateway...")
        try:
            # We assume node server.mjs is the entry point
            subprocess.run(["node", "server.mjs", "gateway", "restart"], check=False)
            print("✅ Restart command sent.")
        except:
            print("❌ Manual restart required.")

if __name__ == "__main__":
    main()
