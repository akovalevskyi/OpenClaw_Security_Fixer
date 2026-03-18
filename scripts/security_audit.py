#!/usr/bin/env python3
import json
import os
import sys
import subprocess
import re

def audit_config(config):
    issues = []
    gateway = config.get('gateway', {})
    control_ui = gateway.get('controlUi', {})
    
    if control_ui.get('allowInsecureAuth') is True:
        issues.append({'id': 'GW_INSECURE_AUTH', 'severity': 'CRITICAL', 'description': 'Gateway allowInsecureAuth is enabled.', 'recommendation': 'Set gateway.controlUi.allowInsecureAuth to false.'})
    
    if control_ui.get('dangerouslyDisableDeviceAuth') is True:
        issues.append({'id': 'GW_NO_DEVICE_AUTH', 'severity': 'HIGH', 'description': 'Gateway dangerouslyDisableDeviceAuth is enabled.', 'recommendation': 'Set gateway.controlUi.dangerouslyDisableDeviceAuth to false.'})
    
    tools = config.get('tools', {})
    fs = tools.get('fs', {})
    if fs.get('workspaceOnly') is not True:
        issues.append({'id': 'FS_NOT_ISOLATED', 'severity': 'HIGH', 'description': 'Filesystem workspaceOnly is not enabled.', 'recommendation': 'Set tools.fs.workspaceOnly to true.'})
    
    # START_CUSTOM_CONFIG_AUDITS
    agents = config.get('agents', {})
    defaults = agents.get('defaults', {})
    sandbox = defaults.get('sandbox', {})
    if sandbox.get('mode') == 'off':
        issues.append({'id': 'SANDBOX_OFF', 'severity': 'CRITICAL', 'description': 'Agent sandbox is disabled.', 'recommendation': 'Set agents.defaults.sandbox.mode to "on".'})
    
    # Check for hardcoded keys in models.providers
    models = config.get('models', {})
    providers = models.get('providers', {})
    for p_name, p_data in providers.items():
        key = p_data.get('apiKey', '')
        if key and not key.startswith('$'):
             issues.append({'id': f'HARDCODED_KEY_{p_name.upper()}', 'severity': 'CRITICAL', 'description': f'Hardcoded API key for {p_name}.', 'recommendation': 'Use environment variables or vault.sh.'})
    
    # Check for telegram bot token
    channels = config.get('channels', {})
    tg = channels.get('telegram', {})
    if tg.get('botToken') and not tg.get('botToken').startswith('$'):
         issues.append({'id': 'HARDCODED_TG_TOKEN', 'severity': 'CRITICAL', 'description': 'Hardcoded Telegram Bot Token.', 'recommendation': 'Use environment variables.'})
    # Check for allowlist policy in channels
    for channel_name, channel_data in channels.items():
        if channel_name in ['telegram', 'signal']:
            if channel_data.get('dmPolicy') != 'allowlist':
                issues.append({'id': f'{channel_name.upper()}_DM_POLICY', 'severity': 'CRITICAL', 'description': f'{channel_name} dmPolicy is not allowlist.', 'recommendation': f'Set channels.{channel_name}.dmPolicy to "allowlist".'})
            if channel_data.get('groupPolicy') != 'allowlist':
                issues.append({'id': f'{channel_name.upper()}_GROUP_POLICY', 'severity': 'CRITICAL', 'description': f'{channel_name} groupPolicy is not allowlist.', 'recommendation': f'Set channels.{channel_name}.groupPolicy to "allowlist".'})

    # Check for dangerous tools in telegram bot tools.deny
    telegram_bot = config.get('telegramBot', {})
    if 'tools' in telegram_bot and 'deny' in telegram_bot['tools']:
        dangerous_tools = ["exec", "process", "nodes", "gateway", "cron"]
        for tool in dangerous_tools:
            if tool not in telegram_bot['tools']['deny']:
                issues.append({'id': f'TELEGRAM_DENY_{tool.upper()}', 'severity': 'CRITICAL', 'description': f'Telegram bot does not deny dangerous tool: {tool}.', 'recommendation': f'Add "{tool}" to telegramBot.tools.deny.'})
    # END_CUSTOM_CONFIG_AUDITS
    
    return issues

def audit_permissions():
    issues = []
    checks = [('/data/.openclaw/openclaw.json', '600'), ('/data/.openclaw/credentials', '700')]
    for path, mode in checks:
        if os.path.exists(path):
            curr = oct(os.stat(path).st_mode & 0o777)[2:]
            if curr != mode:
                issues.append({'id': f'PERM_MISMATCH_{os.path.basename(path)}', 'severity': 'WARNING', 'description': f'Perms for {path} are {curr} (expected {mode})', 'recommendation': f'chmod {mode} {path}'})
    
    # START_CUSTOM_PERMISSION_AUDITS
    try:
        if os.getuid() == 0:
            issues.append({'id': 'RUNNING_AS_ROOT', 'severity': 'HIGH', 'description': 'Process is running as root.', 'recommendation': 'Run as a non-privileged user.'})
    except: pass
    
    dirs_to_check = [('/data', '700'), ('/data/.openclaw', '700'), ('/data/.signal-data', '700')]
    for path, mode in dirs_to_check:
        if os.path.isdir(path):
            curr = oct(os.stat(path).st_mode & 0o777)[2:]
            if curr not in ['700', '711', '755']:
                if curr != mode:
                    issues.append({'id': f'DIR_PERM_MISMATCH_{os.path.basename(path)}', 'severity': 'HIGH', 'description': f'Directory perms for {path} are {curr} (expected {mode})', 'recommendation': f'chmod {mode} {path}'})
                    
    try:
        with open('/proc/self/status', 'r') as f:
            if 'NoNewPrivs:\t0' in f.read():
                issues.append({'id': 'DOCKER_NO_NEW_PRIVS_MISSING', 'severity': 'HIGH', 'description': 'Docker container lacks no-new-privileges security option.', 'recommendation': 'Add security_opt: ["no-new-privileges:true"] to docker-compose.yml'})
    except: pass
    # END_CUSTOM_PERMISSION_AUDITS
    
    return issues

def audit_workspace_leaks():
    issues = []
    # Patterns for common secrets: OpenAI, Groq, OpenRouter, generic passwords
    patterns = [
        (re.compile(r'sk-[a-zA-Z0-9]{30,}'), 'OpenAI/OpenRouter API Key'),
        (re.compile(r'gsk_[a-zA-Z0-9]{30,}'), 'Groq API Key'),
        (re.compile(r'PASSWORD:\s*\S+'), 'Plaintext Password'),
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
                            for pattern, desc in patterns:
                                if pattern.search(content):
                                    issues.append({
                                        'id': 'DATA_LEAK_IN_WORKSPACE',
                                        'severity': 'CRITICAL',
                                        'description': f'Potential {desc} found in {f_path}',
                                        'recommendation': f'Redact secrets in {f_path} and move to vault.sh.'
                                    })
                    except: pass
    return issues

def main():
    print('--- OPENCLAW SECURITY AUDIT ---')
    config_path = '/data/.openclaw/openclaw.json'
    
    all_issues = []
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = json.load(f)
        all_issues += audit_config(config)
    
    all_issues += audit_permissions()
    all_issues += audit_workspace_leaks()
    
    if not all_issues:
        print('✅ No security issues found. System is hardened.')
    else:
        print(f'⚠️ Found {len(all_issues)} issues:\n')
        for issue in all_issues:
            print(f"[{issue['severity']}] {issue['id']}\nDescription: {issue['description']}\nRecommendation: {issue['recommendation']}\n")

if __name__ == '__main__':
    main()
