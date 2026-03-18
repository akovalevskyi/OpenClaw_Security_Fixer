#!/usr/bin/env python3
import json
import os
import sys
import subprocess
import re
import math
import shlex
from datetime import datetime

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    RED = Fore.RED + Style.BRIGHT
    GREEN = Fore.GREEN + Style.BRIGHT
    YELLOW = Fore.YELLOW + Style.BRIGHT
    CYAN = Fore.CYAN + Style.BRIGHT
    RESET = Style.RESET_ALL
except ImportError:
    RED = GREEN = YELLOW = CYAN = RESET = ""

DEFAULT_CONFIG_PATH = os.getenv("OPENCLAW_CONFIG", "/data/.openclaw/openclaw.json")
DEFAULT_WORKSPACE_ROOTS = [
    os.getenv("OPENCLAW_WORKSPACES", "/data/.openclaw/workspaces"),
    os.getenv("OPENCLAW_WORKSPACE", "/data/.openclaw/workspace"),
]
DEFAULT_CONTAINER = os.getenv("OPENCLAW_CONTAINER")

TEXT_EXTENSIONS = (
    ".md", ".txt", ".json", ".env", ".credentials",
    ".yaml", ".yml", ".toml", ".ini", ".conf",
    ".py", ".js", ".ts", ".sh", ".log"
)

def make_issue(
    issue_id,
    severity,
    description,
    recommendation,
    category="general",
    component=None,
    path=None,
    line=None,
    evidence=None,
    auto_fixable=False,
):
    return {
        "id": issue_id,
        "severity": severity,
        "category": category,
        "component": component,
        "path": path,
        "line": line,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "auto_fixable": auto_fixable,
    }

def check_failed(issues, issue_id, description, component=None, path=None):
    issues.append(make_issue(
        issue_id,
        "INFO",
        description,
        "Rerun the audit with sufficient permissions and verify this check manually.",
        category="audit_reliability",
        component=component,
        path=path,
        auto_fixable=False,
    ))

def audit_config(config):
    issues = []
    gateway = config.get('gateway', {})
    control_ui = gateway.get('controlUi', {})
    
    if control_ui.get('allowInsecureAuth') is True:
        issues.append(make_issue('GW_INSECURE_AUTH', 'CRITICAL', 'Gateway allowInsecureAuth is enabled.', 'Set gateway.controlUi.allowInsecureAuth to false.', category='gateway_security', auto_fixable=True))
    
    if control_ui.get('dangerouslyDisableDeviceAuth') is True:
        issues.append(make_issue('GW_NO_DEVICE_AUTH', 'HIGH', 'Gateway dangerouslyDisableDeviceAuth is enabled.', 'Set gateway.controlUi.dangerouslyDisableDeviceAuth to false.', category='gateway_security', auto_fixable=True))
    
    tools = config.get('tools', {})
    fs = tools.get('fs', {})
    if fs.get('workspaceOnly') is not True:
        issues.append(make_issue('FS_NOT_ISOLATED', 'HIGH', 'Filesystem workspaceOnly is not enabled.', 'Set tools.fs.workspaceOnly to true.', category='tool_security', auto_fixable=True))
    
    agents = config.get('agents', {})
    defaults = agents.get('defaults', {})
    sandbox = defaults.get('sandbox', {})
    if sandbox.get('mode') == 'off':
        issues.append(make_issue('SANDBOX_OFF', 'CRITICAL', 'Agent sandbox is disabled.', 'Set agents.defaults.sandbox.mode to "on".', category='sandbox', auto_fixable=True))
    
    models = config.get('models', {})
    providers = models.get('providers', {})
    for p_name, p_data in providers.items():
        key = p_data.get('apiKey', '')
        if key and not key.startswith('$'):
             issues.append(make_issue(f'HARDCODED_KEY_{p_name.upper()}', 'CRITICAL', f'Hardcoded API key for {p_name}.', 'Use environment variables or vault.sh.', category='secret_management', component=p_name))
    
    channels = config.get('channels', {})
    tg = channels.get('telegram', {})
    if tg.get('botToken') and not tg.get('botToken').startswith('$'):
         issues.append(make_issue('HARDCODED_TG_TOKEN', 'CRITICAL', 'Hardcoded Telegram Bot Token.', 'Use environment variables.', category='secret_management', component='telegram'))
    
    for channel_name, channel_data in channels.items():
        if channel_name in ['telegram', 'signal']:
            if channel_data.get('dmPolicy') != 'allowlist':
                issues.append(make_issue(f'{channel_name.upper()}_DM_POLICY', 'CRITICAL', f'{channel_name} dmPolicy is not allowlist.', f'Set channels.{channel_name}.dmPolicy to "allowlist".', category='channel_security', auto_fixable=True))
            if channel_data.get('groupPolicy') != 'allowlist':
                issues.append(make_issue(f'{channel_name.upper()}_GROUP_POLICY', 'CRITICAL', f'{channel_name} groupPolicy is not allowlist.', f'Set channels.{channel_name}.groupPolicy to "allowlist".', category='channel_security', auto_fixable=True))

    telegram_bot = config.get('telegramBot', {})
    tb_tools = telegram_bot.get('tools', {})
    tb_deny = tb_tools.get('deny', [])
    
    dangerous_tools = ["exec", "process", "nodes", "gateway", "cron", "bash", "shell"]
    
    if not tb_tools or not tb_deny:
        issues.append(make_issue('TELEGRAM_NO_DENYLIST', 'CRITICAL', 'Telegram bot has no tools.deny section. All tools might be allowed.', 'Add a tools.deny section to telegramBot.', category='tool_security', component='telegram', auto_fixable=True))
    else:
        for tool in dangerous_tools:
            if tool not in tb_deny:
                issues.append(make_issue(f'TELEGRAM_DENY_{tool.upper()}', 'CRITICAL', f'Telegram bot does not deny dangerous tool: {tool}.', f'Add "{tool}" to telegramBot.tools.deny.', category='tool_security', component='telegram', auto_fixable=True))
    
    if not telegram_bot.get('budgets') and not config.get('gateway', {}).get('rateLimit'):
         issues.append(make_issue('NO_RATE_LIMITS', 'HIGH', 'No budgets or rate limits configured. Vulnerable to financial DoS.', 'Configure telegramBot.budgets or gateway rate limits.', category='financial_security'))

    # 2. Context Window Poisoning
    history_limit = config.get('agents', {}).get('defaults', {}).get('history', {}).get('maxMessages')
    if not history_limit:
        for agent in config.get('agents', {}).get('list', []):
            if not agent.get('history', {}).get('maxMessages'):
                issues.append(make_issue(
                    f'NO_HISTORY_LIMIT_{agent.get("id", "unknown")}', 
                    'WARNING', 
                    f'Agent {agent.get("id")} has no maxMessages limit. Vulnerable to context window poisoning.', 
                    'Set agents.defaults.history.maxMessages to a safe value (e.g., 50).', 
                    category='agent_security', 
                    auto_fixable=True
                ))

    if "sandbox" in defaults:
        if defaults["sandbox"].get("network") != "none":
            issues.append(make_issue('SANDBOX_NETWORK_EGRESS', 'WARNING', 'Agent sandbox network is not disabled. Agent could call external sites.', 'Set agents.defaults.sandbox.network to "none".', category='sandbox', auto_fixable=True))
    
    if not defaults.get("limits"):
         issues.append(make_issue('NO_AGENT_LIMITS', 'HIGH', 'No execution limits (timeouts, tool-call caps) defined for agents.', 'Configure agents.defaults.limits with maxSteps, timeout, etc.', category='agent_security', auto_fixable=True))

    if not gateway.get('approvalGates') and not config.get('approval_gates'):
         issues.append(make_issue('NO_APPROVAL_GATES', 'WARNING', 'Dangerous tools may run without human confirmation.', 'Enable approval gates for tools like exec, shell, write_file.', category='gateway_security'))
         
    if not config.get("plugins", {}).get("output_filter"):
        issues.append(make_issue('NO_OUTPUT_FILTERING', 'WARNING', 'No live output filtering configured to block secrets or prompt leaks.', 'Install or enable an output filtering middleware/plugin.', category='data_security'))

    # 8. System Prompt Presence
    for agent in config.get("agents", {}).get("list", []):
        if not agent.get("systemPrompt") and not defaults.get("systemPrompt"):
            issues.append(make_issue(f'NO_SYSTEM_PROMPT_{agent.get("id", "unknown").upper()}', 'HIGH', f'Agent {agent.get("id")} has no systemPrompt configured.', 'Configure a robust systemPrompt with defensive instructions.', category='prompt_security'))

    return issues

def audit_output_sanitization(config):
    issues = []
    output_filter = config.get("plugins", {}).get("output_filter", {})
    if not output_filter:
        return issues
    
    patterns = output_filter.get("patterns", [])
    if not patterns:
        issues.append(make_issue('OUTPUT_FILTER_NO_PATTERNS', 'HIGH', 'Output filter is enabled but has no redaction patterns.', 'Configure patterns for secrets (sk-, ghp_) and PII in output_filter plugin.', category='data_security', auto_fixable=True))
    else:
        essential_patterns = ["sk-", "ghp_", "password"]
        configured_patterns = str(patterns).lower()
        for p in essential_patterns:
            if p not in configured_patterns:
                issues.append(make_issue(f'OUTPUT_FILTER_MISSING_{p.upper()}', 'WARNING', f'Output filter is missing pattern for: {p}', f'Add a regex pattern to block {p} in the output_filter configuration.', category='data_security', auto_fixable=True))
    return issues

def audit_indirect_injection_vectors(config):
    issues = []
    defaults = config.get("agents", {}).get("defaults", {})
    untrusted_data_tools = ["web_search", "fetch", "read_url", "gmail.read"]
    approval_gates = str(config.get("approval_gates", []) or config.get("gateway", {}).get("approvalGates", []))
    
    for tool in untrusted_data_tools:
        is_denied_globally = tool in defaults.get("tools", {}).get("deny", [])
        if not is_denied_globally:
            if tool not in approval_gates:
                issues.append(make_issue(
                    f'INDIRECT_INJECTION_RISK_{tool.upper()}',
                    'HIGH',
                    f'Tool "{tool}" is enabled without human approval (HITL).',
                    f'Enable an approval_gate for "{tool}" to prevent indirect prompt injection from untrusted external data.',
                    category='prompt_security'
                ))
    return issues

def audit_monitoring_status(config):
    issues = []
    if not config.get("logging") and not config.get("logs"):
        issues.append(make_issue(
            'LOGGING_DISABLED',
            'WARNING',
            'System logging is disabled or not configured.',
            'Enable logging in openclaw.json for security auditing and forensics.',
            category='monitoring',
            auto_fixable=True
        ))
    return issues

def audit_prompt_defense_markers():
    issues = []
    defensive_keywords = ['ignore previous', 'do not share', 'system prompt', 'security', 'confidential', 'under no circumstances']
    
    for root in DEFAULT_WORKSPACE_ROOTS:
        if not os.path.exists(root): continue
        for base, dirs, files in os.walk(root):
            if '.git' in base: continue
            for f_name in ['SOUL.md', 'IDENTITY.md', 'system.md']:
                if f_name in files:
                    f_path = os.path.join(base, f_name)
                    try:
                        with open(f_path, 'r', errors='ignore') as f:
                            content = f.read().lower()
                            has_defense = any(kw in content for kw in defensive_keywords)
                            if not has_defense:
                                issues.append(make_issue(
                                    "MISSING_PROMPT_DEFENSE_MARKERS",
                                    "WARNING",
                                    f"Agent identity file {f_path} lacks defensive instructions.",
                                    "This is a heuristic check only. Add explicit anti-exfiltration and anti-prompt-extraction instructions, then validate with real prompt-injection tests.",
                                    category="prompt_security",
                                    path=f_path,
                                    auto_fixable=False,
                                ))
                    except Exception as e:
                        check_failed(issues, "CHECK_FAILED_PROMPT_DEFENSE", f"Failed to read identity file: {e}", path=f_path)
    return issues

def audit_permissions():
    issues = []
    checks = [(DEFAULT_CONFIG_PATH, '600'), (os.path.join(os.path.dirname(DEFAULT_CONFIG_PATH), 'credentials'), '700')]
    for path, mode in checks:
        if os.path.exists(path):
            try:
                curr = oct(os.stat(path).st_mode & 0o777)[2:]
                if curr != mode:
                    issues.append(make_issue(f'PERM_MISMATCH_{os.path.basename(path)}', 'WARNING', f'Perms for {path} are {curr} (expected {mode})', f'chmod {mode} {path}', category='permissions', path=path))
            except Exception as e:
                check_failed(issues, "CHECK_FAILED_PERMISSIONS", f"Failed to stat {path}: {e}", path=path)
    
    try:
        if os.getuid() == 0:
            issues.append(make_issue(
                "RUNNING_AS_ROOT", 
                "HIGH", 
                "Process is running as root.", 
                "Run the service as a non-privileged user. Note: Infrastructure audits (SSH) may require sudo, but the application should not run as root.", 
                category="host_security"
            ))
    except Exception as e:
        check_failed(issues, "CHECK_FAILED_ROOT", f"Failed to check UID: {e}")
    
    data_dir = os.path.dirname(DEFAULT_CONFIG_PATH)
    dirs_to_check = [('/data', '700'), (data_dir, '700'), (os.path.join(data_dir, '.signal-data'), '700')]
    for path, mode in dirs_to_check:
        if os.path.isdir(path):
            try:
                curr = oct(os.stat(path).st_mode & 0o777)[2:]
                if curr not in ['700', '711', '755']:
                    if curr != mode:
                        issues.append(make_issue(f'DIR_PERM_MISMATCH_{os.path.basename(path)}', 'HIGH', f'Directory perms for {path} are {curr} (expected {mode})', f'chmod {mode} {path}', category='permissions', path=path))
            except Exception as e:
                check_failed(issues, "CHECK_FAILED_DIR_PERMISSIONS", f"Failed to stat {path}: {e}", path=path)
                    
    try:
        with open('/proc/self/status', 'r') as f:
            if 'NoNewPrivs:\t0' in f.read():
                issues.append(make_issue('DOCKER_NO_NEW_PRIVS_MISSING', 'HIGH', 'Docker container lacks no-new-privileges security option.', 'Add security_opt: ["no-new-privileges:true"] to docker-compose.yml', category='container_security'))
    except Exception as e:
         check_failed(issues, "CHECK_FAILED_NO_NEW_PRIVS", f"Failed to check NoNewPrivs: {e}")
    
    return issues

def calculate_entropy(s):
    if not s: return 0
    probabilities = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in probabilities])
    return entropy

def tokenize_for_entropy(line):
    raw = re.split(r"[\s=:'\",(){}\[\]<>]+", line)
    return [t for t in raw if t]

def audit_workspace_leaks():
    issues = []
    
    SECRET_PATTERNS = [
        (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OPENAI_COMPATIBLE_KEY"),
        (re.compile(r"gsk_[A-Za-z0-9]{20,}"), "GROQ_KEY"),
        (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "GITHUB_PAT"),
        (re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{20,}\b"), "TELEGRAM_BOT_TOKEN"),
        (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----"), "PRIVATE_KEY_PEM"),
        (re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}"), "JWT"),
        (re.compile(r"(?:API_KEY|SECRET|TOKEN|PASSWORD)\s*[:=]\s*\S+", re.IGNORECASE), "GENERIC_SECRET_ASSIGNMENT"),
    ]
    
    for root in DEFAULT_WORKSPACE_ROOTS:
        if not os.path.exists(root): continue
        for base, dirs, files in os.walk(root):
            if '.git' in base: continue
            for f_name in files:
                if f_name.endswith(TEXT_EXTENSIONS):
                    f_path = os.path.join(base, f_name)
                    try:
                        with open(f_path, 'r', errors='ignore') as f:
                            for line_num, line in enumerate(f, 1):
                                for pattern, label in SECRET_PATTERNS:
                                    if pattern.search(line):
                                        issues.append(make_issue(
                                            "WORKSPACE_SECRET_PATTERN",
                                            "CRITICAL",
                                            f"Potential secret detected: {label}",
                                            "Remove plaintext secrets from workspaces and move them to a dedicated secret store.",
                                            category="secret_management",
                                            component="workspace_scan",
                                            path=f_path,
                                            line=line_num,
                                            evidence=line.strip()[:160],
                                            auto_fixable=False,
                                        ))
                                
                                for token in tokenize_for_entropy(line):
                                    if token.startswith(('http://', 'https://', 'ftp://')):
                                        continue
                                    if len(token) >= 32 and calculate_entropy(token) >= 4.5:
                                        if not re.fullmatch(r"[a-f0-9]{32,64}", token.lower()):
                                            issues.append(make_issue(
                                                "POTENTIAL_HIGH_ENTROPY_SECRET",
                                                "WARNING",
                                                "High-entropy token found.",
                                                "Verify whether this token is a secret or an expected identifier/hash.",
                                                category="secret_management",
                                                component="workspace_scan",
                                                path=f_path,
                                                line=line_num,
                                                evidence=token[:12] + "..." + token[-4:],
                                                auto_fixable=False,
                                            ))
                    except Exception as e:
                        check_failed(issues, "CHECK_FAILED_WORKSPACE_READ", f"Failed to scan workspace file {f_path}: {e}", path=f_path)
    return issues

def get_sshd_effective_config():
    result = subprocess.run(
        ["sshd", "-T"],
        capture_output=True,
        text=True,
        check=True
    )
    cfg = {}
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            cfg[parts[0].lower()] = parts[1]
    return cfg

def audit_ssh_config():
    issues = []
    try:
        cfg = get_sshd_effective_config()

        if cfg.get("port") == "22":
            issues.append(make_issue(
                "SSH_DEFAULT_PORT",
                "WARNING",
                "SSH is listening on the default port 22.",
                "Use a non-default SSH port or document why 22 is intentionally kept.",
                category="host_security",
                component="ssh",
                auto_fixable=False,
            ))

        if cfg.get("passwordauthentication", "").lower() == "yes":
            issues.append(make_issue(
                "SSH_PASSWORD_AUTH_ENABLED",
                "CRITICAL",
                "SSH password authentication is enabled.",
                "Set PasswordAuthentication no and rely on key-based authentication.",
                category="host_security",
                component="ssh",
                auto_fixable=False,
            ))

        if cfg.get("permitrootlogin", "").lower() not in ("no", "prohibit-password"):
            issues.append(make_issue(
                "SSH_ROOT_LOGIN_ALLOWED",
                "HIGH",
                "SSH root login is not fully disabled.",
                "Set PermitRootLogin no.",
                category="host_security",
                component="ssh",
                auto_fixable=False,
            ))
    except Exception as e:
        check_failed(issues, "CHECK_FAILED_SSH_AUDIT", f"SSH audit failed: {e}", component="ssh")

    return issues

def detect_openclaw_containers():
    if DEFAULT_CONTAINER:
        return [DEFAULT_CONTAINER]

    try:
        # Try discovery via label first
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}", "-f", "label=com.openclaw.service=true"],
            capture_output=True,
            text=True,
            check=True
        )
        names = [n.strip() for n in result.stdout.splitlines() if n.strip()]
        if names:
            return names

        # Fallback to name-based pattern matching
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=True
        )
        names = [n.strip() for n in result.stdout.splitlines() if n.strip()]
        return [n for n in names if "openclaw" in n.lower() or "gateway" in n.lower() or "agent" in n.lower()]
    except Exception:
        return []

def audit_docker_env_secrets():
    issues = []
    containers = detect_openclaw_containers()

    if not containers:
        check_failed(
            issues,
            "CHECK_SKIPPED_DOCKER_CONTAINER_DISCOVERY",
            "No OpenClaw-like containers were discovered.",
            component="docker"
        )
        return issues

    suspicious_keys = [
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "GROQ_API_KEY",
        "OPENROUTER_API_KEY",
        "TELEGRAM_BOT_TOKEN",
        "ANTHROPIC_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    ]

    for container in containers:
        try:
            result = subprocess.run(
                ["docker", "inspect", container, "--format", "{{range .Config.Env}}{{println .}}{{end}}"],
                capture_output=True,
                text=True,
                check=True
            )
            env_lines = result.stdout.splitlines()
            for key in suspicious_keys:
                if any(line.startswith(f"{key}=") for line in env_lines):
                    issues.append(make_issue(
                        "DOCKER_ENV_SECRET_PRESENT",
                        "HIGH",
                        f"Secret-like variable {key} is present in container environment.",
                        "Prefer file-based secrets, Docker secrets, or an external secret manager over long-lived environment exposure.",
                        category="secret_management",
                        component="docker",
                        evidence=f"container={container}, key={key}",
                        auto_fixable=False,
                    ))
        except Exception as e:
            check_failed(
                issues,
                "CHECK_FAILED_DOCKER_ENV_AUDIT",
                f"Docker env audit failed for {container}: {e}",
                component="docker"
            )

    return issues

def audit_container_runtime():
    issues = []
    containers = detect_openclaw_containers()
    if not containers:
        return issues

    for container in containers:
        try:
            result = subprocess.run(
                ["docker", "inspect", container],
                capture_output=True,
                text=True,
                check=True
            )
            data = json.loads(result.stdout)[0]
            host = data.get("HostConfig", {})
            config = data.get("Config", {})

            if host.get("Privileged"):
                issues.append(make_issue(
                    "CONTAINER_PRIVILEGED",
                    "CRITICAL",
                    f"Container {container} runs in privileged mode.",
                    "Disable privileged mode.",
                    category="container_security",
                    component="docker",
                    evidence=f"container={container}",
                ))

            if host.get("NetworkMode") == "host":
                issues.append(make_issue(
                    "CONTAINER_HOST_NETWORK",
                    "HIGH",
                    f"Container {container} uses host network mode.",
                    "Use bridge networking unless host networking is strictly required.",
                    category="container_security",
                    component="docker",
                    evidence=f"container={container}",
                ))

            if not host.get("ReadonlyRootfs"):
                issues.append(make_issue(
                    "CONTAINER_RW_ROOTFS",
                    "WARNING",
                    f"Container {container} has writable root filesystem.",
                    "Use read-only rootfs with dedicated writable mounts where possible.",
                    category="container_security",
                    component="docker",
                    evidence=f"container={container}",
                ))

            if not config.get("User"):
                issues.append(make_issue(
                    "CONTAINER_NO_USER_SET",
                    "HIGH",
                    f"Container {container} does not set an explicit non-root user.",
                    "Set a dedicated non-root user in the image or runtime config.",
                    category="container_security",
                    component="docker",
                    evidence=f"container={container}",
                ))
        except Exception as e:
            check_failed(
                issues,
                "CHECK_FAILED_CONTAINER_RUNTIME",
                f"Container runtime audit failed for {container}: {e}",
                component="docker"
            )
    return issues

def audit_docker_compose():
    issues = []
    # Search for docker-compose.yml in common locations
    possible_paths = ["docker-compose.yml", "../docker-compose.yml", "./docker-compose.yaml"]
    compose_path = None
    for p in possible_paths:
        if os.path.exists(p):
            compose_path = p
            break
    
    if not compose_path:
        return issues

    try:
        with open(compose_path, "r") as f:
            content = f.read()
            if "no-new-privileges:true" not in content.replace(" ", ""):
                issues.append(make_issue('DOCKER_COMPOSE_NO_NEW_PRIVS', 'HIGH', 'docker-compose.yml is missing no-new-privileges:true.', 'Add security_opt: ["no-new-privileges:true"] to your service definition.', category='container_security', path=compose_path, auto_fixable=True))
            if "read_only:true" not in content.replace(" ", ""):
                issues.append(make_issue('DOCKER_COMPOSE_RW_ROOTFS', 'WARNING', 'docker-compose.yml is missing read_only:true.', 'Set read_only: true and use volumes for writable paths.', category='container_security', path=compose_path, auto_fixable=True))
    except Exception as e:
        check_failed(issues, "CHECK_FAILED_DOCKER_COMPOSE", f"Failed to audit docker-compose.yml: {e}", path=compose_path)
    
    return issues

def dedupe_issues(issues):
    seen = set()
    deduped = []
    for item in issues:
        key = (
            item.get("id"),
            item.get("path"),
            item.get("line"),
            item.get("evidence"),
            item.get("description"),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped

def main():
    use_json = '--json' in sys.argv
    
    if not use_json:
        print(f'{CYAN}--- OPENCLAW SECURITY AUDIT v1.6 ---{RESET}')
    
    all_issues = []
    if os.path.exists(DEFAULT_CONFIG_PATH):
        try:
            with open(DEFAULT_CONFIG_PATH, 'r') as f:
                config = json.load(f)
            all_issues += audit_config(config)
            all_issues += audit_output_sanitization(config)
            all_issues += audit_indirect_injection_vectors(config)
            all_issues += audit_monitoring_status(config)
        except Exception as e:
            if not use_json: print(f"{RED}Error loading config: {e}{RESET}")    
    all_issues += audit_permissions()
    all_issues += audit_workspace_leaks()
    all_issues += audit_prompt_defense_markers()
    all_issues += audit_ssh_config()
    all_issues += audit_docker_env_secrets()
    all_issues += audit_container_runtime()
    all_issues += audit_docker_compose()
    
    all_issues = dedupe_issues(all_issues)
    
    if use_json:
        summary = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "issues_count": len(all_issues),
            "critical": sum(1 for i in all_issues if i["severity"] == "CRITICAL"),
            "high": sum(1 for i in all_issues if i["severity"] == "HIGH"),
            "warning": sum(1 for i in all_issues if i["severity"] == "WARNING"),
            "info": sum(1 for i in all_issues if i["severity"] == "INFO"),
            "issues": all_issues,
        }
        print(json.dumps(summary, indent=2))
        sys.exit(1 if any(i['severity'] in ['CRITICAL', 'HIGH'] for i in all_issues) else 0)

    if not all_issues:
        print(f'{GREEN}✅ No security issues found. System is hardened.{RESET}')
    else:
        print(f'{YELLOW}⚠️ Found {len(all_issues)} issues:\n{RESET}')
        for issue in all_issues:
            sev_color = RED if issue['severity'] == 'CRITICAL' else YELLOW
            print(f"[{sev_color}{issue['severity']}{RESET}] {issue['id']}\nDescription: {issue['description']}\nRecommendation: {issue['recommendation']}\n")
        
        if any(i['severity'] in ['CRITICAL', 'HIGH'] for i in all_issues):
            sys.exit(1)

if __name__ == '__main__':
    main()