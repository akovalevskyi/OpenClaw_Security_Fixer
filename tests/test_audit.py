import sys
import os
import pytest

# Add scripts directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts')))

from security_audit import audit_config

def test_audit_insecure_auth():
    config = {
        "gateway": {
            "controlUi": {"allowInsecureAuth": True}
        }
    }
    issues = audit_config(config)
    assert any(i['id'] == 'GW_INSECURE_AUTH' for i in issues)

def test_audit_telegram_deny_missing():
    config = {
        "telegramBot": {} # No tools section
    }
    issues = audit_config(config)
    assert any(i['id'] == 'TELEGRAM_NO_DENYLIST' for i in issues)

def test_audit_history_limit_missing():
    config = {
        "agents": {
            "defaults": {"history": {}},
            "list": [{"id": "main", "history": {}}]
        }
    }
    issues = audit_config(config)
    assert any(i['id'] == 'NO_HISTORY_LIMIT_main' for i in issues)
