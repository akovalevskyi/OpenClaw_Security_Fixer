# OpenClaw Security Checklist (Host & Infrastructure)

Этот чек-лист описывает критические шаги для обеспечения безопасности хоста (VPS), контейнеров и самой инсталляции OpenClaw.

## 🛡️ 1. Infrastructure Hardening (SSH & OS)
**Цель:** Изоляция сервера и предотвращение несанкционированного доступа.
- [ ] **SSH Port:** Использовать нестандартный порт (не 22). *Проверяется скриптом `security_audit.py`.*
- [ ] **SSH Auth:** Отключить вход по паролю (`PasswordAuthentication no`). Использовать только SSH-ключи. *Проверяется скриптом `security_audit.py`.*
- [ ] **Root Login:** Отключить прямой вход под root (`PermitRootLogin no`).
- [ ] **Fail2ban:** Установить и настроить для защиты SSH и других портов.
- [ ] **UFW Firewall:** Разрешить только необходимые порты (SSH, HTTP/HTTPS прокси). Все остальные закрыть.
- [ ] **Updates:** Настроить `unattended-upgrades` для автоматической установки патчей безопасности ОС.

## 📦 2. Docker & Container Security
**Цель:** Предотвращение побега из контейнера и минимизация векторов атак.
- [ ] **Privileged Mode:** Контейнер должен быть запущен **без** флага `--privileged`. *Проверяется скриптом `security_audit.py`.*
- [ ] **User:** Запускать процесс внутри контейнера от имени не-root пользователя. *Проверяется скриптом `security_audit.py`.*
- [ ] **Docker Socket:** Не монтировать `/var/run/docker.sock` внутрь контейнера. *Проверяется скриптом `security_audit.py`.*
- [ ] **Read-Only FS:** Монтировать корень контейнера в режиме read-only, используя тома для записи данных. *Проверяется скриптом `security_audit.py`.*
- [ ] **Capabilities:** Использовать `cap_drop: [ALL]` и явно разрешать только необходимые возможности.
- [ ] **No New Privs:** Включить опцию `no-new-privileges:true` в `docker-compose.yml`.

## 🔑 3. Secret Management
**Цель:** Защита финансовых ресурсов и персональных данных.
- [ ] **No Hardcoded Keys:** Удалить все ключи `sk-...` из `openclaw.json` и `docker-compose.yml`. *Проверяется скриптом `security_audit.py`.*
- [ ] **ENV Variables:** Не передавать долгоживущие секреты через переменные окружения контейнера. *Проверяется скриптом `security_audit.py`.*
- [ ] **Workspace Scanning:** Регулярно сканировать папки `workspaces` на наличие забытых ключей или паролей. *Автоматизировано в `security_fixer.py`.*
- [ ] **Vault:** Использовать `vault.sh` или аналоги для динамической инъекции секретов.

## 🦀 4. OpenClaw Application Hardening
**Цель:** Ограничение возможностей AI агента.
- [ ] **Sandboxing:** Убедиться, что `agents.defaults.sandbox.mode` установлено в `on`. *Автоматизировано в `security_fixer.py`.*
- [ ] **Network Egress:** Установить `sandbox.network` в `none` для агентов, которым не нужен интернет. *Проверяется скриптом `security_audit.py`.*
- [ ] **Allowlist Policy:** Установить `dmPolicy` и `groupPolicy` в `allowlist` для всех каналов (Telegram, Signal). *Автоматизировано в `security_fixer.py`.*
- [ ] **Dangerous Tools:** Добавить `exec`, `bash`, `shell` в `tools.deny` для публичных каналов. *Автоматизировано в `security_fixer.py`.*
- [ ] **Approval Gates:** Включить подтверждение человеком для опасных инструментов.

## 💾 5. Backups & Recovery
**Цель:** Возможность быстрого восстановления после сбоя или взлома.
- [ ] **Config Backups:** Скрипт `security_fixer.py` создает бэкапы автоматически, но их нужно хранить вне сервера.
- [ ] **Automated Backups:** Настроить ежедневный бэкап папки `/data` (включая БД и логи).
- [ ] **Restore Testing:** Проверить процедуру восстановления из бэкапа хотя бы один раз.

---
*Документ обновлен: Март 2026*
