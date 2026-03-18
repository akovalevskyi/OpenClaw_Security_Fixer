#!/bin/bash

# OpenClaw Security Toolkit v1.4 - Interactive Menu

# Colors and formatting
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Get directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Preflight checks
command -v python3 >/dev/null 2>&1 || { echo -e "${RED}Error: python3 not found.${NC}"; exit 1; }
[[ -f "$DIR/scripts/security_audit.py" ]] || { echo -e "${RED}Error: scripts/security_audit.py not found.${NC}"; exit 1; }
[[ -f "$DIR/scripts/security_fixer.py" ]] || { echo -e "${RED}Error: scripts/security_fixer.py not found.${NC}"; exit 1; }

clear
echo -e "${CYAN}${BOLD}"
echo "       ___     🛡️      ___ "
echo "      /   \  [====]  /   \ "
echo "     |  |  |  \__/  |  |  |"
echo "      \  \ \__/__\__/ /  / "
echo "       \__\  (o o)  /__/   "
echo "          | /_++_\ |       "
echo "         /  |____|  \      "
echo "        / /        \ \     "
echo "       / /          \ \    "
echo "      \"-\"            \"-\"   "
echo -e "${NC}"
echo -e "${BLUE}${BOLD}================================================${NC}"
echo -e "${BLUE}${BOLD}   OpenClaw Security Toolkit - v1.4 Hardened   ${NC}"
echo -e "${BLUE}${BOLD}================================================${NC}"
echo ""

show_menu() {
    echo -e "Please select an operation to perform:"
    echo -e "  ${GREEN}[1]${NC} 🔍 Run Full Security Audit (Safe)"
    echo -e "  ${GREEN}[2]${NC} 📋 Generate Machine-Readable Audit (JSON)"
    echo -e "  ${YELLOW}[3]${NC} 🛡️  Fixer: Dry-Run (See what would change)"
    echo -e "  ${YELLOW}[4]${NC} 🧭 Fixer: Interactive mode (Guided)"
    echo -e "  ${RED}[5]${NC} 🛠️  Fixer: Apply Changes (Unattended)"
    echo -e "  ${CYAN}[6]${NC} 📕 View Threat Model & Manual Checklist"
    echo -e "  ${CYAN}[7]${NC} 🔎 Show Detected Environment"
    echo -e "  ${RED}[q]${NC} 🚪 Quit"
    echo ""
}

while true; do
    show_menu
    read -p "Select option [1-7, q]: " choice
    echo ""
    
    case $choice in
        1)
            echo -e "${GREEN}>>> Starting Security Audit...${NC}\n"
            python3 "$DIR/scripts/security_audit.py"
            echo -e "\n${GREEN}<<< Audit Complete.${NC}\n"
            ;;
        2)
            echo -e "${GREEN}>>> Generating JSON Audit Report...${NC}\n"
            python3 "$DIR/scripts/security_audit.py" --json
            echo -e "\n${GREEN}<<< JSON Output above.${NC}\n"
            ;;
        3)
            echo -e "${YELLOW}>>> Running Fixer in DRY-RUN mode...${NC}\n"
            python3 "$DIR/scripts/security_fixer.py" --dry-run
            echo -e "\n${YELLOW}<<< Dry-Run Complete. No files were modified.${NC}\n"
            ;;
        4)
            echo -e "${YELLOW}>>> Running Fixer in INTERACTIVE mode...${NC}\n"
            python3 "$DIR/scripts/security_fixer.py" --interactive
            echo -e "\n${YELLOW}<<< Interactive Fixer Complete.${NC}\n"
            ;;
        5)
            echo -e "${RED}>>> Starting Automated Fixer (LIVE)...${NC}"
            echo -e "${RED}WARNING: This will modify configs and potentially restart the gateway.${NC}"
            read -p "A backup will be created. Proceed? (y/N): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                echo ""
                python3 "$DIR/scripts/security_fixer.py"
            else
                echo -e "Operation cancelled.\n"
            fi
            echo -e "\n${RED}<<< Fixer Complete.${NC}\n"
            ;;
        6)
            echo -e "${CYAN}>>> Threat Model Highlights${NC}\n"
            if [[ -f "$DIR/docs/THREAT_MODEL.md" ]]; then
                head -n 25 "$DIR/docs/THREAT_MODEL.md"
            else
                echo "Threat model file not found at docs/THREAT_MODEL.md"
            fi
            echo -e "\n${CYAN}>>> Manual Checklist Preview${NC}\n"
            if [[ -f "$DIR/docs/openclaw_security_checklist.md" ]]; then
                head -n 25 "$DIR/docs/openclaw_security_checklist.md"
            else
                echo "Checklist file not found at docs/openclaw_security_checklist.md"
            fi
            echo -e "\n${CYAN}>>> Recent Config Backups:${NC}"
            data_dir=$(dirname "${OPENCLAW_CONFIG:-/data/.openclaw/openclaw.json}")
            ls -lt "$data_dir"/*.bak 2>/dev/null | head -n 5
            echo -e "\n${CYAN}<<< End of Info.${NC}\n"
            ;;
        7)
            echo -e "${CYAN}>>> Detected Environment${NC}\n"
            echo "Config Path:       ${OPENCLAW_CONFIG:-/data/.openclaw/openclaw.json}"
            echo "Container Name:    ${OPENCLAW_CONTAINER:-<auto-discovery>}"
            echo "Restart Command:   ${OPENCLAW_RESTART_CMD:-<not set>}"
            echo "Workspaces:        ${OPENCLAW_WORKSPACES:-/data/.openclaw/workspaces}"
            echo "Workspace Root:    ${OPENCLAW_WORKSPACE:-/data/.openclaw/workspace}"
            echo ""
            ;;
        q|Q)
            echo -e "Stay secure! 🦀🛡️ Goodbye."
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option. Please try again.${NC}\n"
            ;;
    esac
done
