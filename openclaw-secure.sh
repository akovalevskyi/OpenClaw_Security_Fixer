#!/bin/bash

# OpenClaw Security Toolkit v1.1 - Interactive Menu

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
echo -e "${BLUE}${BOLD}   OpenClaw Security Toolkit - v1.2 Enterprise  ${NC}"
echo -e "${BLUE}${BOLD}================================================${NC}"
echo ""

show_menu() {
    echo -e "Please select an operation to perform:"
    echo -e "  ${GREEN}[1]${NC} 🔍 Run Full Security Audit (Safe)"
    echo -e "  ${GREEN}[2]${NC} 📋 Generate Machine-Readable Audit (JSON)"
    echo -e "  ${YELLOW}[3]${NC} 🛡️  Fixer: Dry-Run (See what would change)"
    echo -e "  ${RED}[4]${NC} 🛠️  Fixer: Apply Changes (With auto-backup)"
    echo -e "  ${CYAN}[5]${NC} 📕 View Threat Model & Manual Checklist"
    echo -e "  ${RED}[q]${NC} 🚪 Quit"
    echo ""
}

while true; do
    show_menu
    read -p "Select option [1-5, q]: " choice
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
        5)
            echo -e "${CYAN}>>> Threat Model Highlights${NC}\n"
            head -n 20 "$DIR/docs/THREAT_MODEL.md"
            echo -e "\n${CYAN}>>> Manual Checklist Preview${NC}\n"
            head -n 15 "$DIR/docs/openclaw_security_checklist.md"
            echo -e "\n${CYAN}>>> Recent Config Backups:${NC}"
            ls -lt /data/.openclaw/*.bak 2>/dev/null | head -n 5
            echo -e "\n${CYAN}<<< End of Info.${NC}\n"
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
