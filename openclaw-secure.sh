#!/bin/bash

# OpenClaw Security Toolkit - Interactive Menu

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
echo -e "${BLUE}${BOLD}   OpenClaw Security Toolkit - The Guardian     ${NC}"
echo -e "${BLUE}${BOLD}================================================${NC}"
echo ""

show_menu() {
    echo -e "Please select an operation to perform:"
    echo -e "  ${GREEN}[1]${NC} 🔍 Run Full Security Audit (Safe)"
    echo -e "  ${YELLOW}[2]${NC} 🛠️  Apply Automated Fixes (Modifies config)"
    echo -e "  ${CYAN}[3]${NC} 📋 View Manual Host Checklist"
    echo -e "  ${RED}[q]${NC} 🚪 Quit"
    echo ""
}

while true; do
    show_menu
    read -p "Select option [1-3, q]: " choice
    echo ""
    
    case $choice in
        1)
            echo -e "${GREEN}>>> Starting Security Audit...${NC}\n"
            python3 "$DIR/scripts/security_audit.py"
            echo -e "\n${GREEN}<<< Audit Complete.${NC}\n"
            ;;
        2)
            echo -e "${YELLOW}>>> Starting Automated Fixer...${NC}"
            echo -e "${RED}WARNING: This may modify your openclaw.json and restart the gateway.${NC}"
            read -p "Are you sure you want to proceed? (y/N): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                echo ""
                python3 "$DIR/scripts/security_fixer.py"
            else
                echo -e "Operation cancelled.\n"
            fi
            echo -e "\n${YELLOW}<<< Fixer Complete.${NC}\n"
            ;;
        3)
            echo -e "${CYAN}>>> Host Security Checklist${NC}\n"
            cat "$DIR/docs/openclaw_security_checklist.md"
            echo -e "\n${CYAN}<<< End of Checklist.${NC}\n"
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