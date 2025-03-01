#!/bin/bash

# Define colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Function to check if a file/directory exists
check_path() {
    if [ -e "$1" ]; then
        echo -e "${GREEN}✓${NC} $1 exists"
        return 0
    else
        echo -e "${RED}✗${NC} $1 is missing"
        return 1
    fi
}

# Check core directories
directories=(
    "data/rules"
    "models/trained"
    "scripts"
    "static/css"
    "static/js"
    "static/sounds"
    "templates"
    ".github"
)

# Check essential files
files=(
    "requirements.txt"
    "pyproject.toml"
    "README.md"
    "CONTRIBUTING.md"
    "DOCUMENTATION.md"
    "LICENSE"
    ".gitignore"
    ".replit"
    "network_analyzer.py"
    "dashboard.py"
)

echo "Verifying project structure..."
echo "-----------------------------"

# Check directories
echo "Checking directories..."
for dir in "${directories[@]}"; do
    check_path "$dir"
done

echo -e "\nChecking files..."
for file in "${files[@]}"; do
    check_path "$file"
done

echo -e "\nChecking setup scripts..."
check_path "scripts/install_dependencies.sh"
check_path "scripts/setup_project.sh"
check_path "scripts/generate_requirements.py"

# Make scripts executable
chmod +x scripts/*.sh

echo -e "\nProject structure verification complete!"
