#!/bin/bash
# Install required system dependencies
apt-get update
apt-get install -y libpcap-dev

# Generate requirements.txt from pyproject.toml
python3 scripts/generate_requirements.py

# Install Python packages
pip install -r requirements.txt