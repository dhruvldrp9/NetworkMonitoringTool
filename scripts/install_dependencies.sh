#!/bin/bash
# Install required system dependencies
apt-get update
apt-get install -y libpcap-dev

# Install Python packages
pip install -r requirements.txt
