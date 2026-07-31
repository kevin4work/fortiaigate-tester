#!/bin/bash
set -euo pipefail

# ── FortiAIGate Attack Tester — EC2 bootstrap script ──
# Installs Python 3.12, clones the repo, installs deps, runs Streamlit as a systemd service.

# Update system
dnf update -y

# Install Python 3.12, pip, git
dnf install -y python3.12 python3.12-pip git

# Create app directory
APP_DIR="/opt/fortiaigate-tester"
mkdir -p "$APP_DIR"
chown ec2-user:ec2-user "$APP_DIR"

# Clone the repo (or update if already cloned)
runuser -u ec2-user -- bash -c '
  if [ -d "/opt/fortiaigate-tester/.git" ]; then
    cd /opt/fortiaigate-tester && git pull
  else
    git clone https://github.com/kevin4work/fortiaigate-tester.git /opt/fortiaigate-tester
  fi
'

# Install Python dependencies into a venv
runuser -u ec2-user -- bash -c '
  python3.12 -m venv /opt/fortiaigate-tester/.venv
  /opt/fortiaigate-tester/.venv/bin/pip install --upgrade pip
  /opt/fortiaigate-tester/.venv/bin/pip install -r /opt/fortiaigate-tester/requirements.txt
'

# Create systemd service for Streamlit
cat > /etc/systemd/system/fortiaigate-tester.service << 'UNITFILE'
[Unit]
Description=FortiAIGate Attack Tester (Streamlit)
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/opt/fortiaigate-tester/attack_tester
ExecStart=/opt/fortiaigate-tester/.venv/bin/streamlit run app.py
Restart=always
RestartSec=5
Environment=STREAMLIT_SERVER_HEADLESS=true
Environment=STREAMLIT_SERVER_PORT=8501
Environment=STREAMLIT_SERVER_ADDRESS=0.0.0.0

[Install]
WantedBy=multi-user.target
UNITFILE

# Enable and start the service
systemctl daemon-reload
systemctl enable fortiaigate-tester
systemctl start fortiaigate-tester

# Wait for the service to be active
sleep 5
systemctl status fortiaigate-tester --no-pager || true
