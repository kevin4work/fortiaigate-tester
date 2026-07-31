#!/bin/bash
# ── Deploy code updates to the running EC2 instance ──
# Usage: AWS_PROFILE=fortinet-admin ./deploy/update-ec2.sh
#
# This script SSHs into the EC2 instance, pulls the latest code from GitHub,
# reinstalls dependencies, and restarts the Streamlit service.
# Run this after pushing new code to the remote repo.

set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"

# Get the EC2 public IP from Terraform output
echo "Getting EC2 instance details from Terraform..."
EC2_IP=$(terraform -chdir="$DEPLOY_DIR" output -raw ec2_public_ip 2>/dev/null || echo "")

if [ -z "$EC2_IP" ]; then
  echo "Error: Could not get EC2 public IP. Is the infrastructure deployed?"
  echo "Run: cd $DEPLOY_DIR && terraform apply"
  exit 1
fi

KEY_FILE="${AWS_SSH_KEY:-$HOME/.ssh/aws-demo-us-west-2.pem}"

echo "EC2 public IP: $EC2_IP"
echo "SSH key: $KEY_FILE"
echo ""

# SSH into EC2, pull latest code, reinstall deps, restart service
echo "Deploying update to EC2..."
ssh -o StrictHostKeyChecking=no -i "$KEY_FILE" "ec2-user@$EC2_IP" bash << 'REMOTE_SCRIPT'
set -euo pipefail
APP_DIR="/opt/fortiaigate-tester"

echo "=== Pulling latest code from GitHub ==="
cd "$APP_DIR"
git pull

echo "=== Reinstalling dependencies ==="
.venv/bin/pip install -r requirements.txt

echo "=== Restarting Streamlit service ==="
sudo systemctl restart fortiaigate-tester
sleep 3
sudo systemctl status fortiaigate-tester --no-pager || true

echo "=== Update complete ==="
REMOTE_SCRIPT

echo ""
echo "Done! The app should be running with the latest code."
echo "Check the app URL: $(terraform -chdir="$DEPLOY_DIR" output -raw app_url)"
