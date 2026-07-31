#!/bin/bash
# ── Deploy code updates to the running EC2 instance via NLB ──
# Usage: AWS_PROFILE=fortinet-admin ./deploy/update-ec2.sh
#
# This script SSHs into the EC2 instance through the NLB on port 2222,
# pulls the latest code from GitHub, reinstalls dependencies, and
# restarts the Streamlit service.
# Run this after pushing new code to the remote repo.

set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"

# Get the NLB DNS name from Terraform output
echo "Getting NLB DNS from Terraform..."
NLB_DNS=$(terraform -chdir="$DEPLOY_DIR" output -raw ssh_nlb_dns 2>/dev/null || echo "")

if [ -z "$NLB_DNS" ]; then
  echo "Error: Could not get NLB DNS. Is the infrastructure deployed?"
  echo "Run: cd $DEPLOY_DIR && terraform apply"
  exit 1
fi

KEY_FILE="${AWS_SSH_KEY:-$HOME/.ssh/aws-demo-us-west-2.pem}"
SSH_PORT=2222

echo "NLB DNS: $NLB_DNS"
echo "SSH port: $SSH_PORT"
echo "SSH key: $KEY_FILE"
echo ""

# SSH into EC2 via NLB on port 2222, pull latest code, reinstall deps, restart service
echo "Deploying update to EC2 (via NLB port $SSH_PORT)..."
ssh -o StrictHostKeyChecking=no -i "$KEY_FILE" -p "$SSH_PORT" "ec2-user@$NLB_DNS" bash << 'REMOTE_SCRIPT'
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
