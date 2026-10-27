#!/bin/bash
# ── Deploy code updates to the running EC2 instance via NLB ──
# Usage: AWS_PROFILE=fortinet-admin ./deploy/update-ec2.sh
#
# This script SSHs into the EC2 instance through the NLB on port 2222,
# pulls the latest code from GitHub, installs app and runner dependencies,
# provisions a loopback-only runner, and restarts both services.
# Run this after pushing new code to the remote main branch.

set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"

# Prefer an explicit override, then Terraform state, then this deployment's known NLB.
DEFAULT_NLB_DNS="fortiaigate-tester-nlb-f602ec6341a5956d.elb.us-west-2.amazonaws.com"
NLB_DNS="${AWS_SSH_NLB_DNS:-}"
if [ -z "$NLB_DNS" ]; then
  echo "Getting NLB DNS from Terraform..."
  if ! NLB_DNS=$(terraform -chdir="$DEPLOY_DIR" output -raw ssh_nlb_dns 2>/dev/null); then
    echo "Warning: Terraform output 'ssh_nlb_dns' is unavailable; using configured NLB $DEFAULT_NLB_DNS"
    NLB_DNS="$DEFAULT_NLB_DNS"
  elif [ -z "$NLB_DNS" ]; then
    echo "Warning: Terraform returned an empty NLB DNS; using configured NLB $DEFAULT_NLB_DNS"
    NLB_DNS="$DEFAULT_NLB_DNS"
  fi
fi

if [ -z "$NLB_DNS" ]; then
  echo "Error: NLB DNS is empty. Set AWS_SSH_NLB_DNS or configure Terraform output 'ssh_nlb_dns'." >&2
  exit 1
fi

SSH_PORT="${AWS_SSH_PORT:-2222}"
KEY_FILE="${AWS_SSH_KEY:-$DEPLOY_DIR/../aws-demo-us-west-2.pem}"
DEPLOY_BRANCH="${DEPLOY_BRANCH:-main}"
if [[ ! "$DEPLOY_BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] || ! git -C "$DEPLOY_DIR/.." check-ref-format --branch "$DEPLOY_BRANCH" >/dev/null 2>&1; then
  echo "Error: Invalid deployment branch name." >&2
  exit 1
fi

printf 'NLB DNS: %s\nSSH port: %s\nSSH key: %s\n\n' "$NLB_DNS" "$SSH_PORT" "$KEY_FILE"
echo "Deploying branch '$DEPLOY_BRANCH' to EC2..."
ssh -i "$KEY_FILE" -p "$SSH_PORT" \
  "ec2-user@$NLB_DNS" "DEPLOY_BRANCH='$DEPLOY_BRANCH' bash" <<'REMOTE_SCRIPT'
set -euo pipefail
APP_DIR="/opt/fortiaigate-tester"
RUNNER_ENV_FILE="/etc/fortiaigate-runner.env"

cd "$APP_DIR"
if [ -n "$(git status --porcelain)" ]; then
  echo "Error: EC2 checkout has local changes; refusing to overwrite them." >&2
  exit 1
fi

echo "=== Pulling branch '$DEPLOY_BRANCH' from GitHub ==="
git fetch origin "$DEPLOY_BRANCH"
if [ "$(git rev-parse --abbrev-ref HEAD)" = "$DEPLOY_BRANCH" ]; then
  git merge --ff-only "origin/$DEPLOY_BRANCH"
else
  git checkout -B "$DEPLOY_BRANCH" "origin/$DEPLOY_BRANCH"
fi

echo "=== Installing app dependencies ==="
.venv/bin/pip install --quiet --no-cache-dir -r requirements.txt

if [ ! -x .venv-runner/bin/python ]; then
  AVAILABLE_KB=$(df -Pk / | awk 'NR==2 {print $4}')
  if [ "$AVAILABLE_KB" -lt 6291456 ]; then
    echo "Error: less than 6 GB free on / for the runner venv; grow the root volume first." >&2
    exit 1
  fi
  python3.12 -m venv .venv-runner
fi

echo "=== Installing runner dependencies ==="
PIP_TMP_DIR=$(mktemp -d /var/tmp/fortiaigate-pip.XXXXXX)
trap 'rmdir "$PIP_TMP_DIR" 2>/dev/null || true' EXIT
TMPDIR="$PIP_TMP_DIR" .venv-runner/bin/pip install --quiet --no-cache-dir -r runner/requirements.lock
rmdir "$PIP_TMP_DIR"
trap - EXIT
.venv-runner/bin/python -c 'import fastapi, garak, httpx, uvicorn'
.venv/bin/python -c 'import streamlit, requests'

# Keep an existing service token and run history; never print or rotate either.
mkdir -p "$APP_DIR/.runner-data"
if [ ! -f "$RUNNER_ENV_FILE" ]; then
  TOKEN="$(openssl rand -hex 32)"
  sudo install -m 600 -o root -g root /dev/null "$RUNNER_ENV_FILE"
  if ! (umask 077; printf 'FORTIAIGATE_RUNNER_TOKEN=%s\nFORTIAIGATE_RUNNER_DATA=%s\nFORTIAIGATE_SCANS_ENABLED=true\n' \
    "$TOKEN" "$APP_DIR/.runner-data" | sudo tee "$RUNNER_ENV_FILE" >/dev/null); then
    unset TOKEN
    echo "Error: could not provision the runner environment file." >&2
    exit 1
  fi
  unset TOKEN
  sudo chown root:root "$RUNNER_ENV_FILE"
  sudo chmod 600 "$RUNNER_ENV_FILE"
  sudo restorecon "$RUNNER_ENV_FILE" 2>/dev/null || true
  echo "Created runner environment file with a new service token (not printed)."
fi

if ! sudo grep -qx 'FORTIAIGATE_SCANS_ENABLED=true' "$RUNNER_ENV_FILE" || \
   ! sudo grep -q '^FORTIAIGATE_RUNNER_TOKEN=.' "$RUNNER_ENV_FILE" || \
   ! sudo grep -qx "FORTIAIGATE_RUNNER_DATA=$APP_DIR/.runner-data" "$RUNNER_ENV_FILE"; then
  echo "Error: runner environment must contain a token, the expected data path, and FORTIAIGATE_SCANS_ENABLED=true." >&2
  exit 1
fi
sudo chown root:root "$RUNNER_ENV_FILE"
sudo chmod 600 "$RUNNER_ENV_FILE"
sudo restorecon "$RUNNER_ENV_FILE" 2>/dev/null || true
sudo install -d -o ec2-user -g ec2-user "$APP_DIR/.runner-data"

sudo tee /etc/systemd/system/fortiaigate-runner.service >/dev/null <<'UNIT'
[Unit]
Description=FortiAIGate scan runner (loopback only)
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/opt/fortiaigate-tester
EnvironmentFile=/etc/fortiaigate-runner.env
ExecStart=/opt/fortiaigate-tester/.venv-runner/bin/python -m uvicorn runner.api:create_app --factory --host 127.0.0.1 --port 8765 --workers 1 --no-access-log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/fortiaigate-tester.service >/dev/null <<'UNIT'
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
EnvironmentFile=/etc/fortiaigate-runner.env

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable fortiaigate-runner
sudo systemctl restart fortiaigate-runner
sudo systemctl restart fortiaigate-tester
sleep 3
sudo systemctl is-active --quiet fortiaigate-runner
sudo systemctl is-active --quiet fortiaigate-tester

# Authenticated runner health check; config keeps the token out of curl's argv.
TOKEN="$(sudo awk -F= '/^FORTIAIGATE_RUNNER_TOKEN=/{print substr($0, index($0, "=") + 1)}' "$RUNNER_ENV_FILE")"
curl -fsS -o /dev/null --config <(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN") \
  http://127.0.0.1:8765/health
unset TOKEN
curl -fsS -o /dev/null --max-time 15 http://127.0.0.1:8501/
echo "Runner and Streamlit health checks passed."
REMOTE_SCRIPT

echo "Deployment complete."
if APP_URL=$(terraform -chdir="$DEPLOY_DIR" output -raw app_url 2>/dev/null); then
  echo "Check the app URL: $APP_URL"
fi
