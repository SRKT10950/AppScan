#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
command -v docker >/dev/null || { echo 'Install Docker Engine and the Docker Compose plugin, then rerun this script.'; exit 1; }
docker compose version >/dev/null
if [ ! -f .env ]; then
  umask 077
  secret=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
  cat > .env <<EOF
APPSCAN_USER=admin
APPSCAN_PASSWORD=$secret
APPSCAN_BIND=127.0.0.1
APPSCAN_PORT=8089
EOF
  echo 'Created .env with a random admin password. Read it locally to sign in.'
fi
docker compose up -d --build
echo 'AppScan: http://127.0.0.1:8089. For remote access, use the SSH tunnel in README.md.'
