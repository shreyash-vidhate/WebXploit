#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose -f docker/docker-compose.yml up -d --build
echo "WebXploit lab started: WAF http://127.0.0.1:8080, Juice Shop http://127.0.0.1:3000"
