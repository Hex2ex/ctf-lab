#!/bin/bash
# Runs where the web labs live (targets VM or local Docker). LABS_DIR / LISTEN_IP come from `ctf`.
set -e
D="${LABS_DIR:-/opt/labs}/crapi/src"
[ -d "$D/.git" ] || git clone --depth 1 https://github.com/OWASP/crAPI.git "$D"
cd "$D/deploy/docker"
LISTEN_IP="${LISTEN_IP:-0.0.0.0}" docker compose -p crapi pull
LISTEN_IP="${LISTEN_IP:-0.0.0.0}" docker compose -p crapi up -d
