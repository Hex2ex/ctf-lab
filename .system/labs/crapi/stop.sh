#!/bin/bash
cd "${LABS_DIR:-/opt/labs}/crapi/src/deploy/docker" 2>/dev/null && LISTEN_IP="${LISTEN_IP:-0.0.0.0}" docker compose -p crapi down
