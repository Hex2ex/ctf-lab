#!/bin/bash
# Runs where the web labs live (targets VM or local Docker). LABS_DIR / LISTEN_IP come from `ctf`.
set -e
D="${LABS_DIR:-/opt/labs}/nodegoat/src"
[ -d "$D/.git" ] || git clone --depth 1 https://github.com/OWASP/NodeGoat.git "$D"
cd "$D"
# In docker mode ctf passes the port-binding tool: the upstream compose file must not listen on every interface
[ -n "${CTF_BIND_TOOL:-}" ] && python3 "$CTF_BIND_TOOL" "${LISTEN_IP:-127.0.0.1}" docker-compose.yml >/dev/null
docker compose -p nodegoat up -d --build
