#!/bin/bash
cd "${LABS_DIR:-/opt/labs}/nodegoat/src" 2>/dev/null && docker compose -p nodegoat down
