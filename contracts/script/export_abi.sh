#!/usr/bin/env bash
# Regenerate the backend's committed ABI from the Foundry build output.
set -euo pipefail
cd "$(dirname "$0")/.."
forge build --silent
python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["abi"], indent=2))' \
  out/ThreatRegistry.sol/ThreatRegistry.json > ../backend/app/registry/abi/ThreatRegistry.json
echo "wrote backend/app/registry/abi/ThreatRegistry.json"
