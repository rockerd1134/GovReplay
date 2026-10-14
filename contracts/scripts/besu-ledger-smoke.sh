#!/bin/sh
set -eu

: "${GOVPROV_DEV_DEPLOYER_PRIVATE_KEY:?Set GOVPROV_DEV_DEPLOYER_PRIVATE_KEY in an ignored local env file or shell environment.}"

rpc_url="${BESU_RPC_URL:-http://besu-dev:8545}"
manifest="${GOVPROV_DEPLOYMENT_MANIFEST:-../runs/besu-dev/ledger/deployment_manifest.json}"
output="${GOVPROV_LEDGER_SMOKE_OUTPUT:-../runs/besu-dev/ledger/smoke.json}"

if [ ! -f "$manifest" ]; then
    echo "Deployment manifest not found: $manifest" >&2
    echo "Run sh ./scripts/deploy-besu-dev.sh first." >&2
    exit 1
fi

mkdir -p "$(dirname "$output")"

forge script script/BesuLedgerSmoke.s.sol:BesuLedgerSmoke \
    --rpc-url "$rpc_url" \
    --broadcast \
    --legacy

if ! grep -Eq '"readback_ok"[[:space:]]*:[[:space:]]*true' "$output"; then
    echo "Ledger smoke output did not confirm readback_ok=true: $output" >&2
    exit 1
fi

echo "Wrote ledger smoke output: $output"
