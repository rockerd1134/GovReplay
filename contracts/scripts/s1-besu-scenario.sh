#!/bin/sh
set -eu

: "${GOVPROV_DEV_DEPLOYER_PRIVATE_KEY:?Set GOVPROV_DEV_DEPLOYER_PRIVATE_KEY in an ignored local env file or shell environment.}"

rpc_url="${BESU_RPC_URL:-http://besu-dev:8545}"
manifest="${GOVPROV_DEPLOYMENT_MANIFEST:-../runs/besu-dev/ledger/deployment_manifest.json}"
output="${GOVPROV_S1_BESU_OUTPUT:-../runs/besu-dev/scenarios/S1_runbook_update/govreplay_besu.json}"

if [ ! -f "$manifest" ]; then
    echo "Deployment manifest not found: $manifest" >&2
    echo "Run sh ./scripts/deploy-besu-dev.sh first." >&2
    exit 1
fi

mkdir -p "$(dirname "$output")"

forge script script/S1BesuScenario.s.sol:S1BesuScenario \
    --rpc-url "$rpc_url" \
    --broadcast \
    --legacy

if ! grep -Eq '"readback_ok"[[:space:]]*:[[:space:]]*true' "$output"; then
    echo "S1 Besu scenario output did not confirm readback_ok=true: $output" >&2
    exit 1
fi

echo "Wrote S1 Besu scenario output: $output"
