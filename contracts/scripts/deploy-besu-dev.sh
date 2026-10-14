#!/bin/sh
set -eu

: "${GOVPROV_DEV_DEPLOYER_PRIVATE_KEY:?Set GOVPROV_DEV_DEPLOYER_PRIVATE_KEY in an ignored local env file or shell environment.}"

rpc_url="${BESU_RPC_URL:-http://besu-dev:8545}"
manifest="${GOVPROV_DEPLOYMENT_MANIFEST:-../runs/besu-dev/ledger/deployment_manifest.json}"

mkdir -p "$(dirname "$manifest")"

forge script script/DeployBesuDev.s.sol:DeployBesuDev \
    --rpc-url "$rpc_url" \
    --broadcast \
    --legacy

sh ./scripts/export-contract-abis.sh validate-manifest "$manifest"
echo "Wrote deployment manifest: $manifest"
