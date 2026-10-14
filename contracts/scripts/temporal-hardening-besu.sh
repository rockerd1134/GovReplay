#!/bin/sh
set -eu
: "${GOVPROV_TEMPORAL_RUN_ID:?Set a fresh hardened run ID.}"
case "$GOVPROV_TEMPORAL_RUN_ID" in
    hardening-*) ;;
    *) echo "Hardened run ID must start with hardening-" >&2; exit 1 ;;
esac
export GOVPROV_HARDENED_PROVENANCE=true
export GOVPROV_DEPLOYMENT_CONTRACT_SET_LABEL=govprov:contract-set:hardening-v1
exec sh ./scripts/temporal-ordering-besu.sh
