#!/bin/sh
set -eu

./scripts/sync-foundry-deps.sh

exec "$@"
