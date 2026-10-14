#!/bin/sh
set -eu

network_dir="/var/lib/besu-experiment/network"
genesis_file="$network_dir/genesis.json"

if [ ! -f "$genesis_file" ] || [ "$(find "$network_dir/keys" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)" -ne 4 ]; then
    mkdir -p "$network_dir"
    find "$network_dir" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    besu operator generate-blockchain-config \
        --config-file=/etc/besu/qbft-config.json \
        --to="$network_dir" \
        --private-key-file-name=key \
        --public-key-file-name=key.pub
fi

echo "Besu experiment network material is ready at $network_dir"
