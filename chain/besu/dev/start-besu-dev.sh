#!/bin/sh
set -eu

network_dir="/var/lib/besu/generated-network"
genesis_file="$network_dir/genesis.json"

if [ ! -f "$genesis_file" ] || [ ! -f "/var/lib/besu/key" ]; then
    config_file=/etc/besu/qbft-config.json
    if [ -n "${GOVPROV_DEV_ADMIN_ADDRESS:-}" ]; then
        admin_address=$(printf '%s' "$GOVPROV_DEV_ADMIN_ADDRESS" | sed 's/^0x//')
        case "$admin_address" in
            *[!0-9a-fA-F]*|'') echo "Invalid development administrator address" >&2; exit 1 ;;
        esac
        [ "${#admin_address}" -eq 40 ] || { echo "Expected a 20-byte administrator address" >&2; exit 1; }
        config_file=/var/lib/besu/runtime-qbft-config.json
        sed "s/7E5F4552091A69125d5DfCb7b8C2659029395Bdf/$admin_address/" /etc/besu/qbft-config.json > "$config_file"
    fi
    rm -rf "$network_dir"
    besu operator generate-blockchain-config \
        --config-file="$config_file" \
        --to="$network_dir" \
        --private-key-file-name=key \
        --public-key-file-name=key.pub
    node_dir="$(find "$network_dir/keys" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
    cp "$node_dir/key" /var/lib/besu/key
    cp "$node_dir/key.pub" /var/lib/besu/key.pub
fi

exec besu \
    --genesis-file="$genesis_file" \
    --data-path=/var/lib/besu \
    --rpc-http-enabled \
    --rpc-http-host=0.0.0.0 \
    --rpc-http-port=8545 \
    --rpc-http-api=ETH,NET,WEB3,QBFT \
    --host-allowlist=localhost,127.0.0.1,besu-dev \
    --min-gas-price=0
