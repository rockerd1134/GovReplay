#!/bin/sh
set -eu

: "${BESU_NODE_INDEX:?Set BESU_NODE_INDEX to 1, 2, 3, or 4.}"

network_dir="/var/lib/besu-experiment/network"
data_dir="/var/lib/besu"
genesis_file="$network_dir/genesis.json"
static_nodes_file="$data_dir/static-nodes.json"

if [ ! -f "$genesis_file" ]; then
    echo "Generated genesis not found: $genesis_file" >&2
    echo "Run the besu-experiment-init service first." >&2
    exit 1
fi

node_dir="$(find "$network_dir/keys" -mindepth 1 -maxdepth 1 -type d | sort | sed -n "${BESU_NODE_INDEX}p")"
if [ -z "$node_dir" ]; then
    echo "No generated key directory for BESU_NODE_INDEX=$BESU_NODE_INDEX" >&2
    exit 1
fi

mkdir -p "$data_dir"
if [ ! -f "$data_dir/key" ]; then
    cp "$node_dir/key" "$data_dir/key"
    cp "$node_dir/key.pub" "$data_dir/key.pub"
fi

tmp_nodes="$static_nodes_file.tmp"
printf '[' > "$tmp_nodes"
separator=""
index=1
for dir in $(find "$network_dir/keys" -mindepth 1 -maxdepth 1 -type d | sort); do
    public_key="$(cat "$dir/key.pub" | sed 's/^0x//')"
    node_ip="172.28.0.$((10 + index))"
    printf '%s"enode://%s@%s:30303"' "$separator" "$public_key" "$node_ip" >> "$tmp_nodes"
    separator=","
    index=$((index + 1))
done
printf ']\n' >> "$tmp_nodes"
mv "$tmp_nodes" "$static_nodes_file"

bootnodes="$(tr -d '[]" \n' < "$static_nodes_file")"

exec besu \
    --genesis-file="$genesis_file" \
    --data-path="$data_dir" \
    --node-private-key-file="$data_dir/key" \
    --p2p-host=0.0.0.0 \
    --p2p-port=30303 \
    --bootnodes="$bootnodes" \
    --rpc-http-enabled \
    --rpc-http-host=0.0.0.0 \
    --rpc-http-port=8545 \
    --rpc-http-api=ETH,NET,WEB3,QBFT \
    --host-allowlist=localhost,127.0.0.1,besu-experiment-1,besu-experiment-2,besu-experiment-3,besu-experiment-4 \
    --min-gas-price=0
