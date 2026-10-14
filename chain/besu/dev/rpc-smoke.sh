#!/bin/sh
set -eu

rpc_url="${BESU_RPC_URL:-http://besu-dev:8545}"
expected_chain_id="${BESU_EXPECTED_CHAIN_ID:-0x539}"
funded_account="${BESU_FUNDED_ACCOUNT:-0xfe3b557e8fb62b89f4916b721be55ceb828dbd73}"

post_rpc() {
  curl -fsS \
    -H "Content-Type: application/json" \
    --data "$1" \
    "$rpc_url"
}

chain_id_payload='{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
balance_payload='{"jsonrpc":"2.0","method":"eth_getBalance","params":["'"$funded_account"'","latest"],"id":2}'

attempt=1
chain_id_response=""
while [ "$attempt" -le 30 ]; do
  if chain_id_response="$(post_rpc "$chain_id_payload" 2>/dev/null)"; then
    if printf '%s' "$chain_id_response" | grep -q "\"result\":\"$expected_chain_id\""; then
      break
    fi
  fi
  attempt=$((attempt + 1))
  sleep 1
done

if ! printf '%s' "$chain_id_response" | grep -q "\"result\":\"$expected_chain_id\""; then
  echo "Besu RPC did not report expected chain ID $expected_chain_id"
  echo "Last response: $chain_id_response"
  exit 1
fi

balance_response="$(post_rpc "$balance_payload")"
if printf '%s' "$balance_response" | grep -q '"result":"0x0"'; then
  echo "Funded account $funded_account has zero balance"
  echo "Response: $balance_response"
  exit 1
fi

echo "Besu dev RPC healthy"
echo "chain_id_response=$chain_id_response"
echo "balance_response=$balance_response"
