#!/bin/sh
set -eu

rpc_url="${BESU_RPC_URL:-http://besu-experiment-1:8545}"
expected_chain_id="${BESU_EXPECTED_CHAIN_ID:-0x53a}"
funded_account="${BESU_FUNDED_ACCOUNT:-0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf}"
expected_validators="${BESU_EXPECTED_VALIDATORS:-4}"

post_rpc() {
  curl -fsS \
    -H "Content-Type: application/json" \
    --data "$1" \
    "$rpc_url"
}

chain_id_payload='{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
balance_payload='{"jsonrpc":"2.0","method":"eth_getBalance","params":["'"$funded_account"'","latest"],"id":2}'
peer_count_payload='{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":3}'
validators_payload='{"jsonrpc":"2.0","method":"qbft_getValidatorsByBlockNumber","params":["latest"],"id":4}'

attempt=1
chain_id_response=""
while [ "$attempt" -le 60 ]; do
  if chain_id_response="$(post_rpc "$chain_id_payload" 2>/dev/null)"; then
    if printf '%s' "$chain_id_response" | grep -q "\"result\":\"$expected_chain_id\""; then
      break
    fi
  fi
  attempt=$((attempt + 1))
  sleep 1
done

if ! printf '%s' "$chain_id_response" | grep -q "\"result\":\"$expected_chain_id\""; then
  echo "Besu experiment RPC did not report expected chain ID $expected_chain_id"
  echo "Last response: $chain_id_response"
  exit 1
fi

balance_response="$(post_rpc "$balance_payload")"
if printf '%s' "$balance_response" | grep -q '"result":"0x0"'; then
  echo "Funded account $funded_account has zero balance"
  echo "Response: $balance_response"
  exit 1
fi

attempt=1
peer_count_response=""
while [ "$attempt" -le 60 ]; do
  peer_count_response="$(post_rpc "$peer_count_payload")"
  if ! printf '%s' "$peer_count_response" | grep -Eq '"result":"0x[0-2]"'; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done

if printf '%s' "$peer_count_response" | grep -Eq '"result":"0x[0-2]"'; then
  echo "Experiment node does not report at least 3 peers"
  echo "Response: $peer_count_response"
  exit 1
fi

attempt=1
validators_response=""
validator_count="0"
while [ "$attempt" -le 60 ]; do
  validators_response="$(post_rpc "$validators_payload")"
  validator_count="$(printf '%s' "$validators_response" | grep -o '0x[0-9a-fA-F]\{40\}' | wc -l | tr -d ' ')"
  if [ "$validator_count" = "$expected_validators" ]; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done

if [ "$validator_count" != "$expected_validators" ]; then
  echo "Expected $expected_validators QBFT validators, found $validator_count"
  echo "Response: $validators_response"
  exit 1
fi

echo "Besu experiment RPC healthy"
echo "chain_id_response=$chain_id_response"
echo "balance_response=$balance_response"
echo "peer_count_response=$peer_count_response"
echo "validators_response=$validators_response"
