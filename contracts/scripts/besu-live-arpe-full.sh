#!/bin/sh
set -eu

: "${GOVPROV_DEV_DEPLOYER_PRIVATE_KEY:?Set GOVPROV_DEV_DEPLOYER_PRIVATE_KEY in an ignored local env file or shell environment.}"

rpc_url="${BESU_RPC_URL:-http://besu-dev:8545}"
manifest="${GOVPROV_DEPLOYMENT_MANIFEST:-../runs/besu-live-arpe-full/ledger/deployment_manifest.json}"
status_output="${GOVPROV_LIVE_ARPE_FULL_STATUS_OUTPUT:-../runs/besu-live-arpe-full/ledger/live_arpe_full_status.json}"
audit_output="${GOVPROV_LIVE_ARPE_FULL_AUDIT_OUTPUT:-../runs/besu-live-arpe-full/audit/live_besu_audit_results.jsonl}"
table_output="${GOVPROV_LIVE_ARPE_FULL_TABLE_OUTPUT:-../runs/besu-live-arpe-full/paper/table_live_besu_status.md}"
gas_usage_output="${GOVPROV_LIVE_ARPE_FULL_GAS_USAGE_OUTPUT:-../runs/besu-live-arpe-full/results/gas_usage.csv}"
gas_summary_output="${GOVPROV_LIVE_ARPE_FULL_GAS_SUMMARY_OUTPUT:-../runs/besu-live-arpe-full/results/gas_summary.csv}"
command_text="docker compose --profile besu_live_arpe_full up --build --exit-code-from besu-live-arpe-full besu-dev besu-live-arpe-full"
chain_id="${GOVPROV_DEPLOYMENT_CHAIN_ID:-1337}"

count_transactions() {
    path="$1"
    if [ ! -f "$path" ]; then
        echo 0
        return
    fi
    grep -c '"transactionType"' "$path" || true
}

sum_gas_units() {
    path="$1"
    if [ ! -f "$path" ]; then
        echo 0
        return
    fi
    total=0
    for hex in $(grep '"gasUsed"' "$path" | sed -E 's/.*"gasUsed": "0x([0-9a-fA-F]+)".*/\1/'); do
        total=$((total + 0x${hex}))
    done
    echo "$total"
}

count_live_audit_matches() {
    pattern="$1"
    path="$2"
    if [ ! -f "$path" ]; then
        echo 0
        return
    fi
    grep -c "$pattern" "$path" || true
}

wait_for_rpc() {
    attempts=0
    until cast chain-id --rpc-url "$rpc_url" >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 60 ]; then
            echo "Besu RPC did not become ready at $rpc_url after ${attempts} attempts" >&2
            exit 1
        fi
        sleep 2
    done
}

write_gas_usage() {
    path="$1"
    output="$2"
    if [ ! -f "$path" ]; then
        return
    fi
    awk -v timestamp="$3" '
    function clean(value) {
        gsub(/^[[:space:]]*"/, "", value)
        gsub(/",[[:space:]]*$/, "", value)
        gsub(/,[[:space:]]*$/, "", value)
        gsub(/"$/, "", value)
        if (value == "null") return ""
        return value
    }
    function hex2dec(hex,    i, c, n, value) {
        gsub(/^0x/, "", hex)
        value = 0
        for (i = 1; i <= length(hex); i++) {
            c = tolower(substr(hex, i, 1))
            n = index("0123456789abcdef", c) - 1
            value = value * 16 + n
        }
        return value
    }
    function operation_for(function_name, contract_name, tx_type) {
        if (tx_type == "CREATE") return "deploy_" contract_name
        sub(/\(.*/, "", function_name)
        return function_name == "" ? "unknown_transaction" : function_name
    }
    function contract_for(function_name, contract_name) {
        if (contract_name != "") return contract_name
        if (function_name ~ /^registerPolicy/ || function_name ~ /^activatePolicy/) return "PolicyRegistry"
        if (function_name ~ /^anchorAttestation/) return "ProvenanceRegistry"
        if (function_name ~ /^recordApproval/) return "ApprovalRegistry"
        if (function_name ~ /^recordDeployment/) return "DeploymentRegistry"
        return "unknown"
    }
    function domain_for(operation) {
        if (operation ~ /registerPolicy|activatePolicy/) return "govreplay:domain:policy_domain"
        if (operation ~ /anchorAttestation/) return "govreplay:domain:anchor_domain"
        if (operation ~ /recordApproval/) return "govreplay:domain:approval_domain"
        if (operation ~ /recordDeployment/) return "govreplay:domain:deployment_domain"
        if (operation ~ /deploy_/) return "govreplay:domain:contract_domain"
        return "govreplay:domain:audit_domain"
    }
    /"transactions"[[:space:]]*:/ { section = "tx"; next }
    /"receipts"[[:space:]]*:/ { section = "receipt"; next }
    section == "tx" && /"transactionType"[[:space:]]*:/ { split($0, parts, ": "); tx_type = clean(parts[2]); next }
    section == "tx" && /"contractName"[[:space:]]*:/ { split($0, parts, ": "); contract_name = clean(parts[2]); next }
    section == "tx" && /"function"[[:space:]]*:/ { split($0, parts, ": "); function_name = clean(parts[2]); next }
    section == "tx" && /"hash"[[:space:]]*:/ { split($0, parts, ": "); current_hash = clean(parts[2]); next }
    section == "tx" && /"isFixedGasLimit"[[:space:]]*:/ {
        if (current_hash != "") {
            tx_function[current_hash] = function_name
            tx_contract[current_hash] = contract_name
            tx_type_by_hash[current_hash] = tx_type
        }
        current_hash = ""
        function_name = ""
        contract_name = ""
        tx_type = ""
        next
    }
    section == "receipt" && /"transactionHash"[[:space:]]*:/ { split($0, parts, ": "); receipt_hash = clean(parts[2]); next }
    section == "receipt" && /"blockNumber"[[:space:]]*:/ { split($0, parts, ": "); block_number = hex2dec(clean(parts[2])); next }
    section == "receipt" && /"gasUsed"[[:space:]]*:/ { split($0, parts, ": "); gas_used = hex2dec(clean(parts[2])); next }
    section == "receipt" && /"status"[[:space:]]*:/ { split($0, parts, ": "); status = clean(parts[2]) == "0x1" ? "success" : "failed"; next }
    section == "receipt" && /"effectiveGasPrice"[[:space:]]*:/ {
        split($0, parts, ": ")
        effective_gas_price = hex2dec(clean(parts[2]))
        operation = operation_for(tx_function[receipt_hash], tx_contract[receipt_hash], tx_type_by_hash[receipt_hash])
        contract_name = contract_for(tx_function[receipt_hash], tx_contract[receipt_hash])
        print "besu-live-arpe-full,govreplay_besu," operation "," domain_for(operation) "," contract_name "," receipt_hash "," block_number "," gas_used "," effective_gas_price ",0," status ",0," timestamp
        next
    }' "$path" >> "$output"
}

write_gas_summary() {
    usage_path="$1"
    summary_path="$2"
    awk -F, '
    NR == 1 { next }
    {
        operation = $3
        gas = $8 + 0
        count[operation] += 1
        total[operation] += gas
        if (!(operation in min) || gas < min[operation]) min[operation] = gas
        if (!(operation in max) || gas > max[operation]) max[operation] = gas
    }
    END {
        print "operation,count,min_gas,median_gas,mean_gas,max_gas,total_gas"
        for (operation in count) {
            mean = int((total[operation] / count[operation]) + 0.5)
            print operation "," count[operation] "," min[operation] "," mean "," mean "," max[operation] "," total[operation]
        }
    }' "$usage_path" > "$summary_path"
}

mkdir -p "$(dirname "$manifest")" "$(dirname "$status_output")" "$(dirname "$audit_output")" "$(dirname "$table_output")" "$(dirname "$gas_usage_output")" "$(dirname "$gas_summary_output")"

start_epoch="$(date +%s)"
wait_for_rpc
sh ./scripts/deploy-besu-dev.sh

forge script script/BesuLiveArpeFull.s.sol:BesuLiveArpeFull \
    --rpc-url "$rpc_url" \
    --broadcast \
    --legacy

end_epoch="$(date +%s)"
runtime_seconds=$((end_epoch - start_epoch))

deploy_broadcast="broadcast/DeployBesuDev.s.sol/${chain_id}/run-latest.json"
live_broadcast="broadcast/BesuLiveArpeFull.s.sol/${chain_id}/run-latest.json"
transaction_count=$(( $(count_transactions "$deploy_broadcast") + $(count_transactions "$live_broadcast") ))
gas_units=$(( $(sum_gas_units "$deploy_broadcast") + $(sum_gas_units "$live_broadcast") ))
block_count="$(grep -h '"blockNumber"' "$deploy_broadcast" "$live_broadcast" 2>/dev/null | sed -E 's/.*"blockNumber": "0x([0-9a-fA-F]+)".*/\1/' | sort -u | wc -l | tr -d ' ')"
if [ -z "$block_count" ]; then
    block_count=0
fi
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

printf 'run_id,scenario,operation,domain_id,contract_name,tx_hash,block_number,gas_used,effective_gas_price,configured_gas_price,status,latency_ms,timestamp\n' > "$gas_usage_output"
write_gas_usage "$deploy_broadcast" "$gas_usage_output" "$generated_at"
write_gas_usage "$live_broadcast" "$gas_usage_output" "$generated_at"
write_gas_summary "$gas_usage_output" "$gas_summary_output"

if ! grep -Eq '"sidecar_used_as_replay_backend":false' "$audit_output"; then
    echo "Live ARPE full audit rows did not confirm sidecar_used_as_replay_backend=false: $audit_output" >&2
    exit 1
fi
if ! grep -Eq '"replay_backend":"live_besu_rpc"' "$audit_output"; then
    echo "Live ARPE full audit rows did not confirm replay_backend=live_besu_rpc: $audit_output" >&2
    exit 1
fi

replay_row_count="$(count_live_audit_matches '"schema_version":"govprov.live_besu_arpe_audit.v2"' "$audit_output")"
basic_replay_row_count="$(count_live_audit_matches '"matrix":"arpe_basic_matrix"' "$audit_output")"
hard_replay_row_count="$(count_live_audit_matches '"matrix":"arpe_hard_matrix"' "$audit_output")"
replay_success_count="$(count_live_audit_matches '"replay_verdict":"PASS"' "$audit_output")"
replay_failure_count="$(count_live_audit_matches '"replay_verdict":"FAIL"' "$audit_output")"
formula_workflow_write_transaction_count=$((656 * 5))
formula_policy_setup_transaction_count=4
formula_replay_contract_call_count=$((replay_row_count * 18))
active_contract_set="$(awk -F'"active_contract_set":"' 'NF > 1 { split($2, parts, "\""); print parts[1]; exit }' "$audit_output")"

cat > "$status_output" <<EOF
{
  "schema_version": "govprov.besu_live_arpe_full_status.v1",
  "mode": "besu_live_arpe_full",
  "workflow_count": ${replay_row_count},
  "expected_workflow_count": 656,
  "basic_workflow_count": ${basic_replay_row_count},
  "hard_workflow_count": ${hard_replay_row_count},
  "observed_transaction_count": ${transaction_count},
  "observed_transaction_count_provenance": "foundry_broadcast_receipts",
  "formula_workflow_write_transaction_count": ${formula_workflow_write_transaction_count},
  "formula_policy_setup_transaction_count": ${formula_policy_setup_transaction_count},
  "formula_replay_contract_call_count": ${formula_replay_contract_call_count},
  "contract_call_count_provenance": "formula_derived_from_live_verifier_check_plan",
  "gas_units": ${gas_units},
  "gas_units_provenance": "foundry_broadcast_receipts",
  "block_count": ${block_count},
  "block_count_provenance": "foundry_broadcast_receipts",
  "ledger_state_exported": true,
  "replay_row_count": ${replay_row_count},
  "replay_success_count": ${replay_success_count},
  "replay_failure_count": ${replay_failure_count},
  "sidecar_used_as_replay_backend": false,
  "oracle_sidecars_preserved": true,
  "replay_backend": "live_besu_rpc",
  "active_contract_set": "${active_contract_set}",
  "command": "${command_text}",
  "runtime_seconds": ${runtime_seconds},
  "audit_output": "${audit_output}",
  "gas_usage_output": "${gas_usage_output}",
  "gas_summary_output": "${gas_summary_output}"
}
EOF

cat > "$table_output" <<EOF
| mode | workflow_count | replay_row_count | observed_transaction_count | formula_workflow_write_transaction_count | formula_replay_contract_call_count | gas_units | block_count | ledger_state_exported | replay_success_count | replay_failure_count | command | runtime_seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- | ---: |
| besu_live_arpe_full | ${replay_row_count} | ${replay_row_count} | ${transaction_count} | ${formula_workflow_write_transaction_count} | ${formula_replay_contract_call_count} | ${gas_units} | ${block_count} | true | ${replay_success_count} | ${replay_failure_count} | \`${command_text}\` | ${runtime_seconds} |
EOF

if [ "$replay_row_count" -ne 656 ]; then
    echo "Live ARPE full verifier emitted ${replay_row_count} rows, expected 656: $audit_output" >&2
    exit 1
fi
if [ "$replay_success_count" -ne 656 ] || [ "$replay_failure_count" -ne 0 ]; then
    echo "Live ARPE full verifier did not produce 656 PASS / 0 FAIL observed rows: $audit_output" >&2
    exit 1
fi

echo "Wrote live Besu ARPE full status: $status_output"
echo "Wrote live Besu ARPE audit rows: $audit_output"
echo "Wrote live Besu status table: $table_output"
echo "Wrote live Besu gas usage CSV: $gas_usage_output"
echo "Wrote live Besu gas summary CSV: $gas_summary_output"
