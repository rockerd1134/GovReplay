#!/bin/sh
set -eu

: "${GOVPROV_DEV_DEPLOYER_PRIVATE_KEY:?Set GOVPROV_DEV_DEPLOYER_PRIVATE_KEY in an ignored local env file or shell environment.}"

chain_id="${GOVPROV_DEPLOYMENT_CHAIN_ID:-1337}"
status_output="${GOVPROV_LIVE_BESU_STATUS_OUTPUT:-../runs/besu-dev/ledger/live_smoke_status.json}"
status_table="${GOVPROV_LIVE_BESU_STATUS_TABLE:-../runs/besu-dev/paper/table_live_besu_status.md}"
smoke_output="${GOVPROV_LEDGER_SMOKE_OUTPUT:-../runs/besu-dev/ledger/smoke.json}"
gas_usage_output="${GOVPROV_GAS_USAGE_OUTPUT:-../runs/besu-dev/results/gas_usage.csv}"
gas_summary_output="${GOVPROV_GAS_SUMMARY_OUTPUT:-../runs/besu-dev/results/gas_summary.csv}"
command_text="docker compose --profile besu-dev run --rm besu-live-smoke"

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

append_foundry_gas_usage() {
    path="$1"
    source_label="$2"
    scenario_label="$3"
    timestamp="$4"
    if [ ! -f "$path" ]; then
        return
    fi
    awk -v run_id="besu-dev" -v source_label="$source_label" -v scenario_label="$scenario_label" -v timestamp="$timestamp" '
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
    function csv(value) {
        gsub(/"/, "\"\"", value)
        return "\"" value "\""
    }
    function operation_for(function_name, contract_name, tx_type) {
        if (tx_type == "CREATE") return "deploy_" contract_name
        sub(/\(.*/, "", function_name)
        return function_name == "" ? "unknown_transaction" : function_name
    }
    function contract_for(function_name, contract_name) {
        if (contract_name != "") return contract_name
        if (function_name ~ /^registerActor/ || function_name ~ /^grantGovRole/) return "ActorRegistry"
        if (function_name ~ /^registerPolicy/ || function_name ~ /^activatePolicy/) return "PolicyRegistry"
        if (function_name ~ /^anchorAttestation/) return "ProvenanceRegistry"
        if (function_name ~ /^recordApproval/) return "ApprovalRegistry"
        if (function_name ~ /^recordDeployment/) return "DeploymentRegistry"
        if (function_name ~ /^registerContract/ || function_name ~ /^activateContractSet/) return "ContractDirectory"
        return "unknown"
    }
    function domain_for(operation) {
        if (operation ~ /Actor|registerActor|grantGovRole/) return "govreplay:domain:identity_domain"
        if (operation ~ /Policy|registerPolicy|activatePolicy/) return "govreplay:domain:policy_domain"
        if (operation ~ /anchorAttestation/) return "govreplay:domain:anchor_domain"
        if (operation ~ /Approval|recordApproval/) return "govreplay:domain:approval_domain"
        if (operation ~ /Deployment|recordDeployment/) return "govreplay:domain:deployment_domain"
        if (operation ~ /ContractDirectory|registerContract|activateContractSet/) return "govreplay:domain:contract_domain"
        return "govreplay:domain:anchor_domain"
    }
    /"transactions"[[:space:]]*:/ { section = "tx"; next }
    /"receipts"[[:space:]]*:/ { section = "receipt"; next }
    section == "tx" && /"transactionType"[[:space:]]*:/ {
        split($0, parts, ": ")
        tx_type = clean(parts[2])
        next
    }
    section == "tx" && /"contractName"[[:space:]]*:/ {
        split($0, parts, ": ")
        contract_name = clean(parts[2])
        next
    }
    section == "tx" && /"function"[[:space:]]*:/ {
        split($0, parts, ": ")
        function_name = clean(parts[2])
        next
    }
    section == "tx" && /"hash"[[:space:]]*:/ {
        split($0, parts, ": ")
        current_hash = clean(parts[2])
        next
    }
    section == "tx" && /"isFixedGasLimit"[[:space:]]*:/ {
        if (current_hash != "") {
            tx_function[current_hash] = function_name
            tx_contract[current_hash] = contract_name
            tx_type_by_hash[current_hash] = tx_type
            tx_configured_gas_price[current_hash] = 0
        }
        current_hash = ""
        function_name = ""
        contract_name = ""
        tx_type = ""
        next
    }
    section == "receipt" && /"transactionHash"[[:space:]]*:/ {
        split($0, parts, ": ")
        receipt_hash = clean(parts[2])
        next
    }
    section == "receipt" && /"blockNumber"[[:space:]]*:/ {
        split($0, parts, ": ")
        block_number = hex2dec(clean(parts[2]))
        next
    }
    section == "receipt" && /"effectiveGasPrice"[[:space:]]*:/ {
        split($0, parts, ": ")
        effective_gas_price = hex2dec(clean(parts[2]))
        operation = operation_for(tx_function[receipt_hash], tx_contract[receipt_hash], tx_type_by_hash[receipt_hash])
        contract_name = contract_for(tx_function[receipt_hash], tx_contract[receipt_hash])
        print run_id "," scenario_label "," operation "," domain_for(operation) "," contract_name "," receipt_hash "," block_number "," gas_used "," effective_gas_price "," tx_configured_gas_price[receipt_hash] "," status ",0," timestamp
        next
    }
    section == "receipt" && /"status"[[:space:]]*:/ {
        split($0, parts, ": ")
        status = clean(parts[2]) == "0x1" ? "success" : "failed"
        next
    }
    section == "receipt" && /"gasUsed"[[:space:]]*:/ {
        split($0, parts, ": ")
        gas_used = hex2dec(clean(parts[2]))
        next
    }' "$path" >> "$gas_usage_output"
}

write_gas_summary() {
    usage_path="$1"
    summary_path="$2"
    if [ ! -f "$usage_path" ]; then
        return
    fi
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

start_epoch="$(date +%s)"

sh ./scripts/deploy-besu-dev.sh
sh ./scripts/besu-ledger-smoke.sh

end_epoch="$(date +%s)"
runtime_seconds=$((end_epoch - start_epoch))

if ! grep -Eq '"readback_ok"[[:space:]]*:[[:space:]]*true' "$smoke_output"; then
    echo "Live Besu smoke did not confirm readback_ok=true: $smoke_output" >&2
    exit 1
fi
if ! grep -Eq '"approval_recorded"[[:space:]]*:[[:space:]]*true' "$smoke_output"; then
    echo "Live Besu smoke did not confirm approval_recorded=true: $smoke_output" >&2
    exit 1
fi
if ! grep -Eq '"deployment_recorded"[[:space:]]*:[[:space:]]*true' "$smoke_output"; then
    echo "Live Besu smoke did not confirm deployment_recorded=true: $smoke_output" >&2
    exit 1
fi

deploy_broadcast="broadcast/DeployBesuDev.s.sol/${chain_id}/run-latest.json"
smoke_broadcast="broadcast/BesuLedgerSmoke.s.sol/${chain_id}/run-latest.json"
transaction_count="$(count_transactions "$deploy_broadcast")"
smoke_transactions="$(count_transactions "$smoke_broadcast")"
transaction_count=$((transaction_count + smoke_transactions))
gas_units="$(sum_gas_units "$deploy_broadcast")"
smoke_gas="$(sum_gas_units "$smoke_broadcast")"
gas_units=$((gas_units + smoke_gas))

mkdir -p "$(dirname "$status_output")" "$(dirname "$status_table")"
mkdir -p "$(dirname "$gas_usage_output")" "$(dirname "$gas_summary_output")"

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'run_id,scenario,operation,domain_id,contract_name,tx_hash,block_number,gas_used,effective_gas_price,configured_gas_price,status,latency_ms,timestamp\n' > "$gas_usage_output"
append_foundry_gas_usage "$deploy_broadcast" "foundry_broadcast:DeployBesuDev" "besu_live_smoke_setup" "$generated_at"
append_foundry_gas_usage "$smoke_broadcast" "foundry_broadcast:BesuLedgerSmoke" "besu_live_smoke" "$generated_at"
write_gas_summary "$gas_usage_output" "$gas_summary_output"

cat > "$status_output" <<EOF
{
  "schema_version": "govprov.besu_live_status.v1",
  "mode": "besu_live_smoke",
  "workflow_count": 1,
  "transaction_count": ${transaction_count},
  "gas_units": ${gas_units},
  "ledger_state_exported": true,
  "replay_success_count": 1,
  "replay_failure_count": 0,
  "command": "${command_text}",
  "runtime_seconds": ${runtime_seconds},
  "ledger_state_export": "${smoke_output}",
  "gas_usage_output": "${gas_usage_output}",
  "gas_summary_output": "${gas_summary_output}",
  "besu_live_arpe_subset": "optional_follow_up"
}
EOF

cat > "$status_table" <<EOF
| mode | workflow_count | transaction_count | gas_units | ledger_state_exported | replay_success_count | replay_failure_count | command | runtime_seconds |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- | ---: |
| besu_live_smoke | 1 | ${transaction_count} | ${gas_units} | true | 1 | 0 | \`${command_text}\` | ${runtime_seconds} |
EOF

echo "Wrote live Besu status: $status_output"
echo "Wrote live Besu status table: $status_table"
echo "Wrote gas usage CSV: $gas_usage_output"
echo "Wrote gas summary CSV: $gas_summary_output"
