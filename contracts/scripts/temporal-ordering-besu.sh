#!/bin/sh
set -eu

: "${GOVPROV_DEV_DEPLOYER_PRIVATE_KEY:?Set the local Besu development admin key.}"
: "${GOVPROV_TEMPORAL_ACTOR_PRIVATE_KEY:?Set a distinct local experiment actor key.}"

rpc_url="${BESU_RPC_URL:-http://besu-dev:8545}"
run_id="${GOVPROV_TEMPORAL_RUN_ID:-temporal-$(date -u +%Y%m%dT%H%M%SZ)}"
run_root="../runs/$run_id/temporal_ordering"
hardened="${GOVPROV_HARDENED_PROVENANCE:-false}"
if [ -e "$run_root" ]; then
    echo "Refusing to overwrite existing temporal run: $run_root" >&2
    exit 1
fi
mkdir -p "$run_root/receipts"
export GOVPROV_DEPLOYMENT_MANIFEST="$run_root/deployment_manifest.json"

attempts=0
until cast chain-id --rpc-url "$rpc_url" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 60 ]; then
        echo "Besu RPC unavailable: $rpc_url" >&2
        exit 1
    fi
    sleep 2
done

forge script script/DeployBesuDev.s.sol:DeployBesuDev --rpc-url "$rpc_url" --broadcast --legacy
sh ./scripts/export-contract-abis.sh validate-manifest "$GOVPROV_DEPLOYMENT_MANIFEST"

manifest=$(cat "$GOVPROV_DEPLOYMENT_MANIFEST")
actor_registry=$(printf '%s' "$manifest" | sed -E 's/.*"ActorRegistry":\{"address":"([^"]+)".*/\1/')
policy_registry=$(printf '%s' "$manifest" | sed -E 's/.*"PolicyRegistry":\{"address":"([^"]+)".*/\1/')
provenance_registry=$(printf '%s' "$manifest" | sed -E 's/.*"ProvenanceRegistry":\{"address":"([^"]+)".*/\1/')
approval_registry=$(printf '%s' "$manifest" | sed -E 's/.*"ApprovalRegistry":\{"address":"([^"]+)".*/\1/')
deployment_registry=$(printf '%s' "$manifest" | sed -E 's/.*"DeploymentRegistry":\{"address":"([^"]+)".*/\1/')
case "$actor_registry$policy_registry$provenance_registry$approval_registry$deployment_registry" in
    *'"'*) echo "Could not parse deployed contract addresses" >&2; exit 1 ;;
esac

admin_key="$GOVPROV_DEV_DEPLOYER_PRIVATE_KEY"
actor_key="$GOVPROV_TEMPORAL_ACTOR_PRIVATE_KEY"
admin=$(cast wallet address --private-key "$admin_key")
actor=$(cast wallet address --private-key "$actor_key")
if [ "$admin" = "$actor" ]; then
    echo "The temporal actor must differ from the governance admin" >&2
    exit 1
fi
deployer_role=$(cast keccak DEPLOYER_ROLE)
ledger_writer_role=$(cast keccak LEDGER_WRITER_ROLE)
policy_hash=$(cast keccak govprov:policy:delivery-v1)
scope_hash=$(cast keccak scope:default)

printf '{"run_id":"%s","chain_id":1337,"attestation_actor":"%s","anchor_transaction_sender":"%s","default_deployment_transaction_sender":"%s","approval_actor":"%s","required_role_at_N":"%s","deployer_role":"%s","ledger_writer_role":"%s","policy_hash":"%s","scope_hash":"%s","contracts":{"ActorRegistry":"%s","PolicyRegistry":"%s","ProvenanceRegistry":"%s","ApprovalRegistry":"%s","DeploymentRegistry":"%s"}}\n' \
    "$run_id" "$actor" "$admin" "$admin" "$admin" "$deployer_role" "$deployer_role" "$ledger_writer_role" "$policy_hash" "$scope_hash" \
    "$actor_registry" "$policy_registry" "$provenance_registry" "$approval_registry" "$deployment_registry" > "$run_root/run_metadata.json"
if [ "$hardened" = true ]; then
    printf '{"implementation":"hardened","contract_version":"HardenedProvenanceRegistry.v1"}\n' > "$run_root/hardening_metadata.json"
    : > "$run_root/skipped_steps.jsonl"
fi
: > "$run_root/transactions.jsonl"
: > "$run_root/signatures.jsonl"

send_tx() {
    case_id="$1"
    step="$2"
    signer_key="$3"
    contract="$4"
    signature="$5"
    shift 5
    receipt_file="$run_root/receipts/${case_id}_${step}.json"
    if cast send --rpc-url "$rpc_url" --legacy --gas-limit 1000000 --private-key "$signer_key" --json "$contract" "$signature" "$@" > "$receipt_file" 2> "$run_root/receipts/${case_id}_${step}.stderr"; then
        :
    elif [ ! -s "$receipt_file" ]; then
        echo "No receipt for $case_id/$step; see stderr" >&2
        exit 1
    fi
    # Some cast versions append a late RPC poller diagnostic to stdout after
    # emitting a complete one-line receipt. Preserve that text as diagnostics;
    # the report subsequently refetches the receipt by transaction hash.
    first_line=$(sed -n '1p' "$receipt_file")
    if ! printf '%s' "$first_line" | grep -q '"transactionHash":"0x'; then
        echo "Malformed receipt for $case_id/$step" >&2
        exit 1
    fi
    extra_lines=$(sed -n '2,$p' "$receipt_file")
    if [ -n "$extra_lines" ]; then
        printf '%s\n' "$extra_lines" >> "$run_root/receipts/${case_id}_${step}.stderr"
        printf '%s\n' "$first_line" > "$receipt_file"
    fi
    printf '{"case_id":"%s","step":"%s","receipt_file":"receipts/%s_%s.json"}\n' "$case_id" "$step" "$case_id" "$step" >> "$run_root/transactions.jsonl"
}

send_tx SETUP register_actor "$admin_key" "$actor_registry" 'registerActor(address,bytes32,uint8,bytes32)' \
    "$actor" "$(cast keccak temporal:actor)" 1 "$(cast keccak temporal:actor:metadata)"
cast send --rpc-url "$rpc_url" --legacy --gas-limit 100000 --private-key "$admin_key" --value 100000000000000000 --json "$actor" \
    > "$run_root/receipts/SETUP_fund_actor.json"
printf '{"case_id":"SETUP","step":"fund_actor","receipt_file":"receipts/SETUP_fund_actor.json"}\n' >> "$run_root/transactions.jsonl"

case_steps() {
    case "$1" in
        T1) echo 'A S N D' ;;
        T2) echo 'A S R N D' ;;
        T3) echo 'A R S N D' ;;
        T4) echo 'A S N R D' ;;
        T5) echo 'A S N D R' ;;
        T6) echo 'A R N S D' ;;
        T7) echo 'A R G S N D' ;;
        T8) echo 'A S N D R AUDIT' ;;
        T4_SELF) echo 'A S N R D' ;;
        *) echo "Unknown case $1" >&2; exit 1 ;;
    esac
}

if [ -n "${GOVPROV_TEMPORAL_CASES_TSV:-}" ]; then
    cp "$GOVPROV_TEMPORAL_CASES_TSV" "$run_root/cases.tsv"
    cp "${GOVPROV_TEMPORAL_CASES_JSON:?Set generated manifest JSON}" "$run_root/cases.json"
else
    : > "$run_root/cases.tsv"
    for original_case in T1 T2 T3 T4 T5 T6 T7 T8 T4_SELF; do
        original_sender=writer
        if [ "$original_case" = T4_SELF ]; then original_sender=actor; fi
        printf '%s|%s|%s\n' "$original_case" "$original_sender" "$(case_steps "$original_case")" >> "$run_root/cases.tsv"
    done
    cp ../packages/experiments/temporal-ordering/cases.json "$run_root/cases.json"
fi

while IFS='|' read -r case_id deployment_sender event_steps; do
    event_steps=$(printf '%s' "$event_steps" | tr -d '\r')
    action_hash=$(cast keccak "temporal:$run_id:$case_id:action")
    approval_hash=$(cast keccak "temporal:$run_id:$case_id:approval")
    deployment_attestation_hash=$(cast keccak "temporal:$run_id:$case_id:deployment-attestation")
    deployment_id_hash=$(cast keccak "temporal:$run_id:$case_id:deployment-id")
    artifact_hash=$(cast keccak "temporal:$run_id:$case_id:artifact")
    approval_root=$(cast keccak "temporal:$run_id:$case_id:approval-root")
    environment_hash=$(cast keccak "temporal:$run_id:$case_id:environment")
    printf '{"case_id":"%s","action_hash":"%s","approval_hash":"%s","deployment_attestation_hash":"%s","deployment_id_hash":"%s","artifact_hash":"%s"}\n' \
        "$case_id" "$action_hash" "$approval_hash" "$deployment_attestation_hash" "$deployment_id_hash" "$artifact_hash" >> "$run_root/case_hashes.jsonl"

    n_rejected=0
    # Each case begins with an authoritative grant so prior cases cannot set its initial role state.
    send_tx "$case_id" setup_grant "$admin_key" "$actor_registry" 'grantGovRole(address,bytes32)' "$actor" "$deployer_role"

    revoke_count=0
    regrant_count=0
    for step in $event_steps; do
        case "$step" in
            A) : ;; # Local policy decision; current policy is the stable deployed policy.
            S)
                signature=$(cast wallet sign --private-key "$actor_key" "$action_hash")
                printf '{"case_id":"%s","message":"%s","signature":"%s","claimed_created_at":"2026-10-01T00:00:00Z"}\n' \
                    "$case_id" "$action_hash" "$signature" >> "$run_root/signatures.jsonl"
                ;;
            R)
                revoke_count=$((revoke_count + 1))
                revoke_step=revoke
                if [ "$revoke_count" -gt 1 ]; then revoke_step="revoke_$revoke_count"; fi
                send_tx "$case_id" "$revoke_step" "$admin_key" "$actor_registry" 'revokeGovRole(address,bytes32)' "$actor" "$deployer_role" ;;
            G)
                regrant_count=$((regrant_count + 1))
                regrant_step=regrant
                if [ "$regrant_count" -gt 1 ]; then regrant_step="regrant_$regrant_count"; fi
                send_tx "$case_id" "$regrant_step" "$admin_key" "$actor_registry" 'grantGovRole(address,bytes32)' "$actor" "$deployer_role" ;;
            N)
                send_tx "$case_id" anchor_N "$admin_key" "$provenance_registry" 'anchorAttestation(bytes32,bytes32,bytes32,address,bytes32,bytes32,bytes32,bytes32)' \
                    "$action_hash" "$(cast keccak ACTION_PROPOSAL_ATTESTATION)" "$artifact_hash" "$actor" "$policy_hash" \
                    "$(cast keccak "temporal:$case_id:parent")" "$(cast keccak "temporal:$case_id:metadata")" "$scope_hash"
                if [ "$hardened" = true ] && grep -q '"status":"0x0"' "$run_root/receipts/${case_id}_anchor_N.json"; then
                    n_rejected=1
                fi
                ;;
            D)
                if [ "$hardened" = true ] && [ "$n_rejected" -eq 1 ]; then
                    printf '{"case_id":"%s","step":"D","disposition":"NOT_ATTEMPTED","reason":"N_REVERTED"}\n' "$case_id" >> "$run_root/skipped_steps.jsonl"
                    continue
                fi
                send_tx "$case_id" approval_anchor "$admin_key" "$provenance_registry" 'anchorAttestation(bytes32,bytes32,bytes32,address,bytes32,bytes32,bytes32,bytes32)' \
                    "$approval_hash" "$(cast keccak APPROVAL_ATTESTATION)" "$artifact_hash" "$admin" "$policy_hash" \
                    "$(cast keccak "temporal:$case_id:approval-parent")" "$(cast keccak "temporal:$case_id:approval-metadata")" "$scope_hash"
                send_tx "$case_id" approval_record "$admin_key" "$approval_registry" 'recordApproval(bytes32,bytes32,bytes32,bytes32,address,bytes32,uint64)' \
                    "$action_hash" "$approval_hash" "$artifact_hash" "$(cast keccak "temporal:$case_id:policy-decision")" "$actor" "$(cast keccak APPROVER_ROLE)" 0
                send_tx "$case_id" deployment_anchor "$admin_key" "$provenance_registry" 'anchorAttestation(bytes32,bytes32,bytes32,address,bytes32,bytes32,bytes32,bytes32)' \
                    "$deployment_attestation_hash" "$(cast keccak DEPLOYMENT_ATTESTATION)" "$deployment_id_hash" "$admin" "$policy_hash" \
                    "$(cast keccak "temporal:$case_id:deployment-parent")" "$(cast keccak "temporal:$case_id:deployment-metadata")" "$scope_hash"
                if [ "$deployment_sender" = actor ]; then deployment_key="$actor_key"; else deployment_key="$admin_key"; fi
                send_tx "$case_id" deployment_D "$deployment_key" "$deployment_registry" 'recordDeployment(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)' \
                    "$deployment_id_hash" "$deployment_attestation_hash" "$action_hash" "$artifact_hash" "$policy_hash" "$approval_root" "$environment_hash"
                ;;
            AUDIT) : ;;
        esac
    done
done < "$run_root/cases.tsv"

echo "Temporal Besu receipts: $run_root"
