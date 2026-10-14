#!/bin/sh
set -eu

mode="${1:-export}"
export_root="${GOVPROV_CONTRACT_EXPORT_DIR:-../artifacts/contracts}"
abi_dir="$export_root/abis"
manifest_dir="$export_root/manifests"
sample_manifest="deployments/samples/contract-addresses.synthetic.json"

phase1_contracts="
ActorRegistry src/ActorRegistry.sol 0x1000000000000000000000000000000000000001
PolicyRegistry src/PolicyRegistry.sol 0x1000000000000000000000000000000000000002
ProvenanceRegistry src/ProvenanceRegistry.sol 0x1000000000000000000000000000000000000003
ApprovalRegistry src/ApprovalRegistry.sol 0x1000000000000000000000000000000000000004
DeploymentRegistry src/DeploymentRegistry.sol 0x1000000000000000000000000000000000000005
ContractDirectory src/ContractDirectory.sol 0x1000000000000000000000000000000000000006
"

hash_file() {
    sha256sum "$1" | awk '{ print $1 }'
}

hash_text() {
    printf "%s" "$1" | sha256sum | awk '{ print $1 }'
}

require_json_field() {
    file="$1"
    field="$2"
    if ! grep -q "\"$field\"" "$file"; then
        echo "Missing manifest field: $field" >&2
        exit 1
    fi
}

validate_manifest() {
    file="$1"
    if [ ! -f "$file" ]; then
        echo "Manifest not found: $file" >&2
        exit 1
    fi

    for field in \
        schema_version \
        chain \
        build \
        contract_set_id \
        governance_admin \
        active_scopes \
        active_policies \
        contracts
    do
        require_json_field "$file" "$field"
    done

    for field in address name_hash version_hash source_hash abi_hash metadata_hash; do
        require_json_field "$file" "$field"
    done

    is_synthetic=0
    if grep -q '"manifest_kind"[[:space:]]*:[[:space:]]*"synthetic-fixture"' "$file"; then
        is_synthetic=1
    fi

    echo "$phase1_contracts" | while read -r name source_file synthetic_address; do
        case "$name" in
            "") continue ;;
        esac
        if ! grep -q "\"$name\"" "$file"; then
            echo "Missing Phase 1 contract in manifest: $name" >&2
            exit 1
        fi
        if [ "$is_synthetic" -eq 1 ] && ! grep -q "$synthetic_address" "$file"; then
            echo "Missing synthetic address for $name: $synthetic_address" >&2
            exit 1
        fi
    done

    if ! grep -Eq '"chain_id"[[:space:]]*:[[:space:]]*[0-9]+' "$file"; then
        echo "Manifest chain.chain_id must be numeric" >&2
        exit 1
    fi
    if ! grep -Eq '0x[0-9a-fA-F]{40}' "$file"; then
        echo "Manifest must include at least one Ethereum address" >&2
        exit 1
    fi
    if ! grep -Eq '0x[0-9a-fA-F]{64}' "$file"; then
        echo "Manifest must include bytes32-compatible hashes" >&2
        exit 1
    fi

    echo "Validated manifest shape: $file"
}

if [ "$mode" = "validate-manifest" ]; then
    validate_manifest "${2:-$sample_manifest}"
    exit 0
fi

if [ "$mode" != "export" ]; then
    echo "Usage: $0 [export|validate-manifest] [manifest-path]" >&2
    exit 1
fi

mkdir -p "$abi_dir" "$manifest_dir"

forge build >/dev/null

contracts_json=""
contract_set_material=""
first_contract=1

echo "$phase1_contracts" | while read -r name source_file synthetic_address; do
    case "$name" in
        "") continue ;;
    esac

    forge inspect "$source_file:$name" abi --json > "$abi_dir/$name.json"
    echo "Exported ABI: $abi_dir/$name.json"
done

while read -r name source_file synthetic_address; do
    case "$name" in
        "") continue ;;
    esac

    artifact_file="out/$(basename "$source_file")/$name.json"
    source_hash="0x$(hash_file "$source_file")"
    abi_hash="0x$(hash_file "$abi_dir/$name.json")"
    if [ -f "$artifact_file" ]; then
        metadata_hash="0x$(hash_file "$artifact_file")"
    else
        metadata_hash="$abi_hash"
    fi
    version_hash="0x$(hash_text "$name|$source_hash|$abi_hash")"
    name_hash="0x$(hash_text "govprov:contract:$name")"
    contract_set_material="$contract_set_material|$name:$synthetic_address:$version_hash"

    entry="    \"$name\": {
      \"address\": \"$synthetic_address\",
      \"name_hash\": \"$name_hash\",
      \"version_hash\": \"$version_hash\",
      \"source_hash\": \"$source_hash\",
      \"abi_hash\": \"$abi_hash\",
      \"metadata_hash\": \"$metadata_hash\",
      \"source_path_hash\": \"0x$(hash_text "$source_file")\"
    }"

    if [ "$first_contract" -eq 1 ]; then
        contracts_json="$entry"
        first_contract=0
    else
        contracts_json="$contracts_json,
$entry"
    fi
done <<EOF
$phase1_contracts
EOF

contract_set_id="0x$(hash_text "$contract_set_material")"
manifest="$manifest_dir/contract-addresses.synthetic.json"

cat > "$manifest" <<EOF
{
  "schema_version": "govprov.contract-addresses.v1",
  "chain": {
    "chain_id": 1337,
    "network": "synthetic-foundry-export",
    "genesis_hash": "0x$(hash_text "govprov:synthetic-foundry-export:genesis")",
    "rpc_endpoint_hash": "0x$(hash_text "http://127.0.0.1:8545")"
  },
  "build": {
    "generated_at": "1970-01-01T00:00:00Z",
    "tool": "forge",
    "solc_version": "0.8.26",
    "manifest_kind": "synthetic-fixture"
  },
  "contract_set_id": "$contract_set_id",
  "governance_admin": {
    "address": "0x10000000000000000000000000000000000000aa",
    "actor_id_hash": "0x$(hash_text "govprov:actor:governance-admin")"
  },
  "active_scopes": [
    {
      "scope_hash": "0x$(hash_text "scope:default")",
      "metadata_hash": "0x$(hash_text "govprov:scope:default:metadata")"
    }
  ],
  "active_policies": [
    {
      "scope_hash": "0x$(hash_text "scope:default")",
      "policy_hash": "0x$(hash_text "govprov:policy:delivery-v1")",
      "metadata_hash": "0x$(hash_text "govprov:policy:delivery-v1:metadata")"
    }
  ],
  "contracts": {
$contracts_json
  }
}
EOF

validate_manifest "$manifest"
echo "Wrote synthetic manifest: $manifest"
