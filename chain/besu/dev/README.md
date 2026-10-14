# One-Node Besu Dev Profile

This directory documents the local one-node Besu profile. It is a development
chain for RPC wiring and fast contract deployment,
not the four-node experiment network. See `../README.md` for the side-by-side
profile comparison and shared failure modes.

## Network

The `besu-dev` Compose profile starts `hyperledger/besu:25.6.0` with a
generated one-node QBFT development network:

- RPC endpoint: `http://localhost:8545`
- chain ID: `1337` (`0x539`)
- profile: `dev`
- data path: `chain/besu/dev/data/` on the host, ignored by git
- consensus: single-node QBFT development validation

The tracked `qbft-config.json` gives this profile a deterministic chain identity
and a funded development account. `start-besu-dev.sh` generates the local QBFT
genesis and validator key under ignored `chain/besu/dev/data/` on first start.
Validator keys, node keys, and private signing material are not committed.
Deployment tooling targets this RPC endpoint and writes run-scoped deployment
manifests.

## Funded Development Accounts

The profile documents only addresses. Private keys are dev-only local material
and must not be committed.

| Account | Address | Intended use |
| --- | --- | --- |
| `governance_admin` | `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf` | bootstrap admin and miner coinbase |
| `ledger_writer` | `0x627306090abab3a6e1400e9345bc60c78a8bef57` | ledger writer transactions |
| `deployer` | `0xf17f52151ebef6c7334fad080c5704d77216b732` | contract deployment |

Additional actor roles from the contract spec should be assigned by setup
scripts. If those roles need signing keys, generate or import
them into ignored local files or environment-specific secret stores.

Contract deployment and the current ledger smoke command sign as
`governance_admin`. Put the matching development private key in an ignored local
environment file or export it in the shell as `GOVPROV_DEV_DEPLOYER_PRIVATE_KEY`
before running deployment commands. Do not commit the local env file.

## Start

From the `git/software` repository root:

```powershell
docker compose --profile besu-dev up -d besu-dev
```

Inspect logs:

```powershell
docker compose --profile besu-dev logs -f besu-dev
```

## Smoke Check

Run the containerized JSON-RPC smoke check:

```powershell
docker compose --profile besu-dev run --rm besu-rpc-smoke
```

The smoke check waits for the RPC endpoint, confirms `eth_chainId` is `0x539`,
and confirms the documented `governance_admin` account has a nonzero balance.

## Deploy Contracts

Set the local development signing key in the shell or an ignored local env file,
then run the deployment service:

```powershell
$env:GOVPROV_DEV_DEPLOYER_PRIVATE_KEY="<local-dev-private-key>"
docker compose --profile besu-dev run --rm besu-contract-deploy
```

The service deploys `ActorRegistry`, `PolicyRegistry`, `ProvenanceRegistry`,
`ApprovalRegistry`, `DeploymentRegistry`, and `ContractDirectory`; bootstraps
the local governance admin, ledger writer, deployer, default scope, and
`delivery-v1` policy; activates the deployed contract set; and writes an ignored
manifest to:

```text
runs/besu-dev/ledger/deployment_manifest.json
```

Validate that manifest directly if needed:

```powershell
docker compose run --rm foundry sh ./scripts/export-contract-abis.sh validate-manifest ../runs/besu-dev/ledger/deployment_manifest.json
```

## Ledger Smoke

After deployment, run the minimal write/read smoke:

```powershell
docker compose --profile besu-dev run --rm besu-ledger-smoke
```

The smoke reads the deployment manifest, writes a deterministic test attestation
anchor through `ProvenanceRegistry`, reads the attestation back from contract
state, and writes ignored output to:

```text
runs/besu-dev/ledger/smoke.json
```

## S1 Besu Scenario Smoke

After the dev contracts are deployed, run the S1 full-mode scenario smoke:

```powershell
docker compose --profile besu-dev run --rm scenario-s1-besu-test
```

The command writes ignored scenario output to:

```text
runs/besu-dev/scenarios/S1_runbook_update/govreplay_besu.json
```

It records the S1 happy-path attestation hashes against the dev Besu
registries, confirms readback from policy/provenance/approval/deployment state,
and points to the ignored Foundry broadcast trace at:

```text
contracts/broadcast/S1BesuScenario.s.sol/1337/run-latest.json
```

Use the broadcast trace when transaction hashes, block numbers, or event log
indexes are needed before full replay reports are generated.

## S4 Besu Scenario Smoke

After the dev contracts are deployed, run the S4 full-mode scenario smoke:

```powershell
docker compose --profile besu-dev run --rm scenario-s4-besu-test
```

The command writes ignored scenario output to:

```text
runs/besu-dev/scenarios/S4_policy_gated_deployment/govreplay_besu.json
```

It registers and activates the P3 deployment policy, anchors the S4 happy-path
attestation hashes, records the approval and deployment, confirms readback from
policy/provenance/approval/deployment state, and points to the ignored Foundry
broadcast trace at:

```text
contracts/broadcast/S4BesuScenario.s.sol/1337/run-latest.json
```

## Stop

```powershell
docker compose --profile besu-dev down
```

## Reset Local State

After stopping the profile, delete the ignored local data directory if a clean
chain is needed. Also remove ignored run output if you want deployment and smoke
artifacts to match only the new chain:

```powershell
Remove-Item -Recurse -Force .\chain\besu\dev\data
Remove-Item -Recurse -Force .\runs\besu-dev
Remove-Item -Recurse -Force .\contracts\broadcast\S1BesuScenario.s.sol
Remove-Item -Recurse -Force .\contracts\cache\S1BesuScenario.s.sol
Remove-Item -Recurse -Force .\contracts\broadcast\S4BesuScenario.s.sol
Remove-Item -Recurse -Force .\contracts\cache\S4BesuScenario.s.sol
```

Review each path before running reset commands. They remove only ignored local
Besu chain state and generated run output; they do not touch committed
configuration.
