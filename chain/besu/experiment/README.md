# Four-Node Besu Experiment Profile

This profile is the paper-facing local permissioned network for experiments. It
uses four generated QBFT validators, a deterministic chain ID, and the same
development account addresses as the one-node profile. It is slower than
`besu-dev`, but it exercises multi-node consensus before scenario and
audit-replay work depends on ledger state.

## Network

- RPC endpoint: `http://localhost:8546`
- Compose service used for RPC: `besu-experiment-1`
- container RPC URL: `http://besu-experiment-1:8545`
- chain ID: `1338` (`0x53a`)
- consensus: four-validator QBFT
- static node IPs: `172.28.0.11` through `172.28.0.14` on the Compose
  `besu-experiment-net` network
- generated network material: `chain/besu/experiment/network/`
- node chain data: `chain/besu/experiment/node-*/data/`
- deployment manifest: `runs/besu-experiment/ledger/deployment_manifest.json`
- ledger smoke output: `runs/besu-experiment/ledger/smoke.json`

The repository tracks only the QBFT generation config and wrapper scripts.
Generated genesis, validator keys, node keys, chain state, static node files,
deployment manifests, and smoke outputs are ignored.

## Funded Development Accounts

The profile documents only addresses. Private keys remain in ignored local env
files or shell variables.

| Account | Address | Intended use |
| --- | --- | --- |
| `governance_admin` | `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf` | bootstrap admin and deployment signer |
| `ledger_writer` | `0x627306090abab3a6e1400e9345bc60c78a8bef57` | ledger writer transactions |
| `deployer` | `0xf17f52151ebef6c7334fad080c5704d77216b732` | deployment actor |

The current contract deploy and ledger smoke commands sign as
`governance_admin`, just like the one-node dev profile.

## Start

From the `git/software` repository root:

```powershell
docker compose --profile besu-experiment up -d besu-experiment-init
docker compose --profile besu-experiment up -d besu-experiment-1 besu-experiment-2 besu-experiment-3 besu-experiment-4
```

Inspect logs:

```powershell
docker compose --profile besu-experiment logs -f besu-experiment-1
```

## Network Smoke Check

Run the containerized smoke check:

```powershell
docker compose --profile besu-experiment run --rm besu-experiment-rpc-smoke
```

The check waits for RPC, confirms chain ID `0x53a`, confirms the funded
`governance_admin` account has a nonzero balance, checks that node 1 sees at
least three peers, and confirms QBFT reports four validators.

## Deploy Contracts

Set the local development signing key in the shell or an ignored local env file,
then run the experiment deployment service:

```powershell
$env:GOVPROV_DEV_DEPLOYER_PRIVATE_KEY="<local-dev-private-key>"
docker compose --profile besu-experiment run --rm besu-experiment-contract-deploy
```

The command reuses the deployment script with experiment-specific
manifest fields and writes:

```text
runs/besu-experiment/ledger/deployment_manifest.json
```

## Ledger Smoke

After deployment:

```powershell
docker compose --profile besu-experiment run --rm besu-experiment-ledger-smoke
```

The smoke reuses the `ProvenanceRegistry` write/read path against the experiment
RPC endpoint and writes:

```text
runs/besu-experiment/ledger/smoke.json
```

## Stop

```powershell
docker compose --profile besu-experiment down
```

## Reset Local State

After stopping the profile, remove ignored experiment output if a clean network
is needed:

```powershell
Remove-Item -Recurse -Force .\chain\besu\experiment\network
Remove-Item -Recurse -Force .\chain\besu\experiment\node-1\data
Remove-Item -Recurse -Force .\chain\besu\experiment\node-2\data
Remove-Item -Recurse -Force .\chain\besu\experiment\node-3\data
Remove-Item -Recurse -Force .\chain\besu\experiment\node-4\data
Remove-Item -Recurse -Force .\runs\besu-experiment
```

Review paths before running reset commands. They remove ignored generated
network material, local chain data, and run output only.
