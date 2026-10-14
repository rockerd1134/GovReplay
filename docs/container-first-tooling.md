# Container-First Tooling Guide

GovReplay's validation source of truth is Docker or Docker Compose. Host-local
tools can make development faster, but paper-facing artifact instructions should
use containerized entrypoints when those entrypoints exist.

## Canonical Targets

| Area | Canonical validation target | Host-local status |
| --- | --- | --- |
| Foundry contracts | `docker compose run --rm foundry` from the repository root | Optional convenience only |
| Besu dev network | `docker compose --profile besu-dev up -d besu-dev` plus `docker compose --profile besu-dev run --rm besu-rpc-smoke` | Not required directly on host |
| Besu experiment network | `docker compose --profile besu-experiment up -d ...` plus `docker compose --profile besu-experiment run --rm besu-experiment-rpc-smoke` | Not required directly on host |
| TypeScript packages | `docker compose run --rm attestations-test` and `docker compose run --rm policy-bundle-test` for current package slices | Optional convenience only |
| Deterministic gateway suite | `docker compose run --rm gateway-test` from the repository root | Optional convenience only |
| Rust/Cedar policy service | `docker compose run --rm policy-service-test` from the repository root | Optional convenience only |
| Experiment runner | Compose profile that validates environment, runs debug workload, and writes `runs/<run_id>/` | Optional convenience only |

## Foundry Contracts

The contract bootstrap now has a committed Compose entrypoint. The
`foundry` service pins the Foundry image in `compose.yaml`, syncs dependencies
declared in `contracts/foundry-deps.lock`, and runs `forge test` in
`contracts/`.

Tracked dependency declaration:

```text
contracts/foundry-deps.lock
```

Local generated dependency checkouts:

```text
contracts/lib/forge-std/
contracts/lib/openzeppelin-contracts/
```

The local checkouts are intentionally ignored so validation can recreate them
inside the container without vendoring dependency source into the research
artifact repository.

The same Foundry container exports contract ABIs and validates the synthetic
deployment manifest fixture:

```powershell
docker compose run --rm foundry sh ./scripts/export-contract-abis.sh
docker compose run --rm foundry sh ./scripts/export-contract-abis.sh validate-manifest
```

Generated ABI files and synthetic manifests are written under
`artifacts/contracts/` at the software repository root and stay untracked.
The tracked manifest schema and synthetic fixture live under
`contracts/deployments/`.

## Besu Dev Network

The one-node Besu dev profile is containerized in `compose.yaml` under the
`besu-dev` profile and documented in `chain/besu/dev/README.md`.

Start the node:

```powershell
docker compose --profile besu-dev up -d besu-dev
```

Run the JSON-RPC smoke check:

```powershell
docker compose --profile besu-dev run --rm besu-rpc-smoke
```

Stop the profile:

```powershell
docker compose --profile besu-dev down
```

The local RPC endpoint is `http://localhost:8545`; the deterministic chain ID is
`1337` (`0x539`). Local chain data is written under `chain/besu/dev/data/` and
is ignored. The repository documents funded development addresses only; private
keys, node keys, logs, and local chain state must remain outside git.

Deploy the governance contracts to the running one-node profile:

```powershell
$env:GOVPROV_DEV_DEPLOYER_PRIVATE_KEY="<local-dev-private-key>"
docker compose --profile besu-dev run --rm besu-contract-deploy
```

The deployment service runs the Foundry script in the pinned Foundry image and
validates the generated manifest shape. The generated manifest is local run
output at `runs/besu-dev/ledger/deployment_manifest.json` and remains ignored.

Run the minimal ledger write/read smoke:

```powershell
docker compose --profile besu-dev run --rm besu-ledger-smoke
```

The smoke service reads the deployment manifest, anchors a deterministic test
attestation in `ProvenanceRegistry`, reads it back, and writes
`runs/besu-dev/ledger/smoke.json`. The smoke is idempotent for an already
anchored smoke attestation.

The quick `besu-live-smoke` wrapper also parses Foundry broadcast receipts from
the deploy and smoke scripts and writes receipt-derived gas outputs:

```text
runs/besu-dev/results/gas_usage.csv
runs/besu-dev/results/gas_summary.csv
```

Besu dev networks may use zero gas price. These files report `gas_used` as EVM
execution overhead only; they are not cryptocurrency-cost reports.

## Besu Experiment Network

The four-node QBFT experiment profile is containerized under the
`besu-experiment` profile. It tracks only generation config and wrapper scripts;
generated validator material, node keys, chain data, manifests, and smoke output
stay ignored.

Generate/start the profile:

```powershell
docker compose --profile besu-experiment up -d besu-experiment-init
docker compose --profile besu-experiment up -d besu-experiment-1 besu-experiment-2 besu-experiment-3 besu-experiment-4
```

Run the network smoke check:

```powershell
docker compose --profile besu-experiment run --rm besu-experiment-rpc-smoke
```

The host RPC endpoint is `http://localhost:8546`; the container RPC endpoint is
`http://besu-experiment-1:8545`; the chain ID is `1338` (`0x53a`).

Deploy and smoke the contract layer against the experiment endpoint:

```powershell
$env:GOVPROV_DEV_DEPLOYER_PRIVATE_KEY="<local-dev-private-key>"
docker compose --profile besu-experiment run --rm besu-experiment-contract-deploy
docker compose --profile besu-experiment run --rm besu-experiment-ledger-smoke
```

Stop the profile:

```powershell
docker compose --profile besu-experiment down
```

## Attestation Package

The attestation foundation uses a pinned Node container in the
`attestations-test` Compose service:

```powershell
docker compose run --rm attestations-test
```

The service runs Node's built-in test runner with TypeScript type stripping over
`packages/attestations/test/*.test.ts`. It currently has no package-manager
install step and no host-local Node requirement.

## Policy Bundle Format

The policy bundle format uses a pinned Node container in the
`policy-bundle-test` Compose service:

```powershell
docker compose run --rm policy-bundle-test
```

The service validates `packages/policy-service/test/*.test.ts` without a
package-manager install step. It checks the policy bundle directory layout,
metadata and obligations schemas, compact fixture bundles, and deterministic
bundle hashing. Cedar allow/deny execution is covered by the Rust/Cedar service
entrypoint.

## Rust/Cedar Policy Evaluator And Obligation Resolver

The Rust/Cedar validation surface is the `policy-service-test` Compose service:

```powershell
docker compose run --rm policy-service-test
```

The service pins `rust:1.89.0-slim-bookworm`, runs from
`packages/policy-service/`, and executes:

```text
cargo test --locked
```

Rust dependencies are pinned in `Cargo.toml` and locked in `Cargo.lock`,
including `cedar-policy = "=4.11.1"`. Cargo's downloaded registry/cache state
uses ignored `.tmp/cargo-home/`, and build output remains ignored under
`packages/policy-service/target/`.

The current tests prove the Cedar evaluation surface: Cedar links, the fixture
bundles load, their Cedar schemas and policies parse, fixture
principal/action/resource/context records map to Cedar requests, all current
fixture allow/deny expectations evaluate deterministically, and
action-applicable obligations resolve to deterministic records bound to the
same policy bundle hash as the Cedar decision.

## Deterministic Gateway Suite

The deterministic gateway suite uses a pinned Node container in the
`gateway-test` Compose service:

```powershell
docker compose run --rm gateway-test
```

The service runs the gateway tests, validates allowed and denied S1-S5
`AgentActionRequest` fixtures, and writes reviewer-inspectable smoke outputs
under ignored `runs/gateway-smoke/` paths. Allowed requests emit signed
`PolicyDecisionAttestation` and `AgentActionAttestation` records before the
example client writes downstream workflow records. Denied requests fail closed:
they emit the policy decision only and do not write approved downstream
workflow records.

## Validation Rule

When both host and container commands exist, treat the container command as the
authoritative result. Host commands are supplemental developer checks.
