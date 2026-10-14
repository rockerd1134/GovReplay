# Besu Local Profiles

GovReplay has two local Besu profiles. Both are Docker Compose first and
keep generated chain material out of git.

| Profile | Purpose | Host RPC | Chain ID | Use for |
| --- | --- | --- | ---: | --- |
| `besu-dev` | fast one-node QBFT development chain | `http://localhost:8545` | `1337` | contract deploy, quick RPC smoke work, and the full live ARPE profile |
| `besu-experiment` | four-node QBFT permissioned network | `http://localhost:8546` | `1338` | optional multi-node local ledger experiments |

The profiles share the same documented development account addresses. The
current deploy and smoke commands sign as the local `governance_admin` account.
Keep `GOVPROV_DEV_DEPLOYER_PRIVATE_KEY` in the shell or an ignored local env
file; do not commit it.

## One-Node Dev Path

Start and validate:

```powershell
docker compose --profile besu-dev up -d besu-dev
docker compose --profile besu-dev run --rm besu-rpc-smoke
```

Deploy and smoke:

```powershell
$env:GOVPROV_DEV_DEPLOYER_PRIVATE_KEY="<local-dev-private-key>"
docker compose --profile besu-dev run --rm besu-contract-deploy
docker compose --profile besu-dev run --rm besu-ledger-smoke
docker compose --profile besu-dev run --rm besu-live-smoke
```

`besu-live-smoke` is a quick live development smoke, not the full paper-facing
profile. It wraps deployment plus the enhanced ledger smoke, records
provenance/approval/deployment state through live Besu RPC, and writes:

```text
runs/besu-dev/ledger/live_smoke_status.json
runs/besu-dev/paper/table_live_besu_status.md
runs/besu-dev/results/gas_usage.csv
runs/besu-dev/results/gas_summary.csv
```

The gas CSVs are derived from Foundry broadcast receipts. They report EVM
`gasUsed` as implementation overhead for the permissioned Besu prototype. Local
Besu profiles can use zero gas price, so these values are not cryptocurrency
costs.

## Full Live ARPE Path

The `besu_live_arpe_full` profile is the paper-facing live GovReplay-Besu
evaluation path. It keeps deterministic ARPE sidecars as oracle and baseline
artifacts, then writes the GovReplay-Besu basic and hard subsets to live Besu
contract state.

```powershell
$env:GOVPROV_DEV_DEPLOYER_PRIVATE_KEY="<local-dev-private-key>"
docker compose --profile besu_live_arpe_full run --rm paper-arpe-full
docker compose --profile besu_live_arpe_full up --build --exit-code-from besu-live-arpe-full besu-dev besu-live-arpe-full
docker compose down
```

The live run writes:

```text
runs/besu-live-arpe-full/ledger/live_arpe_full_status.json
runs/besu-live-arpe-full/audit/live_besu_audit_results.jsonl
runs/besu-live-arpe-full/results/gas_usage.csv
runs/besu-live-arpe-full/results/gas_summary.csv
runs/besu-live-arpe-full/paper/table_live_besu_status.md
```

The optional `besu_live_arpe_subset` mode is superseded by this full profile and
should be treated only as a possible quick-check convenience if restored later.

Stop:

```powershell
docker compose --profile besu-dev down
```

Reset ignored local state after stopping:

```powershell
Remove-Item -Recurse -Force .\chain\besu\dev\data
Remove-Item -Recurse -Force .\runs\besu-dev
```

## Four-Node Experiment Path

Generate/start and validate:

```powershell
docker compose --profile besu-experiment up -d besu-experiment-init
docker compose --profile besu-experiment up -d besu-experiment-1 besu-experiment-2 besu-experiment-3 besu-experiment-4
docker compose --profile besu-experiment run --rm besu-experiment-rpc-smoke
```

Deploy and smoke:

```powershell
$env:GOVPROV_DEV_DEPLOYER_PRIVATE_KEY="<local-dev-private-key>"
docker compose --profile besu-experiment run --rm besu-experiment-contract-deploy
docker compose --profile besu-experiment run --rm besu-experiment-ledger-smoke
```

Stop:

```powershell
docker compose --profile besu-experiment down
```

Reset ignored local state after stopping:

```powershell
Remove-Item -Recurse -Force .\chain\besu\experiment\network
Remove-Item -Recurse -Force .\chain\besu\experiment\node-1\data
Remove-Item -Recurse -Force .\chain\besu\experiment\node-2\data
Remove-Item -Recurse -Force .\chain\besu\experiment\node-3\data
Remove-Item -Recurse -Force .\chain\besu\experiment\node-4\data
Remove-Item -Recurse -Force .\runs\besu-experiment
```

## Generated Paths

These paths are local generated state and should remain ignored:

- `chain/besu/dev/data/`
- `chain/besu/experiment/network/`
- `chain/besu/experiment/node-*/data/`
- `runs/besu-dev/`
- `runs/besu-experiment/`
- `contracts/broadcast/`
- `contracts/cache/`
- `contracts/out/`
- `contracts/lib/`
- `artifacts/`
- `.env` and `.env.*`

## Failure Modes

- **Docker Desktop pipe permission errors.** Errors that mention
  `npipe:////./pipe/dockerDesktopLinuxEngine` usually mean the same Docker
  command needs escalation. Keep the Docker Compose validation path; do not
  switch to host-local Besu or Foundry as the source of truth.
- **Foundry dependency sync lock collisions.** Do not run two Foundry container
  commands in parallel. They may both update ignored `contracts/lib/`
  checkouts and collide on git lock files.
- **Stale chain data.** Deployment manifests and smoke outputs are tied to the
  local chain instance. If a profile behaves strangely after script changes,
  stop it and reset the profile's ignored chain/run paths.
- **Generated QBFT validator material.** Genesis and validator keys are created
  under ignored directories. If the tracked QBFT config changes, reset the
  generated profile state before validating.
- **Missing local deployer key.** Deployment and ledger smoke commands fail
  early unless `GOVPROV_DEV_DEPLOYER_PRIVATE_KEY` is set. Use placeholders in
  docs and ignored local env files for actual values.
- **Wrong profile manifest.** Dev manifests live under `runs/besu-dev/`; the
  experiment profile uses `runs/besu-experiment/`. If ledger smoke reads the
  wrong manifest, it will target the wrong contract addresses.
- **Slow or non-producing blocks.** The project uses QBFT because the earlier
  custom Ethash attempt produced impractically slow local blocks. Check
  `docker compose logs` for peer count, validator, or block-production messages.
- **RPC endpoint confusion.** Host users call `localhost:8545` for dev and
  `localhost:8546` for experiment. Compose services use internal URLs:
  `http://besu-dev:8545` or `http://besu-experiment-1:8545`.
- **Experiment static nodes.** Besu bootnode enodes require literal IP
  addresses. The experiment profile therefore uses a deterministic Compose
  subnet and node IPs `172.28.0.11` through `172.28.0.14`.

## Notes

Use `chain/besu/dev/README.md` and `chain/besu/experiment/README.md` for
profile-specific account and reset details. This guide is the comparison and
operator checklist.
