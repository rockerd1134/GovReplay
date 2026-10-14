# GovReplay Contracts

This directory is the Foundry project for the GovReplay smart contract layer:
actor, policy, provenance, approval, deployment, and contract-directory
registries described in the architecture.

## Layout

```text
contracts/
  foundry.toml
  remappings.txt
  src/
  test/
  script/
  deployments/
  lib/
```

OpenZeppelin and forge-std are expected through a declarative, pinned dependency
path. The tracked dependency declaration is `foundry-deps.lock`; downloaded
checkouts under `lib/` are generated local state and are not committed.

Canonical validation from the `git/software` repository root:

```powershell
docker compose run --rm foundry
```

Host-local Foundry can be used as an optional shortcut when available:

```powershell
sh ./scripts/sync-foundry-deps.sh
forge test
```

## Smoke Test

Run the bootstrap smoke test from this directory:

```powershell
# optional host-local shortcut
forge test
```

The smoke test proves that Solidity, Foundry, forge-std, OpenZeppelin, and the
governance registries compile and test through the local toolchain.

## ABI Export And Manifest Shape

The ABI export path is container-first from the software repository
root:

```powershell
docker compose run --rm foundry sh ./scripts/export-contract-abis.sh
```

The command builds the Foundry project, exports only the governance contract
ABIs, and writes generated local artifacts under `artifacts/contracts/` at the
software repository root. That directory is ignored and should not be committed.

The tracked manifest contract is:

```text
contracts/deployments/contract-addresses.schema.json
contracts/deployments/samples/contract-addresses.synthetic.json
```

`contract-addresses.synthetic.json` is not a real deployment. It is a stable
fixture that documents the shape Besu deployment tooling writes to
`runs/<run_id>/ledger/deployment_manifest.json` or an equivalent run-scoped
path. The manifest records chain identity, build metadata, a contract set ID,
governance-admin identity, active scope/policy hashes, and each governance
contract's address plus name, version, source, ABI, and metadata hashes.

Validate the tracked fixture through the same Foundry container:

```powershell
docker compose run --rm foundry sh ./scripts/export-contract-abis.sh validate-manifest
```

## Besu Dev Deployment

The container-first Besu deployment path is:

```powershell
$env:GOVPROV_DEV_DEPLOYER_PRIVATE_KEY="<local-dev-private-key>"
docker compose --profile besu-dev up -d besu-dev
docker compose --profile besu-dev run --rm besu-contract-deploy
```

The deployment command runs `script/DeployBesuDev.s.sol`, deploys the six Phase
1 contracts to the Besu RPC endpoint, bootstraps local roles and the default
policy, activates the contract directory set, and validates the generated
manifest. Generated manifests and Foundry broadcast/cache files are ignored.

Run the ledger smoke after deployment:

```powershell
docker compose --profile besu-dev run --rm besu-ledger-smoke
```

That command runs `script/BesuLedgerSmoke.s.sol`, writes one deterministic
attestation anchor through `ProvenanceRegistry`, reads it back, and writes an
ignored smoke result under `runs/besu-dev/ledger/`.
