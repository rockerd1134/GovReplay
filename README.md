# GovReplay

GovReplay is a research prototype for historical authorization replay in software-delivery workflows. It distinguishes the infrastructure writer from the actor a proposal represents. Replay checks actor authority at **first action-hash commitment (N)** and the deployment sender, policy and approval conditions at **deployment (D)**. Signature verification remains retrospective.

The associated paper is **Historical Authorization at Commitment Boundaries in Software-Delivery Audit Trails**, prepared for IEEE ICC 2027's Communication and Information System Security (CISS) Symposium. See [CITATIONS.md](CITATIONS.md); author, submission and public-paper-link metadata await confirmation.

## Evaluated behavior

The baseline `ProvenanceRegistry` admits an authorized writer naming an active actor. `HardenedProvenanceRegistry` additionally checks the represented actor's deployer role for action-proposal commitments. The baseline is deliberately retained as the comparator.

The bounded model contains **420 orderings and six boundary-authority classes**. Expected guarded outcomes are 152 rejected N-invalid commitments, 268 accepted N-valid commitments, and 214 passing full histories. These are finite conformance results, not independent attack trials. See [the evaluation guide](docs/ciss-evaluation.md) for scope, frozen predictions and denominators.

## Prerequisites

- Git, Docker Engine/Desktop with Linux containers, and Docker Compose 2.24.4 or newer (`!override` support).
- PowerShell 7 (`pwsh`) for the reproduction helper on Windows, Linux or macOS.
- Internet access for initial image/dependency downloads; disk space for ignored chain/run outputs.

[compose.yaml](compose.yaml) pins Node 24.2.0, Foundry 1.0.0, Besu 25.6.0, Rust 1.89.0 and curl 8.10.1. Solidity is pinned to 0.8.26; [foundry-deps.lock](contracts/foundry-deps.lock) pins contract dependencies. Host Node, Rust, Solidity and Besu are optional.

## Quick start

```powershell
git clone https://github.com/rockerd1134/GovReplay.git
cd GovReplay
docker compose run --rm temporal-ordering-test
docker compose run --rm attestations-test
docker compose run --rm foundry
pwsh -File scripts/reproduce-ciss.ps1 -Mode named
```

The helper generates disposable wallets, funds the administrator in a fresh single-node QBFT genesis, deploys contracts and runs nine named cases on separate baseline/guarded chains. It refetches receipts, verifies signed SEGL replay and checks outcomes, printing `status: PASS`. Its isolated chains publish **no host RPC ports**. Runtime keys stay under ignored `.tmp/`; no production credentials are needed.

For the complete bounded experiment, use a fresh identifier:

```powershell
pwsh -File scripts/reproduce-ciss.ps1 -Mode full -RunId review-full-001
```

The full run submits thousands of sequential transactions at a one-second block period. Allow substantially more time than the smoke test. It checks exact 420-plan membership, six classes, frozen predictions and 1,840 observed-output property comparisons. See [reproduction details](docs/ciss-evaluation.md) for separate phases and parallel chains.

## Layout

| Path | Purpose |
| --- | --- |
| `contracts/src/` | Actor, policy, approval, deployment and provenance registries; baseline and guard |
| `packages/experiments/temporal-ordering/` | Case manifests, expectation implementations, SEGL/Besu replay, coverage and property checks |
| `packages/attestations/` | Canonicalization, hashes, signed synthetic fixtures and experimental cryptography |
| `packages/audit-replay/` | General software-delivery lineage replay |
| `packages/policy-service/`, `packages/gateway/`, `packages/scenarios/` | Optional Cedar-policy and deterministic scenario/demo paths |
| `packages/experiments/` | Historical ARPE workloads/metrics and optional third-party probes |
| `packages/audit-ui/` | Optional local static results viewer |
| `examples/`, `schemas/` | Synthetic fixtures and data contracts |
| `chain/besu/`, `compose*.yaml`, `scripts/` | Local networks and container reproduction |

[ARCHITECTURE.md](ARCHITECTURE.md) covers the broader prototype, including historical modules. The primary CISS entry point is temporal ordering; other ARPE configurations do not expand its evidence. ARPE is an author-defined synthetic benchmark, not a certification suite.

## Other package checks

```powershell
docker compose run --rm policy-bundle-test
docker compose run --rm policy-service-test
docker compose run --rm gateway-test
docker compose run --rm scenario-manifest-test
docker compose run --rm audit-replay-test
docker compose run --rm audit-ui-data-test
```

Optional workload commands: [experiments](packages/experiments/README.md), [third-party boundary analogs](packages/experiments/third-party-boundary/README.md), and [local UI](packages/audit-ui/README.md).

## Outputs and troubleshooting

Receipts, signed streams and reports are in `runs/temporal-<RunId>/temporal_ordering/` and `runs/hardening-<RunId>/temporal_ordering/`. Aggregate reports, runtime wallets and chain data are in `.tmp/ciss-<RunId>/`. Both paths are ignored. Preserve chain state through reporting. The helper stops its own chains after reporting and keeps data for inspection.

Existing RunIds are never overwritten. After a failure, inspect preserved receipts/logs and retry with a fresh identifier. The baseline retries only explicit nonce-too-low rejection, never an ambiguous send failure. Start Docker if its engine is unavailable; dependency/image/compiler downloads need internet access.

After inspection, use Compose `down` only for the specific `govreplay-<RunId>-baseline` or `govreplay-<RunId>-hardened` project. Delete only the chosen ignored run/chain directories when finished. Do not upload `.env`, runtime wallets, generated archives or validator keys.

## Security and scope

See [SECURITY.md](SECURITY.md). This is a local synthetic research artifact. Its handwritten signature implementation is experimental, without a cryptographic security audit. The guard does not verify signatures at write time, establish signing order, bind delivered content or enforce all attestation types. Independent multi-party administration and arbitrary-history correctness remain outside evaluated evidence.

## License and credit

Copyright 2026 Rocker D'Antonio. [Apache-2.0](LICENSE), with attribution in [NOTICE](NOTICE) and dependency credits in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Please cite the software release and associated paper in research; citation requests are separate from legal license conditions.