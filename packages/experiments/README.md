# GovReplay Experiments

This package owns the Audit Replay under Policy Evolution (ARPE) experiment runner.

It generates deterministic workload and ground-truth records, writes the
standard `runs/<run_id>/` output layout, emits structured-log and signed Merkle
baseline outputs, GovReplay-compatible audit result JSONL, metrics
summaries, matrix summaries, per-fault detection-boundary tables, and
paper-facing tables/plot CSVs.

The runner intentionally keeps the replay boundary narrow:

- `baseline_structured_logs` is parsed as a conventional structured-log
  baseline without cryptographic replay.
- `baseline_signed_merkle_log` emits structured lifecycle events with
  per-event secp256k1 signatures, a hash chain, a Merkle root manifest, policy
  version fields, actor/role snapshots, artifact hashes, and approval
  references where available. It intentionally has no Besu dependency or shared
  smart-contract actor, policy, approval, deployment, anchor, or
  contract-directory state.
- `SEGL` emits a Signed Event-Sourced Governance Log. It stores the same
  governance object classes as GovReplay-Besu as append-only signed transition
  events, including actor-role history, policy activations, approvals,
  deployments, anchors, and contract-directory records. Replay folds those
  events into historical governance state without using Besu.
- `govreplay_offchain_only`, `baseline_hash_only_ledger`, and `govreplay_besu`
  emit records in the audit replay report schema so downstream metrics
  consume `audit/audit_results.jsonl`.
- `baseline_hash_only_ledger` is an optional ST-S1 ablation. It emits
  deterministic hash-anchor records and anchor readback metadata, but it has no
  actor, policy, approval, deployment, or contract-directory registry state.
- Deterministic sidecars are oracle, reproducibility, and debugging artifacts.
  They are not the replay backend for `besu_live_arpe_full`, which writes the
  GovReplay-Besu basic and hard subsets through live Besu RPC and contract
  calls. The live profile emits observed verifier rows from live contract state
  and derives success/failure counts from those rows.

Run from the software repository root:

```powershell
docker compose run --rm experiment-runner-test
docker compose run --rm experiment-basic-matrix-test
docker compose run --rm experiment-minimum-matrix-test
docker compose run --rm experiment-hard-matrix-test
docker compose --profile paper-arpe run --rm paper-arpe
docker compose --profile besu_live_arpe_full run --rm paper-arpe-full
```

`paper-arpe` is the quick debug bundle. `paper-arpe-full` is the promoted
paper-facing deterministic command; it regenerates the basic matrix, hard
matrix, and hash-only hard ablation. The SEGL event stream and manifest are
generated with the same commands:

```text
runs/<run_id>/baseline_logs/segl_events.jsonl
runs/<run_id>/baseline_logs/segl_manifest.json
```

Run the full live Besu-backed ARPE profile:

```powershell
$env:GOVPROV_DEV_DEPLOYER_PRIVATE_KEY="<local-dev-private-key>"
docker compose --profile besu_live_arpe_full run --rm paper-arpe-full
docker compose --profile besu_live_arpe_full up --build --exit-code-from besu-live-arpe-full besu-dev besu-live-arpe-full
docker compose down
```

Generated runs are local artifacts under ignored `runs/`.

Metric formulas and generated-field mappings are tracked in
`docs/metrics_spec.md`. Each run emits reviewer-separable
`inputs/ground_truth.*`, `audit/replay_report.*`, `results/metrics.*`,
`config.*`, `inputs/scenario.json`, and `faults/fault_injection.*` files before
writing paper-facing tables and figure CSVs.
