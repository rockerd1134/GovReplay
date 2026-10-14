# Audit Replay under Policy Evolution (ARPE) Metrics Specification

This file maps each paper-facing ARPE metric to the generated fields under
`runs/<run_id>/`. Ground truth is generated before replay under `inputs/`;
verifier output is emitted under `audit/`; metrics are derived afterward under
`results/`.

## Separation Contract

Each run exposes these reviewer-inspectable files:

| Artifact | Path | Purpose |
| --- | --- | --- |
| run config | `config.json`, `config.yaml` | Matrix, configurations, scenarios, policies, faults, and seeds. |
| scenario/workload summary | `inputs/scenario.json`, `inputs/workload.jsonl` | Generated workload instances without verifier outcomes. |
| ground truth | `inputs/ground_truth.json`, `inputs/ground_truth.jsonl` | Independent expected verdict, stage, code, and policy-drift labels. |
| fault injection | `faults/fault_injection.json`, `faults/injection_log.jsonl` | Injected fault plan and expected failure boundary. |
| SEGL event source | `baseline_logs/segl_events.jsonl`, `baseline_logs/segl_manifest.json` | Signed Event-Sourced Governance Log transition history for the state-equivalent non-ledger baseline. |
| replay output | `audit/replay_report.json`, `audit/audit_results.jsonl` | Verifier output only. |
| metrics | `results/metrics.json`, `results/metrics_summary.json` | Aggregated comparison of replay output against ground truth. |
| per-fault oracle agreement | `results/per_fault_oracle_agreement.csv`, `paper/table_per_fault_oracle_agreement.md` | Fault-by-configuration counts for injected faults, detected faults, misses, false positives, and false negatives. |
| taxonomy metrics | `results/metrics_by_test_class.csv`, `results/metrics_by_external_tradition.csv`, `results/metrics_by_required_state.csv`, `results/metrics_by_governance_domain.csv`, `results/metrics_by_governance_domain_and_config.csv` | Taxonomy-aware aggregates by system configuration, ARPE test class, external inspiration tradition, ledger-state requirement, and governance domain. |
| gas metrics | `results/gas_usage.csv`, `results/gas_summary.csv`, `results/gas_summary_by_scenario.csv`, `telemetry/ledger_metrics.jsonl` | Per-transaction EVM gas usage and operation-level summaries for ledger-backed configurations. |
| paper exports | `paper/*.md`, `paper/figures/*.csv` | Table and figure inputs used by the manuscript. |
| reproducibility metadata | `results/reproducibility_summary.json` | Command, output inventory, and live Besu status pointer. |

The verifier must not read `inputs/ground_truth.*` or `faults/fault_injection.*`.
Those files are inputs only to metrics aggregation.

## Metric Formulas

Let one workflow instance be matched by
`system_configuration + workflow_id` across ground truth and replay output.

| Metric | Formula | Generated field |
| --- | --- | --- |
| reconstruction completeness | `reconstructed_links / required_links`, averaged over workflows in a group | `results/metrics_summary.json: configurations[].reconstruction_completeness`; per-record inputs are `audit/*.metrics.reconstructed_links` and `audit/*.metrics.required_links` |
| violation true positives | count where `expected_verdict = fail` and replay `verdict = FAIL` | implicit in precision, recall, F1, and `fault_detection_boundaries.csv` |
| violation false positives | count where `expected_verdict = pass` and replay `verdict = FAIL` | `configurations[].false_positive_count` |
| violation false negatives | count where `expected_verdict = fail` and replay `verdict = PASS` | `configurations[].false_negative_count` |
| violation precision | `TP / (TP + FP)`, or `1` when `TP + FP = 0` | `configurations[].precision` |
| violation recall | `TP / (TP + FN)`, or `1` when `TP + FN = 0` | `configurations[].recall` |
| violation F1 | `(2 * TP) / ((2 * TP) + FP + FN)`, or `0` when `TP = 0` | `configurations[].f1` |
| localization accuracy | workflows with `expected_verdict = fail` and `failure_stage = expected_failure_stage`, divided by workflows with `expected_verdict = fail` | `configurations[].localization_accuracy` |
| policy drift classification accuracy | workflows where replay `policy_drift_class` equals `expected_policy_drift_class`, divided by workflows | `configurations[].drift_classification_accuracy` |
| workflow latency | median and p95 of per-record `workflow_total_ms` | `configurations[].median_workflow_latency_ms`, `configurations[].p95_workflow_latency_ms` |
| verification latency | median of per-record `verification_time_ms` | `configurations[].median_verification_ms` |
| storage per workflow | mean per-record `storage_bytes`, rounded to bytes | `configurations[].storage_bytes_per_workflow` |
| transaction count | mean per-record `ledger_transaction_count` | `configurations[].transactions_per_workflow` |
| gas units | mean per-record `gas_used`, rounded to gas units | `configurations[].gas_per_workflow` |

## Gas Usage Metrics

GovReplay runs on permissioned Hyperledger Besu. Local profiles may configure a
zero gas price, but the EVM still meters execution with `gasUsed` in each
transaction receipt. ARPE treats gas usage as an implementation-overhead metric
for EVM execution. It is not interpreted as cryptocurrency cost, and zero
`effective_gas_price` or zero configured gas price does not make `gas_used`
irrelevant.

The experiment runner emits `results/gas_usage.csv` with one row per modeled
ledger transaction:

```text
run_id
scenario
operation
domain_id
contract_name
tx_hash
block_number
gas_used
effective_gas_price
configured_gas_price
status
latency_ms
timestamp
```

`results/gas_summary.csv` groups by `operation` and reports:

```text
operation,count,min_gas,median_gas,mean_gas,max_gas,total_gas
```

`results/gas_summary_by_scenario.csv` adds `scenario` to that grouping. The
live Besu smoke path derives the same `gas_usage.csv` and `gas_summary.csv`
shape from Foundry broadcast receipts under `contracts/broadcast/`.

## Taxonomy-Aware Aggregates

The experiment runner writes taxonomy-aware CSV exports derived from the same post-replay
comparison as `metrics_summary.json`:

| Export | Grouping | Reconciliation rule |
| --- | --- | --- |
| `results/metrics_by_test_class.csv` | `test_class_id + system_configuration` | `workflow_count` summed across rows equals the run's `workflow_count`. |
| `results/metrics_by_external_tradition.csv` | `external_tradition + system_configuration` | `workflow_count` summed across rows equals the run's `workflow_count`. |
| `results/metrics_by_required_state.csv` | `requires_ledger_state + system_configuration` | `workflow_count` summed across rows equals the run's `workflow_count`. |
| `results/metrics_by_governance_domain.csv` | `governance_domain` | `workflow_count` summed across rows equals the run's `workflow_count`. |
| `results/metrics_by_governance_domain_and_config.csv` | `governance_domain + system_configuration` | `workflow_count` summed across rows equals the run's `workflow_count`. |

ARPE models a single organizational governance environment with multiple
governance domains. The domain fields are replay metadata for authority
boundaries inside that environment; they do not claim multi-organization
federation.

`baseline_hash_only_ledger` is an optional ST-S1 ablation configuration. It
models deterministic ledger hash anchoring and anchor readback without
smart-contract governance registries for actors, policies, approvals,
deployments, or contract directories. It can distinguish anchor presence or
anchor mismatch faults from purely off-chain provenance, but it is not evidence
of full governance-state replay.

Each row reports workflow count, injected fault count, TP/TN/FP/FN, precision,
recall, F1, localization accuracy, reconstruction completeness, and the
taxonomy metadata represented by the row. `paper/table_arpe_test_classes.md`
maps external research traditions to the author-defined ARPE test classes. The
table is a positioning aid only; it does not encode SLSA, in-toto, Rekor,
SCITT, DARPA TC, OpTC, or ProvSec compliance.
`paper/table_governance_domain_mapping.md` maps domain names, domain types,
test classes, fault IDs, and any cross-domain dependency metadata used by the
generated workload.

`results/per_fault_oracle_agreement.csv` is the compact reviewer-facing
confusion table by `fault_id + system_configuration`. It excludes no-fault
controls and reports:

```text
fault_type
system_configuration
expected_failure_code
expected_failure_stage
injected_count
detected
missed
false_positive_count
false_negative_count
localization_matches
oracle_agreement_count
```

This export is derived only after replay completes by comparing
`inputs/ground_truth.*` with `audit/replay_report.*`.

## Reconstruction Denominator

`required_links` is the count of required lifecycle links in the ARPE replay
contract:

```text
observation
evidence
policy_version
policy_decision
action_proposal
approval_chain
artifact
deployment
ledger_anchor
```

Optional debug links, UI convenience fields, baseline-only metadata, and
human-readable Markdown reports are excluded from scoring. For configurations
without a ledger, `ledger_anchor` remains in the denominator because the metric
measures paper-facing lifecycle reconstruction against the full governance
replay contract.

## Reproduction Commands

The container-first paper-facing deterministic path is:

```powershell
docker compose --profile besu_live_arpe_full run --rm paper-arpe-full
```

It regenerates the 2,700-record basic matrix, 580-record hard matrix, and
580-record hash-only hard ablation, including observed replay outputs, result
CSVs/JSONs, paper table exports, paper figure CSVs, and
`results/reproducibility_summary.json`. Those generated summaries identify
`paper-arpe-full` as the promoted deterministic command for release-facing
matrices.

The faster debug subset remains available for local inspection:

```powershell
docker compose --profile paper-arpe run --rm paper-arpe
```

The live Besu profile is regenerated separately after setting a local
development key:

```powershell
$env:GOVPROV_DEV_DEPLOYER_PRIVATE_KEY="<local-dev-private-key>"
docker compose --profile besu_live_arpe_full up --build --exit-code-from besu-live-arpe-full besu-dev besu-live-arpe-full
```

The live profile writes `runs/besu-live-arpe-full/ledger/live_arpe_full_status.json`
and `runs/besu-live-arpe-full/audit/live_besu_audit_results.jsonl`.
