# Result Provenance Gate

PX-S33 added a non-default result-provenance gate for paper-facing ARPE and live
Besu outputs. PX-S34 separates ARPE oracle records, verifier input records,
observed verifier output, and scored metric rows. PX-S35 replaces deterministic
ARPE sidecar verdict synthesis with observed replay evidence checks and promotes
the hash-only hard ablation into the paper-facing full command. PX-S36 replaces
static live Besu PASS rows with per-workflow verifier rows emitted from live
RPC-backed contract state. PX-S37 makes SEGL workflow verification consume only
signed event logs and neutral workflow references. PX-S38 routes policy and
gateway decisions through observed policy evaluation and keeps expected labels
as oracle/test metadata only. The gate is green when all seven invariants pass.

Run from `git/software`:

```powershell
docker compose run --rm result-provenance-gate
```

The default experiment test service remains green and includes unit coverage
that the gate reports the current all-green boundary:

```powershell
docker compose run --rm experiment-runner-test
```

## Invariants

| ID | Policy | PX-S35 status | Owning repair sprint |
| --- | --- | --- | --- |
| `PX-S33-1` | Ground-truth label mutation must not change replay verdicts, and replay synthesis must not consume in-memory oracle labels. | Green | PX-S34 complete |
| `PX-S33-2` | Replay report rows must not carry expected labels or raw fault IDs as verifier inputs. | Green | PX-S34 complete |
| `PX-S33-3` | PASS-like paper-facing rows must name observed verifier provenance. | Green | PX-S34 complete |
| `PX-S33-4` | Live Besu success/failure counts must be derived from verifier rows, not constants. | Green | PX-S36 complete |
| `PX-S33-5` | SEGL semantic detection must come from the event log and reconstructed state, not `fault_id`. | Green | PX-S37 complete |
| `PX-S33-6` | Policy replay must recompute historical decisions without expected compliance labels. | Green | PX-S38 complete |
| `PX-S33-7` | Promoted paper commands must regenerate every paper-discussed result, including the hash-only hard ablation if retained. | Green | PX-S35 complete |

## Gate Behavior

The gate generates a small debug ARPE run in a temporary directory, mutates only
`inputs/ground_truth.*`, and confirms the already-written replay report remains
unchanged. PX-S34 also removes the runner source patterns where replay rows were
created from in-memory ground-truth objects.

PX-S34 emits distinct artifacts:

```text
inputs/workload.jsonl
inputs/ground_truth.json and inputs/ground_truth.jsonl
audit/replay_inputs.json and audit/replay_inputs.jsonl
audit/replay_report.json and audit/audit_results.jsonl
results/scored_metric_rows.jsonl
results/metrics.json and results/metrics_summary.json
```

`audit/replay_inputs.*` exclude `expected_verdict`,
`expected_failure_stage`, `expected_failure_code`,
`expected_policy_drift_class`, and `fault_id`. Replay rows name
`replay_id`, `verifier_source`, `replay_backend`, an observed check list, and
input provenance. Metrics are produced by joining observed verifier output to
oracle records by `replay_id` after replay output exists.

PX-S35 keeps the separated artifact boundary and changes deterministic replay
rows to be derived from observed replay evidence. The fault injector can still
create corrupted workload-specific inputs, but `replayOutput.ts` verifies only
the replay input's observed evidence/state and does not branch on oracle fields
or raw `fault_id`.

The `paper-arpe-full` service now regenerates:

```text
configs/arpe_basic_matrix.json
configs/arpe_hard_debug.json
configs/arpe_hash_only_ablation_hard_debug.json
```

The supplemental hash-only evidence is therefore a full regenerated
580-record hard-ablation matrix, not a single 116-record appended
configuration and not a dependency on stale `runs/` output.

PX-S36 changes the live Besu full profile so
`contracts/script/BesuLiveArpeFull.s.sol` emits one observed
`govprov.live_besu_arpe_audit.v2` row for each of the 656 live workflows after
querying actor, policy, approval, deployment, provenance-anchor, and
contract-directory contract state through the live RPC-backed Foundry script.
`contracts/scripts/besu-live-arpe-full.sh` no longer writes replay PASS rows.
It counts the observed audit JSONL rows, derives replay success/failure totals
from `replay_verdict`, preserves receipt-derived gas and transaction totals,
and labels replay contract-call totals as formula-derived from the verifier
check plan.

PX-S37 keeps SEGL fault injection in the generator but changes
`verifySeglWorkflow` to accept only a neutral workflow reference. H-series SEGL
faults are represented as signed transition events or state mismatches, such as
actor-role revocation, policy re-activation between decision and deployment,
conflicting policy activations, approval lifecycle-link mismatch, deployment
scope mismatch, and contract-directory supersession. The remaining check
inspects targeted source boundaries for expected-label-derived policy decisions.

PX-S38 removes the remaining expected-label policy sources. Gateway request
matching now locates the deterministic policy input, but the decision material
comes from the shared policy evaluator over policy source, bundle version,
principal/action/resource/context input, and obligation resolution. Policy
decision attestations record the observed decision, policy bundle/version,
input digest, evaluator identity/version, matched permit IDs, obligations, and
decision hash. Audit replay derives historical and current compliance from the
signed policy-decision predicate and optional current-policy version instead of
reading expected compliance labels from replay fixtures.
