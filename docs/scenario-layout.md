# Scenario Layout

Deterministic workflow scenarios live under:

```text
examples/scenarios/<scenario_id>/
```

The first seed scenarios are:

```text
examples/scenarios/S1_runbook_update/
  README.md
  manifest.json
  observation.json
  input/
  evidence/
  expected/
  faults/

examples/scenarios/S4_policy_gated_deployment/
  README.md
  manifest.json
  observation.json
  input/
  evidence/
  expected/
```

Additional scenario fixtures include:

```text
examples/scenarios/S2_configuration_change/
examples/scenarios/S3_patch_proposal/
```

The deterministic gateway suite adds scripted pre-action fixtures for S1-S5
under `packages/gateway/fixtures/`. See
[gateway-scenarios.md](gateway-scenarios.md) for the gateway-specific request
layout, allow/deny behavior, generated `runs/gateway-smoke/` outputs, and
inspection commands.

Scenario manifests are validated against
`schemas/scenarios/manifest.schema.json` and use schema version
`govprov.scenario_manifest.v1`.

## Manifest Fields

- `scenario_id`: stable scenario directory identifier, such as
  `S1_runbook_update`.
- `scenario_name`: short human-readable scenario name.
- `workflow_id`: deterministic run identifier for the policy/fault/mode case.
- `policy_version`: policy bundle version label such as `P1`, `P2`, or `P3`.
- `fault_id`: `F0` for happy path or a numbered injected fault.
- `mode`: scenario manifests use implementation modes such as
  `structured_logs`, `signed_offchain`, and `govreplay_besu`; ARPE-level
  experiment configuration names also include `baseline_structured_logs`,
  `baseline_signed_merkle_log`, `govreplay_offchain_only`, `SEGL`,
  `baseline_hash_only_ledger`, and `govreplay_besu`.
- `expected_verdict`: `pass` or `fail`.
- `expected_failure_code`: null for passing runs; stable failure code for
  faulted runs.
- `expected_failure_stage`: null for passing runs; lifecycle localization for
  faulted runs.
- `expected_historical_compliance`: replay result under the policy active at
  action time.
- `expected_current_compliance`: replay result under the current/latest policy.
- `primary_actor_id`: actor responsible for the governed action.
- `resource_id`: governed resource or deployment identifier.
- `created_at`: deterministic UTC timestamp.

## Local S1 Runner Output

The local S1 runner consumes
`examples/scenarios/S1_runbook_update/manifest.json` and writes deterministic
run outputs under ignored `runs/scenarios/wf-S1-P1-F0-0001/`:

- `run_manifest.json`
- `observation.json`
- `evidence_bundle.json`
- `policy_decision.json`
- `action.json`
- `approval.json`
- `artifact.json`
- `deployment.json`
- `baseline_logs.jsonl`
- `attestations/<type>/<attestation_hash>.json`
- `objects/sha256/<prefix>/<prefix>/<attestation_hash>.json`
- `manifests/attestation_index.json`
- `manifests/local_replay_fixture.json`
- `manifests/local_fault_replay.json`

The seven signed attestations correspond to the S1 happy-path lifecycle:

```text
ObservationAttestation
  -> EvidenceBundleAttestation
  -> PolicyDecisionAttestation
  -> AgentActionAttestation
  -> ApprovalAttestation
  -> ArtifactAttestation
  -> DeploymentAttestation
```

The local replay fixture is intentionally narrow. It names the deployment
attestation hash to start from, records the expected parent-linked chain, and
is sufficient for local checks of deterministic files, hashes, signatures, and
parent links. It does not query Besu, re-run current policy, traverse arbitrary
graphs, or emit full audit reports; those are covered by the audit replay
package and Besu smoke paths.

## Local S1 Fault Subset

The S1 subset includes curated local signed-offchain fixtures:

| Fault | Mutation | Local failure code | Localized stage |
| --- | --- | --- | --- |
| F1 missing evidence | Omits the current-runbook evidence reference from the evidence bundle. | `evidence_missing` | `evidence` |
| F2 evidence tampered | Records a post-attestation evidence mutation with a mismatched digest. | `evidence_hash_mismatch` | `evidence` |
| F6 missing approval | Omits the approval record and `ApprovalAttestation`. | `approval_missing` | `approval` |
| F10 artifact substitution | Publishes a deployment digest that differs from the approved artifact digest. | `artifact_hash_mismatch` | `artifact_deployment` |

The runner writes `manifests/local_fault_replay.json` with the deterministic
fixture-level verdict, checks, failure code, and failure stage. Besu writes,
arbitrary replay graph traversal, current policy re-evaluation, other
scenarios, experiment runner, UI, and paper-facing outputs are separate
validation surfaces.

## S1 Besu Full Mode

S1 includes a Compose-gated `govreplay_besu` smoke path. The path reuses the
S1 happy-path signed attestations, registers the extra S1 actors needed by the
dev deployment, anchors observation, evidence, policy-decision, action,
approval, artifact, and deployment attestation hashes in `ProvenanceRegistry`,
records approval state in `ApprovalRegistry`, records deployment state in
`DeploymentRegistry`, and reads policy, provenance, approval, and deployment
records back before passing.

The generated S1 Besu output remains ignored under:

```text
runs/besu-dev/scenarios/S1_runbook_update/govreplay_besu.json
```

That JSON links the S1 local attestation hashes to the active dev Besu contract
addresses, event names, deployment ID hash, approval root, and the ignored
Foundry broadcast trace:

```text
contracts/broadcast/S1BesuScenario.s.sol/1337/run-latest.json
```

The broadcast trace contains per-transaction hashes, receipts, block numbers,
and log indexes for emitted events. Replay tooling queries those state/events;
the S1 full mode proves that the required dev Besu records can be written and
read.

## Local S4 Deployment Fixture

`S4_policy_gated_deployment` is the deployment-centered
scenario. The S4 local runner consumes
`examples/scenarios/S4_policy_gated_deployment/manifest.json` and writes
deterministic output under ignored `runs/scenarios/wf-S4-P3-F0-0001/`.

S4 emits the same seven signed lifecycle attestations as S1, but the fixture is
centered on a deployment start point:

```text
deployment-S4-0001
  -> DeploymentAttestation
  -> ArtifactAttestation
  -> ApprovalAttestation
  -> AgentActionAttestation
  -> PolicyDecisionAttestation
  -> EvidenceBundleAttestation
  -> ObservationAttestation
```

The runner writes both `manifests/local_replay_fixture.json` and
`manifests/deployment_backward_chain.json`. The latter names
`deployment-S4-0001`, its deployment attestation hash, the expected backward
chain, and the ledger event families that replay should query. It does not
perform full graph traversal, current-policy replay, or report generation.

## S4 Besu Full Mode

The S4 `govreplay_besu` smoke path registers the S4 actors, registers and
activates the P3 deployment policy, anchors the S4 happy-path attestation
hashes, records the approval, and records `deployment-S4-0001` in
`DeploymentRegistry`. The generated output remains ignored under:

```text
runs/besu-dev/scenarios/S4_policy_gated_deployment/govreplay_besu.json
```

That JSON links the deployment ID, active P3 policy hash, local S4 attestation
hashes, approval root, deployment ID hash, registry addresses, and ignored
Foundry broadcast trace:

```text
contracts/broadcast/S4BesuScenario.s.sol/1337/run-latest.json
```

## Local S2 Approval Fixture

`S2_configuration_change` is the approval-governance scenario. The
happy path uses P2, a configuration approver, and separation of duties between
`agent.config_operator` and `human.reviewer.blair`. The curated fault fixture is
`F8`, which records the proposing actor as the approver and localizes the
failure as `separation_of_duties_violation` at the approval stage.

S2 local output remains ignored under:

```text
runs/scenarios/wf-S2-P2-F0-0001/
```

S2 Besu full mode is not part of the current smoke path; the local signed
fixture establishes the approval-stage failure contract.

## Local S3 Patch Fixture

`S3_patch_proposal` is the supply-chain-style artifact scenario. The
happy path uses P3, links issue evidence, simulated test evidence, a patch file,
code-review approval, and deployment readiness. The curated fault fixture is
`F10`, which substitutes the deployment artifact digest and localizes the
failure as `artifact_hash_mismatch` at the artifact/deployment stage.

S3 local output remains ignored under:

```text
runs/scenarios/wf-S3-P3-F0-0001/
```

S3 Besu full mode is not part of the current smoke path.

## Gateway S1-S5 Fixtures

The gateway package contains one allowed and one denied `AgentActionRequest`
fixture for each implemented gateway scenario:

| Scenario | Allowed fixture | Denied fixture |
| --- | --- | --- |
| `S1_runbook_update` | `s1-runbook-allow.request.json` | `s1-runbook-deny.request.json` |
| `S2_configuration_change` | `s2-config-allow.request.json` | `s2-config-deny.request.json` |
| `S3_patch_proposal` | `s3-patch-allow.request.json` | `s3-patch-deny.request.json` |
| `S4_policy_gated_deployment` | `s4-deployment-allow.request.json` | `s4-deployment-deny.request.json` |
| `S5_governance_state_change` | `s5-governance-allow.request.json` | `s5-governance-deny.request.json` |

Run the full gateway fixture suite through Docker Compose:

```powershell
docker compose run --rm gateway-test
```

The smoke command writes direct S1 allow/deny decisions and deterministic
client outputs under ignored `runs/gateway-smoke/` paths. Allowed gateway
requests emit `PolicyDecisionAttestation` and `AgentActionAttestation`, then
the deterministic client writes downstream workflow records linked by
`gateway_decision_hash` and `gateway_policy_decision_attestation_hash`. Denied
requests emit the policy decision only and do not produce approved downstream
workflow records.

## Scenario UI Fixtures

The scenario package includes a UI-readable JSON fixture generator.
The generator writes ignored output under:

```text
artifacts/scenario-ui-fixtures/scenario-runs.json
```

The bundle schema is `govprov.scenario_ui_fixture_bundle.v1` and summarizes:

- scenario, workflow, policy, fault, and verdict fields;
- lifecycle stage order;
- actor IDs;
- evidence paths;
- approval role and separation-of-duties status;
- artifact and deployed digest match status;
- replay start pointer;
- relative file paths for the generated local run records.

The audit UI owns presentation, navigation, filtering, and visual design. The
audit replay package owns full replay reports. The fixture is the stable data
contract between deterministic scenario runs and those consumers.

## Container Validation

Run the manifest validation through Docker Compose from the software repo:

```powershell
docker compose run --rm scenario-manifest-test
```

Run the local S1 runner tests and produce the deterministic local output
for S1, S2, S3, and S4 through Docker Compose:

```powershell
docker compose run --rm scenario-runner-test
```

Run the UI fixture generator contract through Docker Compose:

```powershell
docker compose run --rm scenario-ui-fixture-test
```

Run the S1 Besu full-mode smoke through Docker Compose:

```powershell
docker compose --profile besu-dev run --rm besu-contract-deploy
docker compose --profile besu-dev run --rm scenario-s1-besu-test
docker compose --profile besu-dev run --rm scenario-s4-besu-test
```

To restart from clean generated Besu state, stop the dev profile and remove only
ignored dev outputs:

```powershell
docker compose --profile besu-dev down
Remove-Item -Recurse -Force .\chain\besu\dev\data
Remove-Item -Recurse -Force .\runs\besu-dev
Remove-Item -Recurse -Force .\contracts\broadcast\S1BesuScenario.s.sol
Remove-Item -Recurse -Force .\contracts\cache\S1BesuScenario.s.sol
Remove-Item -Recurse -Force .\contracts\broadcast\S4BesuScenario.s.sol
Remove-Item -Recurse -Force .\contracts\cache\S4BesuScenario.s.sol
```
