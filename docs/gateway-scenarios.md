# Gateway Scenario Suite

The gateway scenario suite is a deterministic, pre-action adapter for paper and
reviewer inspection. It exercises scripted `AgentActionRequest` fixtures across
five software-delivery governance domains. It is not a production HTTP gateway,
SDK, MCP adapter, LangGraph integration, AutoGen integration, live LLM-agent
runtime, or general agent framework.

Run the suite from the software repository root:

```powershell
docker compose run --rm gateway-test
```

The Compose target runs the gateway unit tests, writes direct allow and deny
gateway decisions, and runs the deterministic example client on one allow and
one deny request. Generated smoke outputs are ignored and remain under:

```text
runs/gateway-smoke/
  allow-decision.json
  deny-decision.json
  allow-client/
    gateway_decision.json
    workflow_records.json
    client_result.json
  deny-client/
    gateway_decision.json
    client_result.json
```

The wider test suite also evaluates every allowed and denied fixture under
`packages/gateway/fixtures/`.

## Request Layout

Each fixture uses schema version `govreplay.agent_action_request.v1` and
includes:

- `scenario_id`, `workflow_id`, `run_id`, and `request_id`;
- actor identity and roles;
- action type and risk;
- resource and target environment;
- policy bundle reference and policy version;
- policy context fields evaluated by the deterministic Cedar policy subset;
- `evidence_refs`, `artifact_refs`, `approval_refs`, and `deployment_refs`.

The request schema lives at:

```text
schemas/agent-action-request/v1.schema.json
```

The gateway implementation lives at:

```text
packages/gateway/src/gateway.ts
packages/gateway/src/example-agent-client.ts
```

## S1-S5 Coverage

| Scenario | Allowed case | Denied case | Primary coverage |
| --- | --- | --- | --- |
| `S1_runbook_update` | Incident evidence and documentation approval reference. | Missing evidence. | Evidence sufficiency and policy decision binding. |
| `S2_configuration_change` | High-risk config change with dual distinct approval references. | Self-approval posture. | Actor roles, approval authority, and separation of duties. |
| `S3_patch_proposal` | Issue evidence, test evidence, and patch artifact reference. | Missing patch artifact linkage. | Artifact provenance and supply-chain-style evidence. |
| `S4_policy_gated_deployment` | Approved artifact, deployment approval, and ledger-anchor evidence. | Unapproved artifact linkage. | Deployment/artifact consistency and policy decision lineage. |
| `S5_governance_state_change` | Governance-admin actor requests policy or governance-state transition. | Non-admin actor attempts the same action. | Governance-state administration and policy/contract-directory state. |

Fixture filenames:

```text
packages/gateway/fixtures/s1-runbook-allow.request.json
packages/gateway/fixtures/s1-runbook-deny.request.json
packages/gateway/fixtures/s2-config-allow.request.json
packages/gateway/fixtures/s2-config-deny.request.json
packages/gateway/fixtures/s3-patch-allow.request.json
packages/gateway/fixtures/s3-patch-deny.request.json
packages/gateway/fixtures/s4-deployment-allow.request.json
packages/gateway/fixtures/s4-deployment-deny.request.json
packages/gateway/fixtures/s5-governance-allow.request.json
packages/gateway/fixtures/s5-governance-deny.request.json
```

## Allow And Deny Semantics

Every gateway run emits a signed `PolicyDecisionAttestation`.
The decision is produced by evaluating the request-derived policy input against
the referenced policy bundle. Allowed/denied fixture labels are retained as
test oracle metadata and are not the runtime decision source.

Allowed requests also emit a signed `AgentActionAttestation`. The deterministic
example client writes downstream records only after this allow decision. Those
records include a `gateway_lineage` object with:

```text
gateway_decision_hash
gateway_policy_decision_attestation_hash
agent_action_attestation_hash
```

Scenario-specific downstream records also carry the gateway hashes. For
example, S2 writes a `config_change` record, S3 writes a `patch` record, S4
writes a `deployment` record, and S5 writes a `governance_state` record.

Denied requests fail closed. They emit the policy decision only, set
`agent_action_attestation` to `null`, and produce no approved
`workflow_records.json`.

## Inspection Commands

After running `gateway-test`, inspect the direct allow/deny decisions:

```powershell
Get-Content -Raw runs\gateway-smoke\allow-decision.json
Get-Content -Raw runs\gateway-smoke\deny-decision.json
```

Inspect allowed downstream linkage:

```powershell
Get-Content -Raw runs\gateway-smoke\allow-client\workflow_records.json
```

Confirm the denied client did not write approved workflow records:

```powershell
Test-Path runs\gateway-smoke\deny-client\workflow_records.json
```

Expected result:

```text
False
```

These outputs are generated validation artifacts and should remain untracked.
