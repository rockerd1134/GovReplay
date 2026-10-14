# S2 Configuration Change

S2 models a higher-risk service configuration change. A configuration operator
agent proposes increasing a payment API timeout after an alert shows elevated
timeout errors. Under P2, the action requires stricter approval governance and
separation of duties.

The local fixture emits deterministic lifecycle records and seven signed
attestations for observation, evidence, policy decision, action, approval,
artifact, and deployment. The curated fault fixture `F8` records a proposer
self-approval so replay can localize the failure to the approval stage.

Run the local checks through:

```powershell
docker compose run --rm scenario-runner-test
```

The current S2 path is local signed provenance. The local runner writes ignored
output under:

```text
runs/scenarios/wf-S2-P2-F0-0001/
```
