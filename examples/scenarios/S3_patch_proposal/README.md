# S3 Patch Proposal

S3 models a supply-chain-style patch proposal. A patch author agent receives an
issue report for a retry edge case, proposes a small patch, and binds the patch
to simulated test evidence and code-review approval.

The local fixture emits deterministic lifecycle records and seven signed
attestations for observation, evidence, policy decision, action, approval,
artifact, and deployment readiness. The curated `F10` fault substitutes the
deployed artifact digest to exercise artifact/deployment mismatch localization.

Run the local checks through:

```powershell
docker compose run --rm scenario-runner-test
```

The current S3 path is local signed provenance. The local runner writes ignored
output under:

```text
runs/scenarios/wf-S3-P3-F0-0001/
```
