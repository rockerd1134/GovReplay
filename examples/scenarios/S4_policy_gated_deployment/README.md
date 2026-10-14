# S4 Policy-Gated Deployment

S4 models the deployment-centered audit story for GovReplay. A deploy
operator receives a request to deploy an already-built payment API release
candidate. The governed question is whether the deployment points back to the
approved artifact, the policy decision used the active deployment policy, and
the ledger contains the anchors needed for replay.

The happy path uses policy `P3` because deployment auditability requires an
explicit approved-artifact link, an active policy hash, and a ledger anchor.
The local fixture is intentionally narrow: it emits deterministic records and
signed attestations, then writes a deployment-centered backward chain for the
audit replay CLI.

Run from the software repository:

```powershell
docker compose run --rm scenario-runner-test
```

The generated local output is ignored under:

```text
runs/scenarios/wf-S4-P3-F0-0001/
```

For dev Besu full mode, deploy contracts first and then run:

```powershell
docker compose --profile besu-dev run --rm besu-contract-deploy
docker compose --profile besu-dev run --rm scenario-s4-besu-test
```

The Besu smoke output is ignored under:

```text
runs/besu-dev/scenarios/S4_policy_gated_deployment/govreplay_besu.json
```
