# S1 Runbook Update

This scenario models a runbook author agent responding to repeated service
timeout incidents by proposing a documentation update for
`runbooks/cache-timeout-remediation.md`.

The tracked files in this directory are deterministic inputs and expected
fixture outputs consumed by the scenario runner, attestation chain, ledger
smoke paths, and replay fixtures.

## Layout

- `manifest.json`: happy-path scenario run metadata.
- `observation.json`: incident observation that starts the governed workflow.
- `input/`: source materials available before the proposed action.
- `evidence/`: evidence files referenced by evidence bundle generation.
- `expected/`: concise expected outputs for local runner and replay work.
- `faults/`: fault-specific manifest fixtures.

## Expected Audit Result

The F0 happy path is expected to pass under policy `P1` in signed off-chain
mode. The F1 missing-evidence fixture is expected to fail at the evidence
stage before approval, deployment, or ledger anchoring.
