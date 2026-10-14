# Audit Replay CLI

Audit replay starts from deterministic scenario run outputs under
`runs/scenarios/<workflow_id>/`.

Supported local inputs:

- `--deployment-id <id>`
- `--action-id <id>`
- `--attestation-hash <0x...>`
- `--workflow-id <id>`

The first implementation uses `manifests/attestation_index.json`,
`manifests/local_replay_fixture.json`, signed attestation files, scenario source
fixtures, and optional Besu smoke sidecars from `runs/besu-dev/scenarios/`.

Example:

```sh
node --experimental-strip-types src/cli.ts \
  --run-root ../../runs/scenarios/wf-S4-P3-F0-0001 \
  --deployment-id deployment-S4-0001 \
  --report-dir ../../runs/scenarios/wf-S4-P3-F0-0001/audit_reports
```

Outside this package's current local verifier:

- live Besu RPC event indexing,
- experiment matrix orchestration,
- UI rendering.
