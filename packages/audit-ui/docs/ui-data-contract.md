# Audit UI Data Contract

The audit UI consumes experiment outputs through one normalized data
contract. Views must read this contract instead of parsing raw run files
independently.

## Canonical Inputs

For each run, the adapter reads:

```text
runs/<run_id>/manifest.json
runs/<run_id>/inputs/workload.jsonl
runs/<run_id>/inputs/ground_truth.jsonl
runs/<run_id>/results/metrics_summary.json
runs/<run_id>/audit/audit_results.jsonl
runs/<run_id>/telemetry/*.jsonl
runs/<run_id>/faults/*.jsonl
```

The experiment JSON/JSONL files remain the source of truth. The UI data contract is
a display adapter only; it does not recompute replay traversal or experiment
metrics aggregation.

## Normalized Shape

```json
{
  "schema_version": "govprov.audit_ui_data.v1",
  "generated_at": "2026-06-21T00:00:00.000Z",
  "runs": [
    {
      "run_id": "phase7-debug",
      "created_at": "2026-06-21T00:00:00Z",
      "matrix": "debug",
      "configuration_count": 3,
      "scenario_count": 4,
      "workflow_count": 36,
      "fault_count": 3,
      "policy_count": 1,
      "overall_status": "failures_detected",
      "manifest": {}
    }
  ],
  "metrics": {},
  "replays": [],
  "faults": [],
  "demos": []
}
```

## View Ownership

- Runs and metrics views use `runs` and `metrics`.
- Audit replay view uses `replays`.
- Fault inspection view uses `faults`.
- Demo walkthrough defaults use `demos`.

If a new view needs a field, extend the adapter additively and document it
here. Do not add bespoke parsing in the browser.

## Container Validation

From `git/software`:

```powershell
docker compose run --rm audit-ui-data-test
docker compose run --rm audit-ui-build
```
