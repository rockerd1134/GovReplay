# Temporal authorization ordering

This is the primary GovReplay CISS experiment: actor authority at first commitment N, deployment conditions at D, retrospective signatures and the targeted role guard. See the standalone [evaluation guide](../../../docs/ciss-evaluation.md) and [security boundaries](../../../SECURITY.md).

## Entry points

- `cases.json`: nine named controls/failure cases.
- `cases.enumerated.k1.json`, `.tsv`, `named_mapping.k1.json`: 420 bounded orderings and named mapping.
- `src/oracle.ts`, `intervalOracle.ts`: independent expectations.
- `src/seglTemporal.ts`, `besuTemporal.ts`: signed-stream and ordered-receipt replay.
- `src/cli.ts`, `hardeningReport.ts`: baseline/guarded observations.
- `src/propertyCheck.ts`, `summarizeEnumeration.ts`: properties and frozen-prediction comparisons.
- `src/coverageAudit.mjs`: independent grammar/classification helpers. Its original archival CLI requires private retained study evidence/context; use `scripts/check-ciss-release.ts` for standalone checks.
- `release/frozen-predictions.json`: original pre-execution predictions, copied byte-for-byte.

From the repository root:

```powershell
docker compose run --rm temporal-ordering-test
pwsh -File scripts/reproduce-ciss.ps1 -Mode named
pwsh -File scripts/reproduce-ciss.ps1 -Mode full -RunId review-full-001
```

Use fresh identifiers. The helper generates disposable keys and isolated chains, selects paired JSON/TSV manifests and runs write/report steps. It stops its chains after reporting, preserving receipts and data under ignored `runs/` and `.tmp/`. No sibling context repository or historical chain is required.

## Existing advanced runner paths

The Compose profiles `temporal-ordering` and `temporal-hardening` remain available. Supply distinct local development keys and a new `GOVPROV_TEMPORAL_RUN_ID`. Select both `GOVPROV_TEMPORAL_CASES_JSON` and `GOVPROV_TEMPORAL_CASES_TSV` for enumeration; unset both for named cases. Keep the same chain through reporting; the administrator must be funded in its genesis.

The baseline retry wrapper retries only explicit nonce-too-low rejection, at most twice, never ambiguous submission. The guarded runner records skipped D after rejected N. Reverted writes have no committed boundary; incomplete histories receive `NOT_APPLICABLE` for full-history replay.

The guard checks actor deployer role only for action-proposal anchors. It does not establish signature existence at N, signing order, delivered-content binding or independent administration. The generic comparator is retained deliberately.