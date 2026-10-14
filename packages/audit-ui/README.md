# GovReplay Audit UI

This package provides the lightweight audit UI and the adapter that normalizes
experiment outputs for browser display.

## Container Path

From `git/software`:

```powershell
docker compose run --rm experiment-runner-test
docker compose run --rm --entrypoint node experiment-minimum-matrix-test --experimental-strip-types src/cli.ts --config configs/minimum.json
docker compose run --rm audit-ui-data-test
docker compose run --rm audit-ui-build
```

`audit-ui-build` expects `runs/phase7-minimum` to exist, generates
`packages/audit-ui/public/demo-data/ui-data.json`, and validates that the static
UI entrypoint exists. Generated demo data remains ignored.

## Optional Local Preview

After generating demo data:

```powershell
cd packages/audit-ui
node --experimental-strip-types src/static-server.ts --root public --port 4173
```

Open `http://localhost:4173`.

## Demo Walkthroughs

The UI marks these default walkthroughs when the generated run contains matching
records:

- Demo A: S4 happy-path governance replay.
- Demo B: S1 historical-pass/current-fail policy drift.
- Demo C: S3 artifact substitution detection.
- Demo D: S2 separation-of-duties failure.

The UI is a demo and artifact-inspection surface. It is not evidence for human
auditor productivity claims.
