# CISS evaluation and reproduction

## Scientific boundary

The represented actor must be active and hold `DEPLOYER_ROLE` at the first
authoritative commitment N. Deployment D checks the actual sender's role, a
registered policy and matching valid approval. Ordered historical role state
determines the verdict; later revocation does not retroactively invalidate it.
Local signature event S can occur before or after N. Retrospective verification
authenticates the signed hash, not the signature's existence at N.

The generic registry checks the authorized infrastructure writer and actor
activity. Its guarded derivative adds the actor's deployer-role check for
action-proposal anchors. This is the evaluated intervention; the comparator
and deployment semantics are preserved. Policy, approval, actor activity and
other non-role predicates remain fixed in this bounded fixture.

## Cases and frozen predictions

The nine named cases are in
[`cases.json`](../packages/experiments/temporal-ordering/cases.json).
The full grammar starts with actor setup A, interleaves S/N/D with role words
empty/R/RG/RGR subject to N preceding D, varies the deployment sender between
administrator and represented actor, and optionally appends AUDIT. It generates
420 distinct plans. Eight raw `(sender, actor N role, actor D role)` combinations
reduce to six `(sender, actor N role, sender D authority)` classes because the
administrator's authority is unaffected by the represented actor's D role.

| Sender | Actor role at N | Sender authority at D | Plans |
| --- | --- | --- | ---: |
| Administrator | Valid | Valid | 134 |
| Administrator | Invalid | Valid | 76 |
| Actor | Valid | Valid | 80 |
| Actor | Valid | Invalid | 54 |
| Actor | Invalid | Valid | 22 |
| Actor | Invalid | Invalid | 54 |

Expected guard results: 152 N-invalid reverts, 268 N-valid acceptances, 214
passing full histories, 54 accepted N writes followed by D reverts, and 152
skipped deployments following N reverts. Baseline N admits all 420; 312 baseline
histories commit D, including 98 N-invalid histories rejected by replay. The
baseline's other 108 D writes revert. Replay parity is compared only for full
committed histories: denominators 312 baseline and 214 guarded.

[`release/frozen-predictions.json`](../packages/experiments/temporal-ordering/release/frozen-predictions.json)
is a byte-for-byte copy of the predictions frozen before the original live
enumeration. SHA-256:
`0f90cc0d2121914715adf7c5d9274f59c6c6b47f14d7dffe45cb2f9f1a99680f`.
The original preregistration context commit is
`3556feae58c5704cb41b97ef2a178f327a688392`; that private project record is not a
runtime dependency. `preregister.ts` can generate new model predictions into a
chosen local file, but must not be used to replace this historical freeze.

## Clean local run

From the repository root in PowerShell 7:

```powershell
pwsh -File scripts/reproduce-ciss.ps1 -Mode named -RunId smoke-001
pwsh -File scripts/reproduce-ciss.ps1 -Mode full -RunId full-001
```

Use a new identifier for every attempt. The helper tests/bootstrap-installs
contracts, generates random development wallets, creates two fresh single-node
Besu chains with no host port mappings, and selects named or enumerated manifests.
Each run deploys its own registry set. It verifies actual writes, refetches
receipts/logs, verifies signatures and reconstructs ordered state; it does not
replace observations with expected labels.

For faster wall-clock execution, initialize once and run the independent phases
in two terminals. These chains have separate validator identities and state.
Never run concurrent transaction writers on the same chain.

```powershell
# First initialize once.
pwsh -File scripts/reproduce-ciss.ps1 -Mode full -Phase init -RunId full-002
# Terminal 1:
pwsh -File scripts/reproduce-ciss.ps1 -Mode full -Phase baseline -RunId full-002
# Terminal 2:
pwsh -File scripts/reproduce-ciss.ps1 -Mode full -Phase hardened -RunId full-002
# After both finish:
pwsh -File scripts/reproduce-ciss.ps1 -Mode full -Phase summary -RunId full-002
```

The baseline uses the existing narrow nonce-rejection retry wrapper. The guard
path stops D after an N revert. Every write/report phase preserves its raw run
directory on failure; use a fresh identifier for a new write attempt. Preserve
the same chain from write through report. Keys are saved locally in ignored
`.tmp/ciss-<RunId>/runtime.json` and must never enter an archive or commit.

## Checks and outputs

- `temporal-ordering-test`: seven tests covering the grammar, two expectations,
  SEGL signatures/role folds, Besu ordering and historical verdict invariance.
- `foundry`: contract unit/integration tests, including the baseline/guard.
- `check-ciss-release.ts`: independent last-transition classification, exact
  plan membership, six classes and observed N/D/SEGL/Besu outcomes.
- `propertyCheck.ts`: seven nonempty properties, 1,840 comparisons on overlapping
  participating plans. These are not 1,840 independent trials.
- `summarizeEnumeration.ts`: joins live report rows against the frozen predictions.

Full reports include `.tmp/ciss-<RunId>/properties.json` and aggregate enumeration
tables, plus each run's receipt, signature, SEGL and verdict records under
`runs/`. Raw evidence remains local and ignored. Re-running is the public
artifact's evidence path; the original historical chain is not bundled.

`coverageAudit.mjs` exports the independent `plans`, `partition` and `compare`
functions used by release checks. Its original historical-audit CLI additionally
requires the private context manifest and retained original runs. That optional
archival CLI is not the standalone public reproduction command.

## Limits

The guard checks represented-actor role for action-proposal N, not signature
existence, trusted signing order, delivered content or every attestation type.
Single-node local QBFT measures implementation behavior, not independent
administrative trust. Fixed non-role predicates, synthetic actions and bounded
role cycles define the experiment. Offline k=2 construction gives 1,512 plans
and six classes; it is model evidence, not additional live Besu coverage.
Gas/time from separate fresh chains are descriptive, not performance comparisons.
