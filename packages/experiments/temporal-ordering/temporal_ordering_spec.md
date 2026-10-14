# Temporal Authorization Ordering Experiment Specification

## Scope and boundaries

This role-revocation matrix tests represented-actor authorization at first commitment and deployment-sender authorization at deployment; see the [evaluation guide](../../../docs/ciss-evaluation.md). `S` is an actual local EIP-191 signature over the exact action hash later anchored at `N`, but its claimed time is not authoritative. The action attestation actor requires `DEPLOYER_ROLE` at the first authoritative anchor `N`. At deployment record `D`, the transaction sender requires `DEPLOYER_ROLE` or `LEDGER_WRITER_ROLE`, an existing policy hash, and an approval valid under current contract rules. The experiment uses stable `delivery-v1`; policy activation order is deferred.

The controlled actor is distinct from the governance administrator. The actor signs the action attestation and is named in its anchor. The administrator submits the anchor, issues approval, and submits deployment in T1–T8 using `LEDGER_WRITER_ROLE`. T4_SELF submits deployment from the actor after that actor's `DEPLOYER_ROLE` is revoked. This isolates the contract's sender check from the original attestation actor's role. Every case begins with a fresh authoritative grant of the actor's role; prior cases therefore do not control the initial role state.

`A` is the local policy decision under the stable policy. `R` revokes the controlled actor's `DEPLOYER_ROLE`; `G` restores it. `N` anchors the action attestation hash. To satisfy the existing deployment contract, approval and deployment-attestation writes occur immediately before `D`; their transaction receipts are captured and replay checks require the approval and policy to precede `D`. `AUDIT` is a later replay invocation, not a contract write. Case order and sender identity are machine-readable in [`cases.json`](cases.json).

## Invariants and expected classification

- **I1:** Role membership of the action-attestation actor is evaluated at `N` from ordered historical transitions.
- **I2:** A valid signature and caller-supplied time do not prove `S < R` to the substrate.
- **I3:** The deployment transaction sender and required policy/approval state are evaluated at `D`.
- **I4:** Later revocation does not change the historical verdict at `N` or `D`.
- **I5:** SEGL uses signed append sequence; Besu uses `(blockNumber, transactionIndex, logIndex)` from RPC receipts/events. Wall-clock fields do not order transitions.
- **I6:** Equivalent committed histories have equal historical replay verdicts. A Besu-rejected deployment has no committed D to compare with a SEGL-appended D.
- **I7:** Contract write acceptance and historical replay validity are reported separately.

The independent oracle folds the symbolic role transitions in `cases.json`, starting from the case's setup grant. It derives authority at `N` and `D` and the expected write disposition without importing the replay verifier. The verifier independently folds signed SEGL events or Besu contract events/receipts; it receives no expected labels, fault IDs, or oracle verdicts.

| Case | Human order | Oracle boundary expectation | Realizability |
| --- | --- | --- | --- |
| T1 | A–S–N–D | N valid; writer valid at D | Representable control |
| T2 | A–S–R–N–D | N invalid despite claimed early S; writer valid at D | Representable, expected write gap at N if accepted |
| T3 | A–R–S–N–D | N invalid; writer valid at D | Representable |
| T4 | A–S–N–R–D | N valid; distinct writer remains valid at D | Representable identity control |
| T5 | A–S–N–D–R | N/D valid after later R | Representable no-retroactive-invalidation control |
| T6 | A–R–N–S–D | N invalid regardless of later S; writer valid at D | Representable hash-first commitment |
| T7 | A–R–G–S–N–D | Regrant restores authority at N | Representable stateful-history control |
| T8 | A–S–N–D–R–AUDIT | N/D valid at later audit | Representable audit-time control |
| T4_SELF | A–S–N–R–D | N valid; actor lacks role at D | D write expected to revert |

An accepted N with no required actor role is `WRITE_TIME_ENFORCEMENT_GAP` because the ActorRegistry role is available on-chain. If a different authorized writer subsequently commits D, historical replay reports `FAIL` localized to N. A rejected D is `PREVENTED_AT_WRITE`; no full-history replay verdict is counted for that case. These are generic baseline dispositions. The separately deployed HardenedProvenanceRegistry adds actor-role admission at N for action proposals; the reproduction compares both paths.

## Evidence, limits, and outputs

The Besu runner deploys fresh contracts on the version-pinned local dev profile, submits each role and lifecycle transaction, and saves raw receipts. A bounded RPC adapter refetches receipts and contract logs and reconstructs historical role state. The SEGL path signs append events and uses the existing SEGL integrity verifier before historical role folding. Results include oracle, SEGL event stream, Besu receipts, case table, and security-boundary table under a unique ignored `runs/<run_id>/` directory. Generated outputs are never committed. The checked-in spec, case manifest, runner, verifier, and tests are the reproduction source.

The single-node QBFT dev profile demonstrates implementation behavior, transaction order, and write disposition; it does not establish a multi-administrator trust result or network-performance claim. The signed SEGL stream is generated from the same tracked symbolic case manifest after the Besu run, so parity is limited to equivalent modeled transition order rather than independent operation. No latency percentile is reported without a trustworthy timing path. The experiment does not infer when an off-chain signature was created from its claimed timestamp.
