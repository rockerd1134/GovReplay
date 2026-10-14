# Policy Service Package

This package owns the policy bundle format and deterministic fixture
validation boundary. It includes the Cedar loader/evaluator for fixture
allow/deny tests, the governance obligation resolver for the existing
`obligations.yml` shape, explicit P1/P2/P3 policy-version fixtures, and
deterministic signed policy-decision attestation fixtures. It intentionally
does not implement the HTTP service, gateway behavior, or ledger writes.

## Policy Bundle Layout

Each policy bundle is a directory with this required layout:

```text
metadata.json
schema.cedarschema
policies/
  *.cedar
obligations.yml
tests/
  *.json
```

The bundle is the atomic unit that policy registry and replay work hashes,
registers, loads, and binds to policy decision attestations.

## `metadata.json`

`metadata.json` is canonical JSON metadata for the whole bundle:

```json
{
  "policy_bundle_id": "software-delivery-governance",
  "version": "1.0.0",
  "created_at": "2026-06-20T00:00:00Z",
  "author": "govprov:actor:policy-admin-001",
  "parent_policy_bundle_hash": null,
  "description": "Baseline governance policy for deterministic software delivery fixtures.",
  "compatible_contract_set": "govprov-contracts:v0.1",
  "policy_language": "cedar",
  "schema_version": "govprov.policy_bundle.v1"
}
```

Required semantics:

- `policy_bundle_id`: stable lower-case bundle family identifier.
- `version`: semantic version for the bundle contents.
- `created_at`: UTC timestamp with `Z`.
- `author`: actor reference for the policy administrator.
- `parent_policy_bundle_hash`: `null` for roots or `0x` SHA-256 bytes32 for
  successors.
- `description`: concise human-readable purpose.
- `compatible_contract_set`: contract set label expected by the bundle.
- `policy_language`: `cedar` for the MVP.
- `schema_version`: `govprov.policy_bundle.v1`.

## `obligations.yml`

`obligations.yml` uses a deterministic JSON-compatible YAML subset:
the file contents are JSON text stored with a `.yml` extension. YAML 1.2 parsers
can load this form, and the project validation path can parse it without adding
an unpinned YAML dependency before the Rust/Cedar container exists.

The normalized document shape is:

```json
{
  "schema_version": "govprov.obligations.v1",
  "defaults": {
    "decision_ttl_seconds": 300
  },
  "obligations": [
    {
      "id": "staging-deployment-baseline",
      "description": "Permit staging deployment after evidence and reviewer approval.",
      "applies_to_actions": ["propose_deployment"],
      "required_evidence": {
        "min_count": 1,
        "evidence_types": ["test_report"]
      },
      "required_approval_roles": ["SECURITY_REVIEWER"],
      "separation_of_duties": {
        "proposer_cannot_approve": true,
        "distinct_approval_count": 1
      },
      "deployment_environment_constraints": {
        "allowed_environments": ["staging"],
        "forbidden_environments": ["production"]
      },
      "attestation_requirements": {
        "required_attestation_types": [
          "EvidenceBundleAttestation",
          "PolicyDecisionAttestation"
        ],
        "policy_decision_must_include_bundle_hash": true
      },
      "expiration": {
        "approval_max_age_seconds": 86400,
        "evidence_max_age_seconds": 604800
      }
    }
  ]
}
```

MVP obligation categories are explicit:

- required evidence;
- required approval roles;
- separation of duties;
- deployment environment constraints;
- attestation requirements;
- expiration windows and freshness limits.

The Rust resolver turns these normalized records into resolved obligations
that are bound to the same `policy_bundle_hash` as the Cedar allow/deny
decision.

## Fixtures

Fixture bundles live under:

```text
fixtures/bundles/
```

Current fixtures:

- `software-delivery-p1-baseline`: P1 baseline governance. It permits
  low-risk runbook updates with baseline evidence and a single documentation
  approval, and it models simple configuration approval obligations.
- `software-delivery-p2-strict-approval`: P2 stricter approval governance. It
  requires dual distinct approvals for high-risk configuration changes and a
  deploy approver plus approved artifact linkage for production deployment.
- `software-delivery-p3-evidence-strengthened`: P3 evidence-strengthened
  governance. It requires strengthened runbook evidence, active policy bundle
  references, and deployment provenance obligations that include ledger anchor
  evidence.

The Cedar files are intentionally small. The Rust evaluator loads and evaluates
their fixture tests without changing the bundle layout.

The metadata lineage is hash-bound: P1 has no parent, P2's
`parent_policy_bundle_hash` equals P1's bundle hash, and P3's parent equals
P2's bundle hash. Because the hash is computed over exact file bytes, use the
containerized bundle-format test when updating lineage fields.

## Container Validation

From the software repository root:

```powershell
docker compose run --rm policy-bundle-test
```

The service runs Node's built-in test runner in a pinned Node container. It
validates JSON schemas, bundle directory layout, metadata shape, obligations
shape, deterministic bundle hash stability, and fixture test case shape.

## Rust/Cedar Loader, Evaluator, And Obligation Resolver

The Rust package in this directory establishes the reproducible Cedar
loader/evaluator surface and obligation resolver. It is deliberately
smaller than a deployed policy service: no HTTP interface, policy-decision
attestation signing, ledger writes, or drift replay logic is implemented here.

From the software repository root:

```powershell
docker compose run --rm policy-service-test
```

The Compose service pins `rust:1.89.0-slim-bookworm`, runs
`cargo test --locked`, and uses ignored `.tmp/cargo-home/` for Cargo registry
and crate downloads. Build output under `target/` is generated and ignored.

Pinned Rust dependencies:

```text
cedar-policy = "=4.11.1"
serde_json = "=1.0.150"
sha2 = "=0.10.9"
```

The tests exercise Cedar integration with a tiny authorizer smoke request,
evaluate all current fixture test cases across the P1/P2/P3 bundles, and
assert deterministic resolved obligations for the allowed fixture cases. The
evaluator maps fixture inputs
to:

```text
principal: GovProv::Agent::<input.principal.id>
action: GovProv::Action::"propose_deployment"
resource: GovProv::DeploymentTarget::<input.resource.id>
context: input.context, checked against the action context schema
```

The CLI evaluates the baseline bundle by default:

```powershell
docker compose run --rm policy-service-test cargo run --locked
```

Evaluate every fixture bundle:

```powershell
docker compose run --rm policy-service-test cargo run --locked -- --all-fixtures
```

Host-local Cargo may be used as a convenience, but the Docker Compose command
is the validation source of truth.

### Resolver Boundary

The resolver loads the bundle's JSON-compatible `obligations.yml`, selects
obligations whose `applies_to_actions` contains the evaluated action, and emits
normalized records with:

- `schema_version = govprov.resolved_obligation.v1`;
- the obligation `id`;
- the same `policy_bundle_hash` used by the Cedar decision;
- the evaluated action ID and resource environment;
- the bundle default `decision_ttl_seconds`;
- all six MVP categories: required evidence, approval roles, separation of
  duties, deployment environment constraints, attestation requirements, and
  expiration windows.

Resolved obligation records are sorted by ID and hashed into
`obligations_hash`. The deterministic policy decision hash includes that
obligations hash.

## Policy Decision Attestation Fixtures

The package includes signed `PolicyDecisionAttestation` records for every current
policy-service fixture decision. The generator lives at:

```text
src/policy-decision-attestation.ts
```

Stored fixtures live under:

```text
fixtures/policy-decisions/
```

Each signed attestation binds:

- active policy bundle metadata, version, parent hash, and bundle hash;
- `policy_bundle_hash`;
- `policy_input_hash`;
- allow/deny decision;
- `obligations_hash`;
- resolved obligation IDs and records;
- `policy_decision_hash`.

The generator reuses the attestation package's canonical JSON,
SHA-256 digest, deterministic secp256k1 signing, and signature recovery
utilities. The policy-service fixture signer is the deterministic
`govprov:actor:policy-service` dev actor. This is still a package/fixture
boundary, not a live HTTP service.

Regenerate the signed policy-decision fixtures through Docker Compose:

```powershell
docker compose run --rm policy-bundle-test node --experimental-strip-types src/policy-decision-attestation.ts --write
```

The policy-bundle test suite checks that stored fixtures match deterministic
generation, signatures verify, policy refs are present, and controlled
tampering fails cryptographic verification.

## Policy Drift Fixtures

Fixture-only policy drift replay summaries live at:

```text
fixtures/policy-drift-cases.json
```

The generator lives at:

```text
src/policy-drift-fixtures.ts
```

It pairs historical signed `PolicyDecisionAttestation` fixtures with a current
policy bundle evaluation and emits the required classifications:

- `historical_pass_current_pass`;
- `historical_pass_current_fail`;
- `historical_fail_current_fail`;
- `historical_fail_current_pass`;
- `policy_not_available`;
- `policy_hash_mismatch`.

Regenerate drift fixtures through Docker Compose:

```powershell
docker compose run --rm policy-bundle-test node --experimental-strip-types src/policy-drift-fixtures.ts --write
```

This is deliberately a fixture-level replay boundary. It does not traverse a
full attestation graph, query Besu, or verify approvals/artifacts. The audit
replay package owns full traversal and ledger-aware policy drift checks.
