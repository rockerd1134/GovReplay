# Attestation Package

This package owns the attestation foundation:

- JSON Schemas for the common envelope and MVP attestation types.
- Deterministic canonical JSON serialization.
- SHA-256 content digests.
- `0x`-prefixed bytes32 identifiers for contract-facing references.
- Local content-addressed storage for attestations and raw evidence/artifact
  blobs.
- Ethereum-compatible `personal_sign`/EIP-191-style secp256k1 signing and
  address recovery for the MVP signature profile.
- Deterministic unsigned fixtures for tests and scenario work.
- Deterministic signed fixtures for every MVP attestation type.
- Predictable local run layout and `attestation_index.json` generation for
  signed attestation sets.
- Level 0 structural and Level 1 cryptographic verifier reports for local
  signed attestations.

It intentionally does not implement Besu writes, audit replay, attestation
governance/replay verifier levels, acceptance gates, or scenario generation.
Those are outside this package's current local verification surface.

## Signing And Recovery

`src/signing.ts` implements the local signature profile:

```text
govprov-ethsign-secp256k1-v1
```

Signing uses the existing canonical attestation digest convention. The
signature payload is:

```text
GovReplay Attestation v1
schema_version=<schema_version>
attestation_type=<attestation_type>
attestation_hash=<sha256 digest of attestation without signature/hash fields>
```

The payload is signed with Ethereum `personal_sign`/EIP-191-compatible
secp256k1 signing. Verification recovers the Ethereum address from the
signature and compares it with both the signature signer and the attesting
actor's `created_by.ethereum_address`.

The signature object follows the current schema shape:

```json
{
  "profile": "govprov-ethsign-secp256k1-v1",
  "signature": "0x...",
  "signer": "0x..."
}
```

The test fixtures use only deterministic dev private keys. Do not use or commit
real private keys, personal wallets, credentials, or production actor material.

## Deterministic Signed Fixtures

`src/fixture-generation.ts` builds a compact, signed fixture chain for every
MVP attestation type:

- `ObservationAttestation`
- `EvidenceBundleAttestation`
- `PolicyDecisionAttestation`
- `AgentActionAttestation`
- `ArtifactAttestation`
- `ApprovalAttestation`
- `DeploymentAttestation`
- `LedgerAnchorAttestation`
- `AuditReplayReport`

The generated fixtures are stored in:

```text
fixtures/signed/
```

Regenerate them from the package directory with:

```powershell
npm run generate:signed-fixtures
```

The generator uses deterministic non-secret dev keys, inserts stable
`attestation_hash` values, signs each fixture with the current MVP signature
profile, and links child `parents` to the generated parent attestation hashes.
The private keys are never written to generated fixture files.

## Local Content-Addressed Store

`src/storage.ts` implements a run-local filesystem store around the digest
utilities in `src/digest.ts`.

The store:

- writes JSON attestations by their deterministic SHA-256 attestation digest;
- writes raw evidence or artifact bytes by their SHA-256 content digest;
- returns `cas://sha256/<digest-without-0x>` URIs for both object families;
- reads by digest object, `0x`-prefixed digest string, or CAS URI;
- recomputes digests on read and rejects mutated stored content;
- rejects malformed digests, path traversal-shaped inputs, and unsupported
  algorithms.

The default test layout uses ignored local state under:

```text
.tmp/test-store/
  attestations/sha256/<2>/<2>/<digest>.json
  objects/sha256/<2>/<2>/<digest>.blob
```

Scenario and experiment runs should keep generated run contents ignored by
default.

## Run Layout And Attestation Index

`src/run-layout.ts` writes signed attestation sets into the local run
layout:

```text
runs/<run_id>/
  attestations/<attestation_type>/<attestation_hash>.json
  objects/sha256/<2>/<2>/<attestation_hash>.json
  manifests/attestation_index.json
```

The typed attestation paths are ergonomic for local inspection. The object
paths and `cas://sha256/<digest>` references are content-addressed retrieval
material keyed by the canonical attestation hash.

`attestation_index.json` is byte-stable across repeated generation and records:

- attestation hash;
- attestation type;
- actor Ethereum address;
- creation timestamp;
- parent attestation hashes;
- subject digests;
- local typed path;
- CAS URI.

The run-layout utility rejects duplicate attestation hashes, malformed records,
unsafe relative paths, and records whose claimed `attestation_hash` does not
match the recomputed canonical digest.

## Verifier Levels 0 And 1

`src/verifier.ts` emits deterministic JSON-friendly reports for:

- `LEVEL_0`: structural checks over required fields, supported enum values,
  digest shapes, timestamps, parent link shapes, actor address shape, subject
  digest shape, schema version, and signature object shape.
- `LEVEL_1`: cryptographic and local lookup checks over canonical attestation
  hashes, Ethereum-compatible signature recovery, actor/signature matching,
  parent hash resolution, indexed typed paths, and indexed CAS references.

Each report includes:

```json
{
  "level": "LEVEL_1",
  "status": "PASS",
  "attestation_hash": "0x...",
  "attestation_type": "DeploymentAttestation",
  "failure_codes": [],
  "failures": []
}
```

The verifier treats `attestation_index.json` as untrusted lookup metadata. It
may use indexed paths and CAS URIs to find local records, but still recomputes
attestation hashes and recovers signatures before reporting success.

Package boundaries:

- Acceptance tests are a broad local confidence layer over deterministic
  fixture generation, canonical hashing, signatures, links, run layout/index
  entries, local object verification, Level 0/1 reports, and controlled tamper
  cases.
- The full attestation/storage acceptance gate validates the complete local
  attestation foundation.

## Container Validation

From the software repository root:

```powershell
docker compose run --rm attestations-test
```

The service runs Node's built-in test runner in a pinned Node container and does
not require host-local Node.
