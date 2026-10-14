import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import {
  signedFixtureDir,
  signedFixtureNames,
} from "../src/fixture-generation.ts";
import {
  type AttestationIndex,
  writeAttestationRunLayout,
} from "../src/run-layout.ts";
import {
  verifyAttestationSetLevel1,
  verifyLevel0,
  verifyLevel1,
  type VerificationFailureCode,
} from "../src/verifier.ts";

const runRoot = join(import.meta.dirname, "..", "..", "..", ".tmp", "test-runs", "verifier");
const runId = "run-p3-s7-verifier";

function signedFixtures(): Record<string, unknown>[] {
  return signedFixtureNames.map((name) => JSON.parse(readFileSync(join(signedFixtureDir, name), "utf8")));
}

async function indexedFixtures() {
  const attestations = signedFixtures();
  const layout = await writeAttestationRunLayout({ runRoot, runId, attestations });
  return { attestations, index: layout.index };
}

function hasCode(codes: VerificationFailureCode[], code: VerificationFailureCode): boolean {
  return codes.includes(code);
}

test.beforeEach(async () => {
  await rm(runRoot, { recursive: true, force: true });
});

test.after(async () => {
  await rm(runRoot, { recursive: true, force: true });
});

test("all signed fixtures pass verifier level 0", () => {
  for (const attestation of signedFixtures()) {
    const report = verifyLevel0(attestation);

    assert.equal(report.level, "LEVEL_0");
    assert.equal(report.status, "PASS", JSON.stringify(report));
    assert.deepEqual(report.failure_codes, []);
  }
});

test("all signed fixtures pass verifier level 1 with run index context", async () => {
  const { attestations, index } = await indexedFixtures();
  const reports = await verifyAttestationSetLevel1(attestations, { index, runRoot });

  assert.equal(reports.length, signedFixtureNames.length);
  for (const report of reports) {
    assert.equal(report.level, "LEVEL_1");
    assert.equal(report.status, "PASS", JSON.stringify(report));
    assert.deepEqual(report.failure_codes, []);
  }
});

test("missing required fields fail level 0 with stable structural codes", () => {
  const [attestation] = signedFixtures();
  const malformed = structuredClone(attestation) as Record<string, unknown>;
  delete malformed.created_at;
  delete malformed.subject;

  const report = verifyLevel0(malformed);

  assert.equal(report.status, "FAIL");
  assert.deepEqual(report.failure_codes, ["F_SCHEMA_REQUIRED_FIELD"]);
  assert.deepEqual(report.failures.map((item) => item.field), ["created_at", "subject"]);
});

test("malformed digest and timestamp fields fail level 0 deterministically", () => {
  const [attestation] = signedFixtures();
  const malformed = structuredClone(attestation) as Record<string, unknown>;
  malformed.attestation_hash = "0xABC";
  malformed.created_at = "June 20 2026";

  const report = verifyLevel0(malformed);

  assert.equal(report.status, "FAIL");
  assert.deepEqual(report.failure_codes, ["F_SCHEMA_DIGEST", "F_SCHEMA_TIMESTAMP"]);
});

test("digest tampering fails level 1 with a stable hash mismatch code", async () => {
  const { attestations, index } = await indexedFixtures();
  const tampered = structuredClone(attestations[0]) as Record<string, unknown>;
  (tampered.predicate as Record<string, unknown>).request_summary = "mutated";

  const report = await verifyLevel1(tampered, { records: attestations, index, runRoot });

  assert.equal(report.status, "FAIL");
  assert.equal(hasCode(report.failure_codes, "F_HASH_ATTESTATION_MISMATCH"), true);
});

test("signature tampering fails level 1 with a stable signature code", async () => {
  const { attestations, index } = await indexedFixtures();
  const tampered = structuredClone(attestations[0]) as Record<string, unknown>;
  const signature = tampered.signature as Record<string, unknown>;
  signature.signature = `${String(signature.signature).slice(0, -2)}00`;

  const report = await verifyLevel1(tampered, { records: attestations, index, runRoot });

  assert.equal(report.status, "FAIL");
  assert.equal(hasCode(report.failure_codes, "F_SIGNATURE_INVALID"), true);
});

test("actor/signature mismatch fails level 1 with a stable actor mismatch code", async () => {
  const { attestations, index } = await indexedFixtures();
  const tampered = structuredClone(attestations[0]) as Record<string, unknown>;
  const actor = tampered.created_by as Record<string, unknown>;
  actor.ethereum_address = "0x0000000000000000000000000000000000000001";

  const report = await verifyLevel1(tampered, { records: attestations, index, runRoot });

  assert.equal(report.status, "FAIL");
  assert.equal(hasCode(report.failure_codes, "F_SIGNATURE_ACTOR_MISMATCH"), true);
});

test("unresolved parent links fail level 1 deterministically", async () => {
  const { attestations, index } = await indexedFixtures();
  const tampered = structuredClone(attestations[1]) as Record<string, unknown>;
  tampered.parents = ["0x1212121212121212121212121212121212121212121212121212121212121212"];

  const report = await verifyLevel1(tampered, { records: attestations.slice(2), index, runRoot });

  assert.equal(report.status, "FAIL");
  assert.equal(hasCode(report.failure_codes, "F_LINK_BROKEN"), true);
});

test("unsafe indexed paths fail level 1 deterministically", async () => {
  const { attestations, index } = await indexedFixtures();
  const attestation = attestations[0];
  const unsafeIndex = structuredClone(index) as AttestationIndex;
  unsafeIndex.attestations[0] = {
    ...unsafeIndex.attestations[0],
    path: "../escape.json",
  };

  const report = await verifyLevel1(attestation, { records: attestations, index: unsafeIndex, runRoot });

  assert.equal(report.status, "FAIL");
  assert.equal(hasCode(report.failure_codes, "F_INDEX_PATH_UNSAFE"), true);
});

test("bad indexed CAS references fail level 1 deterministically", async () => {
  const { attestations, index } = await indexedFixtures();
  const attestation = attestations[0];
  const badIndex = structuredClone(index) as AttestationIndex;
  badIndex.attestations[0] = {
    ...badIndex.attestations[0],
    cas_uri: "cas://sha256/0000000000000000000000000000000000000000000000000000000000000000",
  };

  const report = await verifyLevel1(attestation, { records: attestations, index: badIndex, runRoot });

  assert.equal(report.status, "FAIL");
  assert.equal(hasCode(report.failure_codes, "F_HASH_OBJECT_MISMATCH"), true);
});
