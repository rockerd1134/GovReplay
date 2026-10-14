import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import test from "node:test";
import { canonicalJson } from "../src/canonical-json.ts";
import { digestAttestation } from "../src/digest.ts";
import {
  generateSignedFixtureAttestations,
  serializeFixture,
  signedFixtureDir,
  signedFixtureNames,
} from "../src/fixture-generation.ts";
import {
  casObjectPath,
  resolveInsideRun,
  type AttestationIndex,
  writeAttestationRunLayout,
} from "../src/run-layout.ts";
import {
  ContentAddressMismatchError,
  LocalContentAddressedStore,
} from "../src/storage.ts";
import {
  recoverAttestationSigner,
  verifyAttestationSignature,
} from "../src/signing.ts";
import {
  verifyAttestationSetLevel1,
  verifyLevel0,
  verifyLevel1,
  type VerificationFailureCode,
} from "../src/verifier.ts";

const runRoot = join(import.meta.dirname, "..", "..", "..", ".tmp", "test-runs", "acceptance");
const storeRoot = join(import.meta.dirname, "..", "..", "..", ".tmp", "test-store", "acceptance");
const runId = "run-p3-s8-acceptance";

function signedFixtures(): Record<string, unknown>[] {
  return signedFixtureNames.map((name) => JSON.parse(readFileSync(join(signedFixtureDir, name), "utf8")));
}

async function acceptanceContext() {
  const attestations = signedFixtures();
  const layout = await writeAttestationRunLayout({ runRoot, runId, attestations });
  return { attestations, layout };
}

function hasCode(codes: VerificationFailureCode[], code: VerificationFailureCode): boolean {
  return codes.includes(code);
}

function replaceIndexEntry(
  index: AttestationIndex,
  attestationHash: string,
  patch: Partial<AttestationIndex["attestations"][number]>,
): AttestationIndex {
  const copy = structuredClone(index) as AttestationIndex;
  const entryIndex = copy.attestations.findIndex((entry) => entry.attestation_hash === attestationHash);
  assert.notEqual(entryIndex, -1, attestationHash);
  copy.attestations[entryIndex] = {
    ...copy.attestations[entryIndex],
    ...patch,
  };
  return copy;
}

test.beforeEach(async () => {
  await rm(runRoot, { recursive: true, force: true });
  await rm(storeRoot, { recursive: true, force: true });
});

test.after(async () => {
  await rm(runRoot, { recursive: true, force: true });
  await rm(storeRoot, { recursive: true, force: true });
});

test("P3-S8 acceptance: signed fixtures regenerate, store, index, link, and verify end to end", async () => {
  const generated = generateSignedFixtureAttestations();
  const stored = signedFixtures();
  const generatedByName = new Map(signedFixtureNames.map((name) => [name, generated[name]]));

  for (const name of signedFixtureNames) {
    const storedBytes = readFileSync(join(signedFixtureDir, name), "utf8");
    assert.equal(storedBytes, `${serializeFixture(generated[name])}\n`, name);
    assert.equal(canonicalJson(JSON.parse(storedBytes)), canonicalJson(generated[name]), name);
  }

  const layout = await writeAttestationRunLayout({ runRoot, runId, attestations: stored });
  const store = new LocalContentAddressedStore(storeRoot);
  const indexedHashes = new Set(layout.index.attestations.map((entry) => entry.attestation_hash));

  assert.equal(layout.index.schema_version, "govprov.attestation_index.v1");
  assert.equal(layout.index.run_id, runId);
  assert.equal(layout.index.attestation_count, String(signedFixtureNames.length));

  for (const attestation of stored) {
    const hash = String(attestation.attestation_hash);
    const entry = layout.index.attestations.find((item) => item.attestation_hash === hash);
    assert.ok(entry, hash);
    assert.equal(indexedHashes.has(hash), true, hash);
    assert.equal(hash, digestAttestation(attestation).value, hash);
    assert.equal(verifyAttestationSignature(attestation), true, hash);
    assert.equal(recoverAttestationSigner(attestation), String((attestation.created_by as Record<string, unknown>).ethereum_address).toLowerCase(), hash);

    for (const parentHash of attestation.parents as string[]) {
      assert.equal(indexedHashes.has(parentHash), true, `${hash} parent ${parentHash}`);
    }

    const typedPath = resolveInsideRun(runRoot, entry.path);
    const relativeTypedPath = relative(runRoot, typedPath);
    assert.equal(relativeTypedPath.startsWith(".."), false, entry.path);
    assert.match(entry.path, /^attestations\/[a-z_]+\/[0-9a-f]{64}\.json$/);
    assert.match(entry.cas_uri, /^cas:\/\/sha256\/[0-9a-f]{64}$/);

    const typedContent = await readFile(typedPath, "utf8");
    const casContent = await readFile(casObjectPath(runRoot, hash), "utf8");
    assert.equal(typedContent, `${canonicalJson(attestation)}\n`, hash);
    assert.equal(casContent, typedContent, hash);

    const storedObject = await store.putAttestation(attestation);
    assert.equal(storedObject.digest, hash, hash);
    assert.equal(storedObject.uri, entry.cas_uri, hash);
    const retrieved = await store.getAttestation(storedObject.uri);
    assert.equal(canonicalJson(retrieved.attestation), canonicalJson(attestation), hash);
  }

  const evidenceBytes = new TextEncoder().encode("p3-s8 acceptance evidence object\n");
  const storedBlob = await store.putBlob(evidenceBytes);
  const retrievedBlob = await store.getBlob(storedBlob.uri);
  assert.deepEqual([...retrievedBlob.bytes], [...evidenceBytes]);

  const level0Reports = stored.map((attestation) => verifyLevel0(attestation));
  assert.equal(level0Reports.every((report) => report.status === "PASS"), true, JSON.stringify(level0Reports));

  const level1Reports = await verifyAttestationSetLevel1(stored, { index: layout.index, runRoot });
  assert.equal(level1Reports.length, signedFixtureNames.length);
  assert.equal(level1Reports.every((report) => report.status === "PASS"), true, JSON.stringify(level1Reports));

  const auditReport = generatedByName.get("audit-replay-report.signed.attestation.json");
  assert.ok(auditReport);
  assert.deepEqual((auditReport.predicate as Record<string, unknown>).failure_codes, []);
});

test("P3-S8 acceptance: controlled verifier tampering emits stable failure codes", async () => {
  const { attestations, layout } = await acceptanceContext();
  const [observation, evidence] = attestations;

  const contentTamper = structuredClone(observation) as Record<string, unknown>;
  (contentTamper.predicate as Record<string, unknown>).request_summary = "mutated by acceptance test";
  const contentReport = await verifyLevel1(contentTamper, { records: attestations, index: layout.index, runRoot });
  assert.equal(hasCode(contentReport.failure_codes, "F_HASH_ATTESTATION_MISMATCH"), true);

  const signatureTamper = structuredClone(observation) as Record<string, unknown>;
  const signature = signatureTamper.signature as Record<string, unknown>;
  signature.signature = `${String(signature.signature).slice(0, -2)}00`;
  const signatureReport = await verifyLevel1(signatureTamper, { records: attestations, index: layout.index, runRoot });
  assert.equal(hasCode(signatureReport.failure_codes, "F_SIGNATURE_INVALID"), true);

  const brokenParent = structuredClone(evidence) as Record<string, unknown>;
  brokenParent.parents = ["0x1212121212121212121212121212121212121212121212121212121212121212"];
  const linkReport = await verifyLevel1(brokenParent, { records: [observation], index: layout.index, runRoot });
  assert.equal(hasCode(linkReport.failure_codes, "F_LINK_BROKEN"), true);

  const unsafeIndex = replaceIndexEntry(layout.index, String(observation.attestation_hash), {
    path: "../escape.json",
  });
  const unsafePathReport = await verifyLevel1(observation, { records: attestations, index: unsafeIndex, runRoot });
  assert.equal(hasCode(unsafePathReport.failure_codes, "F_INDEX_PATH_UNSAFE"), true);

  const badCasIndex = replaceIndexEntry(layout.index, String(observation.attestation_hash), {
    cas_uri: "cas://sha256/0000000000000000000000000000000000000000000000000000000000000000",
  });
  const badCasReport = await verifyLevel1(observation, { records: attestations, index: badCasIndex, runRoot });
  assert.equal(hasCode(badCasReport.failure_codes, "F_HASH_OBJECT_MISMATCH"), true);
});

test("P3-S8 acceptance: local object content mismatches are detected through verifier and CAS reads", async () => {
  const { attestations, layout } = await acceptanceContext();
  const [observation] = attestations;
  const entry = layout.index.attestations.find((item) => item.attestation_hash === observation.attestation_hash);
  assert.ok(entry);

  const mutatedIndexedObject = structuredClone(observation) as Record<string, unknown>;
  (mutatedIndexedObject.predicate as Record<string, unknown>).request_summary = "mutated local run object";
  await writeFile(resolveInsideRun(runRoot, entry.path), `${canonicalJson(mutatedIndexedObject)}\n`);

  const verifierReport = await verifyLevel1(observation, { records: attestations, index: layout.index, runRoot });
  assert.equal(hasCode(verifierReport.failure_codes, "F_HASH_OBJECT_MISMATCH"), true);

  const store = new LocalContentAddressedStore(storeRoot);
  const storedBlob = await store.putBlob("original acceptance evidence bytes");
  await writeFile(store.blobPath(storedBlob.uri), "mutated acceptance evidence bytes");
  await assert.rejects(() => store.getBlob(storedBlob.uri), ContentAddressMismatchError);
});
