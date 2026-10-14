import assert from "node:assert/strict";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import test from "node:test";
import { readFileSync } from "node:fs";
import { digestAttestation } from "../src/digest.ts";
import {
  ContentAddressMismatchError,
  digestToCasUri,
  LocalContentAddressedStore,
  normalizeDigestReference,
  parseCasUri,
} from "../src/storage.ts";

const fixtureDir = join(import.meta.dirname, "..", "fixtures");
const storeRoot = join(import.meta.dirname, "..", "..", "..", ".tmp", "test-store");

function fixture(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(fixtureDir, name), "utf8"));
}

test.beforeEach(async () => {
  await rm(storeRoot, { recursive: true, force: true });
});

test.after(async () => {
  await rm(storeRoot, { recursive: true, force: true });
});

test("storing the same attestation twice is idempotent", async () => {
  const store = new LocalContentAddressedStore(storeRoot);
  const observation = fixture("observation-request.attestation.json");

  const first = await store.putAttestation(observation);
  const second = await store.putAttestation(observation);

  assert.deepEqual(second, first);
  assert.match(first.uri, /^cas:\/\/sha256\/[0-9a-f]{64}$/);
  assert.equal(first.digest, digestAttestation(observation).value);
});

test("retrieving an attestation recomputes and verifies the digest", async () => {
  const store = new LocalContentAddressedStore(storeRoot);
  const evidence = fixture("evidence-bundle.attestation.json");
  const stored = await store.putAttestation(evidence);

  const retrieved = await store.getAttestation(stored.uri);

  assert.deepEqual(retrieved.attestation, evidence);
  assert.deepEqual(retrieved.digest, digestAttestation(evidence));
  assert.equal(digestToCasUri(retrieved.digest), stored.uri);
});

test("mutated stored attestation content fails verification", async () => {
  const store = new LocalContentAddressedStore(storeRoot);
  const approval = fixture("approval.attestation.json");
  const stored = await store.putAttestation(approval);
  const path = store.attestationPath(stored.digest);

  const mutated = structuredClone(approval);
  (mutated.predicate as Record<string, unknown>).approval_status = "rejected";
  await writeFile(path, `${JSON.stringify(mutated)}\n`);

  await assert.rejects(() => store.getAttestation(stored.digest), ContentAddressMismatchError);
});

test("blob storage and attestation storage use the same digest convention", async () => {
  const store = new LocalContentAddressedStore(storeRoot);
  const blob = new TextEncoder().encode("evidence bytes\n");
  const storedBlob = await store.putBlob(blob);
  const artifact = fixture("artifact.attestation.json");
  const storedAttestation = await store.putAttestation(artifact);

  assert.match(storedBlob.uri, /^cas:\/\/sha256\/[0-9a-f]{64}$/);
  assert.match(storedAttestation.uri, /^cas:\/\/sha256\/[0-9a-f]{64}$/);
  assert.equal(parseCasUri(storedBlob.uri).value, storedBlob.digest);
  assert.equal(parseCasUri(storedAttestation.uri).value, storedAttestation.digest);

  const retrieved = await store.getBlob(storedBlob.digest);
  assert.deepEqual([...retrieved.bytes], [...blob]);
  assert.equal(retrieved.uri, storedBlob.uri);
});

test("mutated stored blob content fails verification", async () => {
  const store = new LocalContentAddressedStore(storeRoot);
  const stored = await store.putBlob("original evidence");
  const path = store.blobPath(stored.uri);

  await writeFile(path, "mutated evidence");

  await assert.rejects(() => store.getBlob(stored.uri), ContentAddressMismatchError);
});

test("unsafe digest, path, URI, and algorithm inputs are rejected", async () => {
  const store = new LocalContentAddressedStore(storeRoot);

  assert.throws(() => normalizeDigestReference("0xABC"), /bytes32/);
  assert.throws(() => normalizeDigestReference("0xabc/../def"), /bytes32/);
  assert.throws(() => parseCasUri("cas://sha256/../../escape"), /Malformed CAS URI/);
  assert.throws(
    () =>
      normalizeDigestReference({
        algorithm: "keccak256" as "sha256",
        value: "0x0000000000000000000000000000000000000000000000000000000000000000",
      }),
    /Unsupported digest algorithm/,
  );
  assert.throws(() => store.blobPath("cas://sha512/00"), /Unsupported digest algorithm/);
});

test("existing mismatched content is rejected during idempotent writes", async () => {
  const store = new LocalContentAddressedStore(storeRoot);
  const deployment = fixture("deployment.attestation.json");
  const digest = digestAttestation(deployment);
  const path = store.attestationPath(digest);

  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify({ ...deployment, predicate: { mutated: true } })}\n`);

  await assert.rejects(() => store.putAttestation(deployment), ContentAddressMismatchError);
});
