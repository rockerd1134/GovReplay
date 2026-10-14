import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { readFile, rm } from "node:fs/promises";
import { join, relative } from "node:path";
import test from "node:test";
import { canonicalJson } from "../src/canonical-json.ts";
import { digestAttestation } from "../src/digest.ts";
import {
  signedFixtureDir,
  signedFixtureNames,
} from "../src/fixture-generation.ts";
import {
  AttestationRunLayoutError,
  casObjectPath,
  resolveInsideRun,
  writeAttestationRunLayout,
} from "../src/run-layout.ts";

const runRoot = join(import.meta.dirname, "..", "..", "..", ".tmp", "test-runs", "run-layout");
const runId = "run-p3-s6-fixtures";

function signedFixtures(): Record<string, unknown>[] {
  return signedFixtureNames.map((name) => JSON.parse(readFileSync(join(signedFixtureDir, name), "utf8")));
}

test.beforeEach(async () => {
  await rm(runRoot, { recursive: true, force: true });
});

test.after(async () => {
  await rm(runRoot, { recursive: true, force: true });
});

test("repeated fixture index generation is byte-stable", async () => {
  const attestations = signedFixtures();
  const first = await writeAttestationRunLayout({ runRoot, runId, attestations });
  const firstBytes = await readFile(first.indexPath, "utf8");

  const second = await writeAttestationRunLayout({ runRoot, runId, attestations: signedFixtures().reverse() });
  const secondBytes = await readFile(second.indexPath, "utf8");

  assert.equal(secondBytes, firstBytes);
  assert.equal(firstBytes, `${canonicalJson(first.index)}\n`);
  assert.deepEqual(second.index, first.index);
});

test("every signed fixture is represented in the index and stored at typed and CAS paths", async () => {
  const attestations = signedFixtures();
  const result = await writeAttestationRunLayout({ runRoot, runId, attestations });
  const indexedHashes = new Set(result.index.attestations.map((entry) => entry.attestation_hash));

  assert.equal(result.index.attestation_count, String(signedFixtureNames.length));
  for (const attestation of attestations) {
    const hash = String((attestation as Record<string, unknown>).attestation_hash);
    assert.equal(indexedHashes.has(hash), true, hash);

    const entry = result.index.attestations.find((item) => item.attestation_hash === hash);
    assert.ok(entry, hash);
    assert.match(entry.path, /^attestations\/[a-z_]+\/[0-9a-f]{64}\.json$/);
    assert.match(entry.cas_uri, /^cas:\/\/sha256\/[0-9a-f]{64}$/);

    const typedContent = await readFile(resolveInsideRun(runRoot, entry.path), "utf8");
    const casContent = await readFile(casObjectPath(runRoot, hash), "utf8");
    assert.equal(typedContent, `${canonicalJson(attestation)}\n`);
    assert.equal(casContent, typedContent);
  }
});

test("parent links in the index resolve where expected", async () => {
  const result = await writeAttestationRunLayout({ runRoot, runId, attestations: signedFixtures() });
  const indexedHashes = new Set(result.index.attestations.map((entry) => entry.attestation_hash));

  for (const entry of result.index.attestations) {
    for (const parentHash of entry.parent_hashes) {
      assert.equal(indexedHashes.has(parentHash), true, `${entry.attestation_hash} parent ${parentHash}`);
    }
  }
});

test("local index paths stay inside the run layout", async () => {
  const result = await writeAttestationRunLayout({ runRoot, runId, attestations: signedFixtures() });

  for (const entry of result.index.attestations) {
    const absolute = resolveInsideRun(runRoot, entry.path);
    const rel = relative(runRoot, absolute);
    assert.equal(rel.startsWith(".."), false, entry.path);
    assert.equal(rel.includes(".."), false, entry.path);
  }

  assert.throws(() => resolveInsideRun(runRoot, "../escape.json"), AttestationRunLayoutError);
  assert.throws(() => resolveInsideRun(runRoot, "attestations\\escape.json"), AttestationRunLayoutError);
});

test("duplicate attestation inputs fail deterministically", async () => {
  const attestations = signedFixtures();
  const duplicate = [attestations[0], ...attestations];

  await assert.rejects(
    () => writeAttestationRunLayout({ runRoot, runId, attestations: duplicate }),
    /Duplicate attestation hash/,
  );
});

test("tampered attestation inputs fail deterministically", async () => {
  const attestations = signedFixtures();
  const tampered = structuredClone(attestations[0]) as Record<string, unknown>;
  (tampered.predicate as Record<string, unknown>).request_summary = "mutated";
  assert.notEqual(digestAttestation(tampered).value, tampered.attestation_hash);

  await assert.rejects(
    () => writeAttestationRunLayout({ runRoot, runId, attestations: [tampered, ...attestations.slice(1)] }),
    /Attestation digest mismatch/,
  );
});
