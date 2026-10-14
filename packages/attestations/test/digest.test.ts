import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson } from "../src/canonical-json.ts";
import {
  assertBytes32Hex,
  attestationBytes32,
  digestAttestation,
  digestJson,
} from "../src/digest.ts";

const fixtureDir = join(import.meta.dirname, "..", "fixtures");
const schemaDir = join(import.meta.dirname, "..", "..", "..", "schemas", "attestations");

function fixture(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(fixtureDir, name), "utf8"));
}

test("canonicalization is stable across object key order variations", () => {
  const left = {
    b: "second",
    a: {
      d: true,
      c: ["x", "y"],
    },
  };
  const right = {
    a: {
      c: ["x", "y"],
      d: true,
    },
    b: "second",
  };

  assert.equal(canonicalJson(left), canonicalJson(right));
  assert.equal(canonicalJson(left), '{"a":{"c":["x","y"],"d":true},"b":"second"}');
});

test("schema and fixture artifacts are valid JSON", () => {
  for (const name of readdirSync(schemaDir).filter((entry) => entry.endsWith(".json"))) {
    assert.doesNotThrow(() => JSON.parse(readFileSync(join(schemaDir, name), "utf8")), name);
  }

  for (const name of readdirSync(fixtureDir).filter((entry) => entry.endsWith(".json"))) {
    const parsed = JSON.parse(readFileSync(join(fixtureDir, name), "utf8")) as Record<string, unknown>;
    assert.equal(parsed._type, "https://govprov.dev/attestation/v1", name);
    assert.equal(parsed.schema_version, "govprov.attestation.v1", name);
  }
});

test("canonicalization rejects unsupported or ambiguous values", () => {
  assert.throws(() => canonicalJson({ bad: undefined }), /undefined/);
  assert.throws(() => canonicalJson({ bad: Number.NaN }), /NaN/);
  assert.throws(() => canonicalJson({ bad: -0 }), /negative zero/);
  assert.throws(() => canonicalJson(new Date("2026-01-01T00:00:00Z")), /plain JSON object/);
});

test("digest outputs are stable and bytes32 compatible", () => {
  const observation = fixture("observation-request.attestation.json");
  const first = digestAttestation(observation);
  const second = digestAttestation(observation);

  assert.deepEqual(first, second);
  assert.equal(first.algorithm, "sha256");
  assertBytes32Hex(first.value);
  assert.equal(attestationBytes32(observation), first.value);
});

test("equivalent fixtures hash the same across key order changes", () => {
  const canonicalFixture = fixture("observation-request.attestation.json");
  const reorderedFixture = fixture("observation-request.reordered.attestation.json");

  assert.equal(digestAttestation(canonicalFixture).value, digestAttestation(reorderedFixture).value);
});

test("mutated fixtures hash differently", () => {
  const evidence = fixture("evidence-bundle.attestation.json");
  const mutated = structuredClone(evidence);
  (mutated.predicate as Record<string, unknown>).evidence_count = "3";

  assert.notEqual(digestAttestation(evidence).value, digestAttestation(mutated).value);
});

test("all MVP fixture attestations produce sha256 bytes32 identifiers", () => {
  const names = [
    "observation-request.attestation.json",
    "evidence-bundle.attestation.json",
    "policy-decision.attestation.json",
    "agent-action.attestation.json",
    "approval.attestation.json",
    "artifact.attestation.json",
    "deployment.attestation.json",
    "ledger-anchor.attestation.json",
    "audit-replay-report.attestation.json",
  ];

  for (const name of names) {
    const digest = digestAttestation(fixture(name));
    assert.equal(digest.algorithm, "sha256", name);
    assertBytes32Hex(digest.value);
  }
});

test("generic JSON digest preserves object semantics", () => {
  assert.equal(digestJson({ x: 1, y: ["z"] }).value, digestJson({ y: ["z"], x: 1 }).value);
});
