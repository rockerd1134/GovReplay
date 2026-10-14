import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
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
  recoverAttestationSigner,
  verifyAttestationSignature,
} from "../src/signing.ts";

function fixture(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(signedFixtureDir, name), "utf8"));
}

test("generated signed fixture files match deterministic generation", () => {
  const generated = generateSignedFixtureAttestations();

  for (const name of signedFixtureNames) {
    const stored = readFileSync(join(signedFixtureDir, name), "utf8");
    assert.equal(stored, `${serializeFixture(generated[name])}\n`, name);
    assert.equal(canonicalJson(fixture(name)), canonicalJson(generated[name]), name);
  }
});

test("every signed fixture recovers the expected actor address", () => {
  for (const name of signedFixtureNames) {
    const attestation = fixture(name);
    const createdBy = attestation.created_by as Record<string, unknown>;

    assert.equal(recoverAttestationSigner(attestation), String(createdBy.ethereum_address).toLowerCase(), name);
    assert.equal(verifyAttestationSignature(attestation), true, name);
    assert.equal(attestation.attestation_hash, digestAttestation(attestation).value, name);
  }
});

test("generated parent links reference generated attestation hashes", () => {
  const fixtures = generateSignedFixtureAttestations();
  const hashes = new Set(Object.values(fixtures).map((attestation) => attestation.attestation_hash));

  for (const name of signedFixtureNames) {
    const attestation = fixtures[name];
    for (const parent of attestation.parents as string[]) {
      assert.equal(hashes.has(parent), true, `${name} parent ${parent}`);
    }
  }
});

test("tampering with generated fixture content fails verification", () => {
  const deployment = fixture("deployment.signed.attestation.json");
  const tampered = structuredClone(deployment);
  (tampered.predicate as Record<string, unknown>).environment = "production";

  assert.equal(verifyAttestationSignature(tampered), false);
});

test("generated signed fixtures do not contain private keys or obvious secret fields", () => {
  for (const name of signedFixtureNames) {
    const raw = readFileSync(join(signedFixtureDir, name), "utf8").toLowerCase();

    assert.equal(raw.includes("private_key"), false, name);
    assert.equal(raw.includes("private key"), false, name);
    assert.equal(raw.includes("secret"), false, name);
    assert.equal(raw.includes("0000000000000000000000000000000000000000000000000000000000000001"), false, name);
  }
});
