import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { digestAttestation } from "../src/digest.ts";
import {
  addressFromPrivateKey,
  recoverAttestationSigner,
  signAttestation,
  signingPayloadForAttestation,
  verifyAttestationSignature,
} from "../src/signing.ts";

const fixtureDir = join(import.meta.dirname, "..", "fixtures");
const devPrivateKey = "0x0000000000000000000000000000000000000000000000000000000000000001";
const devAddress = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";

function fixture(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(fixtureDir, name), "utf8"));
}

test("dev private key derives the expected Ethereum address", () => {
  assert.equal(addressFromPrivateKey(devPrivateKey), devAddress);
});

test("signing the same attestation fixture with the same dev key is stable", () => {
  const approval = fixture("approval.attestation.json");

  const first = signAttestation(approval, devPrivateKey);
  const second = signAttestation(approval, devPrivateKey);

  assert.deepEqual(first, second);
  assert.equal(first.signature.profile, "govprov-ethsign-secp256k1-v1");
  assert.equal(first.signature.signer, devAddress);
  assert.match(first.signature.signature, /^0x[0-9a-f]{130}$/);
  assert.equal(first.attestation_hash, digestAttestation(approval).value);
});

test("recovered signer address matches the expected fixture actor", () => {
  const approval = fixture("approval.attestation.json");
  const signed = signAttestation(approval, devPrivateKey);

  assert.equal(recoverAttestationSigner(signed), devAddress);
  assert.equal(verifyAttestationSignature(signed), true);
});

test("tampering with signed content fails verification", () => {
  const signed = signAttestation(fixture("approval.attestation.json"), devPrivateKey);
  const tampered = structuredClone(signed);
  (tampered.predicate as Record<string, unknown>).decision = "rejected";

  assert.equal(verifyAttestationSignature(tampered), false);
});

test("malformed signatures are rejected", () => {
  const signed = signAttestation(fixture("approval.attestation.json"), devPrivateKey);
  const malformed = structuredClone(signed);
  malformed.signature.signature = "0x1234";

  assert.throws(() => verifyAttestationSignature(malformed), /Malformed signature/);
});

test("unsupported signature profiles are rejected", () => {
  const signed = signAttestation(fixture("approval.attestation.json"), devPrivateKey);
  const unsupported = structuredClone(signed);
  unsupported.signature.profile = "govprov-eip712-v1";

  assert.throws(() => verifyAttestationSignature(unsupported), /Unsupported signature profile/);
});

test("address mismatches fail verification", () => {
  const observation = fixture("observation-request.attestation.json");
  const signedWithWrongActorKey = signAttestation(observation, devPrivateKey);

  assert.equal(recoverAttestationSigner(signedWithWrongActorKey), devAddress);
  assert.equal(verifyAttestationSignature(signedWithWrongActorKey), false);
});

test("signing excludes existing signature fields and preserves digest convention", () => {
  const approval = fixture("approval.attestation.json");
  const signed = signAttestation(approval, devPrivateKey);
  const signedAgain = signAttestation(signed, devPrivateKey);

  assert.equal(signedAgain.attestation_hash, signed.attestation_hash);
  assert.equal(signingPayloadForAttestation(signed).attestation_hash.value, digestAttestation(approval).value);
  assert.equal(signingPayloadForAttestation(signed).signing_input_digest.algorithm, "sha256");
  assert.equal(verifyAttestationSignature(signedAgain), true);
});
