import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson } from "../../attestations/src/canonical-json.ts";
import { digestAttestation } from "../../attestations/src/digest.ts";
import {
  verifyAttestationSignature,
} from "../../attestations/src/signing.ts";
import {
  generatePolicyDecisionAttestations,
  policyDecisionFixtureDir,
  policyDecisionMaterial,
  serializePolicyDecisionAttestation,
} from "../src/policy-decision-attestation.ts";
import { loadPolicyBundle } from "../src/bundle-format.ts";

function fixture(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(policyDecisionFixtureDir, name), "utf8"));
}

test("policy decision attestation fixtures match deterministic generation", () => {
  const generated = generatePolicyDecisionAttestations();
  const names = Object.keys(generated).sort();

  assert.deepEqual(names, readdirSync(policyDecisionFixtureDir).sort());
  assert.equal(names.length, 12);
  for (const name of names) {
    const stored = readFileSync(join(policyDecisionFixtureDir, name), "utf8");
    assert.equal(stored, `${serializePolicyDecisionAttestation(generated[name])}\n`, name);
    assert.equal(canonicalJson(fixture(name)), canonicalJson(generated[name]), name);
  }
});

test("policy decision attestations bind policy refs, decisions, inputs, and obligations", () => {
  const generated = generatePolicyDecisionAttestations();
  const decisions = new Set<string>();
  const policyVersions = new Set<string>();

  for (const [name, attestation] of Object.entries(generated)) {
    assert.equal(attestation.attestation_type, "PolicyDecisionAttestation", name);
    assert.equal(verifyAttestationSignature(attestation), true, name);
    assert.equal(attestation.attestation_hash, digestAttestation(attestation).value, name);

    const predicate = attestation.predicate as Record<string, unknown>;
    const policy = predicate.policy as Record<string, unknown>;
    assert.match(String(predicate.policy_bundle_hash), /^0x[0-9a-f]{64}$/, name);
    assert.match(String(predicate.policy_input_hash), /^0x[0-9a-f]{64}$/, name);
    assert.match(String(predicate.obligations_hash), /^0x[0-9a-f]{64}$/, name);
    assert.match(String(predicate.policy_decision_hash), /^0x[0-9a-f]{64}$/, name);
    assert.equal((policy.policy_hash as Record<string, unknown>).value, predicate.policy_bundle_hash, name);
    assert.ok(Array.isArray(predicate.obligation_ids), name);
    assert.ok((predicate.obligation_ids as unknown[]).length > 0, name);
    assert.ok(Array.isArray(predicate.resolved_obligations), name);
    decisions.add(String(predicate.decision));
    policyVersions.add(String(policy.policy_version));
  }

  assert.deepEqual([...decisions].sort(), ["allow", "deny"]);
  assert.deepEqual([...policyVersions].sort(), ["1.0.0", "2.0.0", "3.0.0"]);
});

test("policy decision material keeps input hashes stable and binds observed evaluator metadata", () => {
  const generated = generatePolicyDecisionAttestations();
  const p1Allow = generated["software-delivery-p1-baseline.allow-runbook-baseline.signed.attestation.json"];
  const predicate = p1Allow.predicate as Record<string, unknown>;

  assert.equal(
    predicate.policy_input_hash,
    "0x442e09b98957618a2817f42cb6919566e14b38d7cbf94b81b69c7f1e2e7d8c86",
  );
  assert.equal(
    predicate.obligations_hash,
    "0x0a95ccdcf61da1e670434426dccc06eb1fe2a44919f3865f6c54f45f898bfefd",
  );
  assert.equal(
    predicate.policy_decision_hash,
    "0xcd87bf6dfbd707d15d5ccd1ce1ed822028dca2943e29be39ab6c368d6788392a",
  );
  assert.equal(predicate.evaluator_identity, "govreplay:policy-evaluator:cedar-subset");
  assert.equal(predicate.evaluator_version, "cedar-policy-4.11.1-compatible-ts-subset.v1");
  assert.deepEqual(predicate.matched_policy_ids, [
    "action_authorization.cedar#permit-1-propose_runbook_update",
  ]);
});

test("policy decision material ignores fixture oracle labels as a decision source", () => {
  const bundleName = "software-delivery-p1-baseline";
  const testFile = "allow-runbook-baseline.json";
  const bundle = loadPolicyBundle(join(policyDecisionFixtureDir, "..", "bundles", bundleName));
  const policyTest = JSON.parse(readFileSync(join(bundle.directory, "tests", testFile), "utf8"));
  policyTest.expected_decision = "deny";

  const material = policyDecisionMaterial(bundle, {
    bundleName,
    testFile,
    testName: String(policyTest.name),
    input: policyTest.input,
  });

  assert.equal(material.decision, "allow");
  assert.equal(material.evaluator_identity, "govreplay:policy-evaluator:cedar-subset");
  assert.deepEqual(material.matched_policy_ids, [
    "action_authorization.cedar#permit-1-propose_runbook_update",
  ]);
});

test("tampering with a signed policy decision attestation fails cryptographic verification", () => {
  const [name] = readdirSync(policyDecisionFixtureDir).sort();
  const tampered = fixture(name);
  const predicate = tampered.predicate as Record<string, unknown>;
  predicate.decision = predicate.decision === "allow" ? "deny" : "allow";

  assert.equal(verifyAttestationSignature(tampered), false);
});
