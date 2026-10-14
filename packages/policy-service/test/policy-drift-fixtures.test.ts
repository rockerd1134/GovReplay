import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  generatePolicyDriftCases,
  policyDriftFixturePath,
  serializePolicyDriftCases,
  type PolicyDriftClassification,
} from "../src/policy-drift-fixtures.ts";

test("stored policy drift fixtures match deterministic generation", () => {
  const generated = generatePolicyDriftCases();
  const stored = readFileSync(policyDriftFixturePath, "utf8");

  assert.equal(stored, `${serializePolicyDriftCases(generated)}\n`);
});

test("policy drift fixtures cover all required classifications", () => {
  const cases = generatePolicyDriftCases();
  const classifications = new Set(cases.map((item) => item.classification));
  const required: PolicyDriftClassification[] = [
    "historical_pass_current_pass",
    "historical_pass_current_fail",
    "historical_fail_current_fail",
    "historical_fail_current_pass",
    "policy_not_available",
    "policy_hash_mismatch",
  ];

  assert.equal(cases.length, required.length);
  assert.deepEqual([...classifications].sort(), [...required].sort());
});

test("policy drift fixtures distinguish unavailable policy from hash mismatch", () => {
  const cases = generatePolicyDriftCases();
  const unavailable = cases.find((item) => item.classification === "policy_not_available");
  const mismatch = cases.find((item) => item.classification === "policy_hash_mismatch");

  assert.equal(unavailable?.current_decision, "unavailable");
  assert.equal(unavailable?.current_policy_bundle_hash, null);
  assert.equal(unavailable?.policy_hash_consistent, true);

  assert.equal(mismatch?.policy_hash_consistent, false);
  assert.notEqual(mismatch?.historical_policy_bundle_hash, mismatch?.current_policy_bundle_hash);
});
