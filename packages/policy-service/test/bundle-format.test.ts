import assert from "node:assert/strict";
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import {
  assertObligationsDocument,
  assertPolicyBundleMetadata,
  computePolicyBundleHash,
  listBundleFiles,
  loadPolicyBundle,
} from "../src/bundle-format.ts";

const packageRoot = join(import.meta.dirname, "..");
const fixtureRoot = join(packageRoot, "fixtures", "bundles");
const schemaRoot = join(packageRoot, "..", "..", "schemas", "policy-bundle");
const tempRoot = join(packageRoot, ".tmp", "bundle-format-test");

test("policy bundle schemas are valid JSON", () => {
  for (const name of readdirSync(schemaRoot).filter((entry) => entry.endsWith(".json"))) {
    assert.doesNotThrow(() => JSON.parse(readFileSync(join(schemaRoot, name), "utf8")), name);
  }
});

test("fixture bundles load and expose deterministic bundle hashes", () => {
  const bundleNames = readdirSync(fixtureRoot).sort();
  assert.deepEqual(bundleNames, [
    "software-delivery-p1-baseline",
    "software-delivery-p2-strict-approval",
    "software-delivery-p3-evidence-strengthened",
  ]);

  const hashes = new Set<string>();
  for (const bundleName of bundleNames) {
    const bundle = loadPolicyBundle(join(fixtureRoot, bundleName));
    assert.equal(bundle.metadata.policy_language, "cedar", bundleName);
    assert.equal(bundle.obligations.schema_version, "govprov.obligations.v1", bundleName);
    assert.match(bundle.bundle_hash, /^0x[0-9a-f]{64}$/, bundleName);
    assert.equal(bundle.bundle_hash, computePolicyBundleHash(join(fixtureRoot, bundleName)), bundleName);
    assert.ok(bundle.policy_files.includes("action_authorization.cedar"), bundleName);
    assert.ok(bundle.test_files.length >= 2, bundleName);
    hashes.add(bundle.bundle_hash);
  }

  assert.equal(hashes.size, bundleNames.length);
});

test("bundle hash is stable across repeated loads", () => {
  const bundleDir = join(fixtureRoot, "software-delivery-p1-baseline");

  assert.equal(loadPolicyBundle(bundleDir).bundle_hash, loadPolicyBundle(bundleDir).bundle_hash);
  assert.deepEqual(listBundleFiles(bundleDir), [
    "metadata.json",
    "obligations.yml",
    "policies/action_authorization.cedar",
    "schema.cedarschema",
    "tests/allow-runbook-baseline.json",
    "tests/deny-runbook-missing-evidence.json",
  ]);
});

test("policy version lineage uses stable parent bundle hashes", () => {
  const p1 = loadPolicyBundle(join(fixtureRoot, "software-delivery-p1-baseline"));
  const p2 = loadPolicyBundle(join(fixtureRoot, "software-delivery-p2-strict-approval"));
  const p3 = loadPolicyBundle(join(fixtureRoot, "software-delivery-p3-evidence-strengthened"));

  assert.equal(p1.metadata.parent_policy_bundle_hash, null);
  assert.equal(p2.metadata.parent_policy_bundle_hash, p1.bundle_hash);
  assert.equal(p3.metadata.parent_policy_bundle_hash, p2.bundle_hash);
});

test("metadata validation rejects invalid parent hashes", () => {
  const metadata = JSON.parse(
    readFileSync(join(fixtureRoot, "software-delivery-p1-baseline", "metadata.json"), "utf8"),
  );
  metadata.parent_policy_bundle_hash = "sha256:not-bytes32";

  assert.throws(() => assertPolicyBundleMetadata(metadata), /parent_policy_bundle_hash/);
});

test("obligations validation requires every MVP obligation category", () => {
  const obligations = JSON.parse(
    readFileSync(join(fixtureRoot, "software-delivery-p1-baseline", "obligations.yml"), "utf8"),
  );
  delete obligations.obligations[0].attestation_requirements;

  assert.throws(() => assertObligationsDocument(obligations), /attestation_requirements/);
});

test("bundle loader rejects non-json-compatible obligations.yml", () => {
  rmSync(tempRoot, { force: true, recursive: true });
  mkdirSync(join(tempRoot, "policies"), { recursive: true });
  mkdirSync(join(tempRoot, "tests"), { recursive: true });
  writeFileSync(
    join(tempRoot, "metadata.json"),
    readFileSync(join(fixtureRoot, "software-delivery-p1-baseline", "metadata.json")),
  );
  writeFileSync(join(tempRoot, "schema.cedarschema"), "entity Agent;\n");
  writeFileSync(join(tempRoot, "policies", "action_authorization.cedar"), "permit(principal, action, resource);\n");
  writeFileSync(
    join(tempRoot, "tests", "allow.json"),
    JSON.stringify({
      name: "allow",
      expected_decision: "allow",
      input: {
        principal: {},
        action: {},
        resource: {},
        context: {},
      },
    }),
  );
  writeFileSync(join(tempRoot, "obligations.yml"), "schema_version: govprov.obligations.v1\n");

  assert.throws(() => loadPolicyBundle(tempRoot), /JSON-compatible YAML subset/);
});
