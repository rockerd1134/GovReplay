import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { validateScenarioManifest } from "../src/manifest.ts";

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const schemaPath = join(packageRoot, "schemas", "scenarios", "manifest.schema.json");
const scenariosRoot = join(packageRoot, "examples", "scenarios");

test("scenario manifest schema is valid JSON with expected contract", () => {
  const schema = JSON.parse(readFileSync(schemaPath, "utf8"));

  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(schema.properties.schema_version.const, "govprov.scenario_manifest.v1");
  assert.deepEqual(schema.properties.mode.enum, ["structured_logs", "signed_offchain", "govreplay_besu"]);

  for (const field of [
    "scenario_id",
    "scenario_name",
    "workflow_id",
    "policy_version",
    "fault_id",
    "mode",
    "expected_verdict",
    "expected_failure_code",
    "expected_failure_stage",
    "expected_historical_compliance",
    "expected_current_compliance",
    "primary_actor_id",
    "resource_id",
    "created_at",
  ]) {
    assert.ok(schema.required.includes(field), `${field} should be required`);
  }
});

test("tracked scenario manifests validate", () => {
  const manifestPaths = findManifestPaths(scenariosRoot);

  assert.ok(manifestPaths.length >= 2, "expected happy-path and fault manifest fixtures");

  for (const manifestPath of manifestPaths) {
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    assert.doesNotThrow(() => validateScenarioManifest(manifest), manifestPath);
  }
});

test("pass and fail verdict invariants are enforced", () => {
  const valid = JSON.parse(readFileSync(join(scenariosRoot, "S1_runbook_update", "manifest.json"), "utf8"));

  assert.throws(
    () => validateScenarioManifest({ ...valid, expected_failure_code: "unexpected" }),
    /expected_failure_code must be null/,
  );

  assert.throws(
    () =>
      validateScenarioManifest({
        ...valid,
        expected_verdict: "fail",
        expected_failure_code: null,
        expected_failure_stage: null,
      }),
    /expected_failure_code must be a non-empty string/,
  );
});

test("S1 fixture includes minimum seed files", () => {
  const scenarioRoot = join(scenariosRoot, "S1_runbook_update");

  for (const relativePath of [
    "README.md",
    "manifest.json",
    "observation.json",
    "evidence/incident_report.md",
    "evidence/service_log_excerpt.txt",
    "input/current_runbook.md",
    "expected/artifact.md",
    "expected/audit_pass.json",
    "faults/F1_missing_evidence.manifest.json",
    "faults/F2_evidence_tampered.manifest.json",
    "faults/F6_missing_approval.manifest.json",
    "faults/F10_artifact_substitution.manifest.json",
  ]) {
    assert.ok(statSync(join(scenarioRoot, relativePath)).isFile(), relativePath);
  }
});

test("S4 fixture includes minimum seed files", () => {
  const scenarioRoot = join(scenariosRoot, "S4_policy_gated_deployment");

  for (const relativePath of [
    "README.md",
    "manifest.json",
    "observation.json",
    "evidence/deployment_request.json",
    "input/artifact_manifest.json",
    "expected/deployment_manifest.json",
    "expected/audit_pass.json",
  ]) {
    assert.ok(statSync(join(scenarioRoot, relativePath)).isFile(), relativePath);
  }
});

test("S2 fixture includes minimum seed files", () => {
  const scenarioRoot = join(scenariosRoot, "S2_configuration_change");

  for (const relativePath of [
    "README.md",
    "manifest.json",
    "observation.json",
    "evidence/alert_summary.json",
    "input/config_diff.patch",
    "expected/config_patch.yaml",
    "expected/deployment_manifest.json",
    "expected/audit_pass.json",
    "faults/F8_separation_of_duties.manifest.json",
  ]) {
    assert.ok(statSync(join(scenarioRoot, relativePath)).isFile(), relativePath);
  }
});

test("S3 fixture includes minimum seed files", () => {
  const scenarioRoot = join(scenariosRoot, "S3_patch_proposal");

  for (const relativePath of [
    "README.md",
    "manifest.json",
    "observation.json",
    "evidence/issue_report.json",
    "evidence/test_report.json",
    "input/retry_edge_case.patch",
    "expected/deployment_manifest.json",
    "expected/audit_pass.json",
    "faults/F10_artifact_substitution.manifest.json",
  ]) {
    assert.ok(statSync(join(scenarioRoot, relativePath)).isFile(), relativePath);
  }
});

function findManifestPaths(root: string): string[] {
  const paths: string[] = [];
  for (const entry of readdirSync(root)) {
    const fullPath = join(root, entry);
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      paths.push(...findManifestPaths(fullPath));
    } else if (entry === "manifest.json" || entry.endsWith(".manifest.json")) {
      paths.push(fullPath);
    }
  }
  return paths;
}
