import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { generateScenarioUiFixtures } from "../src/ui-fixtures.ts";

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const outputRoot = join(packageRoot, ".tmp", "test-runs", "scenario-ui-fixtures");
const runRoot = join(packageRoot, ".tmp", "test-runs", "scenario-ui-fixture-runs");

test("scenario UI fixture bundle summarizes implemented scenario runs", async () => {
  rmSync(outputRoot, { recursive: true, force: true });
  rmSync(runRoot, { recursive: true, force: true });

  const result = await generateScenarioUiFixtures({ outputRoot, runRoot });
  const bundle = JSON.parse(readFileSync(result.outputPath, "utf8"));

  assert.ok(existsSync(result.outputPath));
  assert.equal(bundle.schema_version, "govprov.scenario_ui_fixture_bundle.v1");
  assert.equal(bundle.scenarios.length, 7);
  assert.deepEqual(
    bundle.scenarios.map((scenario: { workflow_id: string }) => scenario.workflow_id),
    [
      "wf-S1-P1-F0-0001",
      "wf-S1-P1-F10-0001",
      "wf-S2-P2-F0-0001",
      "wf-S2-P2-F8-0001",
      "wf-S3-P3-F0-0001",
      "wf-S3-P3-F10-0001",
      "wf-S4-P3-F0-0001",
    ],
  );

  const s2Fault = bundle.scenarios.find((scenario: { workflow_id: string }) => scenario.workflow_id === "wf-S2-P2-F8-0001");
  assert.equal(s2Fault.failure_code, "separation_of_duties_violation");
  assert.equal(s2Fault.failure_stage, "approval");
  assert.equal(s2Fault.approval_summary.separation_of_duties, "violated");

  const s3Fault = bundle.scenarios.find((scenario: { workflow_id: string }) => scenario.workflow_id === "wf-S3-P3-F10-0001");
  assert.equal(s3Fault.failure_code, "artifact_hash_mismatch");
  assert.equal(s3Fault.artifact_summary.digest_match, false);
});
