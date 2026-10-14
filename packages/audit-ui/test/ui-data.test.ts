import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parseExperimentConfig } from "../../experiments/src/config.ts";
import { runExperiment } from "../../experiments/src/runner.ts";
import { buildUiData, writeUiData } from "../src/ui-data.ts";

const experimentsRoot = join(import.meta.dirname, "..", "..", "experiments");

test("P8-S1 normalizes a Phase 7 debug run into the UI data contract", async () => {
  const config = parseExperimentConfig(join(experimentsRoot, "configs", "debug.json"));
  const tempRoot = mkdtempSync(join(tmpdir(), "govprov-p8-"));
  const result = await runExperiment({ ...config, run_id: "phase8-ui-contract" }, { packageRoot: tempRoot });
  const data = buildUiData([result.runRoot], { generatedAt: "2026-06-21T00:00:00.000Z" });

  assert.equal(data.schema_version, "govprov.audit_ui_data.v1");
  assert.equal(data.runs[0].workflow_count, 60);
  assert.equal(data.runs[0].scenario_count, 4);
  assert.equal(data.metrics["phase8-ui-contract"].configurations.length, 5);
  assert.equal(data.replays.length, 60);
  assert.ok(data.faults.some((item) => item.fault_id === "F10" && item.actual_failure_code === "artifact_hash_mismatch"));
});

test("P8-S2 through P8-S5 provide view-ready summaries and demo selections", async () => {
  const config = parseExperimentConfig(join(experimentsRoot, "configs", "minimum.json"));
  const tempRoot = mkdtempSync(join(tmpdir(), "govprov-p8-"));
  const result = await runExperiment({ ...config, run_id: "phase8-ui-minimum" }, { packageRoot: tempRoot });
  const data = buildUiData([result.runRoot], { generatedAt: "2026-06-21T00:00:00.000Z" });

  assert.deepEqual(data.demos.map((item) => item.demo_id), [
    "demo_happy_deploy",
    "demo_policy_drift",
    "demo_artifact_substitution",
    "demo_separation_duties",
  ]);
  const replay = data.replays.find((item) => item.fault_id === "F10" && item.system_configuration === "govreplay_besu");
  assert.ok(replay);
  assert.ok(replay.lifecycle.some((node) => node.key === "artifact" && node.verification_verdict === "FAIL"));
  assert.ok(data.faults.some((item) => item.fault_id === "F8" && item.localization_status === "match"));
  assert.ok(data.faults.some((item) => item.fault_id === "F10" && item.actual_failure_code === "artifact_hash_mismatch"));
  assert.ok(data.faults.some((item) => item.fault_id === "F12"));
  const metrics = data.metrics["phase8-ui-minimum"].configurations.find((item) => item.configuration === "govreplay_besu");
  assert.equal(metrics?.recall, 1);
  // Adapter fidelity, not an assumed perfect result in the historical workload.
  const sourceMetrics = JSON.parse(readFileSync(join(result.runRoot, "results", "metrics_summary.json"), "utf8"));
  const source = sourceMetrics.configurations.find((item: any) => item.configuration === "govreplay_besu");
  assert.equal(metrics?.reconstruction_completeness, source.reconstruction_completeness);
});

test("P8 adapter writes machine-readable data for the static UI", async () => {
  const config = parseExperimentConfig(join(experimentsRoot, "configs", "debug.json"));
  const tempRoot = mkdtempSync(join(tmpdir(), "govprov-p8-"));
  const result = await runExperiment({ ...config, run_id: "phase8-ui-file" }, { packageRoot: tempRoot });
  const out = join(tempRoot, "ui-data.json");
  writeUiData(out, buildUiData([result.runRoot], { generatedAt: "2026-06-21T00:00:00.000Z" }));

  assert.ok(existsSync(out));
  const data = JSON.parse(readFileSync(out, "utf8"));
  assert.equal(data.runs[0].run_id, "phase8-ui-file");
});
