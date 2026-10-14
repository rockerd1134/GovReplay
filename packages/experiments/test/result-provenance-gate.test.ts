import assert from "node:assert/strict";
import { test } from "node:test";
import { runResultProvenanceGate } from "../src/resultProvenanceGate.ts";

test("PX-S38 result provenance gate is green after observed policy-decision repair", async () => {
  const report = await runResultProvenanceGate({ runExperimentProbe: true });

  assert.equal(report.schema_version, "govreplay.result_provenance_gate.v1");
  assert.equal(report.status, "PASS");
  assert.deepEqual(report.checks.map((check) => check.id), [
    "PX-S33-1",
    "PX-S33-2",
    "PX-S33-3",
    "PX-S33-4",
    "PX-S33-5",
    "PX-S33-6",
    "PX-S33-7",
  ]);

  const byId = Object.fromEntries(report.checks.map((check) => [check.id, check]));
  assert.equal(byId["PX-S33-1"].status, "PASS");
  assert.ok(byId["PX-S33-1"].detail.includes("no longer matches"));
  assert.equal(byId["PX-S33-2"].status, "PASS");
  assert.ok(byId["PX-S33-2"].detail.includes("do not expose"));
  assert.equal(byId["PX-S33-3"].status, "PASS");
  assert.ok(byId["PX-S33-3"].detail.includes("observed verifier provenance"));
  assert.equal(byId["PX-S33-4"].status, "PASS");
  assert.ok(byId["PX-S33-4"].detail.includes("observed live verifier rows"));
  assert.equal(byId["PX-S33-5"].status, "PASS");
  assert.ok(byId["PX-S33-5"].detail.includes("generator fault label"));
  assert.equal(byId["PX-S33-6"].status, "PASS");
  assert.ok(byId["PX-S33-6"].detail.includes("do not show expected-label-derived decisions"));
  assert.equal(byId["PX-S33-7"].status, "PASS");
  assert.ok(byId["PX-S33-7"].evidence.some((line) => line.includes("paper-arpe-full includes arpe_hash_only_ablation_hard_debug.json: true")));
});
