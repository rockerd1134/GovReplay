import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { verifyAttestationSetLevel1 } from "../../attestations/src/verifier.ts";
import { runS2LocalScenario } from "../src/s2-local-runner.ts";

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const scenarioRoot = join(packageRoot, "examples", "scenarios", "S2_configuration_change");
const outputRoot = join(packageRoot, ".tmp", "test-runs", "scenarios", "s2-local");

test("S2 local happy path emits approval governance lifecycle outputs", async () => {
  rmSync(outputRoot, { recursive: true, force: true });

  const result = await runS2LocalScenario({ scenarioRoot, outputRoot });

  assert.equal(result.manifest.workflow_id, "wf-S2-P2-F0-0001");
  assert.deepEqual(
    result.events.map((event) => event.stage),
    ["observation", "evidence", "policy", "action", "approval", "artifact", "deployment"],
  );

  for (const name of [
    "run_manifest",
    "observation",
    "evidence_bundle",
    "policy_decision",
    "action",
    "approval",
    "artifact",
    "deployment",
    "baseline_logs",
    "local_fault_replay",
    "attestation_index",
    "local_replay_fixture",
  ]) {
    assert.ok(existsSync(result.files[name]), `${name} output should exist`);
  }

  const approval = JSON.parse(readFileSync(result.files.approval, "utf8"));
  assert.equal(approval.approver_role, "CONFIG_APPROVER");
  assert.equal(approval.approver_actor_id, "human.reviewer.blair");
  assert.equal(approval.separation_of_duties, "satisfied");

  const policyDecision = JSON.parse(readFileSync(result.files.policy_decision, "utf8"));
  assert.equal(policyDecision.policy_version, "P2");
  assert.equal(policyDecision.obligations.some((item: { obligation_type: string }) => item.obligation_type === "two_config_approvals_required"), true);

  assert.equal(result.localVerification.verdict, "pass");
  assert.equal(result.localVerification.failure_code, null);
});

test("S2 local fault localizes separation-of-duties violation to approval stage", async () => {
  const runRoot = join(outputRoot, "wf-S2-P2-F8-0001");
  rmSync(runRoot, { recursive: true, force: true });

  const result = await runS2LocalScenario({
    scenarioRoot,
    manifestPath: join(scenarioRoot, "faults", "F8_separation_of_duties.manifest.json"),
    outputRoot: runRoot,
  });
  const report = JSON.parse(readFileSync(result.files.local_fault_replay, "utf8"));

  assert.equal(result.manifest.workflow_id, "wf-S2-P2-F8-0001");
  assert.equal(result.localVerification.verdict, "fail");
  assert.equal(result.localVerification.failure_code, "separation_of_duties_violation");
  assert.equal(result.localVerification.failure_stage, "approval");
  assert.equal(report.expected_failure_code, "separation_of_duties_violation");

  const approval = JSON.parse(readFileSync(result.files.approval, "utf8"));
  assert.equal(approval.approver_actor_id, "agent.config_operator");
  assert.equal(approval.separation_of_duties, "violated");
});

test("S2 local signed attestations verify and stay deterministic", async () => {
  rmSync(outputRoot, { recursive: true, force: true });

  const first = await runS2LocalScenario({ scenarioRoot, outputRoot });
  const firstIndex = readFileSync(first.files.attestation_index, "utf8");
  const firstFixture = readFileSync(first.files.local_replay_fixture, "utf8");
  const firstHashes = first.attestations.map((attestation) => attestation.attestation_hash);

  const reports = await verifyAttestationSetLevel1(first.attestations, {
    index: JSON.parse(firstIndex),
    runRoot: outputRoot,
  });
  for (const report of reports) {
    assert.equal(report.status, "PASS", JSON.stringify(report));
  }

  const second = await runS2LocalScenario({ scenarioRoot, outputRoot });
  assert.equal(readFileSync(second.files.attestation_index, "utf8"), firstIndex);
  assert.equal(readFileSync(second.files.local_replay_fixture, "utf8"), firstFixture);
  assert.deepEqual(second.attestations.map((attestation) => attestation.attestation_hash), firstHashes);
});
