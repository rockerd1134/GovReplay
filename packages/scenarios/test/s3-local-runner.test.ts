import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { verifyAttestationSetLevel1 } from "../../attestations/src/verifier.ts";
import { runS3LocalScenario } from "../src/s3-local-runner.ts";

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const scenarioRoot = join(packageRoot, "examples", "scenarios", "S3_patch_proposal");
const outputRoot = join(packageRoot, ".tmp", "test-runs", "scenarios", "s3-local");

test("S3 local happy path links patch artifact and test evidence", async () => {
  rmSync(outputRoot, { recursive: true, force: true });

  const result = await runS3LocalScenario({ scenarioRoot, outputRoot });

  assert.equal(result.manifest.workflow_id, "wf-S3-P3-F0-0001");
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

  const evidence = JSON.parse(readFileSync(result.files.evidence_bundle, "utf8"));
  assert.deepEqual(
    evidence.evidence.map((item: { path: string }) => item.path),
    ["evidence/issue_report.json", "evidence/test_report.json", "input/retry_edge_case.patch"],
  );

  const artifact = JSON.parse(readFileSync(result.files.artifact, "utf8"));
  assert.equal(artifact.artifact_type, "source_patch");

  const deployment = JSON.parse(readFileSync(result.files.deployment, "utf8"));
  assert.equal(deployment.approved_artifact_digest.value, deployment.deployed_artifact_digest.value);
  assert.equal(result.localVerification.verdict, "pass");
});

test("S3 local fault localizes artifact substitution", async () => {
  const runRoot = join(outputRoot, "wf-S3-P3-F10-0001");
  rmSync(runRoot, { recursive: true, force: true });

  const result = await runS3LocalScenario({
    scenarioRoot,
    manifestPath: join(scenarioRoot, "faults", "F10_artifact_substitution.manifest.json"),
    outputRoot: runRoot,
  });
  const report = JSON.parse(readFileSync(result.files.local_fault_replay, "utf8"));
  const deployment = JSON.parse(readFileSync(result.files.deployment, "utf8"));

  assert.equal(result.manifest.workflow_id, "wf-S3-P3-F10-0001");
  assert.equal(result.localVerification.verdict, "fail");
  assert.equal(result.localVerification.failure_code, "artifact_hash_mismatch");
  assert.equal(result.localVerification.failure_stage, "artifact_deployment");
  assert.equal(report.expected_failure_code, "artifact_hash_mismatch");
  assert.notEqual(deployment.approved_artifact_digest.value, deployment.deployed_artifact_digest.value);
});

test("S3 local signed attestations verify and stay deterministic", async () => {
  rmSync(outputRoot, { recursive: true, force: true });

  const first = await runS3LocalScenario({ scenarioRoot, outputRoot });
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

  const second = await runS3LocalScenario({ scenarioRoot, outputRoot });
  assert.equal(readFileSync(second.files.attestation_index, "utf8"), firstIndex);
  assert.equal(readFileSync(second.files.local_replay_fixture, "utf8"), firstFixture);
  assert.deepEqual(second.attestations.map((attestation) => attestation.attestation_hash), firstHashes);
});
