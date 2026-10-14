import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { runS1LocalHappyPath, runS1LocalScenario } from "../src/s1-local-runner.ts";
import { verifyAttestationSetLevel1 } from "../../attestations/src/verifier.ts";

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const scenarioRoot = join(packageRoot, "examples", "scenarios", "S1_runbook_update");
const outputRoot = join(packageRoot, ".tmp", "test-runs", "scenarios", "s1-local");

test("S1 local happy path emits deterministic lifecycle outputs", async () => {
  rmSync(outputRoot, { recursive: true, force: true });

  const result = await runS1LocalHappyPath({ scenarioRoot, outputRoot });

  assert.equal(result.manifest.workflow_id, "wf-S1-P1-F0-0001");
  assert.deepEqual(
    result.events.map((event) => event.stage),
    ["observation", "evidence", "policy", "action", "approval", "artifact", "deployment"],
  );
  assert.deepEqual(
    result.events.map((event) => event.sequence),
    [1, 2, 3, 4, 5, 6, 7],
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
    "attestation_index",
    "local_replay_fixture",
    "local_fault_replay",
  ]) {
    assert.ok(existsSync(result.files[name]), `${name} output should exist`);
  }

  const baselineLines = readFileSync(result.files.baseline_logs, "utf8").trim().split("\n");
  assert.equal(baselineLines.length, 7);
  assert.equal(JSON.parse(baselineLines[0]).event_type, "observation_recorded");
  assert.equal(JSON.parse(baselineLines[6]).event_type, "deployment_published");

  const evidenceBundle = JSON.parse(readFileSync(result.files.evidence_bundle, "utf8"));
  assert.deepEqual(
    evidenceBundle.evidence.map((item: { path: string }) => item.path),
    [
      "evidence/incident_report.md",
      "evidence/service_log_excerpt.txt",
      "evidence/support_ticket.json",
      "input/current_runbook.md",
    ],
  );

  const policyDecision = JSON.parse(readFileSync(result.files.policy_decision, "utf8"));
  assert.equal(policyDecision.decision, "allow");
  assert.equal(policyDecision.gateway_state, "POLICY_ALLOWED_APPROVAL_REQUIRED");

  const deployment = JSON.parse(readFileSync(result.files.deployment, "utf8"));
  assert.equal(deployment.status, "published");
  assert.equal(deployment.ledger_anchor, null);
  assert.equal(result.localVerification.verdict, "pass");
  assert.equal(result.localVerification.failure_code, null);
});

test("S1 local happy path emits a signed attestation chain for local replay", async () => {
  rmSync(outputRoot, { recursive: true, force: true });

  const result = await runS1LocalHappyPath({ scenarioRoot, outputRoot });
  const index = JSON.parse(readFileSync(result.files.attestation_index, "utf8"));
  const replayFixture = JSON.parse(readFileSync(result.files.local_replay_fixture, "utf8"));

  assert.deepEqual(
    result.attestations.map((attestation) => attestation.attestation_type),
    [
      "ObservationAttestation",
      "EvidenceBundleAttestation",
      "PolicyDecisionAttestation",
      "AgentActionAttestation",
      "ApprovalAttestation",
      "ArtifactAttestation",
      "DeploymentAttestation",
    ],
  );
  assert.equal(index.attestation_count, "7");
  assert.equal(replayFixture.start.kind, "deployment_attestation_hash");
  assert.equal(replayFixture.start.value, result.attestations[6].attestation_hash);
  assert.equal(replayFixture.boundary.includes("without Besu ledger queries"), true);

  const reports = await verifyAttestationSetLevel1(result.attestations, { index, runRoot: outputRoot });
  for (const report of reports) {
    assert.equal(report.status, "PASS", JSON.stringify(report));
    assert.deepEqual(report.failure_codes, []);
  }
});

test("S1 local fault subset emits deterministic failure localization", async () => {
  const cases = [
    {
      manifest: "faults/F1_missing_evidence.manifest.json",
      workflow: "wf-S1-P1-F1-0001",
      code: "evidence_missing",
      stage: "evidence",
      attestationCount: 7,
    },
    {
      manifest: "faults/F2_evidence_tampered.manifest.json",
      workflow: "wf-S1-P1-F2-0001",
      code: "evidence_hash_mismatch",
      stage: "evidence",
      attestationCount: 7,
    },
    {
      manifest: "faults/F6_missing_approval.manifest.json",
      workflow: "wf-S1-P1-F6-0001",
      code: "approval_missing",
      stage: "approval",
      attestationCount: 6,
    },
    {
      manifest: "faults/F10_artifact_substitution.manifest.json",
      workflow: "wf-S1-P1-F10-0001",
      code: "artifact_hash_mismatch",
      stage: "artifact_deployment",
      attestationCount: 7,
    },
  ] as const;

  for (const item of cases) {
    const runRoot = join(outputRoot, item.workflow);
    rmSync(runRoot, { recursive: true, force: true });

    const result = await runS1LocalScenario({
      scenarioRoot,
      manifestPath: join(scenarioRoot, item.manifest),
      outputRoot: runRoot,
    });
    const report = JSON.parse(readFileSync(result.files.local_fault_replay, "utf8"));

    assert.equal(result.manifest.workflow_id, item.workflow);
    assert.equal(result.localVerification.verdict, "fail");
    assert.equal(result.localVerification.failure_code, item.code);
    assert.equal(result.localVerification.failure_stage, item.stage);
    assert.equal(report.failure_code, item.code);
    assert.equal(report.expected_failure_code, item.code);
    assert.equal(result.attestations.length, item.attestationCount);

    const reports = await verifyAttestationSetLevel1(result.attestations, {
      index: JSON.parse(readFileSync(result.files.attestation_index, "utf8")),
      runRoot,
    });
    for (const verification of reports) {
      assert.equal(verification.status, "PASS", JSON.stringify(verification));
    }
  }
});

test("S1 local replay fixture and attestation index are deterministic across repeated runs", async () => {
  rmSync(outputRoot, { recursive: true, force: true });

  const first = await runS1LocalHappyPath({ scenarioRoot, outputRoot });
  const firstIndex = readFileSync(first.files.attestation_index, "utf8");
  const firstFixture = readFileSync(first.files.local_replay_fixture, "utf8");
  const firstHashes = first.attestations.map((attestation) => attestation.attestation_hash);

  const second = await runS1LocalHappyPath({ scenarioRoot, outputRoot });
  const secondIndex = readFileSync(second.files.attestation_index, "utf8");
  const secondFixture = readFileSync(second.files.local_replay_fixture, "utf8");
  const secondHashes = second.attestations.map((attestation) => attestation.attestation_hash);

  assert.equal(secondIndex, firstIndex);
  assert.equal(secondFixture, firstFixture);
  assert.deepEqual(secondHashes, firstHashes);
});
