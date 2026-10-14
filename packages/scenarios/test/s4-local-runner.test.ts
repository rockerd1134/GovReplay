import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { verifyAttestationSetLevel1 } from "../../attestations/src/verifier.ts";
import { runS4LocalHappyPath } from "../src/s4-local-runner.ts";

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const scenarioRoot = join(packageRoot, "examples", "scenarios", "S4_policy_gated_deployment");
const outputRoot = join(packageRoot, ".tmp", "test-runs", "scenarios", "s4-local");

test("S4 local happy path emits deployment-centered lifecycle outputs", async () => {
  rmSync(outputRoot, { recursive: true, force: true });

  const result = await runS4LocalHappyPath({ scenarioRoot, outputRoot });

  assert.equal(result.manifest.workflow_id, "wf-S4-P3-F0-0001");
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
    "attestation_index",
    "local_replay_fixture",
    "deployment_backward_chain",
  ]) {
    assert.ok(existsSync(result.files[name]), `${name} output should exist`);
  }

  const deployment = JSON.parse(readFileSync(result.files.deployment, "utf8"));
  assert.equal(deployment.deployment_id, "deployment-S4-0001");
  assert.equal(deployment.approved_artifact_digest.value, deployment.deployed_artifact_digest.value);
  assert.equal(deployment.ledger_anchor.status, "required_for_govreplay_besu");

  const policyDecision = JSON.parse(readFileSync(result.files.policy_decision, "utf8"));
  assert.equal(policyDecision.policy_version, "P3");
  assert.equal(policyDecision.gateway_state, "POLICY_ALLOWED_DEPLOYMENT_APPROVAL_REQUIRED");
});

test("S4 local happy path emits signed attestations and backward replay fixture", async () => {
  rmSync(outputRoot, { recursive: true, force: true });

  const result = await runS4LocalHappyPath({ scenarioRoot, outputRoot });
  const index = JSON.parse(readFileSync(result.files.attestation_index, "utf8"));
  const replayFixture = JSON.parse(readFileSync(result.files.local_replay_fixture, "utf8"));
  const backwardFixture = JSON.parse(readFileSync(result.files.deployment_backward_chain, "utf8"));

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
  assert.equal(replayFixture.start.kind, "deployment_id");
  assert.equal(replayFixture.start.value, "deployment-S4-0001");
  assert.equal(replayFixture.start.deployment_attestation_hash, result.attestations[6].attestation_hash);
  assert.deepEqual(
    backwardFixture.expected_backward_chain.map((entry: { attestation_type: string }) => entry.attestation_type),
    [
      "DeploymentAttestation",
      "ArtifactAttestation",
      "ApprovalAttestation",
      "AgentActionAttestation",
      "PolicyDecisionAttestation",
      "EvidenceBundleAttestation",
      "ObservationAttestation",
    ],
  );

  const reports = await verifyAttestationSetLevel1(result.attestations, { index, runRoot: outputRoot });
  for (const report of reports) {
    assert.equal(report.status, "PASS", JSON.stringify(report));
    assert.deepEqual(report.failure_codes, []);
  }
});

test("S4 local replay fixture and attestation index are deterministic across repeated runs", async () => {
  rmSync(outputRoot, { recursive: true, force: true });

  const first = await runS4LocalHappyPath({ scenarioRoot, outputRoot });
  const firstIndex = readFileSync(first.files.attestation_index, "utf8");
  const firstFixture = readFileSync(first.files.deployment_backward_chain, "utf8");
  const firstHashes = first.attestations.map((attestation) => attestation.attestation_hash);

  const second = await runS4LocalHappyPath({ scenarioRoot, outputRoot });
  const secondIndex = readFileSync(second.files.attestation_index, "utf8");
  const secondFixture = readFileSync(second.files.deployment_backward_chain, "utf8");
  const secondHashes = second.attestations.map((attestation) => attestation.attestation_hash);

  assert.equal(secondIndex, firstIndex);
  assert.equal(secondFixture, firstFixture);
  assert.deepEqual(secondHashes, firstHashes);
});
