import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { runS1LocalHappyPath } from "../../scenarios/src/s1-local-runner.ts";
import { runS2LocalScenario } from "../../scenarios/src/s2-local-runner.ts";
import { runS3LocalScenario } from "../../scenarios/src/s3-local-runner.ts";
import { runS4LocalHappyPath } from "../../scenarios/src/s4-local-runner.ts";
import { generateScenarioUiFixtures } from "../../scenarios/src/ui-fixtures.ts";
import { replayAudit } from "../src/replay.ts";

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const outputRoot = join(packageRoot, ".tmp", "test-runs", "audit-replay");
const scenariosRoot = join(packageRoot, "examples", "scenarios");
const s1Root = join(scenariosRoot, "S1_runbook_update");
const s2Root = join(scenariosRoot, "S2_configuration_change");
const s3Root = join(scenariosRoot, "S3_patch_proposal");
const s4Root = join(scenariosRoot, "S4_policy_gated_deployment");

test("P6-S1 traverses S4 deployment backward and S1 simple chain", async () => {
  resetOutput();
  const s4 = await runS4LocalHappyPath({ scenarioRoot: s4Root, outputRoot: join(outputRoot, "s4") });
  const s1 = await runS1LocalHappyPath({ scenarioRoot: s1Root, outputRoot: join(outputRoot, "s1") });

  const s4Report = await replayAudit({
    runRoot: s4.outputRoot,
    input: { type: "deployment_id", value: "deployment-S4-0001" },
    scenarioRoot: s4Root,
  });
  assert.equal(s4Report.verdict, "PASS");
  assert.deepEqual(
    s4Report.nodes.map((node) => node.attestation_type),
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
  assert.equal(s4Report.reconstructed_links.deployment, true);
  assert.equal(s4Report.reconstructed_links.observation, true);

  const s1DeploymentHash = s1.attestations.find((item) => item.attestation_type === "DeploymentAttestation")?.attestation_hash;
  assert.ok(s1DeploymentHash);
  const s1Report = await replayAudit({
    runRoot: s1.outputRoot,
    input: { type: "attestation_hash", value: s1DeploymentHash },
    scenarioRoot: s1Root,
  });
  assert.equal(s1Report.verdict, "PASS");
  assert.equal(s1Report.nodes.length, 7);
});

test("P6-S1 reports incomplete lineage for a broken parent link", async () => {
  resetOutput();
  const s4 = await runS4LocalHappyPath({ scenarioRoot: s4Root, outputRoot: join(outputRoot, "s4-broken") });
  const indexPath = join(s4.outputRoot, "manifests", "attestation_index.json");
  const index = JSON.parse(readFileSync(indexPath, "utf8"));
  const approval = index.attestations.find((item: { attestation_type: string }) => item.attestation_type === "ApprovalAttestation");
  assert.ok(approval);
  rmSync(join(s4.outputRoot, approval.path), { force: true });

  const report = await replayAudit({
    runRoot: s4.outputRoot,
    input: { type: "deployment_id", value: "deployment-S4-0001" },
    scenarioRoot: s4Root,
  });
  assert.equal(report.verdict, "INCOMPLETE");
  assert.equal(report.failure_code, "F_LINK_MISSING");
  assert.ok(report.checks.some((check) => check.code === "F_HASH_OBJECT_MISMATCH" || check.code === "F_LINK_MISSING"));
});

test("P6-S2 detects S3 F10 artifact and deployment digest mismatch", async () => {
  resetOutput();
  const result = await runS3LocalScenario({
    scenarioRoot: s3Root,
    manifestPath: join(s3Root, "faults", "F10_artifact_substitution.manifest.json"),
    outputRoot: join(outputRoot, "s3-f10"),
  });

  const report = await replayAudit({
    runRoot: result.outputRoot,
    input: { type: "deployment_id", value: "deployment-S3-0001" },
    scenarioRoot: s3Root,
  });
  assert.equal(report.verdict, "FAIL");
  assert.equal(report.failure_code, "F_DEPLOYMENT_ARTIFACT_MISMATCH");
  assert.equal(report.failure_stage, "deployment");
  assert.equal(report.metrics.hash_mismatches, 1);
});

test("P6-S3 classifies policy compliance fields without hiding historical failure", async () => {
  resetOutput();
  const result = await runS3LocalScenario({
    scenarioRoot: s3Root,
    manifestPath: join(s3Root, "faults", "F10_artifact_substitution.manifest.json"),
    outputRoot: join(outputRoot, "s3-policy"),
  });

  const report = await replayAudit({
    runRoot: result.outputRoot,
    input: { type: "workflow_id", value: "wf-S3-P3-F10-0001" },
    scenarioRoot: s3Root,
    currentPolicyVersion: "P3",
  });
  assert.equal(report.historical_compliance, "fail");
  assert.equal(report.current_policy_compliance, "fail");
  assert.equal(report.policy_drift, false);
  assert.ok(report.checks.some((check) => check.name === "historical_policy_decision_recompute"));
});

test("P6-S4 detects S2 F8 separation-of-duties approval failure", async () => {
  resetOutput();
  const result = await runS2LocalScenario({
    scenarioRoot: s2Root,
    manifestPath: join(s2Root, "faults", "F8_separation_of_duties.manifest.json"),
    outputRoot: join(outputRoot, "s2-f8"),
  });

  const report = await replayAudit({
    runRoot: result.outputRoot,
    input: { type: "action_id", value: "action-S2-0001" },
    scenarioRoot: s2Root,
  });
  assert.equal(report.verdict, "FAIL");
  assert.equal(report.failure_code, "F_APPROVAL_SOD");
  assert.equal(report.failure_stage, "approval");
});

test("P6-S5 validates ledger sidecar hashes for S4 Besu state", async () => {
  resetOutput();
  const result = await runS4LocalHappyPath({ scenarioRoot: s4Root, outputRoot: join(outputRoot, "s4-ledger") });
  const ledgerSidecarPath = join(outputRoot, "s4-ledger-sidecar.json");
  const hashes = Object.fromEntries(result.attestations.map((item) => [item.attestation_type, item.attestation_hash]));
  const sidecar = {
    schema_version: "govprov.s4_besu_run.v1",
    scenario_id: "S4_policy_gated_deployment",
    workflow_id: "wf-S4-P3-F0-0001",
    mode: "govreplay_besu",
    readback_ok: true,
    observation_attestation_hash: hashes.ObservationAttestation,
    evidence_attestation_hash: hashes.EvidenceBundleAttestation,
    policy_decision_attestation_hash: hashes.PolicyDecisionAttestation,
    action_attestation_hash: hashes.AgentActionAttestation,
    approval_attestation_hash: hashes.ApprovalAttestation,
    artifact_attestation_hash: hashes.ArtifactAttestation,
    deployment_attestation_hash: hashes.DeploymentAttestation,
  };
  await import("node:fs").then(({ writeFileSync }) => writeFileSync(ledgerSidecarPath, `${JSON.stringify(sidecar, null, 2)}\n`));

  const report = await replayAudit({
    runRoot: result.outputRoot,
    input: { type: "deployment_id", value: "deployment-S4-0001" },
    scenarioRoot: s4Root,
    ledgerSidecarPath,
  });
  assert.equal(report.verdict, "PASS");
  assert.equal(report.system_configuration, "govreplay_besu");
  assert.equal(report.reconstructed_links.ledger_anchor, true);
  assert.ok(report.metrics.ledger_queries > 0);
});

test("P6-S6 emits stable JSONL and Markdown reports", async () => {
  resetOutput();
  const result = await runS4LocalHappyPath({ scenarioRoot: s4Root, outputRoot: join(outputRoot, "s4-report") });
  const reportDir = join(result.outputRoot, "audit_reports");

  const report = await replayAudit({
    runRoot: result.outputRoot,
    input: { type: "deployment_id", value: "deployment-S4-0001" },
    scenarioRoot: s4Root,
    reportDir,
  });
  assert.equal(report.verdict, "PASS");
  const jsonl = join(reportDir, "audit_results.jsonl");
  const markdown = join(reportDir, "audit_wf-S4-P3-F0-0001.md");
  assert.equal(existsSync(jsonl), true);
  assert.equal(existsSync(markdown), true);
  assert.equal(JSON.parse(readFileSync(jsonl, "utf8")).workflow_id, "wf-S4-P3-F0-0001");
  assert.match(readFileSync(markdown, "utf8"), /# Audit Replay wf-S4-P3-F0-0001/);
});

test("P6-S7 accepts generated UI fixture bundle as replay input compatibility signal", async () => {
  resetOutput();
  const { outputPath } = await generateScenarioUiFixtures({
    outputRoot: join(outputRoot, "ui"),
    runRoot: join(outputRoot, "ui-runs"),
  });
  const bundle = JSON.parse(readFileSync(outputPath, "utf8"));
  assert.ok(Array.isArray(bundle.scenarios));
  assert.ok(bundle.scenarios.some((row: { scenario_id: string }) => row.scenario_id === "S4_policy_gated_deployment"));
  assert.ok(bundle.scenarios.some((row: { failure_code: string }) => row.failure_code === "separation_of_duties_violation"));
  assert.ok(bundle.scenarios.some((row: { failure_code: string }) => row.failure_code === "artifact_hash_mismatch"));
});

function resetOutput(): void {
  rmSync(outputRoot, { recursive: true, force: true });
}
