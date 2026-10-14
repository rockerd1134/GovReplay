import { join } from "node:path";
import { argv, env } from "node:process";
import { runGenericLocalScenario, standardApprovalChecks, type LocalRunResult } from "./generic-local-runner.ts";

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const defaultScenarioRoot = join(packageRoot, "examples", "scenarios", "S2_configuration_change");
const defaultRunRoot = join(packageRoot, "runs", "scenarios");

export async function runS2LocalScenario(options: {
  scenarioRoot?: string;
  manifestPath?: string;
  outputRoot?: string;
} = {}): Promise<LocalRunResult> {
  const scenarioRoot = options.scenarioRoot ?? defaultScenarioRoot;
  return runGenericLocalScenario({
    scenarioRoot,
    manifestPath: options.manifestPath,
    outputRoot: options.outputRoot ?? join(defaultRunRoot, "wf-S2-P2-F0-0001"),
    expectedScenarioId: "S2_configuration_change",
    supportedFaults: ["F0", "F8"],
    timestamps: [
      "2026-06-21T01:00:00Z",
      "2026-06-21T01:01:00Z",
      "2026-06-21T01:02:00Z",
      "2026-06-21T01:03:00Z",
      "2026-06-21T01:04:00Z",
      "2026-06-21T01:05:00Z",
      "2026-06-21T01:06:00Z",
    ],
    actors: {
      primary: {
        actor_id: "agent.config_operator",
        actor_type: "agent",
        private_key: "0x0000000000000000000000000000000000000000000000000000000000000006",
      },
      policy: {
        actor_id: "system.policy_service",
        actor_type: "service",
        private_key: "0x0000000000000000000000000000000000000000000000000000000000000003",
      },
      approver: {
        actor_id: "human.reviewer.blair",
        actor_type: "human",
        private_key: "0x0000000000000000000000000000000000000000000000000000000000000007",
      },
      deployer: {
        actor_id: "service.config_deployer",
        actor_type: "service",
        private_key: "0x0000000000000000000000000000000000000000000000000000000000000008",
      },
    },
    policy: {
      id: "govprov:policy:software-delivery-p2-strict-approval",
      version: "P2",
      ref: "policy-bundles/P2",
      hashSeed: "govprov-policy-bundle-P2-fixture",
    },
    ids: {
      observation: "obs-S2-0001",
      evidence: "evidence-S2-0001",
      policyDecision: "policy-decision-S2-0001",
      action: "action-S2-0001",
      approval: "approval-S2-0001",
      artifact: "artifact-S2-0001",
      deployment: "deployment-S2-0001",
    },
    files: {
      evidence: ["evidence/alert_summary.json", "input/config_diff.patch"],
      artifact: "expected/config_patch.yaml",
      expectedDeployment: "expected/deployment_manifest.json",
    },
    action: {
      type: "propose_config_change",
      proposedArtifactPath: "expected/config_patch.yaml",
    },
    artifact: {
      type: "configuration_patch",
    },
    approval: {
      role: "CONFIG_APPROVER",
      secondApproverActorId: "human.security.casey",
    },
    expected: {
      scope: "P5-S7 S2 approval separation fixture",
      replayBoundary: "Verifies deterministic approval role and separation records without Besu ledger queries.",
      faultScope: "P5-S7 S2 approval separation fault fixture",
    },
    buildPolicyObligations: ({ evidenceBundleId, artifactId }) => [
      {
        obligation_type: "operational_signal_required",
        status: "satisfied",
        evidence_bundle_id: evidenceBundleId,
      },
      {
        obligation_type: "two_config_approvals_required",
        status: "satisfied",
        approval_role: "CONFIG_APPROVER",
      },
      {
        obligation_type: "approved_artifact_link_required",
        status: "satisfied",
        artifact_id: artifactId,
      },
    ],
    buildFaultChecks: standardApprovalChecks,
  });
}

if (argv[1]?.endsWith("s2-local-runner.ts")) {
  const result = await runS2LocalScenario({
    outputRoot: env.GOVPROV_S2_LOCAL_OUTPUT,
  });
  console.log(JSON.stringify({
    workflow_id: result.manifest.workflow_id,
    output_root: result.outputRoot,
    event_count: result.events.length,
    attestation_count: result.attestations.length,
    verdict: result.localVerification.verdict,
  }, null, 2));
}
