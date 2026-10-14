import { join } from "node:path";
import { argv, env } from "node:process";
import { runGenericLocalScenario, standardApprovalChecks, type LocalRunResult } from "./generic-local-runner.ts";

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const defaultScenarioRoot = join(packageRoot, "examples", "scenarios", "S3_patch_proposal");
const defaultRunRoot = join(packageRoot, "runs", "scenarios");

export async function runS3LocalScenario(options: {
  scenarioRoot?: string;
  manifestPath?: string;
  outputRoot?: string;
} = {}): Promise<LocalRunResult> {
  const scenarioRoot = options.scenarioRoot ?? defaultScenarioRoot;
  return runGenericLocalScenario({
    scenarioRoot,
    manifestPath: options.manifestPath,
    outputRoot: options.outputRoot ?? join(defaultRunRoot, "wf-S3-P3-F0-0001"),
    expectedScenarioId: "S3_patch_proposal",
    supportedFaults: ["F0", "F10"],
    timestamps: [
      "2026-06-21T02:00:00Z",
      "2026-06-21T02:01:00Z",
      "2026-06-21T02:02:00Z",
      "2026-06-21T02:03:00Z",
      "2026-06-21T02:04:00Z",
      "2026-06-21T02:05:00Z",
      "2026-06-21T02:06:00Z",
    ],
    actors: {
      primary: {
        actor_id: "agent.patch_author",
        actor_type: "agent",
        private_key: "0x0000000000000000000000000000000000000000000000000000000000000009",
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
        actor_id: "service.patch_stager",
        actor_type: "service",
        private_key: "0x000000000000000000000000000000000000000000000000000000000000000a",
      },
    },
    policy: {
      id: "govprov:policy:software-delivery-p3-evidence-strengthened",
      version: "P3",
      ref: "policy-bundles/P3",
      hashSeed: "govprov-policy-bundle-P3-fixture",
    },
    ids: {
      observation: "obs-S3-0001",
      evidence: "evidence-S3-0001",
      policyDecision: "policy-decision-S3-0001",
      action: "action-S3-0001",
      approval: "approval-S3-0001",
      artifact: "artifact-S3-0001",
      deployment: "deployment-S3-0001",
    },
    files: {
      evidence: ["evidence/issue_report.json", "evidence/test_report.json", "input/retry_edge_case.patch"],
      artifact: "input/retry_edge_case.patch",
      expectedDeployment: "expected/deployment_manifest.json",
    },
    action: {
      type: "propose_patch",
      proposedArtifactPath: "input/retry_edge_case.patch",
    },
    artifact: {
      type: "source_patch",
    },
    approval: {
      role: "CODE_APPROVER",
    },
    expected: {
      scope: "P5-S8 S3 patch supply-chain fixture",
      replayBoundary: "Verifies patch, issue, test evidence, approval, and deployment readiness without Besu ledger queries.",
      faultScope: "P5-S8 S3 artifact substitution fault fixture",
    },
    buildPolicyObligations: ({ evidenceBundleId, artifactId }) => [
      {
        obligation_type: "issue_evidence_required",
        status: "satisfied",
        evidence_bundle_id: evidenceBundleId,
      },
      {
        obligation_type: "test_report_references_patch_required",
        status: "satisfied",
        artifact_id: artifactId,
      },
      {
        obligation_type: "code_reviewer_approval_required",
        status: "satisfied",
        approval_role: "CODE_APPROVER",
      },
    ],
    buildFaultChecks: standardApprovalChecks,
  });
}

if (argv[1]?.endsWith("s3-local-runner.ts")) {
  const result = await runS3LocalScenario({
    outputRoot: env.GOVPROV_S3_LOCAL_OUTPUT,
  });
  console.log(JSON.stringify({
    workflow_id: result.manifest.workflow_id,
    output_root: result.outputRoot,
    event_count: result.events.length,
    attestation_count: result.attestations.length,
    verdict: result.localVerification.verdict,
  }, null, 2));
}
