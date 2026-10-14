// Research fixture/demo code: embedded keys are public synthetic test vectors.
// Never use these keys or this fixture signer for production accounts. See SECURITY.md.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { basename, join, relative } from "node:path";
import { argv, env } from "node:process";
import { canonicalJson } from "../../attestations/src/canonical-json.ts";
import { digestJson, sha256Hex, type DigestObject } from "../../attestations/src/digest.ts";
import { writeAttestationRunLayout } from "../../attestations/src/run-layout.ts";
import { addressFromPrivateKey, signAttestation, type SignedAttestation } from "../../attestations/src/signing.ts";
import { validateScenarioManifest, type ScenarioManifest } from "./manifest.ts";

type LifecycleStage =
  | "observation"
  | "evidence"
  | "policy"
  | "action"
  | "approval"
  | "artifact"
  | "deployment";

type LocalRunEvent = {
  sequence: number;
  stage: LifecycleStage;
  event_type: string;
  scenario_id: string;
  workflow_id: string;
  created_at: string;
  payload_digest: DigestObject;
  payload: Record<string, unknown>;
};

type S4LocalRunOptions = {
  scenarioRoot?: string;
  outputRoot?: string;
};

export type S4LocalRunResult = {
  outputRoot: string;
  manifest: ScenarioManifest;
  events: LocalRunEvent[];
  files: Record<string, string>;
  attestations: SignedAttestation[];
};

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const defaultScenarioRoot = join(packageRoot, "examples", "scenarios", "S4_policy_gated_deployment");
const defaultRunRoot = join(packageRoot, "runs", "scenarios");

const localTimestamps = [
  "2026-06-21T00:00:00Z",
  "2026-06-21T00:01:00Z",
  "2026-06-21T00:02:00Z",
  "2026-06-21T00:03:00Z",
  "2026-06-21T00:04:00Z",
  "2026-06-21T00:05:00Z",
  "2026-06-21T00:06:00Z",
];

const localActors = {
  deployOperator: {
    actor_id: "agent.deploy_operator",
    actor_type: "agent",
    private_key: "0x0000000000000000000000000000000000000000000000000000000000000002",
  },
  policyService: {
    actor_id: "system.policy_service",
    actor_type: "service",
    private_key: "0x0000000000000000000000000000000000000000000000000000000000000003",
  },
  releaseManager: {
    actor_id: "human.release.drew",
    actor_type: "human",
    private_key: "0x0000000000000000000000000000000000000000000000000000000000000005",
  },
} as const;

export async function runS4LocalHappyPath(options: S4LocalRunOptions = {}): Promise<S4LocalRunResult> {
  const scenarioRoot = options.scenarioRoot ?? defaultScenarioRoot;
  const manifest = validateScenarioManifest(readJson(join(scenarioRoot, "manifest.json")));
  assertS4Manifest(manifest);

  const outputRoot = options.outputRoot ?? join(defaultRunRoot, manifest.workflow_id);
  mkdirSync(outputRoot, { recursive: true });

  const observation = readJson(join(scenarioRoot, "observation.json"));
  const deploymentRequest = readScenarioFile(scenarioRoot, "evidence/deployment_request.json");
  const artifactFile = readScenarioFile(scenarioRoot, "input/artifact_manifest.json");
  const expectedDeployment = readJson(join(scenarioRoot, "expected/deployment_manifest.json"));

  const evidenceBundle = {
    evidence_bundle_id: "evidence-S4-0001",
    workflow_id: manifest.workflow_id,
    policy_version: manifest.policy_version,
    observation_id: field(observation, "observation_id"),
    evidence: [
      {
        path: deploymentRequest.relative_path,
        content_digest: deploymentRequest.digest,
      },
      {
        path: artifactFile.relative_path,
        content_digest: artifactFile.digest,
      },
    ],
  };

  const policyDecision = {
    decision_id: "policy-decision-S4-0001",
    workflow_id: manifest.workflow_id,
    policy_version: manifest.policy_version,
    policy_bundle_ref: "policy-bundles/P3",
    policy_bundle_hash: sha256Hex("govprov-policy-bundle-P3-fixture"),
    decision: "allow",
    gateway_state: "POLICY_ALLOWED_DEPLOYMENT_APPROVAL_REQUIRED",
    obligations: [
      {
        obligation_type: "approved_artifact_link_required",
        status: "satisfied",
        artifact_id: "artifact-S4-0001",
      },
      {
        obligation_type: "deploy_approval_required",
        status: "satisfied",
        approval_role: "DEPLOY_APPROVER",
      },
      {
        obligation_type: "ledger_anchor_required",
        status: "satisfied",
        expected_anchor_subjects: ["policy", "provenance", "approval", "deployment"],
      },
    ],
  };

  const action = {
    action_id: "action-S4-0001",
    workflow_id: manifest.workflow_id,
    action_type: "deploy_artifact",
    actor_id: manifest.primary_actor_id,
    resource_id: manifest.resource_id,
    observation_id: field(observation, "observation_id"),
    evidence_bundle_id: evidenceBundle.evidence_bundle_id,
    policy_decision_id: policyDecision.decision_id,
    artifact_id: "artifact-S4-0001",
    requested_environment: "staging",
  };

  const approval = {
    approval_id: "approval-S4-0001",
    workflow_id: manifest.workflow_id,
    action_id: action.action_id,
    approver_actor_id: "human.release.drew",
    approver_role: "DEPLOY_APPROVER",
    approved_artifact_digest: artifactFile.digest,
    decision: "approved",
    separation_of_duties: "satisfied",
  };

  const artifact = {
    artifact_id: "artifact-S4-0001",
    workflow_id: manifest.workflow_id,
    action_id: action.action_id,
    artifact_type: "container_image_manifest",
    resource_id: manifest.resource_id,
    path: artifactFile.relative_path,
    content_digest: artifactFile.digest,
  };

  const deployment = {
    ...expectedDeployment,
    workflow_id: manifest.workflow_id,
    action_id: action.action_id,
    approved_artifact_digest: artifact.content_digest,
    deployed_artifact_digest: artifact.content_digest,
    policy_decision_id: policyDecision.decision_id,
    ledger_anchor: {
      status: "required_for_govreplay_besu",
      local_fixture_status: "deferred_until_besu_smoke",
    },
  };

  const events = [
    event(1, "observation", "observation_recorded", manifest, localTimestamps[0], observation),
    event(2, "evidence", "evidence_bundle_created", manifest, localTimestamps[1], evidenceBundle),
    event(3, "policy", "policy_decision_allowed", manifest, localTimestamps[2], policyDecision),
    event(4, "action", "deployment_action_proposed", manifest, localTimestamps[3], action),
    event(5, "approval", "deployment_approval_recorded", manifest, localTimestamps[4], approval),
    event(6, "artifact", "artifact_bound_to_approval", manifest, localTimestamps[5], artifact),
    event(7, "deployment", "deployment_recorded", manifest, localTimestamps[6], deployment),
  ];

  const records = {
    run_manifest: {
      schema_version: "govprov.local_scenario_run.v1",
      scenario_id: manifest.scenario_id,
      workflow_id: manifest.workflow_id,
      mode: "local_without_ledger",
      source_manifest_mode: manifest.mode,
      fault_id: manifest.fault_id,
      expected_verdict: manifest.expected_verdict,
      generated_at: "2026-06-21T00:06:00Z",
      attestation_profile: "signed_offchain_deployment_fixture",
      deployment_id: "deployment-S4-0001",
      deferred: ["phase_6_replay_cli_traversal"],
    },
    observation,
    evidence_bundle: evidenceBundle,
    policy_decision: policyDecision,
    action,
    approval,
    artifact,
    deployment,
    baseline_logs: events,
  };
  const files = writeRunOutput(outputRoot, records);

  const attestations = generateS4SignedAttestations({
    manifest,
    observation,
    evidenceBundle,
    policyDecision,
    action,
    approval,
    artifact,
    deployment,
  });
  const layout = await writeAttestationRunLayout({
    runRoot: outputRoot,
    runId: manifest.workflow_id,
    attestations,
  });
  const replayFixture = localReplayFixture(manifest, layout.index);
  const replayFixturePath = join(outputRoot, "manifests", "local_replay_fixture.json");
  await writeFile(replayFixturePath, `${canonicalJson(replayFixture)}\n`);

  const deploymentFixture = deploymentBackwardFixture(manifest, layout.index, replayFixture);
  const deploymentFixturePath = join(outputRoot, "manifests", "deployment_backward_chain.json");
  await writeFile(deploymentFixturePath, `${canonicalJson(deploymentFixture)}\n`);

  files.attestation_index = layout.indexPath;
  files.local_replay_fixture = replayFixturePath;
  files.deployment_backward_chain = deploymentFixturePath;

  return {
    outputRoot,
    manifest,
    events,
    files,
    attestations,
  };
}

function generateS4SignedAttestations(input: {
  manifest: ScenarioManifest;
  observation: Record<string, unknown>;
  evidenceBundle: Record<string, unknown>;
  policyDecision: Record<string, unknown>;
  action: Record<string, unknown>;
  approval: Record<string, unknown>;
  artifact: Record<string, unknown>;
  deployment: Record<string, unknown>;
}): SignedAttestation[] {
  const observation = sign(baseAttestation({
    attestation_type: "ObservationAttestation",
    predicate_type: "https://govprov.dev/predicate/observation/v1",
    subjectName: String(input.observation.observation_id),
    subjectDigest: digestJson(input.observation),
    parents: [],
    created_at: localTimestamps[0],
    actor: localActors.deployOperator,
    predicate: input.observation,
  }), localActors.deployOperator.private_key);

  const evidence = sign(baseAttestation({
    attestation_type: "EvidenceBundleAttestation",
    predicate_type: "https://govprov.dev/predicate/evidence-bundle/v1",
    subjectName: String(input.evidenceBundle.evidence_bundle_id),
    subjectDigest: digestJson(input.evidenceBundle),
    parents: [observation.attestation_hash],
    created_at: localTimestamps[1],
    actor: localActors.deployOperator,
    predicate: input.evidenceBundle,
  }), localActors.deployOperator.private_key);

  const policyDecision = sign(baseAttestation({
    attestation_type: "PolicyDecisionAttestation",
    predicate_type: "https://govprov.dev/predicate/policy-decision/v1",
    subjectName: String(input.policyDecision.decision_id),
    subjectDigest: digestJson(input.policyDecision),
    parents: [evidence.attestation_hash],
    created_at: localTimestamps[2],
    actor: localActors.policyService,
    predicate: input.policyDecision,
  }), localActors.policyService.private_key);

  const action = sign(baseAttestation({
    attestation_type: "AgentActionAttestation",
    predicate_type: "https://govprov.dev/predicate/agent-action/v1",
    subjectName: String(input.action.action_id),
    subjectDigest: digestJson(input.action),
    parents: [observation.attestation_hash, evidence.attestation_hash, policyDecision.attestation_hash],
    created_at: localTimestamps[3],
    actor: localActors.deployOperator,
    predicate: input.action,
  }), localActors.deployOperator.private_key);

  const approval = sign(baseAttestation({
    attestation_type: "ApprovalAttestation",
    predicate_type: "https://govprov.dev/predicate/approval/v1",
    subjectName: String(input.approval.approval_id),
    subjectDigest: digestJson(input.approval),
    parents: [action.attestation_hash],
    created_at: localTimestamps[4],
    actor: localActors.releaseManager,
    predicate: input.approval,
  }), localActors.releaseManager.private_key);

  const artifact = sign(baseAttestation({
    attestation_type: "ArtifactAttestation",
    predicate_type: "https://govprov.dev/predicate/artifact/v1",
    subjectName: String(input.artifact.artifact_id),
    subjectDigest: digestJson(input.artifact),
    parents: [action.attestation_hash, approval.attestation_hash],
    created_at: localTimestamps[5],
    actor: localActors.deployOperator,
    predicate: input.artifact,
  }), localActors.deployOperator.private_key);

  const deployment = sign(baseAttestation({
    attestation_type: "DeploymentAttestation",
    predicate_type: "https://govprov.dev/predicate/deployment/v1",
    subjectName: String(input.deployment.deployment_id),
    subjectDigest: digestJson(input.deployment),
    parents: [approval.attestation_hash, artifact.attestation_hash],
    created_at: localTimestamps[6],
    actor: localActors.deployOperator,
    predicate: input.deployment,
  }), localActors.deployOperator.private_key);

  return [observation, evidence, policyDecision, action, approval, artifact, deployment];
}

function baseAttestation(input: {
  attestation_type: string;
  predicate_type: string;
  subjectName: string;
  subjectDigest: DigestObject;
  parents: string[];
  created_at: string;
  actor: {
    actor_id: string;
    actor_type: "agent" | "human" | "service";
    private_key: string;
  };
  predicate: Record<string, unknown>;
}): Record<string, unknown> {
  return {
    _type: "https://govprov.dev/attestation/v1",
    schema_version: "govprov.attestation.v1",
    attestation_type: input.attestation_type,
    predicate_type: input.predicate_type,
    subject: [
      {
        name: input.subjectName,
        digest: input.subjectDigest,
        uri: `cas://sha256/${input.subjectDigest.value.slice(2)}`,
      },
    ],
    parents: input.parents,
    created_at: input.created_at,
    created_by: {
      actor_id: input.actor.actor_id,
      actor_type: input.actor.actor_type,
      ethereum_address: addressFromPrivateKey(input.actor.private_key),
    },
    ...governanceDomainFields(input.attestation_type),
    policy: {
      policy_id: "govprov:policy:software-delivery-p3-evidence-strengthened",
      policy_hash: {
        algorithm: "sha256",
        value: sha256Hex("govprov-policy-bundle-P3-fixture"),
      },
      policy_version: "P3",
    },
    predicate: input.predicate,
  };
}

function governanceDomainFields(attestationType: string): Record<string, string> {
  const domain = governanceDomainForAttestation(attestationType);
  const domainTypes: Record<string, string> = {
    identity_domain: "actor_registration_and_role_history",
    policy_domain: "policy_registration_activation_and_decision_binding",
    approval_domain: "approval_authority_and_separation_of_duties",
    deployment_domain: "deployment_registry_and_artifact_consistency",
    anchor_domain: "provenance_anchor_and_merkle_root_readback",
    contract_domain: "contract_directory_and_governance_contract_history",
    audit_domain: "audit_replay_reports_and_metrics",
  };
  return {
    governance_domain: domain,
    governance_domain_type: domainTypes[domain],
    governance_domain_id: `govreplay:domain:${domain}`,
  };
}

function governanceDomainForAttestation(attestationType: string): string {
  switch (attestationType) {
    case "PolicyDecisionAttestation":
      return "policy_domain";
    case "ApprovalAttestation":
      return "approval_domain";
    case "ArtifactAttestation":
    case "DeploymentAttestation":
      return "deployment_domain";
    case "LedgerAnchorAttestation":
      return "anchor_domain";
    case "AuditReplayReport":
      return "audit_domain";
    case "ObservationAttestation":
    case "EvidenceBundleAttestation":
    case "AgentActionAttestation":
    default:
      return "audit_domain";
  }
}

function sign(attestation: Record<string, unknown>, privateKey: string): SignedAttestation {
  return signAttestation(attestation, privateKey);
}

function localReplayFixture(manifest: ScenarioManifest, index: {
  attestations: Array<{
    attestation_hash: string;
    attestation_type: string;
    parent_hashes: string[];
    path: string;
  }>;
}): Record<string, unknown> {
  const byType = new Map(index.attestations.map((entry) => [entry.attestation_type, entry]));
  const deployment = byType.get("DeploymentAttestation");
  if (deployment === undefined) {
    throw new Error("S4 replay fixture requires a deployment attestation");
  }

  return {
    schema_version: "govprov.local_replay_fixture.v1",
    scope: "P5-S6 S4 deployment-centered signed-offchain fixture",
    boundary: "Names the deployment ID and backward attestation chain; Phase 6 performs arbitrary traversal and reporting.",
    phase_6_deferred: [
      "graph traversal from arbitrary deployment/action identifiers",
      "policy re-evaluation under current policy",
      "ledger event/state lookup",
      "JSON and Markdown audit reports",
    ],
    scenario_id: manifest.scenario_id,
    workflow_id: manifest.workflow_id,
    start: {
      kind: "deployment_id",
      value: "deployment-S4-0001",
      deployment_attestation_hash: deployment.attestation_hash,
    },
    expected_historical_compliance: manifest.expected_historical_compliance,
    expected_current_compliance: manifest.expected_current_compliance,
    expected_fault: {
      fault_id: manifest.fault_id,
      expected_verdict: manifest.expected_verdict,
      expected_failure_stage: manifest.expected_failure_stage,
      expected_failure_code: manifest.expected_failure_code,
    },
    expected_chain: chainEntries(byType, [
      "ObservationAttestation",
      "EvidenceBundleAttestation",
      "PolicyDecisionAttestation",
      "AgentActionAttestation",
      "ApprovalAttestation",
      "ArtifactAttestation",
      "DeploymentAttestation",
    ]),
  };
}

function deploymentBackwardFixture(
  manifest: ScenarioManifest,
  index: {
    attestations: Array<{
      attestation_hash: string;
      attestation_type: string;
      parent_hashes: string[];
      path: string;
    }>;
  },
  replayFixture: Record<string, unknown>,
): Record<string, unknown> {
  const byType = new Map(index.attestations.map((entry) => [entry.attestation_type, entry]));
  return {
    schema_version: "govprov.deployment_backward_chain_fixture.v1",
    scenario_id: manifest.scenario_id,
    workflow_id: manifest.workflow_id,
    deployment_id: "deployment-S4-0001",
    start: replayFixture.start,
    expected_backward_chain: chainEntries(byType, [
      "DeploymentAttestation",
      "ArtifactAttestation",
      "ApprovalAttestation",
      "AgentActionAttestation",
      "PolicyDecisionAttestation",
      "EvidenceBundleAttestation",
      "ObservationAttestation",
    ]),
    expected_ledger_anchors: [
      "PolicyRegistry.PolicyActivated",
      "ProvenanceRegistry.AttestationAnchored",
      "ApprovalRegistry.ApprovalRecorded",
      "DeploymentRegistry.DeploymentRecorded",
    ],
  };
}

function chainEntries(
  byType: Map<string, { attestation_hash: string; attestation_type: string; parent_hashes: string[]; path: string }>,
  attestationTypes: string[],
): Array<{ attestation_type: string; attestation_hash: string; parent_hashes: string[]; path: string }> {
  return attestationTypes.map((attestationType) => {
    const entry = byType.get(attestationType);
    if (entry === undefined) {
      throw new Error(`Missing S4 attestation fixture entry: ${attestationType}`);
    }
    return {
      attestation_type: entry.attestation_type,
      attestation_hash: entry.attestation_hash,
      parent_hashes: entry.parent_hashes,
      path: entry.path,
    };
  });
}

function assertS4Manifest(manifest: ScenarioManifest): void {
  if (manifest.scenario_id !== "S4_policy_gated_deployment") {
    throw new TypeError(`S4 local runner only supports S4_policy_gated_deployment, got ${manifest.scenario_id}`);
  }
  if (manifest.fault_id !== "F0") {
    throw new TypeError(`S4 local runner only supports happy path F0, got ${manifest.fault_id}`);
  }
  if (manifest.policy_version !== "P3") {
    throw new TypeError(`S4 local runner expects policy P3, got ${manifest.policy_version}`);
  }
  if (manifest.mode === "govreplay_besu") {
    throw new TypeError("S4 local runner does not write to Besu; use the scenario-s4-besu-test service");
  }
}

function event(
  sequence: number,
  stage: LifecycleStage,
  eventType: string,
  manifest: ScenarioManifest,
  createdAt: string,
  payload: Record<string, unknown>,
): LocalRunEvent {
  return {
    sequence,
    stage,
    event_type: eventType,
    scenario_id: manifest.scenario_id,
    workflow_id: manifest.workflow_id,
    created_at: createdAt,
    payload_digest: digestJson(payload),
    payload,
  };
}

function readScenarioFile(scenarioRoot: string, relativePath: string): {
  name: string;
  relative_path: string;
  digest: DigestObject;
} {
  const fullPath = join(scenarioRoot, relativePath);
  const content = readFileSync(fullPath);
  return {
    name: basename(relativePath),
    relative_path: relative(scenarioRoot, fullPath).replaceAll("\\", "/"),
    digest: {
      algorithm: "sha256",
      value: sha256Hex(content),
    },
  };
}

function writeRunOutput(outputRoot: string, records: Record<string, unknown>): Record<string, string> {
  const files: Record<string, string> = {};
  for (const [name, value] of Object.entries(records)) {
    const fileName = name === "baseline_logs" ? "baseline_logs.jsonl" : `${name}.json`;
    const filePath = join(outputRoot, fileName);
    const content = name === "baseline_logs"
      ? `${(value as unknown[]).map((item) => JSON.stringify(item)).join("\n")}\n`
      : `${JSON.stringify(value, null, 2)}\n`;
    writeFileSync(filePath, content);
    files[name] = filePath;
  }
  return files;
}

function readJson(path: string): Record<string, unknown> {
  const value = JSON.parse(readFileSync(path, "utf8"));
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`Expected JSON object: ${path}`);
  }
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): string {
  const value = record[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`Expected non-empty string field ${name}`);
  }
  return value;
}

if (argv[1]?.endsWith("s4-local-runner.ts")) {
  const result = await runS4LocalHappyPath({
    outputRoot: env.GOVPROV_S4_LOCAL_OUTPUT,
  });
  console.log(
    JSON.stringify(
      {
        workflow_id: result.manifest.workflow_id,
        output_root: result.outputRoot,
        event_count: result.events.length,
        attestation_count: result.attestations.length,
      },
      null,
      2,
    ),
  );
}
