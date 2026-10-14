import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { basename, join, relative } from "node:path";
import { canonicalJson } from "../../attestations/src/canonical-json.ts";
import { digestJson, sha256Hex, type DigestObject } from "../../attestations/src/digest.ts";
import { writeAttestationRunLayout } from "../../attestations/src/run-layout.ts";
import { addressFromPrivateKey, signAttestation, type SignedAttestation } from "../../attestations/src/signing.ts";
import { validateScenarioManifest, type ScenarioManifest } from "./manifest.ts";

export type LifecycleStage =
  | "observation"
  | "evidence"
  | "policy"
  | "action"
  | "approval"
  | "artifact"
  | "deployment";

export type LocalRunEvent = {
  sequence: number;
  stage: LifecycleStage;
  event_type: string;
  scenario_id: string;
  workflow_id: string;
  created_at: string;
  payload_digest: DigestObject;
  payload: Record<string, unknown>;
};

export type LocalRunResult = {
  outputRoot: string;
  manifest: ScenarioManifest;
  events: LocalRunEvent[];
  files: Record<string, string>;
  attestations: SignedAttestation[];
  localVerification: LocalVerificationReport;
};

export type LocalVerificationReport = {
  schema_version: "govprov.local_fault_replay.v1";
  scope: string;
  scenario_id: string;
  workflow_id: string;
  fault_id: string;
  verdict: "pass" | "fail";
  failure_stage: ScenarioManifest["expected_failure_stage"];
  failure_code: string | null;
  expected_verdict: ScenarioManifest["expected_verdict"];
  expected_failure_stage: ScenarioManifest["expected_failure_stage"];
  expected_failure_code: string | null;
  checks: Array<{
    stage: LifecycleStage | "artifact_deployment";
    status: "pass" | "fail";
    code: string | null;
    detail: string;
  }>;
  deferred: string[];
};

export type Actor = {
  actor_id: string;
  actor_type: "agent" | "human" | "service";
  private_key: string;
};

export type LocalScenarioConfig = {
  scenarioRoot: string;
  outputRoot: string;
  manifestPath?: string;
  expectedScenarioId: string;
  supportedFaults: string[];
  timestamps: string[];
  actors: {
    primary: Actor;
    policy: Actor;
    approver: Actor;
    deployer: Actor;
  };
  policy: {
    id: string;
    version: string;
    ref: string;
    hashSeed: string;
  };
  ids: {
    observation: string;
    evidence: string;
    policyDecision: string;
    action: string;
    approval: string;
    artifact: string;
    deployment: string;
  };
  files: {
    evidence: string[];
    artifact: string;
    expectedDeployment: string;
  };
  action: {
    type: string;
    proposedArtifactPath: string;
  };
  artifact: {
    type: string;
  };
  approval: {
    role: string;
    secondApproverActorId?: string;
  };
  expected: {
    scope: string;
    replayBoundary: string;
    faultScope: string;
  };
  buildPolicyObligations: (input: { evidenceBundleId: string; artifactId: string }) => Array<Record<string, unknown>>;
  buildFaultChecks: (input: {
    manifest: ScenarioManifest;
    approval: Record<string, unknown>;
    deployment: Record<string, unknown>;
  }) => LocalVerificationReport["checks"];
};

export async function runGenericLocalScenario(config: LocalScenarioConfig): Promise<LocalRunResult> {
  const manifest = validateScenarioManifest(readJson(config.manifestPath ?? join(config.scenarioRoot, "manifest.json")));
  assertManifest(manifest, config);
  const outputRoot = config.outputRoot;
  mkdirSync(outputRoot, { recursive: true });

  const observation = readJson(join(config.scenarioRoot, "observation.json"));
  const evidenceFiles = config.files.evidence.map((path) => readScenarioFile(config.scenarioRoot, path));
  const artifactFile = readScenarioFile(config.scenarioRoot, config.files.artifact);
  const expectedDeployment = readJson(join(config.scenarioRoot, config.files.expectedDeployment));

  const evidenceBundle = {
    evidence_bundle_id: config.ids.evidence,
    workflow_id: manifest.workflow_id,
    policy_version: manifest.policy_version,
    observation_id: field(observation, "observation_id"),
    evidence: evidenceFiles.map((file) => ({
      path: file.relative_path,
      content_digest: file.digest,
    })),
  };

  const policyDecision = {
    decision_id: config.ids.policyDecision,
    workflow_id: manifest.workflow_id,
    policy_version: manifest.policy_version,
    policy_bundle_ref: config.policy.ref,
    policy_bundle_hash: sha256Hex(config.policy.hashSeed),
    decision: manifest.expected_verdict === "pass" ? "allow" : "deny",
    gateway_state: manifest.expected_verdict === "pass" ? "POLICY_ALLOWED_APPROVAL_REQUIRED" : "POLICY_DENIED_APPROVAL_INVALID",
    obligations: config.buildPolicyObligations({
      evidenceBundleId: config.ids.evidence,
      artifactId: config.ids.artifact,
    }),
  };

  const action = {
    action_id: config.ids.action,
    workflow_id: manifest.workflow_id,
    action_type: config.action.type,
    actor_id: manifest.primary_actor_id,
    resource_id: manifest.resource_id,
    observation_id: field(observation, "observation_id"),
    evidence_bundle_id: config.ids.evidence,
    policy_decision_id: config.ids.policyDecision,
    proposed_artifact_path: config.action.proposedArtifactPath,
    proposed_artifact_digest: artifactFile.digest,
  };

  const approval = {
    approval_id: config.ids.approval,
    workflow_id: manifest.workflow_id,
    action_id: config.ids.action,
    approver_actor_id: manifest.fault_id === "F8" ? manifest.primary_actor_id : config.actors.approver.actor_id,
    approver_role: config.approval.role,
    second_approver_actor_id: config.approval.secondApproverActorId ?? null,
    approved_artifact_digest: artifactFile.digest,
    decision: manifest.expected_verdict === "pass" ? "approved" : "rejected",
    separation_of_duties: manifest.fault_id === "F8" ? "violated" : "satisfied",
  };

  const artifact = {
    artifact_id: config.ids.artifact,
    workflow_id: manifest.workflow_id,
    action_id: config.ids.action,
    artifact_type: config.artifact.type,
    resource_id: manifest.resource_id,
    path: artifactFile.relative_path,
    content_digest: artifactFile.digest,
  };

  const substitutedArtifactDigest = {
    algorithm: "sha256" as const,
    value: sha256Hex(`${manifest.scenario_id} ${manifest.fault_id} substituted artifact\n`),
  };
  const deployment = {
    ...expectedDeployment,
    workflow_id: manifest.workflow_id,
    action_id: config.ids.action,
    approval_id: config.ids.approval,
    approved_artifact_digest: artifact.content_digest,
    deployed_artifact_digest: manifest.fault_id === "F10" ? substitutedArtifactDigest : artifact.content_digest,
    policy_decision_id: config.ids.policyDecision,
    ledger_anchor: null,
  };

  const events = [
    event(1, "observation", "observation_recorded", manifest, config.timestamps[0], observation),
    event(2, "evidence", "evidence_bundle_created", manifest, config.timestamps[1], evidenceBundle),
    event(3, "policy", "policy_decision_recorded", manifest, config.timestamps[2], policyDecision),
    event(4, "action", "action_proposed", manifest, config.timestamps[3], action),
    event(5, "approval", "approval_recorded", manifest, config.timestamps[4], approval),
    event(6, "artifact", "artifact_materialized", manifest, config.timestamps[5], artifact),
    event(7, "deployment", "deployment_recorded", manifest, config.timestamps[6], deployment),
  ];

  const localVerification = verifyLocalScenario({
    manifest,
    scope: config.expected.faultScope,
    checks: config.buildFaultChecks({ manifest, approval, deployment }),
  });
  const records = {
    run_manifest: {
      schema_version: "govprov.local_scenario_run.v1",
      scenario_id: manifest.scenario_id,
      workflow_id: manifest.workflow_id,
      mode: "local_without_ledger",
      source_manifest_mode: manifest.mode,
      fault_id: manifest.fault_id,
      expected_verdict: manifest.expected_verdict,
      expected_failure_code: manifest.expected_failure_code,
      expected_failure_stage: manifest.expected_failure_stage,
      generated_at: config.timestamps[6],
      attestation_profile: "signed_offchain_phase5_fixture",
      deferred: ["besu_scenario_mode", "phase_6_replay_cli_traversal"],
    },
    observation,
    evidence_bundle: evidenceBundle,
    policy_decision: policyDecision,
    action,
    approval,
    artifact,
    deployment,
    baseline_logs: events,
    local_fault_replay: localVerification,
  };
  const files = writeRunOutput(outputRoot, records);

  const attestations = generateSignedAttestations({
    manifest,
    config,
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
  const replayFixture = localReplayFixture(manifest, layout.index, config.expected);
  const replayFixturePath = join(outputRoot, "manifests", "local_replay_fixture.json");
  await writeFile(replayFixturePath, `${canonicalJson(replayFixture)}\n`);

  files.attestation_index = layout.indexPath;
  files.local_replay_fixture = replayFixturePath;

  return {
    outputRoot,
    manifest,
    events,
    files,
    attestations,
    localVerification,
  };
}

function generateSignedAttestations(input: {
  manifest: ScenarioManifest;
  config: LocalScenarioConfig;
  observation: Record<string, unknown>;
  evidenceBundle: Record<string, unknown>;
  policyDecision: Record<string, unknown>;
  action: Record<string, unknown>;
  approval: Record<string, unknown>;
  artifact: Record<string, unknown>;
  deployment: Record<string, unknown>;
}): SignedAttestation[] {
  const observation = sign(baseAttestation(input, {
    attestation_type: "ObservationAttestation",
    predicate_type: "https://govprov.dev/predicate/observation/v1",
    subjectName: String(input.observation.observation_id),
    subjectDigest: digestJson(input.observation),
    parents: [],
    created_at: input.config.timestamps[0],
    actor: input.config.actors.primary,
    predicate: input.observation,
  }), input.config.actors.primary.private_key);

  const evidence = sign(baseAttestation(input, {
    attestation_type: "EvidenceBundleAttestation",
    predicate_type: "https://govprov.dev/predicate/evidence-bundle/v1",
    subjectName: String(input.evidenceBundle.evidence_bundle_id),
    subjectDigest: digestJson(input.evidenceBundle),
    parents: [observation.attestation_hash],
    created_at: input.config.timestamps[1],
    actor: input.config.actors.primary,
    predicate: input.evidenceBundle,
  }), input.config.actors.primary.private_key);

  const policyDecision = sign(baseAttestation(input, {
    attestation_type: "PolicyDecisionAttestation",
    predicate_type: "https://govprov.dev/predicate/policy-decision/v1",
    subjectName: String(input.policyDecision.decision_id),
    subjectDigest: digestJson(input.policyDecision),
    parents: [evidence.attestation_hash],
    created_at: input.config.timestamps[2],
    actor: input.config.actors.policy,
    predicate: input.policyDecision,
  }), input.config.actors.policy.private_key);

  const action = sign(baseAttestation(input, {
    attestation_type: "AgentActionAttestation",
    predicate_type: "https://govprov.dev/predicate/agent-action/v1",
    subjectName: String(input.action.action_id),
    subjectDigest: digestJson(input.action),
    parents: [observation.attestation_hash, evidence.attestation_hash, policyDecision.attestation_hash],
    created_at: input.config.timestamps[3],
    actor: input.config.actors.primary,
    predicate: input.action,
  }), input.config.actors.primary.private_key);

  const approvalActor = input.manifest.fault_id === "F8" ? input.config.actors.primary : input.config.actors.approver;
  const approval = sign(baseAttestation(input, {
    attestation_type: "ApprovalAttestation",
    predicate_type: "https://govprov.dev/predicate/approval/v1",
    subjectName: String(input.approval.approval_id),
    subjectDigest: digestJson(input.approval),
    parents: [action.attestation_hash],
    created_at: input.config.timestamps[4],
    actor: approvalActor,
    predicate: input.approval,
  }), approvalActor.private_key);

  const artifact = sign(baseAttestation(input, {
    attestation_type: "ArtifactAttestation",
    predicate_type: "https://govprov.dev/predicate/artifact/v1",
    subjectName: String(input.artifact.artifact_id),
    subjectDigest: digestJson(input.artifact),
    parents: [action.attestation_hash, approval.attestation_hash],
    created_at: input.config.timestamps[5],
    actor: input.config.actors.primary,
    predicate: input.artifact,
  }), input.config.actors.primary.private_key);

  const deployment = sign(baseAttestation(input, {
    attestation_type: "DeploymentAttestation",
    predicate_type: "https://govprov.dev/predicate/deployment/v1",
    subjectName: String(input.deployment.deployment_id),
    subjectDigest: digestJson(input.deployment),
    parents: [approval.attestation_hash, artifact.attestation_hash],
    created_at: input.config.timestamps[6],
    actor: input.config.actors.deployer,
    predicate: input.deployment,
  }), input.config.actors.deployer.private_key);

  return [observation, evidence, policyDecision, action, approval, artifact, deployment];
}

function baseAttestation(
  input: { config: LocalScenarioConfig },
  attestation: {
    attestation_type: string;
    predicate_type: string;
    subjectName: string;
    subjectDigest: DigestObject;
    parents: string[];
    created_at: string;
    actor: Actor;
    predicate: Record<string, unknown>;
  },
): Record<string, unknown> {
  return {
    _type: "https://govprov.dev/attestation/v1",
    schema_version: "govprov.attestation.v1",
    attestation_type: attestation.attestation_type,
    predicate_type: attestation.predicate_type,
    subject: [
      {
        name: attestation.subjectName,
        digest: attestation.subjectDigest,
        uri: `cas://sha256/${attestation.subjectDigest.value.slice(2)}`,
      },
    ],
    parents: attestation.parents,
    created_at: attestation.created_at,
    created_by: {
      actor_id: attestation.actor.actor_id,
      actor_type: attestation.actor.actor_type,
      ethereum_address: addressFromPrivateKey(attestation.actor.private_key),
    },
    ...governanceDomainFields(attestation.attestation_type),
    policy: {
      policy_id: input.config.policy.id,
      policy_hash: {
        algorithm: "sha256",
        value: sha256Hex(input.config.policy.hashSeed),
      },
      policy_version: input.config.policy.version,
    },
    predicate: attestation.predicate,
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

function localReplayFixture(
  manifest: ScenarioManifest,
  index: {
    attestations: Array<{
      attestation_hash: string;
      attestation_type: string;
      parent_hashes: string[];
      path: string;
    }>;
  },
  expected: Pick<LocalScenarioConfig["expected"], "scope" | "replayBoundary">,
): Record<string, unknown> {
  const deployment = index.attestations.find((entry) => entry.attestation_type === "DeploymentAttestation");
  if (deployment === undefined) {
    throw new Error(`${manifest.scenario_id} replay fixture requires a deployment attestation`);
  }

  return {
    schema_version: "govprov.local_replay_fixture.v1",
    scope: expected.scope,
    boundary: expected.replayBoundary,
    phase_6_deferred: [
      "graph traversal from arbitrary deployment/action identifiers",
      "policy re-evaluation under current policy",
      "ledger event/state lookup",
      "JSON and Markdown audit reports",
    ],
    scenario_id: manifest.scenario_id,
    workflow_id: manifest.workflow_id,
    start: {
      kind: "deployment_attestation_hash",
      value: deployment.attestation_hash,
    },
    expected_historical_compliance: manifest.expected_historical_compliance,
    expected_current_compliance: manifest.expected_current_compliance,
    expected_fault: {
      fault_id: manifest.fault_id,
      expected_verdict: manifest.expected_verdict,
      expected_failure_stage: manifest.expected_failure_stage,
      expected_failure_code: manifest.expected_failure_code,
    },
    expected_chain: index.attestations.map((entry) => ({
      attestation_type: entry.attestation_type,
      attestation_hash: entry.attestation_hash,
      parent_hashes: entry.parent_hashes,
      path: entry.path,
    })),
  };
}

function verifyLocalScenario(input: {
  manifest: ScenarioManifest;
  scope: string;
  checks: LocalVerificationReport["checks"];
}): LocalVerificationReport {
  const failed = input.checks.find((check) => check.status === "fail");
  return {
    schema_version: "govprov.local_fault_replay.v1",
    scope: input.scope,
    scenario_id: input.manifest.scenario_id,
    workflow_id: input.manifest.workflow_id,
    fault_id: input.manifest.fault_id,
    verdict: failed === undefined ? "pass" : "fail",
    failure_stage: failed?.stage ?? null,
    failure_code: failed?.code ?? null,
    expected_verdict: input.manifest.expected_verdict,
    expected_failure_stage: input.manifest.expected_failure_stage,
    expected_failure_code: input.manifest.expected_failure_code,
    checks: input.checks,
    deferred: [
      "Besu ledger queries for this scenario",
      "policy re-evaluation under current policy",
      "Phase 6 replay graph traversal",
    ],
  };
}

export function standardApprovalChecks(input: {
  manifest: ScenarioManifest;
  approval: Record<string, unknown>;
  deployment: Record<string, unknown>;
}): LocalVerificationReport["checks"] {
  const separated = input.approval.approver_actor_id !== input.manifest.primary_actor_id;
  const artifactMatches = digestValue(input.deployment.approved_artifact_digest) === digestValue(input.deployment.deployed_artifact_digest);
  return [
    {
      stage: "approval",
      status: separated ? "pass" : "fail",
      code: separated ? null : "separation_of_duties_violation",
      detail: "Approver must be distinct from the proposing actor.",
    },
    {
      stage: "artifact_deployment",
      status: artifactMatches ? "pass" : "fail",
      code: artifactMatches ? null : "artifact_hash_mismatch",
      detail: "Deployment artifact digest must match the approved artifact digest.",
    },
  ];
}

function assertManifest(manifest: ScenarioManifest, config: LocalScenarioConfig): void {
  if (manifest.scenario_id !== config.expectedScenarioId) {
    throw new TypeError(`${config.expectedScenarioId} local runner got ${manifest.scenario_id}`);
  }
  if (!config.supportedFaults.includes(manifest.fault_id)) {
    throw new TypeError(`${manifest.scenario_id} local runner does not support ${manifest.fault_id}`);
  }
  if (manifest.policy_version !== config.policy.version) {
    throw new TypeError(`${manifest.scenario_id} expects policy ${config.policy.version}, got ${manifest.policy_version}`);
  }
  if (manifest.mode === "govreplay_besu") {
    throw new TypeError(`${manifest.scenario_id} local runner does not write to Besu`);
  }
}

function sign(attestation: Record<string, unknown>, privateKey: string): SignedAttestation {
  return signAttestation(attestation, privateKey);
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

function digestValue(value: unknown): string | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) && "value" in value
    ? String((value as { value: unknown }).value)
    : null;
}
