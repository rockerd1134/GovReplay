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
  payload_digest: {
    algorithm: "sha256";
    value: string;
  };
  payload: Record<string, unknown>;
};

type S1LocalRunOptions = {
  scenarioRoot?: string;
  manifestPath?: string;
  outputRoot?: string;
};

export type S1LocalRunResult = {
  outputRoot: string;
  manifest: ScenarioManifest;
  events: LocalRunEvent[];
  files: Record<string, string>;
  attestations: SignedAttestation[];
  localVerification: S1LocalVerificationReport;
};

type S1SupportedFault = "F0" | "F1" | "F2" | "F6" | "F10";

type S1LocalVerificationReport = {
  schema_version: "govprov.s1_local_fault_replay.v1";
  scope: "P5-S4 S1 signed-offchain fault subset";
  scenario_id: string;
  workflow_id: string;
  fault_id: S1SupportedFault;
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

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const defaultScenarioRoot = join(packageRoot, "examples", "scenarios", "S1_runbook_update");
const defaultRunRoot = join(packageRoot, "runs", "scenarios");

const localTimestamps = [
  "2026-06-20T00:00:00Z",
  "2026-06-20T00:01:00Z",
  "2026-06-20T00:02:00Z",
  "2026-06-20T00:03:00Z",
  "2026-06-20T00:04:00Z",
  "2026-06-20T00:05:00Z",
  "2026-06-20T00:06:00Z",
];

const localActors = {
  runbookAuthor: {
    actor_id: "agent.runbook_author",
    actor_type: "agent",
    private_key: "0x0000000000000000000000000000000000000000000000000000000000000002",
  },
  policyService: {
    actor_id: "service.policy",
    actor_type: "service",
    private_key: "0x0000000000000000000000000000000000000000000000000000000000000003",
  },
  documentationReviewer: {
    actor_id: "agent.documentation_reviewer",
    actor_type: "human",
    private_key: "0x0000000000000000000000000000000000000000000000000000000000000001",
  },
  documentationPublisher: {
    actor_id: "service.documentation_publisher",
    actor_type: "service",
    private_key: "0x0000000000000000000000000000000000000000000000000000000000000004",
  },
} as const;

export async function runS1LocalHappyPath(options: S1LocalRunOptions = {}): Promise<S1LocalRunResult> {
  return runS1LocalScenario(options);
}

export async function runS1LocalScenario(options: S1LocalRunOptions = {}): Promise<S1LocalRunResult> {
  const scenarioRoot = options.scenarioRoot ?? defaultScenarioRoot;
  const manifest = readJson(options.manifestPath ?? join(scenarioRoot, "manifest.json"));
  const validatedManifest = validateScenarioManifest(manifest);
  assertS1LocalManifest(validatedManifest);
  const faultId = validatedManifest.fault_id as S1SupportedFault;

  const outputRoot = options.outputRoot ?? join(defaultRunRoot, validatedManifest.workflow_id);
  mkdirSync(outputRoot, { recursive: true });

  const observation = readJson(join(scenarioRoot, "observation.json"));
  const evidenceFiles = [
    "evidence/incident_report.md",
    "evidence/service_log_excerpt.txt",
    "evidence/support_ticket.json",
    "input/current_runbook.md",
  ].map((path) => readScenarioFile(scenarioRoot, path));
  const artifact = readScenarioFile(scenarioRoot, "expected/artifact.md");

  const evidenceForBundle = faultId === "F1"
    ? evidenceFiles.filter((file) => file.relative_path !== "input/current_runbook.md")
    : evidenceFiles;
  const tamperedEvidence = faultId === "F2"
    ? {
        path: "faults/tampered_service_log_excerpt.txt",
        expected_digest: evidenceFiles.find((file) => file.relative_path === "evidence/service_log_excerpt.txt")?.digest,
        actual_digest: {
          algorithm: "sha256" as const,
          value: sha256Hex("S1 F2 tampered service log excerpt\n"),
        },
      }
    : null;

  const evidenceBundle = {
    evidence_bundle_id: "evidence-S1-0001",
    workflow_id: validatedManifest.workflow_id,
    policy_version: validatedManifest.policy_version,
    observation_id: observation.observation_id,
    evidence: evidenceForBundle.map((file) => ({
      path: file.relative_path,
      content_digest: file.digest,
    })),
  };

  const policyDecision = {
    decision_id: "policy-decision-S1-0001",
    workflow_id: validatedManifest.workflow_id,
    policy_version: validatedManifest.policy_version,
    policy_bundle_ref: "policy-bundles/P1",
    policy_bundle_hash: sha256Hex("govprov-policy-bundle-P1-fixture"),
    decision: "allow",
    gateway_state: "POLICY_ALLOWED_APPROVAL_REQUIRED",
    obligations: [
      {
        obligation_type: "evidence_required",
        status: "satisfied",
        evidence_bundle_id: evidenceBundle.evidence_bundle_id,
      },
      {
        obligation_type: "documentation_approval_required",
        status: "satisfied",
        approval_role: "DOC_APPROVER",
      },
    ],
  };

  const action = {
    action_id: "action-S1-0001",
    workflow_id: validatedManifest.workflow_id,
    action_type: "propose_runbook_update",
    actor_id: validatedManifest.primary_actor_id,
    resource_id: validatedManifest.resource_id,
    observation_id: observation.observation_id,
    evidence_bundle_id: evidenceBundle.evidence_bundle_id,
    policy_decision_id: policyDecision.decision_id,
    proposed_artifact_path: "expected/artifact.md",
    proposed_artifact_digest: artifact.digest,
  };

  const approval = faultId === "F6"
    ? null
    : {
    approval_id: "approval-S1-0001",
    workflow_id: validatedManifest.workflow_id,
    action_id: action.action_id,
    approver_actor_id: "agent.documentation_reviewer",
    approver_role: "DOC_APPROVER",
    decision: "approved",
    separation_of_duties: "satisfied",
  };

  const artifactRecord = {
    artifact_id: "artifact-S1-0001",
    workflow_id: validatedManifest.workflow_id,
    action_id: action.action_id,
    artifact_type: "runbook_markdown",
    resource_id: validatedManifest.resource_id,
    path: artifact.relative_path,
    content_digest: artifact.digest,
  };

  const substitutedArtifactDigest = {
    algorithm: "sha256" as const,
    value: sha256Hex("S1 F10 substituted runbook artifact\n"),
  };
  const deployment = {
    deployment_id: "deployment-S1-0001",
    workflow_id: validatedManifest.workflow_id,
    artifact_id: artifactRecord.artifact_id,
    approval_id: approval?.approval_id ?? null,
    approved_artifact_digest: artifactRecord.content_digest,
    deployed_artifact_digest: faultId === "F10" ? substitutedArtifactDigest : artifactRecord.content_digest,
    target: "documentation/runbooks",
    status: "published",
    ledger_anchor: null,
  };

  const events = compact([
    event(1, "observation", "observation_recorded", validatedManifest, localTimestamps[0], observation),
    event(2, "evidence", "evidence_bundle_created", validatedManifest, localTimestamps[1], evidenceBundle),
    event(3, "policy", "policy_decision_allowed", validatedManifest, localTimestamps[2], policyDecision),
    event(4, "action", "action_proposed", validatedManifest, localTimestamps[3], action),
    approval === null ? null : event(5, "approval", "approval_recorded", validatedManifest, localTimestamps[4], approval),
    event(approval === null ? 5 : 6, "artifact", "artifact_materialized", validatedManifest, localTimestamps[5], artifactRecord),
    event(approval === null ? 6 : 7, "deployment", "deployment_published", validatedManifest, localTimestamps[6], deployment),
  ]);

  const records: Record<string, unknown> = {
    run_manifest: {
      schema_version: "govprov.local_scenario_run.v1",
      scenario_id: validatedManifest.scenario_id,
      workflow_id: validatedManifest.workflow_id,
      mode: "local_without_ledger",
      source_manifest_mode: validatedManifest.mode,
      fault_id: faultId,
      expected_verdict: validatedManifest.expected_verdict,
      expected_failure_code: validatedManifest.expected_failure_code,
      expected_failure_stage: validatedManifest.expected_failure_stage,
      generated_at: "2026-06-20T00:06:00Z",
      attestation_profile: "signed_offchain_local_fault_fixture",
      deferred: ["besu_ledger_writes", "phase_6_replay_cli_traversal"],
    },
    observation,
    evidence_bundle: evidenceBundle,
    policy_decision: policyDecision,
    action,
    artifact: artifactRecord,
    deployment,
    baseline_logs: events,
  };
  if (approval !== null) {
    records.approval = approval;
  }
  if (tamperedEvidence !== null) {
    records.fault_injection = {
      fault_id: "F2",
      mutation: "evidence_blob_tampered_after_attestation",
      tampered_evidence: tamperedEvidence,
    };
  }

  const files = writeRunOutput(outputRoot, records);

  const attestations = generateS1SignedAttestations({
    manifest: validatedManifest,
    observation,
    evidenceBundle,
    policyDecision,
    action,
    approval,
    artifactRecord,
    deployment,
  });
  const layout = await writeAttestationRunLayout({
    runRoot: outputRoot,
    runId: validatedManifest.workflow_id,
    attestations,
  });
  const replayFixture = localReplayFixture(validatedManifest, layout.index);
  const replayFixturePath = join(outputRoot, "manifests", "local_replay_fixture.json");
  await writeFile(replayFixturePath, `${canonicalJson(replayFixture)}\n`);
  const localVerification = verifyS1LocalFaultSubset({
    manifest: validatedManifest,
    evidenceBundle,
    approval,
    deployment,
    tamperedEvidence,
  });
  const verificationPath = join(outputRoot, "manifests", "local_fault_replay.json");
  await writeFile(verificationPath, `${canonicalJson(localVerification)}\n`);

  files.attestation_index = layout.indexPath;
  files.local_replay_fixture = replayFixturePath;
  files.local_fault_replay = verificationPath;

  return {
    outputRoot,
    manifest: validatedManifest,
    events,
    files,
    attestations,
    localVerification,
  };
}

function generateS1SignedAttestations(input: {
  manifest: ScenarioManifest;
  observation: Record<string, unknown>;
  evidenceBundle: Record<string, unknown>;
  policyDecision: Record<string, unknown>;
  action: Record<string, unknown>;
  approval: Record<string, unknown> | null;
  artifactRecord: Record<string, unknown>;
  deployment: Record<string, unknown>;
}): SignedAttestation[] {
  const observation = sign(baseAttestation({
    attestation_type: "ObservationAttestation",
    predicate_type: "https://govprov.dev/predicate/observation/v1",
    subjectName: String(input.observation.observation_id),
    subjectDigest: digestJson(input.observation),
    parents: [],
    created_at: localTimestamps[0],
    actor: localActors.runbookAuthor,
    predicate: input.observation,
  }), localActors.runbookAuthor.private_key);

  const evidence = sign(baseAttestation({
    attestation_type: "EvidenceBundleAttestation",
    predicate_type: "https://govprov.dev/predicate/evidence-bundle/v1",
    subjectName: String(input.evidenceBundle.evidence_bundle_id),
    subjectDigest: digestJson(input.evidenceBundle),
    parents: [observation.attestation_hash],
    created_at: localTimestamps[1],
    actor: localActors.runbookAuthor,
    predicate: input.evidenceBundle,
  }), localActors.runbookAuthor.private_key);

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
    actor: localActors.runbookAuthor,
    predicate: input.action,
  }), localActors.runbookAuthor.private_key);

  const approval = input.approval === null
    ? null
    : sign(baseAttestation({
        attestation_type: "ApprovalAttestation",
        predicate_type: "https://govprov.dev/predicate/approval/v1",
        subjectName: String(input.approval.approval_id),
        subjectDigest: digestJson(input.approval),
        parents: [action.attestation_hash],
        created_at: localTimestamps[4],
        actor: localActors.documentationReviewer,
        predicate: input.approval,
      }), localActors.documentationReviewer.private_key);

  const artifact = sign(baseAttestation({
    attestation_type: "ArtifactAttestation",
    predicate_type: "https://govprov.dev/predicate/artifact/v1",
    subjectName: String(input.artifactRecord.artifact_id),
    subjectDigest: digestJson(input.artifactRecord),
    parents: approval === null ? [action.attestation_hash] : [action.attestation_hash, approval.attestation_hash],
    created_at: localTimestamps[5],
    actor: localActors.runbookAuthor,
    predicate: input.artifactRecord,
  }), localActors.runbookAuthor.private_key);

  const deployment = sign(baseAttestation({
    attestation_type: "DeploymentAttestation",
    predicate_type: "https://govprov.dev/predicate/deployment/v1",
    subjectName: String(input.deployment.deployment_id),
    subjectDigest: digestJson(input.deployment),
    parents: approval === null ? [artifact.attestation_hash] : [approval.attestation_hash, artifact.attestation_hash],
    created_at: localTimestamps[6],
    actor: localActors.documentationPublisher,
    predicate: input.deployment,
  }), localActors.documentationPublisher.private_key);

  return compact([observation, evidence, policyDecision, action, approval, artifact, deployment]);
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
      policy_id: "govprov:policy:software-delivery-p1-baseline",
      policy_hash: {
        algorithm: "sha256",
        value: sha256Hex("govprov-policy-bundle-P1-fixture"),
      },
      policy_version: "P1",
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
    throw new Error("S1 replay fixture requires a deployment attestation");
  }

  return {
    schema_version: "govprov.local_replay_fixture.v1",
    scope: manifest.fault_id === "F0" ? "P5-S3 local signed-offchain fixture" : "P5-S4 S1 signed-offchain fault fixture",
    boundary: "Verifies deterministic files, signatures, hashes, and parent links without Besu ledger queries.",
    phase_6_deferred: [
      "graph traversal from arbitrary deployment/action identifiers",
      "policy re-evaluation under current policy",
      "ledger anchor resolution",
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
    expected_chain: [
      "ObservationAttestation",
      "EvidenceBundleAttestation",
      "PolicyDecisionAttestation",
      "AgentActionAttestation",
      "ApprovalAttestation",
      "ArtifactAttestation",
      "DeploymentAttestation",
    ].filter((attestationType) => manifest.fault_id !== "F6" || attestationType !== "ApprovalAttestation").map((attestationType) => {
      const entry = byType.get(attestationType);
      if (entry === undefined) {
        throw new Error(`Missing S1 attestation fixture entry: ${attestationType}`);
      }
      return {
        attestation_type: entry.attestation_type,
        attestation_hash: entry.attestation_hash,
        parent_hashes: entry.parent_hashes,
        path: entry.path,
      };
    }),
  };
}

function verifyS1LocalFaultSubset(input: {
  manifest: ScenarioManifest;
  evidenceBundle: Record<string, unknown>;
  approval: Record<string, unknown> | null;
  deployment: Record<string, unknown>;
  tamperedEvidence: {
    path: string;
    expected_digest?: DigestObject;
    actual_digest: DigestObject;
  } | null;
}): S1LocalVerificationReport {
  const checks: S1LocalVerificationReport["checks"] = [];
  const evidence = Array.isArray(input.evidenceBundle.evidence) ? input.evidenceBundle.evidence : [];
  const hasIncident = evidence.some((item) => isRecord(item) && item.path === "evidence/incident_report.md");
  const hasRunbook = evidence.some((item) => isRecord(item) && item.path === "input/current_runbook.md");
  checks.push({
    stage: "evidence",
    status: hasIncident && hasRunbook ? "pass" : "fail",
    code: hasIncident && hasRunbook ? null : "evidence_missing",
    detail: "P1 S1 local replay requires incident evidence and current runbook evidence.",
  });

  const evidenceUntampered = input.tamperedEvidence === null
    || input.tamperedEvidence.expected_digest?.value === input.tamperedEvidence.actual_digest.value;
  checks.push({
    stage: "evidence",
    status: evidenceUntampered ? "pass" : "fail",
    code: evidenceUntampered ? null : "evidence_hash_mismatch",
    detail: input.tamperedEvidence === null
      ? "No post-attestation evidence mutation recorded."
      : `Evidence mutation ${input.tamperedEvidence.path} recomputes to ${input.tamperedEvidence.actual_digest.value}.`,
  });

  checks.push({
    stage: "approval",
    status: input.approval === null ? "fail" : "pass",
    code: input.approval === null ? "approval_missing" : null,
    detail: "S1 publication requires a documentation approval before deployment.",
  });

  const artifactMatches = digestValue(input.deployment.approved_artifact_digest) === digestValue(input.deployment.deployed_artifact_digest);
  checks.push({
    stage: "artifact_deployment",
    status: artifactMatches ? "pass" : "fail",
    code: artifactMatches ? null : "artifact_hash_mismatch",
    detail: "Deployment artifact digest must match the approved artifact digest.",
  });

  const failed = checks.find((check) => check.status === "fail");
  return {
    schema_version: "govprov.s1_local_fault_replay.v1",
    scope: "P5-S4 S1 signed-offchain fault subset",
    scenario_id: input.manifest.scenario_id,
    workflow_id: input.manifest.workflow_id,
    fault_id: input.manifest.fault_id as S1SupportedFault,
    verdict: failed === undefined ? "pass" : "fail",
    failure_stage: failed?.stage === "artifact_deployment" ? "artifact_deployment" : failed?.stage ?? null,
    failure_code: failed?.code ?? null,
    expected_verdict: input.manifest.expected_verdict,
    expected_failure_stage: input.manifest.expected_failure_stage,
    expected_failure_code: input.manifest.expected_failure_code,
    checks,
    deferred: [
      "Besu ledger queries",
      "policy re-evaluation under current policy",
      "Phase 6 replay graph traversal",
    ],
  };
}

function assertS1LocalManifest(manifest: ScenarioManifest): void {
  if (manifest.scenario_id !== "S1_runbook_update") {
    throw new TypeError(`S1 local runner only supports S1_runbook_update, got ${manifest.scenario_id}`);
  }
  if (!["F0", "F1", "F2", "F6", "F10"].includes(manifest.fault_id)) {
    throw new TypeError(`S1 local runner only supports F0/F1/F2/F6/F10, got ${manifest.fault_id}`);
  }
  if (manifest.mode === "govreplay_besu") {
    throw new TypeError("S1 local runner does not write to Besu; use a non-ledger manifest");
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
  digest: {
    algorithm: "sha256";
    value: string;
  };
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

function compact<T>(items: Array<T | null>): T[] {
  return items.filter((item): item is T => item !== null);
}

function digestValue(value: unknown): string | null {
  return isRecord(value) && typeof value.value === "string" ? value.value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function writeRunOutput(outputRoot: string, records: Record<string, unknown>): Record<string, string> {
  const files: Record<string, string> = {};
  for (const [name, value] of Object.entries(records)) {
    const fileName = name === "baseline_logs" ? "baseline_logs.jsonl" : `${name}.json`;
    const filePath = join(outputRoot, fileName);
    const content = name === "baseline_logs" ? `${(value as unknown[]).map((item) => JSON.stringify(item)).join("\n")}\n` : `${JSON.stringify(value, null, 2)}\n`;
    writeFileSync(filePath, content);
    files[name] = filePath;
  }
  return files;
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

if (argv[1]?.endsWith("s1-local-runner.ts")) {
  const result = await runS1LocalHappyPath({
    outputRoot: env.GOVPROV_S1_LOCAL_OUTPUT,
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
