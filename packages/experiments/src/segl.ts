// Research fixture/demo code: embedded keys are public synthetic test vectors.
// Never use these keys or this fixture signer for production accounts. See SECURITY.md.
import { digestJson } from "../../attestations/src/digest.ts";
import { addressFromPrivateKey, signAttestation, verifyAttestationSignature, type AttestationSignature } from "../../attestations/src/signing.ts";
import { GOVERNANCE_DOMAIN_TYPES, governanceDomainId, type GovernanceDomain, type WorkloadInstance } from "./model.ts";

export const SEGL_PRIVATE_KEY = "0x0000000000000000000000000000000000000000000000000000000000000006";
export const SEGL_SIGNER = addressFromPrivateKey(SEGL_PRIVATE_KEY);

export type SeglEventType =
  | "contract_directory_registered"
  | "actor_role_assigned"
  | "actor_role_revoked"
  | "policy_activated"
  | "evidence_recorded"
  | "policy_decision_recorded"
  | "approval_recorded"
  | "artifact_recorded"
  | "deployment_recorded"
  | "anchor_recorded";

export type SeglEvent = {
  schema_version: "govprov.segl.event.v1";
  attestation_type: "SignedEventSourcedGovernanceLogEvent";
  event_id: string;
  sequence: number;
  domain: GovernanceDomain;
  workflow_id: string;
  event_type: SeglEventType;
  subject: string;
  object: string;
  policy_version: string;
  timestamp: string;
  logical_time: string;
  payload: Record<string, unknown>;
  prev_event_hash: string | null;
  event_hash: string;
  signer: string;
  signature: AttestationSignature;
  attestation_hash: string;
  created_by: {
    actor_id: string;
    ethereum_address: string;
    signing_profile: string;
  };
};

export type SeglManifest = {
  schema_version: "govprov.segl.manifest.v1";
  system_configuration: "SEGL";
  description: string;
  event_count: number;
  signer: string;
  hash_chain_head: string | null;
  state_root: string | null;
  state_equivalence: {
    evidence_integrity_records: true;
    policy_activation_history: true;
    actor_role_history: true;
    approval_records: true;
    separation_of_duties_state: true;
    deployment_records: true;
    artifact_deployment_consistency_state: true;
    anchor_records: true;
    contract_directory_history: true;
    uses_besu: false;
  };
};

export type SeglVerificationIssue = {
  code: string;
  sequence?: number;
  event_id?: string;
  detail: string;
};

export type SeglState = {
  actors: Map<string, Set<string>>;
  policies: Map<string, string>;
  approvals: Map<string, Record<string, unknown>>;
  artifacts: Map<string, Record<string, unknown>>;
  deployments: Map<string, Record<string, unknown>>;
  anchors: Map<string, Record<string, unknown>>;
  contractDirectory: Map<string, string>;
};

export type SeglVerificationResult = {
  ok: boolean;
  issues: SeglVerificationIssue[];
  state: SeglState;
};

export type SeglWorkflowReference = {
  workflow_id: string;
};

type DraftSeglEvent = Omit<SeglEvent, "event_hash" | "signature" | "attestation_hash">;

export function buildSeglLog(instances: WorkloadInstance[]): { events: SeglEvent[]; manifest: SeglManifest } {
  let previousEventHash: string | null = null;
  const events: SeglEvent[] = [];
  for (const instance of instances) {
    for (const draft of seglWorkflowDrafts(instance)) {
      const signed = signSeglEvent({
        ...draft,
        sequence: events.length + 1,
        prev_event_hash: previousEventHash,
      });
      previousEventHash = signed.event_hash;
      events.push(signed);
    }
  }
  const stateRoot = events.length === 0 ? null : digestJson(foldSeglState(events)).value;
  return {
    events,
    manifest: {
      schema_version: "govprov.segl.manifest.v1",
      system_configuration: "SEGL",
      description: "Signed Event-Sourced Governance Log: a non-ledger append-only governance-state substrate with signed transition events.",
      event_count: events.length,
      signer: SEGL_SIGNER,
      hash_chain_head: events.at(-1)?.event_hash ?? null,
      state_root: stateRoot,
      state_equivalence: {
        evidence_integrity_records: true,
        policy_activation_history: true,
        actor_role_history: true,
        approval_records: true,
        separation_of_duties_state: true,
        deployment_records: true,
        artifact_deployment_consistency_state: true,
        anchor_records: true,
        contract_directory_history: true,
        uses_besu: false,
      },
    },
  };
}

export function verifySeglLog(events: SeglEvent[]): SeglVerificationResult {
  const issues: SeglVerificationIssue[] = [];
  const seenSequences = new Map<number, SeglEvent>();
  const seenEvents = new Set<string>();
  let previousEventHash: string | null = null;
  const state = emptySeglState();

  for (const event of events) {
    const priorSequence = seenSequences.get(event.sequence);
    if (priorSequence !== undefined) {
      issues.push({
        code: priorSequence.event_hash === event.event_hash ? "duplicate_sequence" : "conflicting_sequence",
        sequence: event.sequence,
        event_id: event.event_id,
        detail: `Sequence ${event.sequence} is present more than once.`,
      });
    }
    seenSequences.set(event.sequence, event);

    if (seenEvents.has(event.event_id)) {
      issues.push({
        code: "duplicate_event_id",
        sequence: event.sequence,
        event_id: event.event_id,
        detail: `Event id ${event.event_id} is duplicated.`,
      });
    }
    seenEvents.add(event.event_id);

    if (event.sequence !== seenSequences.size) {
      issues.push({
        code: "missing_or_reordered_event",
        sequence: event.sequence,
        event_id: event.event_id,
        detail: `Expected sequence ${seenSequences.size}, observed ${event.sequence}.`,
      });
    }

    if (event.prev_event_hash !== previousEventHash) {
      issues.push({
        code: "broken_hash_chain",
        sequence: event.sequence,
        event_id: event.event_id,
        detail: `Expected prev_event_hash ${previousEventHash ?? "null"}, observed ${event.prev_event_hash ?? "null"}.`,
      });
    }

    const recomputedHash = seglEventHash(event);
    if (event.event_hash !== recomputedHash) {
      issues.push({
        code: "event_hash_mismatch",
        sequence: event.sequence,
        event_id: event.event_id,
        detail: "Event payload no longer matches event_hash.",
      });
    }

    try {
      if (!verifyAttestationSignature(event, event.signer)) {
        issues.push({
          code: "invalid_signature",
          sequence: event.sequence,
          event_id: event.event_id,
          detail: "Event signature does not verify for the declared signer.",
        });
      }
    } catch (error) {
      issues.push({
        code: "invalid_signature",
        sequence: event.sequence,
        event_id: event.event_id,
        detail: error instanceof Error ? error.message : "Event signature verification failed.",
      });
    }

    applySeglEvent(state, event, issues);
    previousEventHash = event.event_hash;
  }

  return { ok: issues.length === 0, issues, state };
}

export function verifySeglWorkflow(events: SeglEvent[], reference: SeglWorkflowReference): SeglVerificationResult {
  const result = verifySeglLog(events);
  const issues = [...result.issues];
  const workflowId = reference.workflow_id;
  const workflowEvents = events.filter((event) => event.workflow_id === workflowId);
  const eventTypes = new Set(workflowEvents.map((event) => event.event_type));
  const requiredTypes: Array<[SeglEventType, string]> = [
    ["contract_directory_registered", "missing_contract_directory_event"],
    ["actor_role_assigned", "missing_role_assignment_event"],
    ["policy_activated", "missing_policy_activation_event"],
    ["evidence_recorded", "missing_evidence_event"],
    ["policy_decision_recorded", "missing_policy_decision_event"],
    ["artifact_recorded", "missing_artifact_event"],
    ["deployment_recorded", "missing_deployment_event"],
    ["anchor_recorded", "missing_anchor_event"],
  ];
  for (const [eventType, code] of requiredTypes) {
    if (!eventTypes.has(eventType)) {
      issues.push({ code, detail: `${workflowId} lacks required SEGL ${eventType} transition.` });
    }
  }
  if (!eventTypes.has("approval_recorded")) {
    issues.push({ code: "missing_approval_event", detail: `${workflowId} lacks required approval transition.` });
  }

  const anchor = workflowEvents.find((event) => event.event_type === "anchor_recorded");
  if (anchor !== undefined && anchor.payload.workflow_root !== digestJson(workflowId).value) {
    issues.push({ code: "anchor_mismatch", sequence: anchor.sequence, event_id: anchor.event_id, detail: "Anchor root does not match reconstructed workflow root." });
  }

  issues.push(...workflowStateIssues(workflowId, workflowEvents));

  return { ok: issues.length === 0, issues, state: result.state };
}

export function seglEventHash(event: Record<string, unknown>): string {
  const content = structuredClone(event) as Record<string, unknown>;
  delete content.event_hash;
  delete content.signature;
  delete content.attestation_hash;
  return digestJson(content).value;
}

export function foldSeglState(events: readonly SeglEvent[]): Record<string, unknown> {
  const state = emptySeglState();
  const issues: SeglVerificationIssue[] = [];
  for (const event of events) {
    applySeglEvent(state, event, issues);
  }
  return serializableState(state);
}

function signSeglEvent(draft: DraftSeglEvent): SeglEvent {
  const withHash = {
    ...draft,
    event_hash: seglEventHash(draft),
  };
  const signed = signAttestation(withHash, SEGL_PRIVATE_KEY);
  return {
    ...withHash,
    attestation_hash: signed.attestation_hash,
    signature: signed.signature,
  };
}

function seglWorkflowDrafts(instance: WorkloadInstance): DraftSeglEvent[] {
  const base = {
    schema_version: "govprov.segl.event.v1" as const,
    attestation_type: "SignedEventSourcedGovernanceLogEvent" as const,
    workflow_id: instance.workflow_id,
    policy_version: instance.policy_version,
    timestamp: "2026-06-21T00:00:00Z",
    signer: SEGL_SIGNER,
    created_by: {
      actor_id: "segl:local-signer",
      ethereum_address: SEGL_SIGNER,
      signing_profile: "experimental-deterministic-secp256k1",
    },
  };
  const deploymentScope = deploymentScopeFor(instance);
  const artifactHash = digestJson({ artifact_id: instance.artifact_id, scenario_id: instance.scenario_id, seed: instance.seed }).value;
  const approvalId = `approval:${instance.workflow_id}:${instance.policy_version}`;
  const anchorId = `anchor:${instance.workflow_id}`;
  const contractSet = `contract-set:${instance.policy_version}`;
  const roles = actorRolesFor(instance);

  const drafts: Array<Omit<DraftSeglEvent, "sequence" | "prev_event_hash">> = [
    eventDraft(base, "contract_domain", "contract_directory_registered", contractSet, instance.deployment_id, "t00", {
      contract_set: contractSet,
      actor_registry: "SEGL.actor_roles",
      policy_registry: "SEGL.policy_activations",
      approval_registry: "SEGL.approvals",
      deployment_registry: "SEGL.deployments",
      anchor_registry: "SEGL.anchors",
    }),
    eventDraft(base, "identity_domain", "actor_role_assigned", instance.agent_id, instance.deployment_id, "t01", {
      roles,
      effective_from: "t01",
    }),
    eventDraft(base, "policy_domain", "policy_activated", instance.policy_version, deploymentScope, "t02", {
      policy_hash: digestJson(instance.policy_version).value,
      scope: deploymentScope,
      active_from: "t02",
    }),
  ];

  if (instance.fault_id === "H3") {
    const conflictingPolicyVersion = nextPolicyVersion(instance.policy_version);
    drafts.push(withEventPolicyVersion(eventDraft(base, "policy_domain", "policy_activated", conflictingPolicyVersion, deploymentScope, "t02c", {
      policy_hash: digestJson(conflictingPolicyVersion).value,
      scope: deploymentScope,
      active_from: "t02",
    }), conflictingPolicyVersion));
  }

  drafts.push(
    eventDraft(base, "audit_domain", "evidence_recorded", instance.agent_id, instance.workflow_id, "t03", {
      evidence_bundle_id: `evidence:${instance.workflow_id}`,
      evidence_hash: digestJson({ workflow_id: instance.workflow_id, evidence: "deterministic-fixture" }).value,
    }),
    eventDraft(base, "policy_domain", "policy_decision_recorded", instance.agent_id, instance.workflow_id, "t04", {
      decision_id: `decision:${instance.workflow_id}`,
      policy_version: instance.policy_version,
      required_roles: ["approver"],
      required_scope: deploymentScope,
      contract_set: contractSet,
    }),
  );

  if (instance.fault_id !== "F6") {
    drafts.push(eventDraft(base, "approval_domain", "approval_recorded", approvalId, instance.artifact_id, "t05", {
      approval_id: approvalId,
      approver: approverFor(instance),
      proposer: instance.agent_id,
      artifact_hash: artifactHash,
      deployment_scope: deploymentScope,
      separation_of_duties_ok: instance.fault_id !== "F8",
      offchain_lifecycle_reference: instance.fault_id === "H5" ? `omitted:${instance.workflow_id}` : instance.workflow_id,
    }));
  }

  if (instance.fault_id === "H1" || instance.fault_id === "H7") {
    drafts.push(eventDraft(base, "identity_domain", "actor_role_revoked", instance.agent_id, instance.deployment_id, "t05r", {
      roles,
      effective_from: "t05r",
    }));
  }

  drafts.push(
    eventDraft(base, "deployment_domain", "artifact_recorded", instance.artifact_id, instance.workflow_id, "t06", {
      artifact_id: instance.artifact_id,
      artifact_hash: artifactHash,
      approved_artifact_hash: artifactHash,
    }),
  );

  if (instance.fault_id === "H2") {
    const changedPolicyVersion = nextPolicyVersion(instance.policy_version);
    drafts.push(withEventPolicyVersion(eventDraft(base, "policy_domain", "policy_activated", changedPolicyVersion, deploymentScope, "t06p", {
      policy_hash: digestJson(changedPolicyVersion).value,
      scope: deploymentScope,
      active_from: "t06p",
    }), changedPolicyVersion));
  }

  if (instance.fault_id === "H8") {
    const supersedingContractSet = `${contractSet}:superseding`;
    drafts.push(eventDraft(base, "contract_domain", "contract_directory_registered", supersedingContractSet, instance.deployment_id, "t06c", {
      contract_set: supersedingContractSet,
      actor_registry: "SEGL.actor_roles.v2",
      policy_registry: "SEGL.policy_activations.v2",
      approval_registry: "SEGL.approvals.v2",
      deployment_registry: "SEGL.deployments.v2",
      anchor_registry: "SEGL.anchors.v2",
      active_from: "t06c",
    }));
  }

  drafts.push(
    eventDraft(base, "deployment_domain", "deployment_recorded", instance.deployment_id, instance.artifact_id, "t07", {
      deployment_id: instance.deployment_id,
      artifact_id: instance.artifact_id,
      artifact_hash: instance.fault_id === "F10" ? digestJson({ substituted: instance.artifact_id }).value : artifactHash,
      approval_id: approvalId,
      deployer: instance.agent_id,
      deployment_scope: instance.fault_id === "H6" ? "prod:wrong-scope" : deploymentScope,
      contract_set: contractSet,
    }),
    eventDraft(base, "anchor_domain", "anchor_recorded", anchorId, instance.workflow_id, "t08", {
      anchor_id: anchorId,
      workflow_root: instance.fault_id === "F12" || instance.fault_id === "H4" ? digestJson({ mismatched_anchor: instance.workflow_id }).value : digestJson(instance.workflow_id).value,
      subjects: [instance.workflow_id, instance.deployment_id, instance.artifact_id, approvalId],
    }),
  );

  return drafts.map((draft) => ({ ...draft, sequence: 0, prev_event_hash: null }));
}

function workflowStateIssues(workflowId: string, workflowEvents: SeglEvent[]): SeglVerificationIssue[] {
  const issues: SeglVerificationIssue[] = [];
  const policyActivations = workflowEvents.filter((event) => event.event_type === "policy_activated");
  const decision = workflowEvents.find((event) => event.event_type === "policy_decision_recorded");
  const deployment = workflowEvents.find((event) => event.event_type === "deployment_recorded");
  issues.push(...policyConflictIssues(policyActivations));

  if (decision !== undefined && deployment !== undefined) {
    const scope = stringValue(deployment.payload.deployment_scope) ?? stringValue(decision.payload.required_scope);
    if (scope !== undefined) {
      const decisionPolicy = latestPolicyActivationAtOrBefore(policyActivations, scope, decision.logical_time);
      const deploymentPolicy = latestPolicyActivationAtOrBefore(policyActivations, scope, deployment.logical_time);
      if (decisionPolicy !== undefined && deploymentPolicy !== undefined && decisionPolicy.policy_version !== deploymentPolicy.policy_version) {
        issues.push({
          code: "policy_changed_between_decision_and_deployment",
          sequence: deployment.sequence,
          event_id: deployment.event_id,
          detail: "SEGL replay detects policy activation drift between decision and deployment logical times.",
        });
      }
    }

    const deployer = stringValue(deployment.payload.deployer) ?? deployment.subject;
    const revokedBeforeDeployment = workflowEvents.find((event) =>
      event.event_type === "actor_role_revoked"
      && event.subject === deployer
      && event.logical_time < deployment.logical_time
      && stringArray(event.payload.roles).length > 0
    );
    if (revokedBeforeDeployment !== undefined) {
      issues.push({
        code: "stale_actor_role_state",
        sequence: revokedBeforeDeployment.sequence,
        event_id: revokedBeforeDeployment.event_id,
        detail: `${workflowId} records an actor-role revocation before deployment-time replay.`,
      });
    }

    const latestContractSet = latestContractDirectoryAtOrBefore(workflowEvents, deployment.logical_time);
    const deploymentContractSet = stringValue(deployment.payload.contract_set);
    if (latestContractSet !== undefined && deploymentContractSet !== undefined && latestContractSet !== deploymentContractSet) {
      issues.push({
        code: "contract_directory_mismatch",
        sequence: deployment.sequence,
        event_id: deployment.event_id,
        detail: "SEGL replay detects contract-directory state that supersedes the replayed governance schema.",
      });
    }
  }

  return issues;
}

function policyConflictIssues(policyActivations: SeglEvent[]): SeglVerificationIssue[] {
  const issues: SeglVerificationIssue[] = [];
  const activePolicies = new Map<string, SeglEvent>();
  for (const event of policyActivations) {
    const scope = stringValue(event.payload.scope) ?? event.object;
    const activeFrom = stringValue(event.payload.active_from) ?? event.logical_time;
    const key = `${scope}/${activeFrom}`;
    const previous = activePolicies.get(key);
    if (previous !== undefined && previous.policy_version !== event.policy_version) {
      issues.push({
        code: "conflicting_policy_activation",
        sequence: event.sequence,
        event_id: event.event_id,
        detail: "SEGL replay detects conflicting active policy transitions for the same scope.",
      });
    }
    activePolicies.set(key, event);
  }
  return issues;
}

function latestPolicyActivationAtOrBefore(events: SeglEvent[], scope: string, logicalTime: string): SeglEvent | undefined {
  return events
    .filter((event) => (stringValue(event.payload.scope) ?? event.object) === scope && event.logical_time <= logicalTime)
    .sort((left, right) => left.logical_time.localeCompare(right.logical_time) || left.sequence - right.sequence)
    .at(-1);
}

function latestContractDirectoryAtOrBefore(events: SeglEvent[], logicalTime: string): string | undefined {
  const event = events
    .filter((candidate) => candidate.event_type === "contract_directory_registered" && candidate.logical_time <= logicalTime)
    .sort((left, right) => left.logical_time.localeCompare(right.logical_time) || left.sequence - right.sequence)
    .at(-1);
  return event === undefined ? undefined : stringValue(event.payload.contract_set) ?? event.subject;
}

function withEventPolicyVersion<T extends Omit<DraftSeglEvent, "sequence" | "prev_event_hash">>(event: T, policyVersion: string): T {
  return { ...event, policy_version: policyVersion };
}

function eventDraft(
  base: Pick<DraftSeglEvent, "schema_version" | "attestation_type" | "workflow_id" | "policy_version" | "timestamp" | "signer" | "created_by">,
  domain: GovernanceDomain,
  eventType: SeglEventType,
  subject: string,
  object: string,
  logicalTime: string,
  payload: Record<string, unknown>,
): Omit<DraftSeglEvent, "sequence" | "prev_event_hash"> {
  return {
    ...base,
    event_id: `segl:${base.workflow_id}:${logicalTime}:${eventType}`,
    domain,
    event_type: eventType,
    subject,
    object,
    logical_time: logicalTime,
    payload: {
      ...payload,
      governance_domain_type: GOVERNANCE_DOMAIN_TYPES[domain],
      governance_domain_id: governanceDomainId(domain),
    },
  };
}

function applySeglEvent(state: SeglState, event: SeglEvent, issues: SeglVerificationIssue[]): void {
  switch (event.event_type) {
    case "actor_role_assigned": {
      const roles = stringArray(event.payload.roles);
      const current = state.actors.get(event.subject) ?? new Set<string>();
      for (const role of roles) {
        current.add(role);
      }
      state.actors.set(event.subject, current);
      break;
    }
    case "actor_role_revoked": {
      const current = state.actors.get(event.subject) ?? new Set<string>();
      for (const role of stringArray(event.payload.roles)) {
        current.delete(role);
      }
      state.actors.set(event.subject, current);
      break;
    }
    case "policy_activated":
      state.policies.set(String(event.object), event.policy_version);
      break;
    case "approval_recorded":
      if (event.payload.separation_of_duties_ok === false) {
        issues.push({ code: "separation_of_duties_violation", sequence: event.sequence, event_id: event.event_id, detail: "Approval proposer and approver are not separated." });
      }
      if (event.payload.offchain_lifecycle_reference !== undefined && event.payload.offchain_lifecycle_reference !== event.workflow_id) {
        issues.push({ code: "ledger_approval_offchain_omission", sequence: event.sequence, event_id: event.event_id, detail: "Approval state does not match the off-chain lifecycle reference." });
      }
      state.approvals.set(String(event.payload.approval_id), event.payload);
      break;
    case "artifact_recorded":
      state.artifacts.set(String(event.payload.artifact_id), event.payload);
      break;
    case "deployment_recorded": {
      const deploymentId = String(event.payload.deployment_id);
      const artifactId = String(event.payload.artifact_id);
      const artifact = state.artifacts.get(artifactId);
      const approval = state.approvals.get(String(event.payload.approval_id));
      if (artifact === undefined) {
        issues.push({ code: "artifact_record_missing", sequence: event.sequence, event_id: event.event_id, detail: `Deployment ${deploymentId} references missing artifact ${artifactId}.` });
      } else if (artifact.artifact_hash !== event.payload.artifact_hash) {
        issues.push({ code: "artifact_deployment_mismatch", sequence: event.sequence, event_id: event.event_id, detail: `Deployment ${deploymentId} artifact hash differs from recorded artifact.` });
      }
      if (approval === undefined) {
        issues.push({ code: "approval_record_missing", sequence: event.sequence, event_id: event.event_id, detail: `Deployment ${deploymentId} references missing approval.` });
      } else if (approval.deployment_scope !== event.payload.deployment_scope) {
        issues.push({ code: "deployment_scope_mismatch", sequence: event.sequence, event_id: event.event_id, detail: `Deployment ${deploymentId} scope differs from approved scope.` });
      }
      state.deployments.set(deploymentId, event.payload);
      break;
    }
    case "anchor_recorded":
      state.anchors.set(String(event.payload.anchor_id), event.payload);
      break;
    case "contract_directory_registered":
      state.contractDirectory.set(String(event.payload.contract_set), String(event.subject));
      break;
    case "evidence_recorded":
    case "policy_decision_recorded":
      break;
  }
}

function emptySeglState(): SeglState {
  return {
    actors: new Map(),
    policies: new Map(),
    approvals: new Map(),
    artifacts: new Map(),
    deployments: new Map(),
    anchors: new Map(),
    contractDirectory: new Map(),
  };
}

function serializableState(state: SeglState): Record<string, unknown> {
  return {
    actors: Object.fromEntries([...state.actors.entries()].sort().map(([actor, roles]) => [actor, [...roles].sort()])),
    policies: Object.fromEntries([...state.policies.entries()].sort()),
    approvals: Object.fromEntries([...state.approvals.entries()].sort()),
    artifacts: Object.fromEntries([...state.artifacts.entries()].sort()),
    deployments: Object.fromEntries([...state.deployments.entries()].sort()),
    anchors: Object.fromEntries([...state.anchors.entries()].sort()),
    contract_directory: Object.fromEntries([...state.contractDirectory.entries()].sort()),
  };
}

function actorRolesFor(instance: WorkloadInstance): string[] {
  if (instance.agent_id === "agent:configbot") {
    return ["configuration_proposer", "deployment_operator", "approver"];
  }
  return ["delivery_engineer", "artifact_builder", "approver"];
}

function approverFor(instance: WorkloadInstance): string {
  return instance.fault_id === "F8" ? instance.agent_id : "human:governance-reviewer";
}

function deploymentScopeFor(instance: WorkloadInstance): string {
  return instance.scenario_id === "S4_policy_gated_deployment" ? "prod:service" : "staging:service";
}

function nextPolicyVersion(policyVersion: string): string {
  switch (policyVersion) {
    case "policy:v1":
      return "policy:v2";
    case "policy:v2":
      return "policy:v3";
    default:
      return "policy:v1";
  }
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    return [];
  }
  return value;
}
