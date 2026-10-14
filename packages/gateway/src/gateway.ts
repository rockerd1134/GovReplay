// Research fixture/demo code: embedded keys are public synthetic test vectors.
// Never use these keys or this fixture signer for production accounts. See SECURITY.md.
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { digestJson, type DigestObject } from "../../attestations/src/digest.ts";
import {
  addressFromPrivateKey,
  signAttestation,
  type SignedAttestation,
} from "../../attestations/src/signing.ts";
import {
  loadPolicyBundle,
  type PolicyBundle,
} from "../../policy-service/src/bundle-format.ts";
import {
  POLICY_SERVICE_PRIVATE_KEY,
  policyDecisionMaterial,
  type PolicyDecisionFixtureInput,
} from "../../policy-service/src/policy-decision-attestation.ts";

export type AgentActionRequest = {
  schema_version: "govreplay.agent_action_request.v1";
  request_id: string;
  scenario_id: string;
  workflow_id: string;
  run_id: string;
  requested_at: string;
  actor: {
    actor_id: string;
    actor_type: "agent" | "service";
    roles: string[];
  };
  action: {
    action_id: string;
    action_type: string;
    risk: "low" | "medium" | "high";
  };
  resource: {
    resource_id: string;
    resource_type: string;
    environment: string;
  };
  policy: {
    bundle_ref: string;
    policy_version: string;
  };
  policy_context: {
    risk_tier: "low" | "medium" | "high";
    evidence_profile: string;
    approval_profile: string;
    artifact_linkage: string;
    policy_ref_profile: string;
  };
  evidence_refs: GatewayRef[];
  artifact_refs: GatewayRef[];
  approval_refs: GatewayRef[];
  deployment_refs: GatewayRef[];
};

export type GatewayRef = {
  id: string;
  type: string;
  uri?: string;
  digest?: DigestObject;
};

export type GatewayDecision = {
  schema_version: "govreplay.gateway_decision.v1";
  request_id: string;
  scenario_id: string;
  workflow_id: string;
  run_id: string;
  evaluated_at: string;
  gateway_state: "POLICY_ALLOWED_ACTION_ATTESTED" | "POLICY_DENIED_ACTION_BLOCKED";
  decision: "allow" | "deny";
  policy_bundle_ref: string;
  policy_bundle_hash: string;
  policy_decision_hash: string;
  obligations: Record<string, unknown>[];
  policy_decision_attestation: SignedAttestation;
  agent_action_attestation: SignedAttestation | null;
  emitted_records: string[];
  blocked: boolean;
  denial_reason: string | null;
};

export type GatewayScenarioCoverage = {
  scenario_id: string;
  scenario_name: string;
  action_type: string;
  allowed_fixture: string;
  denied_fixture: string;
  primary_domains: string[];
  proves: string;
  validation: string;
};

export type GatewayOptions = {
  fixtureRoot?: string;
  evaluatedAt?: string;
};

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const defaultFixtureRoot = join(packageRoot, "packages", "policy-service", "fixtures", "bundles");

const ACTOR_PRIVATE_KEYS: Record<string, string> = {
  "govprov:actor:agent-runbook-001": "0x0000000000000000000000000000000000000000000000000000000000000002",
  "govprov:actor:agent-config-001": "0x0000000000000000000000000000000000000000000000000000000000000006",
  "govprov:actor:agent-patch-001": "0x0000000000000000000000000000000000000000000000000000000000000007",
  "govprov:actor:agent-deploy-001": "0x0000000000000000000000000000000000000000000000000000000000000008",
  "govprov:actor:agent-governance-admin-001": "0x0000000000000000000000000000000000000000000000000000000000000009",
};

export const GATEWAY_SCENARIO_COVERAGE: GatewayScenarioCoverage[] = [
  {
    scenario_id: "S1_runbook_update",
    scenario_name: "Runbook Update",
    action_type: "propose_runbook_update",
    allowed_fixture: "s1-runbook-allow.request.json",
    denied_fixture: "s1-runbook-deny.request.json",
    primary_domains: ["policy decision binding", "evidence sufficiency"],
    proves: "Required evidence and active policy binding are checked before action attestation emission.",
    validation: "docker compose run --rm gateway-test",
  },
  {
    scenario_id: "S2_configuration_change",
    scenario_name: "Configuration Change",
    action_type: "propose_config_change",
    allowed_fixture: "s2-config-allow.request.json",
    denied_fixture: "s2-config-deny.request.json",
    primary_domains: ["identity and actor-role governance", "approval authority and separation of duties"],
    proves: "Invalid approval posture is blocked before downstream configuration records exist.",
    validation: "docker compose run --rm gateway-test",
  },
  {
    scenario_id: "S3_patch_proposal",
    scenario_name: "Patch Proposal",
    action_type: "propose_patch",
    allowed_fixture: "s3-patch-allow.request.json",
    denied_fixture: "s3-patch-deny.request.json",
    primary_domains: ["deployment and artifact consistency", "supply-chain evidence"],
    proves: "Issue, test, and artifact references are required before patch lineage is emitted.",
    validation: "docker compose run --rm gateway-test",
  },
  {
    scenario_id: "S4_policy_gated_deployment",
    scenario_name: "Policy-Gated Deployment",
    action_type: "deploy_artifact",
    allowed_fixture: "s4-deployment-allow.request.json",
    denied_fixture: "s4-deployment-deny.request.json",
    primary_domains: ["deployment and artifact consistency", "policy decision binding"],
    proves: "Deployment records are emitted only for approved artifact and policy-decision lineage.",
    validation: "docker compose run --rm gateway-test",
  },
  {
    scenario_id: "S5_governance_state_change",
    scenario_name: "Governance State Change",
    action_type: "request_governance_state_change",
    allowed_fixture: "s5-governance-allow.request.json",
    denied_fixture: "s5-governance-deny.request.json",
    primary_domains: ["ledger-backed governance-state administration", "contract-directory or policy administration state"],
    proves: "Only governance-admin actors can emit governance-state transition records.",
    validation: "docker compose run --rm gateway-test",
  },
];

export function evaluateGatewayRequest(
  value: unknown,
  options: GatewayOptions = {},
): GatewayDecision {
  const request = validateAgentActionRequest(value);
  const bundle = loadPolicyBundle(join(options.fixtureRoot ?? defaultFixtureRoot, request.policy.bundle_ref));
  const fixture = matchingFixture(bundle, request);
  const material = policyDecisionMaterial(bundle, fixture);
  const evaluatedAt = options.evaluatedAt ?? request.requested_at;
  const policyDecisionAttestation = signPolicyDecisionForRequest({
    request,
    bundle,
    material,
    evaluatedAt,
  });
  const agentActionAttestation = material.decision === "allow"
    ? signAgentActionForRequest({
        request,
        policyDecisionAttestation,
        evaluatedAt,
      })
    : null;

  return {
    schema_version: "govreplay.gateway_decision.v1",
    request_id: request.request_id,
    scenario_id: request.scenario_id,
    workflow_id: request.workflow_id,
    run_id: request.run_id,
    evaluated_at: evaluatedAt,
    gateway_state: material.decision === "allow"
      ? "POLICY_ALLOWED_ACTION_ATTESTED"
      : "POLICY_DENIED_ACTION_BLOCKED",
    decision: material.decision,
    policy_bundle_ref: request.policy.bundle_ref,
    policy_bundle_hash: material.policy_bundle_hash,
    policy_decision_hash: material.policy_decision_hash,
    obligations: material.resolved_obligations,
    policy_decision_attestation: policyDecisionAttestation,
    agent_action_attestation: agentActionAttestation,
    emitted_records: agentActionAttestation === null
      ? ["PolicyDecisionAttestation"]
      : ["PolicyDecisionAttestation", "AgentActionAttestation"],
    blocked: agentActionAttestation === null,
    denial_reason: agentActionAttestation === null
      ? "Policy denied the proposed agent action; gateway did not emit AgentActionAttestation."
      : null,
  };
}

export function writeGatewayDecision(decision: GatewayDecision, outputPath: string): void {
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(decision, null, 2)}\n`);
}

export function validateAgentActionRequest(value: unknown): AgentActionRequest {
  assertRecord(value, "request");
  requireLiteral(value.schema_version, "govreplay.agent_action_request.v1", "schema_version");
  requirePattern(value.request_id, /^req-[A-Za-z0-9._-]+$/, "request_id");
  requirePattern(value.scenario_id, /^S[1-5]_[A-Za-z0-9_]+$/, "scenario_id");
  requirePattern(value.workflow_id, /^wf-[A-Za-z0-9._-]+$/, "workflow_id");
  requireNonEmptyString(value.run_id, "run_id");
  requireUtcTimestamp(value.requested_at, "requested_at");
  assertRecord(value.actor, "actor");
  requireNonEmptyString(value.actor.actor_id, "actor.actor_id");
  requireEnum(value.actor.actor_type, ["agent", "service"], "actor.actor_type");
  requireStringArray(value.actor.roles, "actor.roles");
  assertRecord(value.action, "action");
  requireNonEmptyString(value.action.action_id, "action.action_id");
  requireNonEmptyString(value.action.action_type, "action.action_type");
  requireEnum(value.action.risk, ["low", "medium", "high"], "action.risk");
  assertRecord(value.resource, "resource");
  requireNonEmptyString(value.resource.resource_id, "resource.resource_id");
  requireNonEmptyString(value.resource.resource_type, "resource.resource_type");
  requireNonEmptyString(value.resource.environment, "resource.environment");
  assertRecord(value.policy, "policy");
  requireNonEmptyString(value.policy.bundle_ref, "policy.bundle_ref");
  requirePattern(value.policy.policy_version, /^P[1-9][0-9]*$/, "policy.policy_version");
  assertRecord(value.policy_context, "policy_context");
  requireEnum(value.policy_context.risk_tier, ["low", "medium", "high"], "policy_context.risk_tier");
  requireNonEmptyString(value.policy_context.evidence_profile, "policy_context.evidence_profile");
  requireNonEmptyString(value.policy_context.approval_profile, "policy_context.approval_profile");
  requireNonEmptyString(value.policy_context.artifact_linkage, "policy_context.artifact_linkage");
  requireNonEmptyString(value.policy_context.policy_ref_profile, "policy_context.policy_ref_profile");
  validateRefs(value.evidence_refs, "evidence_refs");
  validateRefs(value.artifact_refs, "artifact_refs");
  validateRefs(value.approval_refs, "approval_refs");
  validateRefs(value.deployment_refs, "deployment_refs");
  return value as AgentActionRequest;
}

function matchingFixture(bundle: PolicyBundle, request: AgentActionRequest): PolicyDecisionFixtureInput {
  const requestInput = policyInputForRequest(request);
  for (const testFile of bundle.test_files) {
    const test = readJson(join(bundle.directory, "tests", testFile));
    assertRecord(test.input, `${testFile}.input`);
    if (samePolicySemantics(test.input, requestInput)) {
      return {
        bundleName: request.policy.bundle_ref,
        testFile,
        testName: String(test.name),
        input: requestInput,
      };
    }
  }
  throw new Error(`No deterministic policy fixture matched ${request.request_id} in ${request.policy.bundle_ref}`);
}

function policyInputForRequest(request: AgentActionRequest): Record<string, unknown> {
  return {
    principal: {
      id: request.actor.actor_id,
      type: actorTypeForPolicy(request.actor.actor_type),
      roles: request.actor.roles,
    },
    action: {
      id: request.action.action_type,
      type: "GovernedAction",
    },
    resource: {
      id: request.resource.resource_id,
      type: request.resource.resource_type,
      environment: request.resource.environment,
    },
    context: {
      risk_tier: request.policy_context.risk_tier,
      evidence_profile: request.policy_context.evidence_profile,
      approval_profile: request.policy_context.approval_profile,
      artifact_linkage: request.policy_context.artifact_linkage,
      policy_ref_profile: request.policy_context.policy_ref_profile,
      workflow_id: request.workflow_id,
      run_id: request.run_id,
    },
  };
}

function signPolicyDecisionForRequest(input: {
  request: AgentActionRequest;
  bundle: PolicyBundle;
  material: ReturnType<typeof policyDecisionMaterial>;
  evaluatedAt: string;
}): SignedAttestation {
  const subjectDigest = digestJson({
    request_id: input.request.request_id,
    decision: input.material.decision,
    policy_decision_hash: input.material.policy_decision_hash,
    policy_input_hash: input.material.policy_input_hash,
  });
  return signAttestation({
    _type: "https://govprov.dev/attestation/v1",
    schema_version: "govprov.attestation.v1",
    attestation_type: "PolicyDecisionAttestation",
    predicate_type: "https://govprov.dev/predicate/policy-decision/v1",
    subject: [
      {
        name: `policy-decision/${input.request.request_id}`,
        digest: subjectDigest,
        uri: digestToCasUri(subjectDigest),
      },
    ],
    parents: [],
    created_at: input.evaluatedAt,
    created_by: {
      actor_id: "govprov:actor:policy-service",
      actor_type: "service",
      ethereum_address: addressFromPrivateKey(POLICY_SERVICE_PRIVATE_KEY),
    },
    governance_domain: "policy_domain",
    governance_domain_type: "policy_registration_activation_and_decision_binding",
    governance_domain_id: "govreplay:domain:policy_domain",
    policy: {
      policy_id: input.bundle.metadata.policy_bundle_id,
      policy_version: input.request.policy.policy_version,
      policy_bundle_version: input.bundle.metadata.version,
      policy_hash: {
        algorithm: "sha256",
        value: input.material.policy_bundle_hash,
      },
    },
    predicate: {
      request_id: input.request.request_id,
      scenario_id: input.request.scenario_id,
      workflow_id: input.request.workflow_id,
      run_id: input.request.run_id,
      evaluated_at: input.evaluatedAt,
      decision: input.material.decision,
      obligations: input.material.obligation_ids,
      policy_version: input.request.policy.policy_version,
      policy_bundle_ref: input.request.policy.bundle_ref,
      policy_bundle_version: input.material.policy_bundle_version,
      policy_bundle_hash: input.material.policy_bundle_hash,
      policy_input_hash: input.material.policy_input_hash,
      policy_input_digest: {
        algorithm: "sha256",
        value: input.material.policy_input_hash,
      },
      evaluator_identity: input.material.evaluator_identity,
      evaluator_version: input.material.evaluator_version,
      evaluator_policy_language: input.material.evaluator_policy_language,
      matched_policy_ids: input.material.matched_policy_ids,
      obligations_hash: input.material.obligations_hash,
      resolved_obligations: input.material.resolved_obligations,
      policy_decision_hash: input.material.policy_decision_hash,
    },
  }, POLICY_SERVICE_PRIVATE_KEY);
}

function signAgentActionForRequest(input: {
  request: AgentActionRequest;
  policyDecisionAttestation: SignedAttestation;
  evaluatedAt: string;
}): SignedAttestation {
  const privateKey = ACTOR_PRIVATE_KEYS[input.request.actor.actor_id];
  if (privateKey === undefined) {
    throw new Error(`No deterministic signing key configured for ${input.request.actor.actor_id}`);
  }
  const subjectDigest = digestJson({
    request_id: input.request.request_id,
    action_id: input.request.action.action_id,
    action_type: input.request.action.action_type,
    workflow_id: input.request.workflow_id,
  });
  return signAttestation({
    _type: "https://govprov.dev/attestation/v1",
    schema_version: "govprov.attestation.v1",
    attestation_type: "AgentActionAttestation",
    predicate_type: "https://govprov.dev/predicate/agent-action/v1",
    subject: [
      {
        name: input.request.action.action_id,
        digest: subjectDigest,
        uri: digestToCasUri(subjectDigest),
      },
    ],
    parents: [input.policyDecisionAttestation.attestation_hash],
    created_at: input.evaluatedAt,
    created_by: {
      actor_id: input.request.actor.actor_id,
      actor_type: input.request.actor.actor_type,
      ethereum_address: addressFromPrivateKey(privateKey),
    },
    governance_domain: "audit_domain",
    governance_domain_type: "audit_replay_reports_and_metrics",
    governance_domain_id: "govreplay:domain:audit_domain",
    policy: {
      policy_id: input.request.policy.bundle_ref,
      policy_version: input.request.policy.policy_version,
    },
    predicate: {
      request_id: input.request.request_id,
      workflow_id: input.request.workflow_id,
      scenario_id: input.request.scenario_id,
      action_id: input.request.action.action_id,
      action_type: input.request.action.action_type,
      risk: input.request.action.risk,
      actor_id: input.request.actor.actor_id,
      resource_id: input.request.resource.resource_id,
      evidence_refs: input.request.evidence_refs,
      artifact_refs: input.request.artifact_refs,
      approval_refs: input.request.approval_refs,
      deployment_refs: input.request.deployment_refs,
      policy_decision_attestation_hash: input.policyDecisionAttestation.attestation_hash,
      gateway_decision_hash: digestJson({
        policy_decision_attestation_hash: input.policyDecisionAttestation.attestation_hash,
        request_id: input.request.request_id,
      }).value,
    },
  }, privateKey);
}

function samePolicySemantics(left: Record<string, unknown>, right: Record<string, unknown>): boolean {
  return JSON.stringify(normalizePolicyInput(left)) === JSON.stringify(normalizePolicyInput(right));
}

function normalizePolicyInput(input: Record<string, unknown>): unknown {
  const clone = structuredClone(input) as Record<string, unknown>;
  if (isRecord(clone.context)) {
    clone.context.workflow_id = "<workflow>";
    clone.context.run_id = "<run>";
  }
  return clone;
}

function actorTypeForPolicy(actorType: "agent" | "service"): "Agent" | "Service" {
  return actorType === "agent" ? "Agent" : "Service";
}

function readJson(path: string): Record<string, unknown> {
  const value = JSON.parse(readFileSync(path, "utf8"));
  assertRecord(value, path);
  return value;
}

function digestToCasUri(digest: DigestObject): string {
  return `cas://sha256/${digest.value.slice(2)}`;
}

function validateRefs(value: unknown, path: string): void {
  if (!Array.isArray(value)) {
    throw new TypeError(`${path} must be an array`);
  }
  for (const [index, item] of value.entries()) {
    assertRecord(item, `${path}[${index}]`);
    requireNonEmptyString(item.id, `${path}[${index}].id`);
    requireNonEmptyString(item.type, `${path}[${index}].type`);
    if ("uri" in item) {
      requireNonEmptyString(item.uri, `${path}[${index}].uri`);
    }
    if ("digest" in item) {
      assertRecord(item.digest, `${path}[${index}].digest`);
      requireLiteral(item.digest.algorithm, "sha256", `${path}[${index}].digest.algorithm`);
      requirePattern(item.digest.value, /^0x[0-9a-f]{64}$/, `${path}[${index}].digest.value`);
    }
  }
}

function assertRecord(value: unknown, path: string): asserts value is Record<string, unknown> {
  if (!isRecord(value)) {
    throw new TypeError(`${path} must be a JSON object`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireLiteral(value: unknown, expected: string, path: string): void {
  if (value !== expected) {
    throw new TypeError(`${path} must be ${expected}`);
  }
}

function requireNonEmptyString(value: unknown, path: string): void {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${path} must be a non-empty string`);
  }
}

function requirePattern(value: unknown, pattern: RegExp, path: string): void {
  requireNonEmptyString(value, path);
  if (!pattern.test(value as string)) {
    throw new TypeError(`${path} has invalid format: ${String(value)}`);
  }
}

function requireStringArray(value: unknown, path: string): void {
  if (!Array.isArray(value) || value.length === 0) {
    throw new TypeError(`${path} must be a non-empty array`);
  }
  for (const [index, item] of value.entries()) {
    requireNonEmptyString(item, `${path}[${index}]`);
  }
}

function requireEnum<T extends string>(value: unknown, expected: readonly T[], path: string): void {
  if (!expected.includes(value as T)) {
    throw new TypeError(`${path} must be one of ${expected.join(", ")}`);
  }
}

function requireUtcTimestamp(value: unknown, path: string): void {
  requireNonEmptyString(value, path);
  if (!String(value).endsWith("Z") || Number.isNaN(Date.parse(String(value)))) {
    throw new TypeError(`${path} must be a UTC timestamp`);
  }
}

export function availablePolicyBundles(fixtureRoot = defaultFixtureRoot): string[] {
  return readdirSync(fixtureRoot).sort();
}
