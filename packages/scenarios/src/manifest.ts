export type ScenarioManifest = {
  schema_version: "govprov.scenario_manifest.v1";
  scenario_id: string;
  scenario_name: string;
  workflow_id: string;
  policy_version: string;
  fault_id: string;
  mode: "structured_logs" | "signed_offchain" | "govreplay_besu";
  governance_domain?: string;
  governance_domain_type?: string;
  governance_domain_id?: string;
  expected_domain?: string;
  domain_fault?: boolean;
  cross_domain_dependency?: string[];
  expected_verdict: "pass" | "fail";
  expected_failure_code: string | null;
  expected_failure_stage:
    | "observation"
    | "evidence"
    | "policy"
    | "action"
    | "approval"
    | "artifact"
    | "deployment"
    | "artifact_deployment"
    | "ledger"
    | "replay"
    | null;
  expected_historical_compliance: "pass" | "fail";
  expected_current_compliance: "pass" | "fail";
  primary_actor_id: string;
  resource_id: string;
  created_at: string;
};

const requiredFields: Array<keyof ScenarioManifest> = [
  "schema_version",
  "scenario_id",
  "scenario_name",
  "workflow_id",
  "policy_version",
  "fault_id",
  "mode",
  "expected_verdict",
  "expected_failure_code",
  "expected_failure_stage",
  "expected_historical_compliance",
  "expected_current_compliance",
  "primary_actor_id",
  "resource_id",
  "created_at",
];

const allowedModes = new Set(["structured_logs", "signed_offchain", "govreplay_besu"]);
const allowedVerdicts = new Set(["pass", "fail"]);
const allowedCompliance = new Set(["pass", "fail"]);
const optionalFields = new Set(["governance_domain", "governance_domain_type", "governance_domain_id", "expected_domain", "domain_fault", "cross_domain_dependency"]);
const allowedGovernanceDomains = new Set([
  "identity_domain",
  "policy_domain",
  "approval_domain",
  "deployment_domain",
  "anchor_domain",
  "contract_domain",
  "audit_domain",
]);
const allowedFailureStages = new Set([
  "observation",
  "evidence",
  "policy",
  "action",
  "approval",
  "artifact",
  "deployment",
  "artifact_deployment",
  "ledger",
  "replay",
]);

export function validateScenarioManifest(value: unknown): ScenarioManifest {
  if (!isRecord(value)) {
    throw new TypeError("manifest must be an object");
  }

  const allowedFields = new Set<string>([...requiredFields, ...optionalFields]);
  for (const key of Object.keys(value)) {
    if (!allowedFields.has(key)) {
      throw new TypeError(`manifest has unknown field: ${key}`);
    }
  }

  for (const field of requiredFields) {
    if (!(field in value)) {
      throw new TypeError(`manifest is missing required field: ${field}`);
    }
  }

  requireLiteral(value.schema_version, "govprov.scenario_manifest.v1", "schema_version");
  requirePattern(value.scenario_id, /^S[1-9][0-9]*(_[a-z0-9]+)*$/, "scenario_id");
  requireNonEmptyString(value.scenario_name, "scenario_name");
  requirePattern(value.workflow_id, /^wf-[A-Za-z0-9_-]+$/, "workflow_id");
  requirePattern(value.policy_version, /^P[1-9][0-9]*$/, "policy_version");
  requirePattern(value.fault_id, /^F[0-9]+$/, "fault_id");
  requireEnum(value.mode, allowedModes, "mode");
  if ("governance_domain" in value) {
    requireEnum(value.governance_domain, allowedGovernanceDomains, "governance_domain");
  }
  if ("governance_domain_type" in value) {
    requireNonEmptyString(value.governance_domain_type, "governance_domain_type");
  }
  if ("governance_domain_id" in value) {
    requirePattern(value.governance_domain_id, /^govreplay:domain:[a-z_]+$/, "governance_domain_id");
  }
  if ("expected_domain" in value) {
    requireEnum(value.expected_domain, allowedGovernanceDomains, "expected_domain");
  }
  if ("domain_fault" in value && typeof value.domain_fault !== "boolean") {
    throw new TypeError("domain_fault must be a boolean");
  }
  if ("cross_domain_dependency" in value) {
    requireDomainArray(value.cross_domain_dependency, "cross_domain_dependency");
  }
  requireEnum(value.expected_verdict, allowedVerdicts, "expected_verdict");
  requireEnum(value.expected_historical_compliance, allowedCompliance, "expected_historical_compliance");
  requireEnum(value.expected_current_compliance, allowedCompliance, "expected_current_compliance");
  requirePattern(value.primary_actor_id, /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/, "primary_actor_id");
  requireNonEmptyString(value.resource_id, "resource_id");
  requireDateTime(value.created_at, "created_at");

  if (value.expected_verdict === "pass") {
    requireNull(value.expected_failure_code, "expected_failure_code");
    requireNull(value.expected_failure_stage, "expected_failure_stage");
  } else {
    requireNonEmptyString(value.expected_failure_code, "expected_failure_code");
    requireEnum(value.expected_failure_stage, allowedFailureStages, "expected_failure_stage");
  }

  return value as ScenarioManifest;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireLiteral(value: unknown, expected: string, field: string): void {
  if (value !== expected) {
    throw new TypeError(`${field} must be ${expected}`);
  }
}

function requireNonEmptyString(value: unknown, field: string): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${field} must be a non-empty string`);
  }
}

function requirePattern(value: unknown, pattern: RegExp, field: string): void {
  requireNonEmptyString(value, field);
  if (!pattern.test(value as string)) {
    throw new TypeError(`${field} has invalid format`);
  }
}

function requireEnum(value: unknown, allowed: Set<string>, field: string): void {
  if (typeof value !== "string" || !allowed.has(value)) {
    throw new TypeError(`${field} is not an allowed value`);
  }
}

function requireNull(value: unknown, field: string): void {
  if (value !== null) {
    throw new TypeError(`${field} must be null`);
  }
}

function requireDateTime(value: unknown, field: string): void {
  requireNonEmptyString(value, field);
  const parsed = Date.parse(value as string);
  if (Number.isNaN(parsed) || !(value as string).endsWith("Z")) {
    throw new TypeError(`${field} must be a UTC RFC 3339 timestamp`);
  }
}

function requireDomainArray(value: unknown, field: string): void {
  if (!Array.isArray(value)) {
    throw new TypeError(`${field} must be an array`);
  }
  for (const item of value) {
    requireEnum(item, allowedGovernanceDomains, field);
  }
}
