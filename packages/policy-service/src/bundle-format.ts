import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";

export type PolicyLanguage = "cedar";

export interface PolicyBundleMetadata {
  policy_bundle_id: string;
  version: string;
  created_at: string;
  author: string;
  parent_policy_bundle_hash: string | null;
  description: string;
  compatible_contract_set: string;
  policy_language: PolicyLanguage;
  schema_version: "govprov.policy_bundle.v1";
}

export interface ObligationsDocument {
  schema_version: "govprov.obligations.v1";
  defaults: {
    decision_ttl_seconds: number;
  };
  obligations: ObligationRule[];
}

export interface ObligationRule {
  id: string;
  description: string;
  applies_to_actions: string[];
  required_evidence: {
    min_count: number;
    evidence_types: string[];
  };
  required_approval_roles: string[];
  separation_of_duties: {
    proposer_cannot_approve: boolean;
    distinct_approval_count: number;
  };
  deployment_environment_constraints: {
    allowed_environments: string[];
    forbidden_environments: string[];
  };
  attestation_requirements: {
    required_attestation_types: string[];
    policy_decision_must_include_bundle_hash: boolean;
  };
  expiration: {
    approval_max_age_seconds: number;
    evidence_max_age_seconds: number;
  };
}

export interface PolicyBundle {
  directory: string;
  metadata: PolicyBundleMetadata;
  obligations: ObligationsDocument;
  cedar_schema: string;
  policy_files: string[];
  test_files: string[];
  bundle_hash: string;
}

export function loadPolicyBundle(directory: string): PolicyBundle {
  assertDirectory(directory, "bundle root");

  const metadata = parseJsonFile(join(directory, "metadata.json")) as unknown;
  assertPolicyBundleMetadata(metadata);

  const obligations = parseJsonCompatibleYaml(join(directory, "obligations.yml")) as unknown;
  assertObligationsDocument(obligations);

  const cedarSchemaPath = join(directory, "schema.cedarschema");
  const cedar_schema = readRequiredText(cedarSchemaPath);
  if (cedar_schema.trim().length === 0) {
    throw new TypeError("schema.cedarschema must not be empty");
  }

  const policyDir = join(directory, "policies");
  const testDir = join(directory, "tests");
  assertDirectory(policyDir, "policies directory");
  assertDirectory(testDir, "tests directory");

  const policy_files = readdirSync(policyDir)
    .filter((name) => name.endsWith(".cedar"))
    .sort();
  if (policy_files.length === 0) {
    throw new TypeError("policies directory must contain at least one .cedar file");
  }
  for (const name of policy_files) {
    const contents = readRequiredText(join(policyDir, name));
    if (!contents.includes("permit") && !contents.includes("forbid")) {
      throw new TypeError(`Policy file ${name} must contain a Cedar permit or forbid policy`);
    }
  }

  const test_files = readdirSync(testDir)
    .filter((name) => name.endsWith(".json"))
    .sort();
  if (test_files.length === 0) {
    throw new TypeError("tests directory must contain at least one .json file");
  }
  for (const name of test_files) {
    assertPolicyTestCase(parseJsonFile(join(testDir, name)), name);
  }

  return {
    directory,
    metadata,
    obligations,
    cedar_schema,
    policy_files,
    test_files,
    bundle_hash: computePolicyBundleHash(directory),
  };
}

export function computePolicyBundleHash(directory: string): string {
  const hash = createHash("sha256");
  for (const relativePath of listBundleFiles(directory)) {
    hash.update(relativePath);
    hash.update("\0");
    hash.update(readFileSync(join(directory, relativePath)));
    hash.update("\0");
  }
  return `0x${hash.digest("hex")}`;
}

export function listBundleFiles(directory: string): string[] {
  const requiredFiles = ["metadata.json", "schema.cedarschema", "obligations.yml"];
  const files: string[] = [];

  for (const name of requiredFiles) {
    const path = join(directory, name);
    if (!statSync(path, { throwIfNoEntry: false })?.isFile()) {
      throw new TypeError(`Missing required bundle file: ${name}`);
    }
    files.push(name);
  }

  for (const childDir of ["policies", "tests"]) {
    assertDirectory(join(directory, childDir), `${childDir} directory`);
    for (const name of readdirSync(join(directory, childDir)).sort()) {
      const path = join(directory, childDir, name);
      if (statSync(path).isFile()) {
        files.push(`${childDir}/${name}`);
      }
    }
  }

  return files.sort();
}

export function assertPolicyBundleMetadata(value: unknown): asserts value is PolicyBundleMetadata {
  assertPlainObject(value, "metadata");
  assertStringPattern(value.policy_bundle_id, /^[a-z0-9][a-z0-9-]*$/, "metadata.policy_bundle_id");
  assertStringPattern(value.version, /^\d+\.\d+\.\d+$/, "metadata.version");
  assertUtcTimestamp(value.created_at, "metadata.created_at");
  assertStringPattern(value.author, /^govprov:actor:[a-zA-Z0-9._:-]+$/, "metadata.author");
  if (value.parent_policy_bundle_hash !== null) {
    assertBytes32(value.parent_policy_bundle_hash, "metadata.parent_policy_bundle_hash");
  }
  assertNonEmptyString(value.description, "metadata.description");
  assertNonEmptyString(value.compatible_contract_set, "metadata.compatible_contract_set");
  assertLiteral(value.policy_language, "cedar", "metadata.policy_language");
  assertLiteral(value.schema_version, "govprov.policy_bundle.v1", "metadata.schema_version");
}

export function assertObligationsDocument(value: unknown): asserts value is ObligationsDocument {
  assertPlainObject(value, "obligations document");
  assertLiteral(value.schema_version, "govprov.obligations.v1", "obligations.schema_version");
  assertPlainObject(value.defaults, "obligations.defaults");
  assertPositiveInteger(value.defaults.decision_ttl_seconds, "obligations.defaults.decision_ttl_seconds");
  assertArray(value.obligations, "obligations.obligations");
  if (value.obligations.length === 0) {
    throw new TypeError("obligations.obligations must not be empty");
  }

  const ids = new Set<string>();
  for (const [index, obligation] of value.obligations.entries()) {
    assertObligationRule(obligation, `obligations.obligations[${index}]`);
    if (ids.has(obligation.id)) {
      throw new TypeError(`Duplicate obligation id: ${obligation.id}`);
    }
    ids.add(obligation.id);
  }
}

function assertObligationRule(value: unknown, path: string): asserts value is ObligationRule {
  assertPlainObject(value, path);
  assertStringPattern(value.id, /^[a-z0-9][a-z0-9-]*$/, `${path}.id`);
  assertNonEmptyString(value.description, `${path}.description`);
  assertStringArray(value.applies_to_actions, `${path}.applies_to_actions`);

  assertPlainObject(value.required_evidence, `${path}.required_evidence`);
  assertPositiveInteger(value.required_evidence.min_count, `${path}.required_evidence.min_count`);
  assertStringArray(value.required_evidence.evidence_types, `${path}.required_evidence.evidence_types`);

  assertStringArray(value.required_approval_roles, `${path}.required_approval_roles`);

  assertPlainObject(value.separation_of_duties, `${path}.separation_of_duties`);
  assertBoolean(value.separation_of_duties.proposer_cannot_approve, `${path}.separation_of_duties.proposer_cannot_approve`);
  assertNonNegativeInteger(value.separation_of_duties.distinct_approval_count, `${path}.separation_of_duties.distinct_approval_count`);

  assertPlainObject(value.deployment_environment_constraints, `${path}.deployment_environment_constraints`);
  assertStringArray(value.deployment_environment_constraints.allowed_environments, `${path}.deployment_environment_constraints.allowed_environments`);
  assertStringArray(value.deployment_environment_constraints.forbidden_environments, `${path}.deployment_environment_constraints.forbidden_environments`);

  assertPlainObject(value.attestation_requirements, `${path}.attestation_requirements`);
  assertStringArray(value.attestation_requirements.required_attestation_types, `${path}.attestation_requirements.required_attestation_types`);
  assertBoolean(
    value.attestation_requirements.policy_decision_must_include_bundle_hash,
    `${path}.attestation_requirements.policy_decision_must_include_bundle_hash`,
  );

  assertPlainObject(value.expiration, `${path}.expiration`);
  assertPositiveInteger(value.expiration.approval_max_age_seconds, `${path}.expiration.approval_max_age_seconds`);
  assertPositiveInteger(value.expiration.evidence_max_age_seconds, `${path}.expiration.evidence_max_age_seconds`);
}

function assertPolicyTestCase(value: unknown, fileName: string): void {
  assertPlainObject(value, `tests/${fileName}`);
  assertNonEmptyString(value.name, `tests/${fileName}.name`);
  assertLiteralOneOf(value.expected_decision, ["allow", "deny"], `tests/${fileName}.expected_decision`);
  assertPlainObject(value.input, `tests/${fileName}.input`);
  assertPlainObject(value.input.principal, `tests/${fileName}.input.principal`);
  assertPlainObject(value.input.action, `tests/${fileName}.input.action`);
  assertPlainObject(value.input.resource, `tests/${fileName}.input.resource`);
  assertPlainObject(value.input.context, `tests/${fileName}.input.context`);
}

function parseJsonFile(path: string): unknown {
  return JSON.parse(readRequiredText(path));
}

function parseJsonCompatibleYaml(path: string): unknown {
  try {
    return JSON.parse(readRequiredText(path));
  } catch (error) {
    throw new TypeError(`${basename(path)} must use the P4-S1 JSON-compatible YAML subset: ${(error as Error).message}`);
  }
}

function readRequiredText(path: string): string {
  const stats = statSync(path, { throwIfNoEntry: false });
  if (!stats?.isFile()) {
    throw new TypeError(`Missing required file: ${path}`);
  }
  return readFileSync(path, "utf8");
}

function assertDirectory(path: string, label: string): void {
  const stats = statSync(path, { throwIfNoEntry: false });
  if (!stats?.isDirectory()) {
    throw new TypeError(`Missing required ${label}: ${path}`);
  }
}

function assertPlainObject(value: unknown, path: string): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${path} must be a JSON object`);
  }
}

function assertArray(value: unknown, path: string): asserts value is unknown[] {
  if (!Array.isArray(value)) {
    throw new TypeError(`${path} must be an array`);
  }
}

function assertStringArray(value: unknown, path: string): asserts value is string[] {
  assertArray(value, path);
  if (value.length === 0) {
    throw new TypeError(`${path} must not be empty`);
  }
  for (const [index, item] of value.entries()) {
    assertNonEmptyString(item, `${path}[${index}]`);
  }
}

function assertNonEmptyString(value: unknown, path: string): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${path} must be a non-empty string`);
  }
}

function assertStringPattern(value: unknown, pattern: RegExp, path: string): asserts value is string {
  assertNonEmptyString(value, path);
  if (!pattern.test(value)) {
    throw new TypeError(`${path} has invalid format: ${value}`);
  }
}

function assertUtcTimestamp(value: unknown, path: string): asserts value is string {
  assertStringPattern(value, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, path);
  if (Number.isNaN(Date.parse(value))) {
    throw new TypeError(`${path} must be a valid UTC timestamp`);
  }
}

function assertBytes32(value: unknown, path: string): asserts value is string {
  assertStringPattern(value, /^0x[0-9a-f]{64}$/, path);
}

function assertBoolean(value: unknown, path: string): asserts value is boolean {
  if (typeof value !== "boolean") {
    throw new TypeError(`${path} must be a boolean`);
  }
}

function assertPositiveInteger(value: unknown, path: string): asserts value is number {
  if (!Number.isInteger(value) || (value as number) <= 0) {
    throw new TypeError(`${path} must be a positive integer`);
  }
}

function assertNonNegativeInteger(value: unknown, path: string): asserts value is number {
  if (!Number.isInteger(value) || (value as number) < 0) {
    throw new TypeError(`${path} must be a non-negative integer`);
  }
}

function assertLiteral<T extends string>(value: unknown, expected: T, path: string): asserts value is T {
  if (value !== expected) {
    throw new TypeError(`${path} must be ${expected}`);
  }
}

function assertLiteralOneOf<T extends string>(value: unknown, expected: readonly T[], path: string): asserts value is T {
  if (!expected.includes(value as T)) {
    throw new TypeError(`${path} must be one of ${expected.join(", ")}`);
  }
}
