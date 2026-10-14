import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ObligationRule, PolicyBundle } from "./bundle-format.ts";

export type PolicyDecision = "allow" | "deny";

export type ObservedPolicyEvaluation = {
  policy_bundle_hash: string;
  policy_bundle_version: string;
  policy_input_hash: string;
  decision: PolicyDecision;
  obligations_hash: string;
  obligation_ids: string[];
  resolved_obligations: Record<string, unknown>[];
  policy_decision_hash: string;
  evaluator_identity: string;
  evaluator_version: string;
  evaluator_policy_language: "cedar";
  matched_policy_ids: string[];
};

type PermitRule = {
  id: string;
  action_id: string;
  conditions: string[];
};

const POLICY_EVALUATOR_IDENTITY = "govreplay:policy-evaluator:cedar-subset";
const POLICY_EVALUATOR_VERSION = "cedar-policy-4.11.1-compatible-ts-subset.v1";

export function evaluatePolicyInput(
  bundle: PolicyBundle,
  input: Record<string, unknown>,
): ObservedPolicyEvaluation {
  assertPolicyInput(input);
  const rules = permitRulesForBundle(bundle);
  const actionId = stringFromPath(input, ["action", "id"], "action.id");
  const matchedPolicyIds = rules
    .filter((rule) => rule.action_id === actionId && rule.conditions.every((condition) => conditionMatches(condition, input)))
    .map((rule) => rule.id);
  const decision: PolicyDecision = matchedPolicyIds.length > 0 ? "allow" : "deny";
  const resolved_obligations = resolveObligations(bundle, input);
  const obligation_ids = resolved_obligations.map((record) => String(record.id));
  const obligations_hash = policyServiceHashJson(resolved_obligations);
  const policy_input_hash = policyServiceHashJson(input);
  const material = {
    schema_version: "govprov.policy_evaluation.v1",
    policy_bundle_hash: bundle.bundle_hash,
    policy_bundle_version: bundle.metadata.version,
    policy_input_hash,
    decision,
    obligations_hash,
    evaluator_identity: POLICY_EVALUATOR_IDENTITY,
    evaluator_version: POLICY_EVALUATOR_VERSION,
    matched_policy_ids: matchedPolicyIds,
  };

  return {
    policy_bundle_hash: bundle.bundle_hash,
    policy_bundle_version: bundle.metadata.version,
    policy_input_hash,
    decision,
    obligations_hash,
    obligation_ids,
    resolved_obligations,
    policy_decision_hash: policyServiceHashJson(material),
    evaluator_identity: POLICY_EVALUATOR_IDENTITY,
    evaluator_version: POLICY_EVALUATOR_VERSION,
    evaluator_policy_language: "cedar",
    matched_policy_ids: matchedPolicyIds,
  };
}

export function resolveObligations(bundle: PolicyBundle, input: Record<string, unknown>): Record<string, unknown>[] {
  const actionId = stringFromPath(input, ["action", "id"], "action.id");
  const environment = stringFromPath(input, ["resource", "environment"], "resource.environment");
  const records = bundle.obligations.obligations
    .filter((obligation) => obligation.applies_to_actions.includes(actionId))
    .map((obligation) => resolvedObligation(bundle, obligation, actionId, environment));

  return records.sort((left, right) => String(left.id).localeCompare(String(right.id)));
}

export function policyServiceHashJson(value: unknown): string {
  return `0x${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

function permitRulesForBundle(bundle: PolicyBundle): PermitRule[] {
  return bundle.policy_files.flatMap((fileName) => {
    const source = readFileSync(join(bundle.directory, "policies", fileName), "utf8");
    const rules: PermitRule[] = [];
    const pattern = /permit\(\s*principal\s*,\s*action\s*==\s*GovProv::Action::"([^"]+)"\s*,\s*resource\s*\)\s*when\s*\{([\s\S]*?)\};/g;
    for (const match of source.matchAll(pattern)) {
      const index = rules.length + 1;
      const action_id = match[1];
      const body = match[2];
      rules.push({
        id: `${fileName}#permit-${index}-${action_id}`,
        action_id,
        conditions: body
          .split("\n")
          .map((line) => line.trim().replace(/&&$/, "").trim())
          .filter((line) => line.length > 0),
      });
    }
    if (rules.length === 0) {
      throw new TypeError(`${fileName} does not contain a supported Cedar permit block`);
    }
    return rules;
  });
}

function conditionMatches(condition: string, input: Record<string, unknown>): boolean {
  if (condition === "principal has roles") {
    return Array.isArray(valueFromPath(input, ["principal", "roles"]));
  }

  const roleMatch = condition.match(/^principal\.roles\.contains\("([^"]+)"\)$/);
  if (roleMatch !== null) {
    const roles = valueFromPath(input, ["principal", "roles"]);
    return Array.isArray(roles) && roles.includes(roleMatch[1]);
  }

  const equalityMatch = condition.match(/^(context|resource)\.([A-Za-z0-9_]+) == "([^"]+)"$/);
  if (equalityMatch !== null) {
    return fieldValue(input, equalityMatch[1], equalityMatch[2]) === equalityMatch[3];
  }

  const containsMatch = condition.match(/^\[([^\]]+)\]\.contains\((context|resource)\.([A-Za-z0-9_]+)\)$/);
  if (containsMatch !== null) {
    const allowed = [...containsMatch[1].matchAll(/"([^"]+)"/g)].map((item) => item[1]);
    return allowed.includes(String(fieldValue(input, containsMatch[2], containsMatch[3]) ?? ""));
  }

  throw new TypeError(`Unsupported Cedar condition in policy fixture: ${condition}`);
}

function fieldValue(input: Record<string, unknown>, scope: string, field: string): unknown {
  return valueFromPath(input, [scope, field]);
}

function resolvedObligation(
  bundle: PolicyBundle,
  obligation: ObligationRule,
  actionId: string,
  resourceEnvironment: string,
): Record<string, unknown> {
  return {
    schema_version: "govprov.resolved_obligation.v1",
    id: obligation.id,
    policy_bundle_hash: bundle.bundle_hash,
    action_id: actionId,
    resource_environment: resourceEnvironment,
    decision_ttl_seconds: bundle.obligations.defaults.decision_ttl_seconds,
    categories: {
      required_evidence: obligation.required_evidence,
      required_approval_roles: obligation.required_approval_roles,
      separation_of_duties: obligation.separation_of_duties,
      deployment_environment_constraints: obligation.deployment_environment_constraints,
      attestation_requirements: obligation.attestation_requirements,
      expiration: obligation.expiration,
    },
  };
}

function assertPolicyInput(input: Record<string, unknown>): void {
  for (const path of [
    ["principal", "roles"],
    ["action", "id"],
    ["resource", "environment"],
    ["context", "risk_tier"],
    ["context", "evidence_profile"],
    ["context", "approval_profile"],
    ["context", "artifact_linkage"],
    ["context", "policy_ref_profile"],
  ]) {
    if (valueFromPath(input, path) === undefined) {
      throw new TypeError(`policy input missing ${path.join(".")}`);
    }
  }
}

function stringFromPath(record: Record<string, unknown>, path: string[], label: string): string {
  const value = valueFromPath(record, path);
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${label} must be a string`);
  }
  return value;
}

function valueFromPath(record: Record<string, unknown>, path: string[]): unknown {
  let value: unknown = record;
  for (const item of path) {
    if (!isRecord(value)) {
      return undefined;
    }
    value = value[item];
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
