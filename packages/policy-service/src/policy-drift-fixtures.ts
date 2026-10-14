import { mkdir, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  loadPolicyBundle,
  type PolicyBundle,
} from "./bundle-format.ts";
import { policyDecisionFixtureDir } from "./policy-decision-attestation.ts";

export const policyDriftFixturePath = join(import.meta.dirname, "..", "fixtures", "policy-drift-cases.json");

export type PolicyDriftClassification =
  | "historical_pass_current_pass"
  | "historical_pass_current_fail"
  | "historical_fail_current_fail"
  | "historical_fail_current_pass"
  | "policy_not_available"
  | "policy_hash_mismatch";

export interface PolicyDriftCase {
  id: string;
  classification: PolicyDriftClassification;
  historical_attestation_file: string;
  historical_policy_bundle_hash: string;
  current_policy_bundle_name: string | null;
  current_policy_bundle_hash: string | null;
  historical_decision: "allow" | "deny";
  current_decision: "allow" | "deny" | "unavailable";
  policy_hash_consistent: boolean;
  action_id: string;
  workflow_id: string;
  note: string;
}

interface DriftCaseSpec {
  id: string;
  historicalFile: string;
  currentBundleName: string | null;
  tamperHistoricalPolicyHash?: boolean;
  note: string;
}

const bundleRoot = join(import.meta.dirname, "..", "fixtures", "bundles");

const driftSpecs: DriftCaseSpec[] = [
  {
    id: "drift-001-p3-historical-current-pass",
    historicalFile: "software-delivery-p3-evidence-strengthened.allow-runbook-strengthened-evidence.signed.attestation.json",
    currentBundleName: "software-delivery-p3-evidence-strengthened",
    note: "P3 runbook decision remains compliant under the current P3 bundle.",
  },
  {
    id: "drift-002-p1-pass-p3-current-fail",
    historicalFile: "software-delivery-p1-baseline.allow-runbook-baseline.signed.attestation.json",
    currentBundleName: "software-delivery-p3-evidence-strengthened",
    note: "P1 baseline runbook evidence passed historically but fails current P3 strengthened evidence requirements.",
  },
  {
    id: "drift-003-p1-fail-p3-current-fail",
    historicalFile: "software-delivery-p1-baseline.deny-runbook-missing-evidence.signed.attestation.json",
    currentBundleName: "software-delivery-p3-evidence-strengthened",
    note: "Missing runbook evidence fails historically and still fails current P3.",
  },
  {
    id: "drift-004-p3-fail-p1-current-pass",
    historicalFile: "software-delivery-p3-evidence-strengthened.deny-runbook-baseline-evidence.signed.attestation.json",
    currentBundleName: "software-delivery-p1-baseline",
    note: "A P3-denied baseline-evidence runbook update would pass the older P1 baseline bundle.",
  },
  {
    id: "drift-005-policy-not-available",
    historicalFile: "software-delivery-p2-strict-approval.allow-config-dual-approval.signed.attestation.json",
    currentBundleName: null,
    note: "Replay cannot load the requested current policy bundle.",
  },
  {
    id: "drift-006-policy-hash-mismatch",
    historicalFile: "software-delivery-p2-strict-approval.deny-config-self-approval.signed.attestation.json",
    currentBundleName: "software-delivery-p2-strict-approval",
    tamperHistoricalPolicyHash: true,
    note: "The historical attestation's claimed policy hash does not match the signed decision predicate.",
  },
];

export function generatePolicyDriftCases(): PolicyDriftCase[] {
  return driftSpecs.map((spec) => generatePolicyDriftCase(spec));
}

export async function writePolicyDriftFixture(path = policyDriftFixturePath): Promise<void> {
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, `${serializePolicyDriftCases(generatePolicyDriftCases())}\n`);
}

export function serializePolicyDriftCases(cases: PolicyDriftCase[]): string {
  return JSON.stringify({ schema_version: "govprov.policy_drift_fixtures.v1", cases }, null, 2);
}

function generatePolicyDriftCase(spec: DriftCaseSpec): PolicyDriftCase {
  const historical = loadHistoricalDecision(spec.historicalFile, spec.tamperHistoricalPolicyHash === true);
  const currentBundle = spec.currentBundleName === null
    ? null
    : loadPolicyBundle(join(bundleRoot, spec.currentBundleName));
  const currentDecision = currentBundle === null
    ? "unavailable"
    : evaluateCurrentDecision(currentBundle, historical.policyInput);
  const classification = classifyDrift(
    historical.decision,
    currentDecision,
    historical.policyHashConsistent,
  );

  return {
    id: spec.id,
    classification,
    historical_attestation_file: spec.historicalFile,
    historical_policy_bundle_hash: historical.policyBundleHash,
    current_policy_bundle_name: spec.currentBundleName,
    current_policy_bundle_hash: currentBundle?.bundle_hash ?? null,
    historical_decision: historical.decision,
    current_decision: currentDecision,
    policy_hash_consistent: historical.policyHashConsistent,
    action_id: historical.actionId,
    workflow_id: historical.workflowId,
    note: spec.note,
  };
}

function loadHistoricalDecision(fileName: string, tamperPolicyHash: boolean) {
  const attestation = JSON.parse(readFileSync(join(policyDecisionFixtureDir, fileName), "utf8")) as Record<string, unknown>;
  const predicate = requiredRecord(attestation.predicate, "predicate");
  const policy = requiredRecord(predicate.policy, "predicate.policy");
  const policyHash = requiredRecord(policy.policy_hash, "predicate.policy.policy_hash");
  const claimedPolicyHash = tamperPolicyHash
    ? "0x0000000000000000000000000000000000000000000000000000000000000000"
    : requiredString(predicate.policy_bundle_hash, "predicate.policy_bundle_hash");
  const policyHashValue = requiredString(policyHash.value, "predicate.policy.policy_hash.value");
  const decision = requiredDecision(predicate.decision);
  const materialInput = signedDecisionInput(fileName);

  return {
    decision,
    policyBundleHash: claimedPolicyHash,
    policyHashConsistent: claimedPolicyHash === policyHashValue,
    policyInput: materialInput,
    actionId: requiredString(predicate.action_id, "predicate.action_id"),
    workflowId: requiredString(predicate.workflow_id, "predicate.workflow_id"),
  };
}

function signedDecisionInput(fileName: string): Record<string, unknown> {
  const [bundleName, testName] = fileName
    .replace(".signed.attestation.json", "")
    .split(/(?<=software-delivery-p[123](?:-baseline|-strict-approval|-evidence-strengthened))\./);
  if (bundleName === undefined || testName === undefined) {
    throw new TypeError(`Cannot map policy decision fixture to policy input: ${fileName}`);
  }
  const testPath = join(bundleRoot, bundleName, "tests", `${testName}.json`);
  const testCase = JSON.parse(readFileSync(testPath, "utf8")) as Record<string, unknown>;
  return requiredRecord(testCase.input, `${testPath}.input`);
}

function evaluateCurrentDecision(bundle: PolicyBundle, input: Record<string, unknown>): "allow" | "deny" {
  const actionId = stringFromPath(input, ["action", "id"], "action.id");
  const environment = stringFromPath(input, ["resource", "environment"], "resource.environment");
  const riskTier = stringFromPath(input, ["context", "risk_tier"], "context.risk_tier");
  const evidenceProfile = stringFromPath(input, ["context", "evidence_profile"], "context.evidence_profile");
  const approvalProfile = stringFromPath(input, ["context", "approval_profile"], "context.approval_profile");
  const artifactLinkage = stringFromPath(input, ["context", "artifact_linkage"], "context.artifact_linkage");
  const policyRefProfile = stringFromPath(input, ["context", "policy_ref_profile"], "context.policy_ref_profile");

  switch (bundle.directory.split(/[\\/]/).pop()) {
    case "software-delivery-p1-baseline":
      if (
        actionId === "propose_runbook_update" &&
        ["staging", "documentation"].includes(environment) &&
        ["low", "medium"].includes(riskTier) &&
        ["baseline", "strengthened"].includes(evidenceProfile)
      ) {
        return "allow";
      }
      if (
        actionId === "propose_config_change" &&
        environment === "staging" &&
        approvalProfile === "single_config_approver"
      ) {
        return "allow";
      }
      return "deny";
    case "software-delivery-p2-strict-approval":
      if (
        actionId === "propose_config_change" &&
        environment === "production" &&
        riskTier === "high" &&
        approvalProfile === "dual_distinct_config_approvers"
      ) {
        return "allow";
      }
      if (
        actionId === "deploy_artifact" &&
        environment === "production" &&
        approvalProfile === "deploy_approver_distinct" &&
        artifactLinkage === "approved_artifact"
      ) {
        return "allow";
      }
      return "deny";
    case "software-delivery-p3-evidence-strengthened":
      if (
        actionId === "propose_runbook_update" &&
        ["documentation", "staging"].includes(environment) &&
        evidenceProfile === "strengthened" &&
        policyRefProfile === "bundle_hash_present"
      ) {
        return "allow";
      }
      if (
        actionId === "deploy_artifact" &&
        environment === "production" &&
        artifactLinkage === "approved_artifact_with_ledger_anchor" &&
        policyRefProfile === "bundle_hash_present"
      ) {
        return "allow";
      }
      return "deny";
    default:
      throw new TypeError(`Unsupported current bundle: ${bundle.directory}`);
  }
}

function classifyDrift(
  historicalDecision: "allow" | "deny",
  currentDecision: "allow" | "deny" | "unavailable",
  hashConsistent: boolean,
): PolicyDriftClassification {
  if (!hashConsistent) {
    return "policy_hash_mismatch";
  }
  if (currentDecision === "unavailable") {
    return "policy_not_available";
  }
  if (historicalDecision === "allow" && currentDecision === "allow") {
    return "historical_pass_current_pass";
  }
  if (historicalDecision === "allow" && currentDecision === "deny") {
    return "historical_pass_current_fail";
  }
  if (historicalDecision === "deny" && currentDecision === "deny") {
    return "historical_fail_current_fail";
  }
  return "historical_fail_current_pass";
}

function requiredDecision(value: unknown): "allow" | "deny" {
  if (value !== "allow" && value !== "deny") {
    throw new TypeError("predicate.decision must be allow or deny");
  }
  return value;
}

function requiredRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${label} must be a string`);
  }
  return value;
}

function stringFromPath(record: Record<string, unknown>, path: string[], label: string): string {
  let value: unknown = record;
  for (const item of path) {
    value = requiredRecord(value, label)[item];
  }
  return requiredString(value, label);
}

if (process.argv.includes("--write")) {
  await writePolicyDriftFixture();
}
