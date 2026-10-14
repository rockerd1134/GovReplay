// Research fixture/demo code: embedded keys are public synthetic test vectors.
// Never use these keys or this fixture signer for production accounts. See SECURITY.md.
import { mkdir, writeFile } from "node:fs/promises";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { digestJson, type DigestObject } from "../../attestations/src/digest.ts";
import {
  addressFromPrivateKey,
  signAttestation,
  type SignedAttestation,
} from "../../attestations/src/signing.ts";
import {
  loadPolicyBundle,
  type PolicyBundle,
} from "./bundle-format.ts";
import {
  evaluatePolicyInput,
  type ObservedPolicyEvaluation,
} from "./policy-evaluator.ts";

export const policyDecisionFixtureDir = join(import.meta.dirname, "..", "fixtures", "policy-decisions");

export const POLICY_SERVICE_PRIVATE_KEY =
  "0x0000000000000000000000000000000000000000000000000000000000000003";

export interface PolicyDecisionFixtureInput {
  bundleName: string;
  testFile: string;
  testName: string;
  input: Record<string, unknown>;
}

export type PolicyDecisionAttestationMaterial = ObservedPolicyEvaluation;

export function generatePolicyDecisionAttestations(
  fixtureRoot = join(import.meta.dirname, "..", "fixtures", "bundles"),
): Record<string, SignedAttestation> {
  const output: Record<string, SignedAttestation> = {};
  for (const bundleName of readdirSync(fixtureRoot).sort()) {
    const bundle = loadPolicyBundle(join(fixtureRoot, bundleName));
    for (const fixture of policyDecisionFixtureInputs(bundleName, bundle)) {
      output[attestationFixtureName(fixture)] = signPolicyDecisionAttestation(bundle, fixture);
    }
  }
  return output;
}

export async function writePolicyDecisionAttestationFixtures(outputDir = policyDecisionFixtureDir): Promise<void> {
  await mkdir(outputDir, { recursive: true });
  const fixtures = generatePolicyDecisionAttestations();
  await Promise.all(
    Object.entries(fixtures).map(([name, attestation]) =>
      writeFile(join(outputDir, name), `${serializePolicyDecisionAttestation(attestation)}\n`),
    ),
  );
}

export function serializePolicyDecisionAttestation(attestation: SignedAttestation): string {
  return JSON.stringify(attestation, null, 2);
}

export function signPolicyDecisionAttestation(
  bundle: PolicyBundle,
  fixture: PolicyDecisionFixtureInput,
): SignedAttestation {
  const material = policyDecisionMaterial(bundle, fixture);
  const workflowId = stringFromPath(fixture.input, ["context", "workflow_id"], "workflow_id");
  const runId = stringFromPath(fixture.input, ["context", "run_id"], "run_id");
  const actionId = stringFromPath(fixture.input, ["action", "id"], "action.id");
  const subject = digestJson({
    decision: material.decision,
    obligations_hash: material.obligations_hash,
    policy_bundle_hash: material.policy_bundle_hash,
    policy_decision_hash: material.policy_decision_hash,
    policy_input_hash: material.policy_input_hash,
  });

  return signAttestation({
    _type: "https://govprov.dev/attestation/v1",
    schema_version: "govprov.attestation.v1",
    attestation_type: "PolicyDecisionAttestation",
    predicate_type: "https://govprov.dev/predicate/policy-decision/v1",
    subject: [
      {
        name: `policy-decision/${fixture.bundleName}/${fixture.testFile}`,
        digest: subject,
        uri: digestToCasUri(subject),
      },
    ],
    parents: [],
    created_at: "2026-06-20T00:00:00Z",
    created_by: {
      actor_id: "govprov:actor:policy-service",
      actor_type: "service",
      ethereum_address: addressFromPrivateKey(POLICY_SERVICE_PRIVATE_KEY),
    },
    policy: {
      policy_id: bundle.metadata.policy_bundle_id,
      policy_hash: material.policy_bundle_hash,
      scope_hash: digestJson({
        action_id: actionId,
        compatible_contract_set: bundle.metadata.compatible_contract_set,
      }).value,
    },
    predicate: {
      workflow_id: workflowId,
      run_id: runId,
      evaluated_at: "2026-06-20T00:00:00Z",
      policy_service_run_id: material.evaluator_identity,
      evaluator_identity: material.evaluator_identity,
      evaluator_version: material.evaluator_version,
      evaluator_policy_language: material.evaluator_policy_language,
      matched_policy_ids: material.matched_policy_ids,
      policy: {
        policy_id: bundle.metadata.policy_bundle_id,
        policy_version: bundle.metadata.version,
        policy_bundle_version: material.policy_bundle_version,
        policy_hash: {
          algorithm: "sha256",
          value: material.policy_bundle_hash,
        },
        parent_policy_bundle_hash: bundle.metadata.parent_policy_bundle_hash,
        policy_bundle_uri: digestToCasUri({ algorithm: "sha256", value: material.policy_bundle_hash }),
        policy_engine: "cedar",
        policy_engine_version: "cedar-policy-4.11.1",
      },
      action_id: actionId,
      decision: material.decision,
      policy_bundle_hash: material.policy_bundle_hash,
      policy_bundle_version: material.policy_bundle_version,
      policy_input_hash: material.policy_input_hash,
      policy_input_digest: {
        algorithm: "sha256",
        value: material.policy_input_hash,
      },
      obligations_hash: material.obligations_hash,
      obligation_ids: material.obligation_ids,
      resolved_obligations: material.resolved_obligations,
      policy_decision_hash: material.policy_decision_hash,
    },
  }, POLICY_SERVICE_PRIVATE_KEY);
}

export function policyDecisionMaterial(
  bundle: PolicyBundle,
  fixture: PolicyDecisionFixtureInput,
): PolicyDecisionAttestationMaterial {
  return evaluatePolicyInput(bundle, fixture.input);
}

function policyDecisionFixtureInputs(bundleName: string, bundle: PolicyBundle): PolicyDecisionFixtureInput[] {
  return bundle.test_files.map((testFile) => {
    const value = JSON.parse(readFileSync(join(bundle.directory, "tests", testFile), "utf8")) as Record<string, unknown>;
    const declaredOracleDecision = value.expected_decision;
    if (declaredOracleDecision !== "allow" && declaredOracleDecision !== "deny") {
      throw new TypeError(`${testFile}.expected_decision must be allow or deny`);
    }
    if (!isRecord(value.input)) {
      throw new TypeError(`${testFile}.input must be an object`);
    }

    return {
      bundleName,
      testFile,
      testName: String(value.name),
      input: value.input,
    };
  });
}

function attestationFixtureName(fixture: PolicyDecisionFixtureInput): string {
  return `${fixture.bundleName}.${fixture.testFile.replace(/\.json$/, "")}.signed.attestation.json`;
}

function stringFromPath(record: Record<string, unknown>, path: string[], label: string): string {
  let value: unknown = record;
  for (const item of path) {
    if (!isRecord(value)) {
      throw new TypeError(`${label} must be a string`);
    }
    value = value[item];
  }
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${label} must be a string`);
  }
  return value;
}

function digestToCasUri(digest: DigestObject): string {
  return `cas://sha256/${digest.value.slice(2)}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

if (process.argv.includes("--write")) {
  await writePolicyDecisionAttestationFixtures();
}
