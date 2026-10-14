import assert from "node:assert/strict";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { verifyAttestationSignature } from "../../attestations/src/signing.ts";
import {
  GATEWAY_SCENARIO_COVERAGE,
  evaluateGatewayRequest,
  writeGatewayDecision,
} from "../src/gateway.ts";
import { runExampleAgentClient } from "../src/example-agent-client.ts";

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const gatewayRoot = join(packageRoot, "packages", "gateway");
const outputRoot = join(packageRoot, ".tmp", "test-runs", "gateway");

test("gateway allows S1 runbook request and emits policy plus agent action attestations", () => {
  const request = readFixture("s1-runbook-allow.request.json");
  const decision = evaluateGatewayRequest(request);

  assert.equal(decision.decision, "allow");
  assert.equal(decision.blocked, false);
  assert.equal(decision.gateway_state, "POLICY_ALLOWED_ACTION_ATTESTED");
  assert.ok(decision.policy_decision_attestation.attestation_hash);
  assert.ok(decision.agent_action_attestation?.attestation_hash);
  assert.deepEqual(decision.emitted_records, ["PolicyDecisionAttestation", "AgentActionAttestation"]);
  assert.equal(verifyAttestationSignature(decision.policy_decision_attestation), true);
  assert.equal(verifyAttestationSignature(decision.agent_action_attestation), true);
});

test("gateway suite allows one request for each implemented scenario", () => {
  for (const scenario of GATEWAY_SCENARIO_COVERAGE) {
    const request = readFixture(scenario.allowed_fixture);
    const decision = evaluateGatewayRequest(request);

    assert.equal(decision.scenario_id, scenario.scenario_id);
    assert.equal(decision.decision, "allow", scenario.scenario_id);
    assert.equal(decision.blocked, false, scenario.scenario_id);
    assert.equal(decision.gateway_state, "POLICY_ALLOWED_ACTION_ATTESTED", scenario.scenario_id);
    assert.ok(decision.policy_decision_attestation.attestation_hash, scenario.scenario_id);
    assert.ok(decision.agent_action_attestation?.attestation_hash, scenario.scenario_id);
    assert.deepEqual(decision.emitted_records, ["PolicyDecisionAttestation", "AgentActionAttestation"]);
    assert.equal(verifyAttestationSignature(decision.policy_decision_attestation), true, scenario.scenario_id);
    assert.equal(verifyAttestationSignature(decision.agent_action_attestation), true, scenario.scenario_id);
  }
});

test("gateway suite denies one request for each implemented scenario and fails closed", () => {
  for (const scenario of GATEWAY_SCENARIO_COVERAGE) {
    const request = readFixture(scenario.denied_fixture);
    const decision = evaluateGatewayRequest(request);

    assert.equal(decision.scenario_id, scenario.scenario_id);
    assert.equal(decision.decision, "deny", scenario.scenario_id);
    assert.equal(decision.blocked, true, scenario.scenario_id);
    assert.equal(decision.gateway_state, "POLICY_DENIED_ACTION_BLOCKED", scenario.scenario_id);
    assert.ok(decision.policy_decision_attestation.attestation_hash, scenario.scenario_id);
    assert.equal(decision.agent_action_attestation, null, scenario.scenario_id);
    assert.deepEqual(decision.emitted_records, ["PolicyDecisionAttestation"]);
  }
});

test("gateway decisions come from observed policy evaluation rather than fixture oracle labels", () => {
  const fixtureRoot = mkdtempSync(join(tmpdir(), "govreplay-gateway-policy-"));
  cpSync(join(packageRoot, "packages", "policy-service", "fixtures", "bundles"), fixtureRoot, { recursive: true });
  const testPath = join(fixtureRoot, "software-delivery-p1-baseline", "tests", "allow-runbook-baseline.json");
  const policyTest = JSON.parse(readFileSync(testPath, "utf8"));
  policyTest.expected_decision = "deny";
  writeFileSync(testPath, `${JSON.stringify(policyTest, null, 2)}\n`);

  const decision = evaluateGatewayRequest(readFixture("s1-runbook-allow.request.json"), { fixtureRoot });

  assert.equal(decision.decision, "allow");
  assert.equal(decision.blocked, false);
  assert.equal(
    (decision.policy_decision_attestation.predicate as Record<string, unknown>).evaluator_identity,
    "govreplay:policy-evaluator:cedar-subset",
  );
});

test("CLI-compatible writer persists gateway decisions", async () => {
  rmSync(outputRoot, { recursive: true, force: true });
  await mkdir(outputRoot, { recursive: true });
  const decision = evaluateGatewayRequest(readFixture("s1-runbook-allow.request.json"));
  const out = join(outputRoot, "decision.json");
  writeGatewayDecision(decision, out);

  const persisted = JSON.parse(readFileSync(out, "utf8"));
  assert.equal(persisted.request_id, "req-s1-runbook-allow");
  assert.equal(persisted.agent_action_attestation.attestation_type, "AgentActionAttestation");
});

test("deterministic client emits workflow records only after gateway allow", () => {
  rmSync(outputRoot, { recursive: true, force: true });
  const allowResult = runExampleAgentClient({
    request: readFixture("s1-runbook-allow.request.json"),
    outputRoot: join(outputRoot, "allow-client"),
  });
  assert.equal(allowResult.blocked, false);
  assert.deepEqual(allowResult.emitted_record_types, ["action", "approval", "artifact"]);
  assert.ok(allowResult.workflow_records_path);
  assert.equal(existsSync(allowResult.workflow_records_path), true);

  const denyResult = runExampleAgentClient({
    request: readFixture("s1-runbook-deny.request.json"),
    outputRoot: join(outputRoot, "deny-client"),
  });
  assert.equal(denyResult.blocked, true);
  assert.deepEqual(denyResult.emitted_record_types, []);
  assert.equal(denyResult.workflow_records_path, null);
  assert.equal(existsSync(join(outputRoot, "deny-client", "workflow_records.json")), false);
});

test("allowed downstream records link gateway decisions into scenario-specific lineage", () => {
  rmSync(outputRoot, { recursive: true, force: true });
  for (const scenario of GATEWAY_SCENARIO_COVERAGE) {
    const result = runExampleAgentClient({
      request: readFixture(scenario.allowed_fixture),
      outputRoot: join(outputRoot, scenario.scenario_id),
    });
    assert.equal(result.blocked, false, scenario.scenario_id);
    assert.ok(result.workflow_records_path, scenario.scenario_id);
    const records = JSON.parse(readFileSync(result.workflow_records_path!, "utf8"));
    assert.equal(records.scenario_id, scenario.scenario_id);
    assert.match(records.gateway_lineage.gateway_decision_hash, /^0x[0-9a-f]{64}$/);
    assert.match(records.gateway_lineage.gateway_policy_decision_attestation_hash, /^0x[0-9a-f]{64}$/);
    assert.equal(records.action.gateway_decision_hash, records.gateway_lineage.gateway_decision_hash);
    assert.equal(records.approval.gateway_decision_hash, records.gateway_lineage.gateway_decision_hash);
    assert.equal(records.artifact.gateway_decision_hash, records.gateway_lineage.gateway_decision_hash);
    if (scenario.scenario_id === "S2_configuration_change") {
      assert.equal(records.config_change.gateway_decision_hash, records.gateway_lineage.gateway_decision_hash);
    }
    if (scenario.scenario_id === "S3_patch_proposal") {
      assert.equal(records.patch.gateway_decision_hash, records.gateway_lineage.gateway_decision_hash);
      assert.equal(records.patch.issue_ref.type, "issue");
      assert.equal(records.patch.test_ref.type, "test_report");
    }
    if (scenario.scenario_id === "S4_policy_gated_deployment") {
      assert.equal(records.deployment.gateway_decision_hash, records.gateway_lineage.gateway_decision_hash);
      assert.deepEqual(records.deployment.approved_artifact_digest, records.deployment.deployed_artifact_digest);
    }
    if (scenario.scenario_id === "S5_governance_state_change") {
      assert.equal(records.governance_state.gateway_decision_hash, records.gateway_lineage.gateway_decision_hash);
      assert.deepEqual(records.governance_state.actor_roles, ["GOVERNANCE_ADMIN"]);
    }
  }
});

test("denied deterministic client runs never produce approved downstream records", () => {
  rmSync(outputRoot, { recursive: true, force: true });
  for (const scenario of GATEWAY_SCENARIO_COVERAGE) {
    const result = runExampleAgentClient({
      request: readFixture(scenario.denied_fixture),
      outputRoot: join(outputRoot, `${scenario.scenario_id}-deny`),
    });
    assert.equal(result.blocked, true, scenario.scenario_id);
    assert.deepEqual(result.emitted_record_types, [], scenario.scenario_id);
    assert.equal(result.workflow_records_path, null, scenario.scenario_id);
    assert.equal(existsSync(join(outputRoot, `${scenario.scenario_id}-deny`, "workflow_records.json")), false);
  }
});

test("scenario coverage table spans all implemented scenarios and paper-facing domains", () => {
  assert.equal(GATEWAY_SCENARIO_COVERAGE.length, 5);
  assert.deepEqual(
    GATEWAY_SCENARIO_COVERAGE.map((scenario) => scenario.scenario_id),
    [
      "S1_runbook_update",
      "S2_configuration_change",
      "S3_patch_proposal",
      "S4_policy_gated_deployment",
      "S5_governance_state_change",
    ],
  );
  const domains = new Set(GATEWAY_SCENARIO_COVERAGE.flatMap((scenario) => scenario.primary_domains));
  assert.ok(domains.has("identity and actor-role governance"));
  assert.ok(domains.has("policy decision binding"));
  assert.ok(domains.has("approval authority and separation of duties"));
  assert.ok(domains.has("deployment and artifact consistency"));
  assert.ok(domains.has("ledger-backed governance-state administration"));
  assert.ok(domains.size >= 5);
});

function readFixture(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(gatewayRoot, "fixtures", name), "utf8"));
}
