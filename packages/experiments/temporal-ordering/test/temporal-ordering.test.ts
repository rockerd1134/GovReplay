import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { addressFromPrivateKey } from "../../../attestations/src/signing.ts";
import { roleAt, type CasePlan, type RoleTransition, type RunMetadata } from "../src/model.ts";
import { oracleFor } from "../src/oracle.ts";
import { enumerate, namedMapping } from "../src/enumerate.ts";
import { intervalExpectation } from "../src/intervalOracle.ts";
import { buildTemporalSeglEvents, verifyTemporalSegl, type CaseHashes } from "../src/seglTemporal.ts";

const operatorKey = `0x${"0".repeat(63)}1`;
const actorKey = `0x${"0".repeat(63)}2`;
const operator = addressFromPrivateKey(operatorKey);
const actor = addressFromPrivateKey(actorKey);
const role = `0x${"a".repeat(64)}`;
const writerRole = `0x${"b".repeat(64)}`;
const policy = `0x${"c".repeat(64)}`;
const meta: RunMetadata = {
  run_id: "temporal-test",
  chain_id: 1337,
  attestation_actor: actor,
  anchor_transaction_sender: operator,
  default_deployment_transaction_sender: operator,
  approval_actor: operator,
  required_role_at_N: role,
  deployer_role: role,
  ledger_writer_role: writerRole,
  policy_hash: policy,
  contracts: { ActorRegistry: operator, PolicyRegistry: operator, ProvenanceRegistry: operator, ApprovalRegistry: operator, DeploymentRegistry: operator },
};

function plan(case_id: string, ordered_events: CasePlan["ordered_events"], deployment_transaction_sender: CasePlan["deployment_transaction_sender"] = "writer"): CasePlan {
  return { case_id, ordered_events, deployment_transaction_sender };
}
function hashes(caseId: string): CaseHashes {
  return {
    case_id: caseId,
    action_hash: `0x${"1".repeat(64)}`,
    approval_hash: `0x${"2".repeat(64)}`,
    deployment_attestation_hash: `0x${"3".repeat(64)}`,
    deployment_id_hash: `0x${"4".repeat(64)}`,
    artifact_hash: `0x${"5".repeat(64)}`,
  };
}

test("symbolic oracle uses adopted N and D boundaries, independent of replay code", () => {
  assert.equal(oracleFor(plan("T1", ["A", "S", "N", "D"])).expected_replay_verdict, "PASS");
  assert.equal(oracleFor(plan("T2", ["A", "S", "R", "N", "D"])).expected_failure_boundary, "N");
  assert.equal(oracleFor(plan("T4", ["A", "S", "N", "R", "D"])).expected_replay_verdict, "PASS");
  assert.equal(oracleFor(plan("T5", ["A", "S", "N", "D", "R"])).expected_replay_verdict, "PASS");
  assert.equal(oracleFor(plan("T7", ["A", "R", "G", "S", "N", "D"])).expected_replay_verdict, "PASS");
  assert.equal(oracleFor(plan("T4_SELF", ["A", "S", "N", "R", "D"], "actor")).expected_write_disposition.D, "reverted");
  const oracleSource = readFileSync(fileURLToPath(new URL("../src/oracle.ts", import.meta.url)), "utf8");
  assert.doesNotMatch(oracleSource, /from\s+["'][^"']*(?:seglTemporal|besuTemporal|replayOutput|observedReplayVerifier)/);
});

test("bounded generator contains all named cases and two oracles agree", () => {
  const generated = enumerate();
  const original = JSON.parse(readFileSync(fileURLToPath(new URL("../cases.json", import.meta.url)), "utf8"));
  assert.equal(generated.cases.length, 420);
  assert.equal(Object.keys(namedMapping(generated, original)).length, 9);
  assert.equal(new Set(generated.cases.map(item => `${item.deployment_transaction_sender}|${item.ordered_events.join("")}`)).size, 420);
  for (const item of generated.cases) {
    const first = oracleFor(item);
    const second = intervalExpectation(item);
    assert.equal(second.authority_at_N, first.authority_at_N, item.case_id);
    assert.equal(second.authority_at_D, first.authority_at_D, item.case_id);
    assert.equal(second.segl_replay, first.expected_replay_verdict, item.case_id);
    assert.equal(second.baseline_replay, first.expected_besu_replay_verdict, item.case_id);
  }
});

test("signed SEGL replay follows append sequence, exact role and regrant despite equal caller times", () => {
  const cases = [
    [plan("T1", ["A", "S", "N", "D"]), "PASS", null],
    [plan("T2", ["A", "S", "R", "N", "D"]), "FAIL", "N"],
    [plan("T4", ["A", "S", "N", "R", "D"]), "PASS", null],
    [plan("T5", ["A", "S", "N", "D", "R"]), "PASS", null],
    [plan("T7", ["A", "R", "G", "S", "N", "D"]), "PASS", null],
    [plan("T4_SELF", ["A", "S", "N", "R", "D"], "actor"), "FAIL", "D"],
  ] as const;
  for (const [casePlan, verdict, boundary] of cases) {
    const events = buildTemporalSeglEvents(casePlan, meta, hashes(casePlan.case_id), operatorKey);
    assert.equal(new Set(events.map((event) => event.logical_time)).size, 1);
    const result = verifyTemporalSegl(events, meta, hashes(casePlan.case_id));
    assert.deepEqual(result.integrity_issues, []);
    assert.equal(result.verdict, verdict, casePlan.case_id);
    assert.equal(result.failure_boundary, boundary, casePlan.case_id);
  }
});

test("Besu role fold uses block, transaction, and log position and honors regrant", () => {
  const at = (block_number: number, transaction_index: number, log_index: number) => ({ block_number, transaction_index, log_index });
  const transitions: RoleTransition[] = [
    { actor, role, kind: "grant", order: at(10, 0, 0), transaction_hash: "grant" },
    { actor, role, kind: "revoke", order: at(10, 1, 2), transaction_hash: "revoke" },
    { actor, role, kind: "grant", order: at(10, 1, 4), transaction_hash: "regrant" },
  ];
  assert.equal(roleAt(transitions, actor, role, at(10, 1, 1)), true);
  assert.equal(roleAt(transitions, actor, role, at(10, 1, 3)), false);
  assert.equal(roleAt(transitions, actor, role, at(10, 1, 5)), true);
  assert.equal(roleAt(transitions, actor, writerRole, at(11, 0, 0)), false);
});

test("replay after a later revocation preserves the verdict at historical N and D", () => {
  const casePlan = plan("T8", ["A", "S", "N", "D", "R", "AUDIT"]);
  const all = buildTemporalSeglEvents(casePlan, meta, hashes("T8"), operatorKey);
  const beforeRevocation = all.slice(0, -1);
  assert.equal(beforeRevocation.at(-1)?.event_type, "deployment_recorded");
  assert.equal(all.at(-1)?.event_type, "actor_role_revoked");
  const before = verifyTemporalSegl(beforeRevocation, meta, hashes("T8"));
  const after = verifyTemporalSegl(all, meta, hashes("T8"));
  assert.equal(before.verdict, "PASS");
  assert.equal(after.verdict, before.verdict);
  assert.equal(after.authority_at_N, before.authority_at_N);
  assert.equal(after.authority_at_D, before.authority_at_D);
});
