import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { plans, partition, compare } from "../packages/experiments/temporal-ordering/src/coverageAudit.mjs";

const [baseRoot, hardRoot] = process.argv.slice(2);
if (!baseRoot || !hardRoot) throw new Error("Usage: check-ciss-release.ts <baseline-run-root> <hardened-run-root>");
const json = (path: string) => JSON.parse(readFileSync(path, "utf8"));
const cases = json(join(baseRoot, "cases.json")).cases;
assert.deepEqual(json(join(hardRoot, "cases.json")).cases, cases);
const base = json(join(baseRoot, "temporal_ordering_results.json")).rows;
const hard = json(join(hardRoot, "hardened_run_results.json")).rows;
const indexed = (rows: any[]) => {
  assert.equal(rows.length, cases.length);
  const map = new Map(rows.map(row => [row.case_id, row]));
  assert.equal(map.size, cases.length);
  for (const plan of cases) assert.ok(map.has(plan.case_id));
  return map;
};
const b = indexed(base), h = indexed(hard);
const classes: Record<string, number> = {};
for (const plan of cases) {
  const q = partition(plan), original = b.get(plan.case_id), guarded = h.get(plan.case_id);
  classes[q.semantic] = (classes[q.semantic] ?? 0) + 1;
  assert.equal(original.authority_N, q.n);
  assert.equal(original.authority_D, q.d);
  assert.equal(original.besu_N_write, "accepted");
  assert.equal(original.besu_D_write, q.d ? "accepted" : "reverted");
  assert.equal(original.besu_replay, q.d ? q.n ? "PASS" : "FAIL" : "NOT_APPLICABLE");
  assert.equal(guarded.authority_at_N, q.n);
  assert.equal(guarded.N_write, q.n ? "ACCEPT" : "REVERT");
  assert.equal(guarded.D_write, !q.n ? "NOT_ATTEMPTED" : q.d ? "ACCEPT" : "REVERT");
  assert.equal(guarded.besu_replay, q.n && q.d ? "PASS" : "NOT_APPLICABLE");
  assert.equal(original.segl_replay, q.n && q.d ? "PASS" : "FAIL");
  assert.equal(guarded.segl_replay, original.segl_replay);
  assert.notEqual(original.parity, "disagree");
  assert.notEqual(guarded.parity, "disagree");
  assert.equal(guarded.signature_valid, true);
}
if (cases.length === 420) {
  const membership = compare(plans(), cases);
  assert.equal(membership.duplicates, 0);
  assert.deepEqual(membership.missing, []);
  assert.deepEqual(membership.extra, []);
  assert.equal(Object.keys(classes).length, 6);
  assert.equal(hard.filter((row: any) => row.N_write === "REVERT").length, 152);
  assert.equal(hard.filter((row: any) => row.besu_replay === "PASS").length, 214);
} else assert.equal(cases.length, 9);
console.log(JSON.stringify({ cases: cases.length, classes, status: "PASS" }, null, 2));
