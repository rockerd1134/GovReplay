import type { CasePlan } from "./model.ts";

// Independently formulated from temporal_ordering_spec.md, Scope and
// boundaries and invariants I1-I4. No dependency on src/oracle.ts.
export function intervalExpectation(plan: CasePlan) {
  const positions = plan.ordered_events.map((event, index) => ({ event, index }));
  const n = plan.ordered_events.indexOf("N");
  const d = plan.ordered_events.indexOf("D");
  if (n < 0 || d <= n) throw new Error(`Invalid N/D order: ${plan.case_id}`);
  const changes = positions.filter(item => item.event === "R" || item.event === "G");
  const intervals: Array<[number, number]> = [];
  let start = -1;
  for (const change of changes) {
    if (change.event === "R") { intervals.push([start, change.index]); start = Number.POSITIVE_INFINITY; }
    else start = change.index;
  }
  if (Number.isFinite(start)) intervals.push([start, Number.POSITIVE_INFINITY]);
  const holds = (at: number) => intervals.some(([begin, end]) => begin < at && at < end);
  const authorityN = holds(n);
  const authorityD = plan.deployment_transaction_sender === "writer" || holds(d);
  return {
    authority_at_N: authorityN,
    authority_at_D: authorityD,
    segl_replay: authorityN && authorityD ? "PASS" : "FAIL",
    segl_failure_boundary: !authorityN ? "N" : !authorityD ? "D" : null,
    baseline_N: "ACCEPT",
    baseline_D: authorityD ? "ACCEPT" : "REVERT",
    baseline_replay: !authorityD ? "NOT_APPLICABLE" : authorityN ? "PASS" : "FAIL",
    hardened_N: authorityN ? "ACCEPT" : "REVERT",
    hardened_D: !authorityN ? "NOT_ATTEMPTED" : authorityD ? "ACCEPT" : "REVERT",
    hardened_replay: authorityN && authorityD ? "PASS" : "NOT_APPLICABLE",
  } as const;
}
