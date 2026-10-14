import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { CaseManifest, CasePlan, Step } from "./model.ts";

type Baseline = { case_id: string; authority_N: boolean; authority_D: boolean; segl_replay: string; besu_N_write: string };
type Hardened = { case_id: string; N_write: string; segl_replay: string };
type Segl = { case_id: string; replay: { authority_at_N: boolean; authority_at_D: boolean; verdict: string } };
type Check = { property: string; evaluated: number; comparisons: string[]; failures: string[] };
const json = <T>(path: string): T => JSON.parse(readFileSync(path, "utf8")) as T;
const baseRoot = resolve(process.argv[2] ?? "");
const hardRoot = resolve(process.argv[3] ?? "");
const outputPath = process.argv[4];
if (!process.argv[2] || !process.argv[3] || !outputPath) throw new Error("Usage: propertyCheck.ts <baseline-run-root> <hardened-run-root> <output-json>");
const manifest = json<CaseManifest>(join(baseRoot, "cases.json"));
const hardManifest = json<CaseManifest>(join(hardRoot, "cases.json"));
if (JSON.stringify(manifest) !== JSON.stringify(hardManifest)) throw new Error("Run manifests differ");
const baseRows = json<{ rows: Baseline[] }>(join(baseRoot, "temporal_ordering_results.json")).rows;
const hardRows = json<{ rows: Hardened[] }>(join(hardRoot, "hardened_run_results.json")).rows;
const seglRows = json<{ cases: Segl[] }>(join(baseRoot, "temporal_ordering_segl_events.json")).cases;
const base = new Map(baseRows.map(row => [row.case_id, row]));
const hard = new Map(hardRows.map(row => [row.case_id, row]));
const segl = new Map(seglRows.map(row => [row.case_id, row.replay]));
const key = (steps: readonly Step[], sender: string) => `${sender}|${steps.join(",")}`;
const byPlan = new Map(manifest.cases.map(plan => [key(plan.ordered_events, plan.deployment_transaction_sender), plan.case_id]));
const checks = new Map<string, Check>(["P1", "P2", "P3a", "P3b", "P4", "P5", "P6"].map(property => [property, { property, evaluated: 0, comparisons: [], failures: [] }]));
function check(name: string, label: string, condition: boolean) {
  const entry = checks.get(name)!;
  entry.evaluated++;
  entry.comparisons.push(label);
  if (!condition) entry.failures.push(label);
}
function mate(plan: CasePlan, events: Step[], sender = plan.deployment_transaction_sender): string | undefined {
  return byPlan.get(key(events, sender));
}
for (const plan of manifest.cases) {
  const id = plan.case_id;
  const a = base.get(id)!, h = hard.get(id)!, s = segl.get(id)!;
  if (!a || !h || !s) throw new Error(`Missing observation ${id}`);
  check("P5", id, (h.N_write === "ACCEPT") === a.authority_N);
  const noS = plan.ordered_events.filter(step => step !== "S").join(",");
  const priorS = manifest.cases.filter(other => other.case_id < id && other.deployment_transaction_sender === plan.deployment_transaction_sender
    && other.ordered_events.filter(step => step !== "S").join(",") === noS);
  for (const other of priorS) {
    const b = base.get(other.case_id)!, t = hard.get(other.case_id)!, u = segl.get(other.case_id)!;
    check("P1", `${other.case_id}/${id}`, a.authority_N === b.authority_N && s.authority_at_N === u.authority_at_N && h.N_write === t.N_write);
  }
  if (!plan.ordered_events.includes("AUDIT")) {
    const audit = mate(plan, [...plan.ordered_events, "AUDIT"]);
    if (audit) {
      const b = base.get(audit)!, u = segl.get(audit)!;
      check("P6", `${id}/${audit}`, a.authority_N === b.authority_N && a.authority_D === b.authority_D
        && s.verdict === u.verdict && s.authority_at_N === u.authority_at_N && s.authority_at_D === u.authority_at_D);
    }
    if (plan.ordered_events.at(-1) === "D") {
      const after = mate(plan, [...plan.ordered_events, "R"]);
      if (after) {
        const b = base.get(after)!, u = segl.get(after)!;
        check("P2", `${id}/${after}`, a.authority_N === b.authority_N && a.authority_D === b.authority_D
          && s.authority_at_N === u.authority_at_N && s.authority_at_D === u.authority_at_D);
      }
    }
  }
  const n = plan.ordered_events.indexOf("N");
  if (a.authority_N) {
    const changed = mate(plan, [...plan.ordered_events.slice(0, n), "R", ...plan.ordered_events.slice(n)]);
    if (changed) check("P3a", `${id}/${changed}`, !base.get(changed)!.authority_N && !segl.get(changed)!.authority_at_N && hard.get(changed)!.N_write === "REVERT");
  } else {
    const changed = mate(plan, [...plan.ordered_events.slice(0, n), "G", ...plan.ordered_events.slice(n)]);
    if (changed) check("P3b", `${id}/${changed}`, base.get(changed)!.authority_N && segl.get(changed)!.authority_at_N && hard.get(changed)!.N_write === "ACCEPT");
  }
  if (plan.deployment_transaction_sender === "writer") {
    const actor = mate(plan, plan.ordered_events, "actor");
    if (actor) check("P4", `${id}/${actor}`, a.authority_N === base.get(actor)!.authority_N
      && s.authority_at_N === segl.get(actor)!.authority_at_N && h.N_write === hard.get(actor)!.N_write);
  }
}
const results = [...checks.values()];
writeFileSync(resolve(outputPath), JSON.stringify({ baseline_run: baseRoot, hardened_run: hardRoot, results }, null, 2) + "\n");
if (results.some(item => item.failures.length || !item.evaluated)) process.exitCode = 1;
process.stdout.write(JSON.stringify(results.map(({ property, evaluated, failures }) => ({ property, evaluated, failures: failures.length })), null, 2) + "\n");
