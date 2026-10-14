import { readFileSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const json = <T>(path: string): T => JSON.parse(readFileSync(path, "utf8")) as T;
const [predictionFile, baselineRoot, hardenedRoot, outputRoot] = process.argv.slice(2);
if (!predictionFile || !baselineRoot || !hardenedRoot || !outputRoot) {
  throw new Error("Usage: summarizeEnumeration.ts <predictions.json> <baseline-run-root> <hardened-run-root> <context-output-root>");
}
type Pred = { case_id: string; ordered_events: string[]; deployment_transaction_sender: string; semantic_class: string;
  authority_at_N: boolean; authority_at_D: boolean; segl_replay: string; segl_failure_boundary: string | null;
  baseline_N: string; baseline_D: string; baseline_replay: string;
  hardened_N: string; hardened_D: string; hardened_replay: string };
type Base = { case_id: string; authority_N: boolean; authority_D: boolean; segl_replay: string; besu_N_write: string;
  besu_D_write: string; besu_replay: string; parity: string };
type Hard = { case_id: string; authority_at_N: boolean; N_write: string; D_write: string;
  besu_replay: string; segl_replay: string; parity: string };
const preds = json<{ rows: Pred[] }>(resolve(predictionFile)).rows;
const base = new Map(json<{ rows: Base[] }>(join(resolve(baselineRoot), "temporal_ordering_results.json")).rows.map(row => [row.case_id, row]));
const hard = new Map(json<{ rows: Hard[] }>(join(resolve(hardenedRoot), "hardened_run_results.json")).rows.map(row => [row.case_id, row]));
const disposition = (write: string) => write === "accepted" ? "ACCEPT" : write === "reverted" ? "REVERT" : write;
type SeglReplay = { integrity_issues: string[]; failure_boundary: string | null; authority_at_N: boolean; authority_at_D: boolean };
const baselineSegl = json<{ cases: Array<{ case_id: string; replay: SeglReplay }> }>(join(resolve(baselineRoot), "temporal_ordering_segl_events.json")).cases;
const hardenedSegl = json<{ cases: Array<{ case_id: string; replay: SeglReplay }> }>(join(resolve(hardenedRoot), "hardened_segl_events.json")).cases;
if (baselineSegl.length !== preds.length || hardenedSegl.length !== preds.length
  || [...baselineSegl, ...hardenedSegl].some(item => item.replay.integrity_issues.length)) throw new Error("SEGL generation or integrity check incomplete");
const baselineSeglById = new Map(baselineSegl.map(row => [row.case_id, row.replay]));
const hardenedSeglById = new Map(hardenedSegl.map(row => [row.case_id, row.replay]));
if (base.size !== preds.length || hard.size !== preds.length) throw new Error("Run case count differs from preregistration");
const records = preds.map(pred => {
  const b = base.get(pred.case_id), h = hard.get(pred.case_id);
  if (!b || !h) throw new Error(`Missing observed case ${pred.case_id}`);
  const segl = b.segl_replay === pred.segl_replay && h.segl_replay === pred.segl_replay
    && baselineSeglById.get(pred.case_id)?.failure_boundary === pred.segl_failure_boundary
    && hardenedSeglById.get(pred.case_id)?.failure_boundary === pred.segl_failure_boundary
    && baselineSeglById.get(pred.case_id)?.authority_at_N === pred.authority_at_N
    && baselineSeglById.get(pred.case_id)?.authority_at_D === pred.authority_at_D
    && hardenedSeglById.get(pred.case_id)?.authority_at_N === pred.authority_at_N
    && hardenedSeglById.get(pred.case_id)?.authority_at_D === pred.authority_at_D;
  const baseline = disposition(b.besu_N_write) === pred.baseline_N && disposition(b.besu_D_write) === pred.baseline_D
    && b.besu_replay === pred.baseline_replay && b.authority_N === pred.authority_at_N && b.authority_D === pred.authority_at_D;
  const hardened = h.N_write === pred.hardened_N && h.D_write === pred.hardened_D && h.besu_replay === pred.hardened_replay
    && h.authority_at_N === pred.authority_at_N;
  return { pred, baseline: b, hardened: h, agrees: { segl, baseline, hardened } };
});
const count = (predicate: (row: typeof records[number]) => boolean) => records.filter(predicate).length;
const byClass = [...new Set(preds.map(row => row.semantic_class))].sort().map(className => {
  const rows = records.filter(row => row.pred.semantic_class === className);
  return { className, count: rows.length, baselineNAdmitted: rows.filter(row => !row.pred.authority_at_N && row.baseline.besu_N_write === "accepted").length,
    hardenedNRejected: rows.filter(row => !row.pred.authority_at_N && row.hardened.N_write === "REVERT").length,
    validPass: rows.filter(row => row.pred.authority_at_N && row.pred.authority_at_D && row.hardened.besu_replay === "PASS").length };
});
function metrics(root: string, file: string) {
  const rows = json<{ receipts: Array<{ receipt: { gasUsed: string } }> }>(join(resolve(root), file)).receipts;
  const transactions = rows.length;
  const gas = rows.reduce((total, row) => total + BigInt(row.receipt.gasUsed), 0n);
  const started = statSync(join(resolve(root), "run_metadata.json")).birthtimeMs;
  const finished = statSync(join(resolve(root), file)).mtimeMs;
  return { transactions, gas: gas.toString(), wall_seconds_approx: Math.max(0, Math.round((finished - started) / 1000)) };
}
const baselineMetrics = metrics(baselineRoot, "temporal_ordering_besu_receipts.json");
const hardenedMetrics = metrics(hardenedRoot, "hardened_besu_receipts.json");
const sep = "| --- | --- | --- | --- | --- | --- | --- |";
const comparison = ["# Preregistered predictions versus observed outcomes", "",
  `Baseline run: \`${json<{run_id:string}>(join(resolve(baselineRoot), "run_metadata.json")).run_id}\`. Hardened run: \`${json<{run_id:string}>(join(resolve(hardenedRoot), "run_metadata.json")).run_id}\`. Every generated case is listed.`, "",
  `SEGL agreement: ${count(row => row.agrees.segl)}/${records.length}; baseline Besu: ${count(row => row.agrees.baseline)}/${records.length}; hardened Besu: ${count(row => row.agrees.hardened)}/${records.length}.`, "",
  "Each cell shows predicted→observed N/D/replay. SEGL N/D entries are role/authorization states, while Besu N/D entries are write dispositions.", "",
  "| Case | Order | Sender | Class | SEGL replay | Baseline N/D/replay | Hardened N/D/replay |",
  sep,
  ...records.map(({ pred, baseline: b, hardened: h }) =>
    `| ${pred.case_id} | ${pred.ordered_events.join("→")} | ${pred.deployment_transaction_sender} | ${pred.semantic_class.replaceAll("|", "/")} | ${Number(pred.authority_at_N)}/${Number(pred.authority_at_D)}/${pred.segl_replay}→${Number(baselineSeglById.get(pred.case_id)!.authority_at_N)}/${Number(baselineSeglById.get(pred.case_id)!.authority_at_D)}/${b.segl_replay} | ${pred.baseline_N}/${pred.baseline_D}/${pred.baseline_replay}→${disposition(b.besu_N_write)}/${disposition(b.besu_D_write)}/${b.besu_replay} | ${pred.hardened_N}/${pred.hardened_D}/${pred.hardened_replay}→${h.N_write}/${h.D_write}/${h.besu_replay} |`), ""];
const results = ["# Bounded ordering enumeration results", "",
  `Model: k=1, ${records.length} raw cases, ${byClass.length} N/D semantic classes. Raw histories are not independent trials.`, "",
  "| Semantic class | Raw cases | Baseline invalid-N admitted | Hardened invalid-N rejected | Valid hardened PASS |", "| --- | ---: | ---: | ---: | ---: |",
  ...byClass.map(row => `| ${row.className.replaceAll("|", "/")} | ${row.count} | ${row.baselineNAdmitted} | ${row.hardenedNRejected} | ${row.validPass} |`), "",
  `Invalid at N: ${count(row => !row.pred.authority_at_N)} cases; baseline N admitted ${count(row => !row.pred.authority_at_N && row.baseline.besu_N_write === "accepted")}; hardened N admitted ${count(row => !row.pred.authority_at_N && row.hardened.N_write === "ACCEPT")}.`,
  `Invalid at D only: ${count(row => row.pred.authority_at_N && !row.pred.authority_at_D)} cases. Valid at both: ${count(row => row.pred.authority_at_N && row.pred.authority_at_D)} cases.`,
  `Baseline SEGL/Besu disagreements: ${count(row => row.baseline.parity === "disagree")}/${count(row => row.baseline.parity !== "not_applicable")} comparable histories. Hardened: ${count(row => row.hardened.parity === "disagree")}/${count(row => row.hardened.parity !== "not_comparable")} comparable histories. Rejected D and rejected N are excluded from full-history replay parity.`, ""];
results.push(`Signed SEGL generation and integrity verification: ${baselineSegl.length}/${preds.length} baseline and ${hardenedSegl.length}/${preds.length} hardened case histories, with zero integrity issues.`, "");
results.push(`Descriptive execution by-products: baseline ${baselineMetrics.transactions} transactions, ${baselineMetrics.gas} gas, approximately ${baselineMetrics.wall_seconds_approx} seconds from run metadata creation through report receipt file; hardened ${hardenedMetrics.transactions} transactions, ${hardenedMetrics.gas} gas, approximately ${hardenedMetrics.wall_seconds_approx} seconds. These are local dev-chain measurements, not comparative performance claims.`, "");
const output = resolve(outputRoot);
writeFileSync(join(output, "prediction_comparison.md"), comparison.join("\n"));
writeFileSync(join(output, "enumeration_results.md"), results.join("\n"));
process.stdout.write(JSON.stringify({ cases: records.length, classes: byClass.length,
  agreements: { segl: count(row => row.agrees.segl), baseline: count(row => row.agrees.baseline), hardened: count(row => row.agrees.hardened) } }, null, 2) + "\n");
if (records.some(row => !Object.values(row.agrees).every(Boolean))) process.exitCode = 1;
