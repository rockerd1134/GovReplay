import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import { oracleFor } from "./oracle.ts";
import { intervalExpectation } from "./intervalOracle.ts";
import type { CaseManifest } from "./model.ts";

const source = join(import.meta.dirname, "../cases.enumerated.k1.json");
const manifest = JSON.parse(readFileSync(source, "utf8")) as CaseManifest;
const rows = manifest.cases.map(plan => {
  const first = oracleFor(plan);
  const second = intervalExpectation(plan);
  if (first.authority_at_N !== second.authority_at_N || first.authority_at_D !== second.authority_at_D
    || first.expected_replay_verdict !== second.segl_replay
    || first.expected_besu_replay_verdict !== second.baseline_replay
    || first.expected_failure_boundary !== second.segl_failure_boundary) {
    throw new Error(`Oracle disagreement at ${plan.case_id}`);
  }
  return { case_id: plan.case_id, ordered_events: plan.ordered_events,
    deployment_transaction_sender: plan.deployment_transaction_sender, ...second,
    semantic_class: `${plan.deployment_transaction_sender}|N${Number(second.authority_at_N)}|D${Number(second.authority_at_D)}` };
});
const output = { schema_version: "govprov.enumerated_predictions.v1", model_bound_k: 1,
  source_manifest: "cases.enumerated.k1.json", rows };
if (!process.argv[2]) throw new Error("Pass the context enumerated_predictions.json destination explicitly");
const destination = resolve(process.argv[2]);
const content = JSON.stringify(output, null, 2) + "\n";
writeFileSync(destination, content);
writeFileSync(destination.replace(/\.json$/, ".sha256"), `${createHash("sha256").update(content).digest("hex")}  enumerated_predictions.json\n`);
const classes = [...new Set(rows.map(row => row.semantic_class))].sort();
process.stdout.write(JSON.stringify({ cases: rows.length, classes, oracle_agreement: rows.length,
  invalid_at_N: rows.filter(row => !row.authority_at_N).length,
  invalid_at_D_only: rows.filter(row => row.authority_at_N && !row.authority_at_D).length }, null, 2) + "\n");
