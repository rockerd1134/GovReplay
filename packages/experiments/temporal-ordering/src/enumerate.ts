import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { CaseManifest, CasePlan, Step } from "./model.ts";

// Fixed grammar from ordering_model.md. RGR includes one completed pair and
// one unmatched final revocation, so every original named case is representable.
const transitions: Step[][] = [[], ["R"], ["R", "G"], ["R", "G", "R"]];

function interleave(left: Step[], right: Step[]): Step[][] {
  if (!left.length) return [right];
  if (!right.length) return [left];
  return [
    ...interleave(left.slice(1), right).map(rest => [left[0]!, ...rest]),
    ...interleave(left, right.slice(1)).map(rest => [right[0]!, ...rest]),
  ];
}

export function enumerate(): CaseManifest {
  const cases: CasePlan[] = [];
  for (const word of transitions) {
    for (const sPosition of [0, 1, 2, 3]) {
      const core: Step[] = ["N", "D"];
      core.splice(sPosition, 0, "S");
      if (core.length !== 3) continue;
      for (const tail of interleave(core, word)) {
        for (const audit of [false, true]) {
          for (const sender of ["writer", "actor"] as const) {
            const ordered_events: Step[] = ["A", ...tail, ...(audit ? ["AUDIT" as const] : [])];
            const key = `${sender}|${ordered_events.join("")}`;
            if (cases.some(item => `${item.deployment_transaction_sender}|${item.ordered_events.join("")}` === key)) continue;
            cases.push({ case_id: `E${String(cases.length + 1).padStart(3, "0")}`, ordered_events, deployment_transaction_sender: sender });
          }
        }
      }
    }
  }
  return { schema_version: "govprov.temporal_ordering_cases.v1", cases };
}

export function namedMapping(generated: CaseManifest, named: CaseManifest): Record<string, string> {
  return Object.fromEntries(named.cases.map(original => {
    const found = generated.cases.find(item => item.deployment_transaction_sender === original.deployment_transaction_sender
      && item.ordered_events.join(",") === original.ordered_events.join(","));
    if (!found) throw new Error(`Named case absent: ${original.case_id}`);
    return [original.case_id, found.case_id];
  }));
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replaceAll("\\", "/"))) {
  const root = join(import.meta.dirname, "..");
  const generated = enumerate();
  const named = JSON.parse(readFileSync(join(root, "cases.json"), "utf8")) as CaseManifest;
  writeFileSync(join(root, "cases.enumerated.k1.json"), JSON.stringify(generated, null, 2) + "\n");
  writeFileSync(join(root, "cases.enumerated.k1.tsv"), generated.cases.map(item =>
    `${item.case_id}|${item.deployment_transaction_sender}|${item.ordered_events.join(" ")}`).join("\n") + "\n");
  writeFileSync(join(root, "named_mapping.k1.json"), JSON.stringify(namedMapping(generated, named), null, 2) + "\n");
  process.stdout.write(`${generated.cases.length} cases\n`);
}
