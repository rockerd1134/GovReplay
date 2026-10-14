import { argv, exit } from "node:process";
import { buildUiData, writeUiData } from "./ui-data.ts";

const args = parseArgs(argv.slice(2));
const runRoot = args["run-root"];
const out = args.out;

if (runRoot === undefined || out === undefined) {
  fail("--run-root and --out are required");
}

const data = buildUiData([runRoot], { generatedAt: "2026-06-21T00:00:00.000Z" });
writeUiData(out, data);

console.log(JSON.stringify({
  schema_version: data.schema_version,
  runs: data.runs.length,
  replays: data.replays.length,
  faults: data.faults.length,
  demos: data.demos.map((demo) => demo.demo_id),
  out,
}, null, 2));

function parseArgs(values: string[]): Record<string, string> {
  const parsed: Record<string, string> = {};
  for (let index = 0; index < values.length; index += 1) {
    const key = values[index];
    const value = values[index + 1];
    if (!key.startsWith("--") || value === undefined || value.startsWith("--")) {
      fail(`Malformed argument: ${key}`);
    }
    parsed[key.slice(2)] = value;
    index += 1;
  }
  return parsed;
}

function fail(message: string): never {
  console.error(message);
  exit(2);
}
