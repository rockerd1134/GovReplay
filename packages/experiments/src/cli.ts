import { argv, exit } from "node:process";
import { join } from "node:path";
import { parseExperimentConfig } from "./config.ts";
import { runExperiment } from "./runner.ts";

const args = parseArgs(argv.slice(2));
if (args.config === undefined) {
  fail("--config is required");
}

const packageRoot = join(import.meta.dirname, "..", "..", "..");
const config = parseExperimentConfig(args.config);
const result = await runExperiment(config, { packageRoot });

console.log(JSON.stringify({
  run_id: config.run_id,
  matrix: config.matrix,
  run_root: result.runRoot,
  workflow_count: result.workload.length,
  audit_records: result.auditRecords.length,
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
