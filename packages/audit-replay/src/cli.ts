import { argv, exit } from "node:process";
import { replayAudit, type ReplayInput } from "./replay.ts";

const args = parseArgs(argv.slice(2));

if (args.runRoot === undefined) {
  fail("--run-root is required");
}

const input = replayInput(args);
if (input === null) {
  fail("one replay input is required: --deployment-id, --action-id, --attestation-hash, or --workflow-id");
}

const report = await replayAudit({
  runRoot: args.runRoot,
  input,
  scenarioRoot: args.scenarioRoot,
  ledgerSidecarPath: args.ledgerSidecar,
  currentPolicyVersion: args.currentPolicy,
  reportDir: args.reportDir,
});

console.log(JSON.stringify({
  workflow_id: report.workflow_id,
  verdict: report.verdict,
  failure_code: report.failure_code,
  reconstructed_links: report.metrics.reconstructed_links,
  required_links: report.metrics.required_links,
}, null, 2));

if (report.verdict !== "PASS") {
  exit(1);
}

function parseArgs(values: string[]): Record<string, string> {
  const parsed: Record<string, string> = {};
  for (let index = 0; index < values.length; index += 1) {
    const key = values[index];
    const value = values[index + 1];
    if (!key.startsWith("--") || value === undefined || value.startsWith("--")) {
      fail(`Malformed argument: ${key}`);
    }
    parsed[key.slice(2).replaceAll("-", "")] = value;
    index += 1;
  }
  return {
    runRoot: parsed.runroot,
    deploymentId: parsed.deploymentid,
    actionId: parsed.actionid,
    attestationHash: parsed.attestationhash,
    workflowId: parsed.workflowid,
    scenarioRoot: parsed.scenarioroot,
    ledgerSidecar: parsed.ledgersidecar,
    currentPolicy: parsed.currentpolicy,
    reportDir: parsed.reportdir,
  };
}

function replayInput(args: Record<string, string>): ReplayInput | null {
  if (args.deploymentId !== undefined) {
    return { type: "deployment_id", value: args.deploymentId };
  }
  if (args.actionId !== undefined) {
    return { type: "action_id", value: args.actionId };
  }
  if (args.attestationHash !== undefined) {
    return { type: "attestation_hash", value: args.attestationHash };
  }
  if (args.workflowId !== undefined) {
    return { type: "workflow_id", value: args.workflowId };
  }
  return null;
}

function fail(message: string): never {
  console.error(message);
  exit(2);
}
