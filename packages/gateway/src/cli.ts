import { readFileSync } from "node:fs";
import { evaluateGatewayRequest, writeGatewayDecision } from "./gateway.ts";

const args = parseArgs(process.argv.slice(2));

if (args.command !== "check") {
  fail("usage: govreplay-gateway check --request <agent-action-request.json> --out <decision.json>");
}
if (args.request === undefined || args.out === undefined) {
  fail("check requires --request <agent-action-request.json> and --out <decision.json>");
}

const request = JSON.parse(readFileSync(args.request, "utf8"));
const decision = evaluateGatewayRequest(request);
writeGatewayDecision(decision, args.out);
console.log(JSON.stringify({
  request_id: decision.request_id,
  decision: decision.decision,
  gateway_state: decision.gateway_state,
  action_attestation_emitted: decision.agent_action_attestation !== null,
}, null, 2));

function parseArgs(values: string[]): { command?: string; request?: string; out?: string } {
  const parsed: { command?: string; request?: string; out?: string } = {};
  parsed.command = values[0];
  for (let index = 1; index < values.length; index += 1) {
    const key = values[index];
    const value = values[index + 1];
    if (key === "--request") {
      parsed.request = value;
      index += 1;
    } else if (key === "--out") {
      parsed.out = value;
      index += 1;
    } else {
      fail(`unknown argument: ${key}`);
    }
  }
  return parsed;
}

function fail(message: string): never {
  console.error(message);
  process.exit(2);
}
