import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  evaluateGatewayRequest,
  type AgentActionRequest,
  type GatewayDecision,
} from "./gateway.ts";

export type ExampleClientResult = {
  schema_version: "govreplay.gateway_example_client.v1";
  request_id: string;
  workflow_id: string;
  blocked: boolean;
  gateway_decision_path: string;
  workflow_records_path: string | null;
  emitted_record_types: string[];
};

export function runExampleAgentClient(input: {
  request: AgentActionRequest;
  outputRoot: string;
}): ExampleClientResult {
  mkdirSync(input.outputRoot, { recursive: true });
  const decision = evaluateGatewayRequest(input.request);
  const decisionPath = join(input.outputRoot, "gateway_decision.json");
  writeFileSync(decisionPath, `${JSON.stringify(decision, null, 2)}\n`);

  if (decision.blocked) {
    const result = resultRecord(input.request, decision, decisionPath, null);
    writeFileSync(join(input.outputRoot, "client_result.json"), `${JSON.stringify(result, null, 2)}\n`);
    return result;
  }

  const records = workflowRecords(input.request, decision);
  const workflowRecordsPath = join(input.outputRoot, "workflow_records.json");
  writeFileSync(workflowRecordsPath, `${JSON.stringify(records, null, 2)}\n`);
  const result = resultRecord(input.request, decision, decisionPath, workflowRecordsPath);
  writeFileSync(join(input.outputRoot, "client_result.json"), `${JSON.stringify(result, null, 2)}\n`);
  return result;
}

function workflowRecords(request: AgentActionRequest, decision: GatewayDecision): Record<string, unknown> {
  const artifactDigest = request.artifact_refs[0]?.digest ?? null;
  const gatewayLineage = {
    gateway_decision_hash: decision.policy_decision_hash,
    gateway_policy_decision_attestation_hash: decision.policy_decision_attestation.attestation_hash,
    agent_action_attestation_hash: decision.agent_action_attestation?.attestation_hash ?? null,
  };
  const records: Record<string, unknown> = {
    schema_version: "govreplay.gateway_example_workflow_records.v1",
    boundary: "The deterministic client emits workflow records only after gateway allow.",
    request_id: request.request_id,
    scenario_id: request.scenario_id,
    workflow_id: request.workflow_id,
    gateway_lineage: gatewayLineage,
    action: {
      action_id: request.action.action_id,
      action_type: request.action.action_type,
      actor_id: request.actor.actor_id,
      resource_id: request.resource.resource_id,
      ...gatewayLineage,
    },
    approval: {
      approval_id: request.approval_refs[0]?.id ?? `approval-${request.request_id}`,
      action_id: request.action.action_id,
      decision: request.approval_refs.length > 0 ? "approved_reference_bound" : "pending_required_approval",
      required_obligations: decision.obligations,
      ...gatewayLineage,
    },
    artifact: {
      artifact_id: request.artifact_refs[0]?.id ?? `artifact-${request.request_id}`,
      action_id: request.action.action_id,
      artifact_type: request.artifact_refs[0]?.type ?? "unknown",
      content_digest: artifactDigest,
      ...gatewayLineage,
    },
  };

  if (request.action.action_type === "propose_config_change") {
    records.config_change = {
      config_change_id: `config-${request.request_id}`,
      resource_id: request.resource.resource_id,
      approval_refs: request.approval_refs,
      evidence_refs: request.evidence_refs,
      ...gatewayLineage,
    };
  }

  if (request.action.action_type === "propose_patch") {
    records.patch = {
      patch_id: `patch-${request.request_id}`,
      issue_ref: request.evidence_refs.find((ref) => ref.type === "issue") ?? null,
      test_ref: request.evidence_refs.find((ref) => ref.type === "test_report") ?? null,
      artifact_ref: request.artifact_refs[0] ?? null,
      ...gatewayLineage,
    };
  }

  if (request.action.action_type === "deploy_artifact") {
    records.deployment = {
      deployment_id: request.deployment_refs[0]?.id ?? `deployment-${request.request_id}`,
      action_id: request.action.action_id,
      status: "approved_artifact_bound",
      target_environment: request.resource.environment,
      approved_artifact_digest: artifactDigest,
      deployed_artifact_digest: artifactDigest,
      approval_refs: request.approval_refs,
      ...gatewayLineage,
    };
  }

  if (request.action.action_type === "request_governance_state_change") {
    records.governance_state = {
      governance_state_change_id: `governance-state-${request.request_id}`,
      requested_transition: request.resource.resource_id,
      actor_roles: request.actor.roles,
      evidence_refs: request.evidence_refs,
      ...gatewayLineage,
    };
  }

  return records;
}

function resultRecord(
  request: AgentActionRequest,
  decision: GatewayDecision,
  decisionPath: string,
  workflowRecordsPath: string | null,
): ExampleClientResult {
  return {
    schema_version: "govreplay.gateway_example_client.v1",
    request_id: request.request_id,
    workflow_id: request.workflow_id,
    blocked: decision.blocked,
    gateway_decision_path: decisionPath,
    workflow_records_path: workflowRecordsPath,
    emitted_record_types: workflowRecordsPath === null ? [] : emittedRecordTypes(request),
  };
}

function emittedRecordTypes(request: AgentActionRequest): string[] {
  const types = ["action", "approval", "artifact"];
  if (request.action.action_type === "propose_config_change") {
    types.push("config_change");
  }
  if (request.action.action_type === "propose_patch") {
    types.push("patch");
  }
  if (request.action.action_type === "deploy_artifact") {
    types.push("deployment");
  }
  if (request.action.action_type === "request_governance_state_change") {
    types.push("governance_state");
  }
  return types;
}

if (process.argv[1]?.endsWith("example-agent-client.ts")) {
  const args = parseArgs(process.argv.slice(2));
  if (args.request === undefined || args.out === undefined) {
    console.error("usage: node --experimental-strip-types src/example-agent-client.ts --request <request.json> --out <output-dir>");
    process.exit(2);
  }
  const request = JSON.parse(readFileSync(args.request, "utf8")) as AgentActionRequest;
  const result = runExampleAgentClient({ request, outputRoot: args.out });
  console.log(JSON.stringify(result, null, 2));
}

function parseArgs(values: string[]): { request?: string; out?: string } {
  const parsed: { request?: string; out?: string } = {};
  for (let index = 0; index < values.length; index += 1) {
    const key = values[index];
    const value = values[index + 1];
    if (key === "--request") {
      parsed.request = value;
      index += 1;
    } else if (key === "--out") {
      parsed.out = value;
      index += 1;
    } else {
      throw new TypeError(`unknown argument: ${key}`);
    }
  }
  return parsed;
}
