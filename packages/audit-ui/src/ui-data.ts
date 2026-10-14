import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

export type UiData = {
  schema_version: "govprov.audit_ui_data.v1";
  generated_at: string;
  runs: UiRunSummary[];
  metrics: Record<string, UiMetricsSummary>;
  replays: UiReplay[];
  faults: UiFaultInspection[];
  demos: UiDemo[];
};

export type UiRunSummary = {
  run_id: string;
  created_at: string | null;
  matrix: string | null;
  configuration_count: number;
  scenario_count: number;
  workflow_count: number;
  fault_count: number;
  policy_count: number;
  overall_status: "pass" | "failures_detected" | "unknown";
  manifest: Record<string, unknown>;
};

export type UiMetricsSummary = {
  run_id: string;
  workflow_count: number;
  bounded_claim: string | null;
  configurations: Array<{
    configuration: string;
    workflow_count: number;
    precision: number;
    recall: number;
    f1: number;
    reconstruction_completeness: number;
    drift_classification_accuracy: number;
    localization_accuracy: number;
    median_workflow_latency_ms: number;
    p95_workflow_latency_ms: number;
    median_verification_ms: number;
    storage_bytes_per_workflow: number;
    transactions_per_workflow: number;
    gas_per_workflow: number;
  }>;
};

export type UiReplay = {
  run_id: string;
  workflow_id: string;
  deployment_id: string;
  scenario_id: string;
  system_configuration: string;
  policy_version: string | null;
  fault_id: string | null;
  verdict: "PASS" | "FAIL";
  failure_stage: string | null;
  failure_code: string | null;
  historical_compliance: string;
  current_policy_compliance: string;
  policy_drift: boolean;
  lifecycle: UiLifecycleNode[];
  checks: Array<{
    name: string;
    stage: string;
    status: string;
    code: string | null;
    detail: string;
  }>;
};

export type UiLifecycleNode = {
  key: string;
  label: string;
  present: boolean;
  hash_status: "present" | "missing" | "not_applicable";
  signature_status: "verified" | "not_evaluated";
  ledger_status: "verified" | "missing" | "not_applicable";
  policy_status: "verified" | "drift" | "not_applicable";
  verification_verdict: "PASS" | "FAIL" | "NOT_EVALUATED";
};

export type UiFaultInspection = {
  run_id: string;
  workflow_id: string;
  deployment_id: string;
  scenario_id: string;
  system_configuration: string;
  policy_version: string | null;
  fault_id: string;
  injected_at_boundary: string | null;
  expected_verdict: string;
  actual_verdict: string;
  expected_failure_stage: string | null;
  actual_failure_stage: string | null;
  expected_failure_code: string | null;
  actual_failure_code: string | null;
  localization_status: "match" | "mismatch" | "not_applicable";
  replay_trace_summary: string;
};

export type UiDemo = {
  demo_id: string;
  title: string;
  run_id: string;
  workflow_id: string;
  deployment_id: string;
  scenario_id: string;
  policy_version: string | null;
  fault_id: string | null;
  purpose: string;
};

const LIFECYCLE: Array<{ key: string; label: string }> = [
  { key: "observation", label: "Observation" },
  { key: "evidence", label: "Evidence" },
  { key: "policy_decision", label: "Policy decision" },
  { key: "action_proposal", label: "Action proposal" },
  { key: "approval_chain", label: "Approvals" },
  { key: "artifact", label: "Artifact" },
  { key: "deployment", label: "Deployment" },
  { key: "ledger_anchor", label: "Ledger anchor" },
];

const DEMO_TARGETS = [
  {
    demo_id: "demo_happy_deploy",
    title: "Demo A: Happy Path Governance Replay",
    scenario: "S4_policy_gated_deployment",
    policy: "policy:v3",
    fault: "F0",
    purpose: "Full pass replay with policy, approval, artifact, deployment, and ledger-anchor checks.",
  },
  {
    demo_id: "demo_policy_drift",
    title: "Demo B: Policy Drift Explanation",
    scenario: "S1_runbook_update",
    policy: "policy:v1",
    fault: "F0",
    purpose: "Historical pass/current fail replay under the latest policy.",
  },
  {
    demo_id: "demo_artifact_substitution",
    title: "Demo C: Artifact Substitution Detection",
    scenario: "S3_patch_proposal",
    policy: "policy:v3",
    fault: "F10",
    purpose: "Artifact/deployment hash mismatch surfaced in replay.",
  },
  {
    demo_id: "demo_separation_duties",
    title: "Demo D: Separation Of Duties Failure",
    scenario: "S2_configuration_change",
    policy: "policy:v2",
    fault: "F8",
    purpose: "Approval governance failure localized to separation of duties.",
  },
] as const;

type AuditRecord = {
  run_id: string;
  workflow_id: string;
  scenario_id: string;
  system_configuration: string;
  replay_input: string;
  verdict: "PASS" | "FAIL";
  failure_stage: string | null;
  failure_code: string | null;
  historical_compliance: string;
  current_policy_compliance: string;
  policy_drift: boolean;
  reconstructed_links: Record<string, boolean>;
  checks: UiReplay["checks"];
};

type WorkloadRecord = {
  workflow_id: string;
  policy_version: string;
  fault_id: string;
};

type GroundTruthRecord = WorkloadRecord & {
  system_configuration: string;
  scenario_id: string;
  deployment_id: string;
  expected_verdict: string;
  expected_failure_stage: string | null;
  expected_failure_code: string | null;
};

type FaultLogRecord = {
  workflow_id: string;
  fault_id: string;
  injected_at_boundary: string;
  expected_failure_stage: string | null;
  expected_failure_code: string | null;
};

export function buildUiData(runRoots: string[], options: { generatedAt?: string } = {}): UiData {
  const runs: UiRunSummary[] = [];
  const metrics: Record<string, UiMetricsSummary> = {};
  const replays: UiReplay[] = [];
  const faults: UiFaultInspection[] = [];

  for (const runRoot of runRoots) {
    const run = readRun(runRoot);
    runs.push(run.summary);
    metrics[run.summary.run_id] = run.metrics;
    replays.push(...run.replays);
    faults.push(...run.faults);
  }

  return {
    schema_version: "govprov.audit_ui_data.v1",
    generated_at: options.generatedAt ?? new Date().toISOString(),
    runs,
    metrics,
    replays,
    faults,
    demos: selectDemos(replays),
  };
}

export function writeUiData(path: string, data: UiData): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`);
}

function readRun(runRoot: string): {
  summary: UiRunSummary;
  metrics: UiMetricsSummary;
  replays: UiReplay[];
  faults: UiFaultInspection[];
} {
  const manifest = readJson(join(runRoot, "manifest.json"));
  const workload = readJsonl<WorkloadRecord>(join(runRoot, "inputs", "workload.jsonl"));
  const truth = readJsonl<GroundTruthRecord>(join(runRoot, "inputs", "ground_truth.jsonl"));
  const audit = readJsonl<AuditRecord>(join(runRoot, "audit", "audit_results.jsonl"));
  const faultLogs = readFaultLogs(join(runRoot, "faults"));
  const metricsRaw = readJson(join(runRoot, "results", "metrics_summary.json"));
  const runId = stringValue(manifest.run_id) ?? basename(runRoot);
  const workloadById = new Map(workload.map((item) => [item.workflow_id, item]));
  const truthById = new Map(truth.map((item) => [`${item.system_configuration}/${item.workflow_id}`, item]));
  const faultById = new Map(faultLogs.map((item) => [item.workflow_id, item]));
  const scenarios = new Set(workload.map((item: any) => item.scenario_id).filter(Boolean));
  const policies = new Set(workload.map((item) => item.policy_version).filter(Boolean));
  const faultsSeen = new Set(workload.map((item) => item.fault_id).filter((item) => item !== "F0"));
  const configurations = new Set(audit.map((item) => item.system_configuration).filter(Boolean));

  const replays = audit.map((record) => {
    const workloadRecord = workloadById.get(record.workflow_id);
    return toReplay(runId, record, workloadRecord);
  });

  const faultInspections = audit
    .map((record) => {
      const truthRecord = truthById.get(`${record.system_configuration}/${record.workflow_id}`);
      if (truthRecord === undefined || truthRecord.fault_id === "F0") {
        return null;
      }
      return toFaultInspection(runId, record, truthRecord, faultById.get(record.workflow_id));
    })
    .filter((item): item is UiFaultInspection => item !== null);

  return {
    summary: {
      run_id: runId,
      created_at: stringValue(manifest.created_at),
      matrix: stringValue(manifest.matrix),
      configuration_count: configurations.size,
      scenario_count: scenarios.size,
      workflow_count: audit.length,
      fault_count: faultsSeen.size,
      policy_count: policies.size,
      overall_status: audit.some((record) => record.verdict === "FAIL") ? "failures_detected" : "pass",
      manifest,
    },
    metrics: normalizeMetrics(runId, metricsRaw),
    replays,
    faults: faultInspections,
  };
}

function toReplay(runId: string, record: AuditRecord, workloadRecord: WorkloadRecord | undefined): UiReplay {
  return {
    run_id: runId,
    workflow_id: record.workflow_id,
    deployment_id: record.replay_input,
    scenario_id: record.scenario_id,
    system_configuration: record.system_configuration,
    policy_version: workloadRecord?.policy_version ?? null,
    fault_id: workloadRecord?.fault_id ?? null,
    verdict: record.verdict,
    failure_stage: record.failure_stage,
    failure_code: record.failure_code,
    historical_compliance: record.historical_compliance,
    current_policy_compliance: record.current_policy_compliance,
    policy_drift: record.policy_drift,
    lifecycle: LIFECYCLE.map((node) => lifecycleNode(node, record)),
    checks: record.checks ?? [],
  };
}

function lifecycleNode(node: { key: string; label: string }, record: AuditRecord): UiLifecycleNode {
  const present = record.reconstructed_links[node.key] === true;
  const failedHere = record.verdict === "FAIL" && stageMatchesNode(record.failure_stage, node.key);
  return {
    key: node.key,
    label: node.label,
    present,
    hash_status: present ? "present" : "missing",
    signature_status: present && !["policy_version", "ledger_anchor"].includes(node.key) ? "verified" : "not_evaluated",
    ledger_status: node.key === "ledger_anchor" ? (present ? "verified" : "missing") : "not_applicable",
    policy_status: ["policy_version", "policy_decision"].includes(node.key)
      ? record.policy_drift ? "drift" : "verified"
      : "not_applicable",
    verification_verdict: failedHere ? "FAIL" : present ? "PASS" : "NOT_EVALUATED",
  };
}

function toFaultInspection(
  runId: string,
  record: AuditRecord,
  truth: GroundTruthRecord,
  fault: FaultLogRecord | undefined,
): UiFaultInspection {
  const stageMatch = normalizeStage(record.failure_stage) === normalizeStage(truth.expected_failure_stage);
  const codeMatch = (record.failure_code ?? null) === (truth.expected_failure_code ?? null);
  const expectedFail = truth.expected_verdict === "fail";
  return {
    run_id: runId,
    workflow_id: record.workflow_id,
    deployment_id: record.replay_input,
    scenario_id: record.scenario_id,
    system_configuration: record.system_configuration,
    policy_version: truth.policy_version,
    fault_id: truth.fault_id,
    injected_at_boundary: fault?.injected_at_boundary ?? null,
    expected_verdict: truth.expected_verdict,
    actual_verdict: record.verdict.toLowerCase(),
    expected_failure_stage: truth.expected_failure_stage,
    actual_failure_stage: record.failure_stage,
    expected_failure_code: truth.expected_failure_code,
    actual_failure_code: record.failure_code,
    localization_status: expectedFail ? stageMatch && codeMatch ? "match" : "mismatch" : "not_applicable",
    replay_trace_summary: `${record.workflow_id}: expected ${truth.expected_failure_code ?? "none"} at ${truth.expected_failure_stage ?? "none"}, observed ${record.failure_code ?? "none"} at ${record.failure_stage ?? "none"}.`,
  };
}

function normalizeMetrics(runId: string, raw: any): UiMetricsSummary {
  return {
    run_id: runId,
    workflow_count: numberValue(raw.workflow_count),
    bounded_claim: stringValue(raw.bounded_claim),
    configurations: Array.isArray(raw.configurations) ? raw.configurations.map((item: any) => ({
      configuration: stringValue(item.configuration) ?? "unknown",
      workflow_count: numberValue(item.workflow_count),
      precision: numberValue(item.precision),
      recall: numberValue(item.recall),
      f1: numberValue(item.f1),
      reconstruction_completeness: numberValue(item.reconstruction_completeness),
      drift_classification_accuracy: numberValue(item.drift_classification_accuracy),
      localization_accuracy: numberValue(item.localization_accuracy),
      median_workflow_latency_ms: numberValue(item.median_workflow_latency_ms),
      p95_workflow_latency_ms: numberValue(item.p95_workflow_latency_ms),
      median_verification_ms: numberValue(item.median_verification_ms),
      storage_bytes_per_workflow: numberValue(item.storage_bytes_per_workflow),
      transactions_per_workflow: numberValue(item.transactions_per_workflow),
      gas_per_workflow: numberValue(item.gas_per_workflow),
    })) : [],
  };
}

function selectDemos(replays: UiReplay[]): UiDemo[] {
  return DEMO_TARGETS.map((target) => {
    const replay = replays.find((item) =>
      item.system_configuration === "govreplay_besu"
      && item.scenario_id === target.scenario
      && item.policy_version === target.policy
      && item.fault_id === target.fault
    );
    if (replay === undefined) {
      return null;
    }
    return {
      demo_id: target.demo_id,
      title: target.title,
      run_id: replay.run_id,
      workflow_id: replay.workflow_id,
      deployment_id: replay.deployment_id,
      scenario_id: replay.scenario_id,
      policy_version: replay.policy_version,
      fault_id: replay.fault_id,
      purpose: target.purpose,
    };
  }).filter((item): item is UiDemo => item !== null);
}

function stageMatchesNode(stage: string | null, nodeKey: string): boolean {
  if (stage === null) {
    return false;
  }
  if (stage === "artifact" && ["artifact", "deployment"].includes(nodeKey)) {
    return true;
  }
  if (stage === "approval" && nodeKey === "approval_chain") {
    return true;
  }
  if (stage === "policy" && ["policy_version", "policy_decision"].includes(nodeKey)) {
    return true;
  }
  return stage === nodeKey;
}

function normalizeStage(stage: string | null): string | null {
  if (stage === "artifact_deployment") {
    return "artifact";
  }
  return stage;
}

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, "utf8"));
}

function readJsonl<T>(path: string): T[] {
  const text = readFileSync(path, "utf8").trim();
  return text === "" ? [] : text.split("\n").map((line) => JSON.parse(line));
}

function readFaultLogs(dir: string): FaultLogRecord[] {
  if (!existsSync(dir)) {
    return [];
  }
  return readdirSync(dir)
    .filter((name) => name.endsWith(".jsonl"))
    .flatMap((name) => readJsonl<FaultLogRecord>(join(dir, name)));
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function numberValue(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}
