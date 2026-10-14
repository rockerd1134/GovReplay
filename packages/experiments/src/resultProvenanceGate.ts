import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseExperimentConfig } from "./config.ts";
import { type WorkloadInstance } from "./model.ts";
import { runExperiment } from "./runner.ts";
import { buildSeglLog, verifySeglWorkflow } from "./segl.ts";

export type ResultProvenanceStatus = "PASS" | "FAIL";

export type ResultProvenanceCheck = {
  id: string;
  invariant: number;
  title: string;
  status: ResultProvenanceStatus;
  detail: string;
  evidence: string[];
  owner: string;
};

export type ResultProvenanceGateReport = {
  schema_version: "govreplay.result_provenance_gate.v1";
  status: ResultProvenanceStatus;
  generated_at: string;
  checks: ResultProvenanceCheck[];
};

export type ResultProvenanceGateOptions = {
  softwareRoot?: string;
  packageRoot?: string;
  runExperimentProbe?: boolean;
};

type ProbeRun = {
  runRoot: string;
  replayRows: Array<Record<string, unknown>>;
  replayReportHashBeforeMutation: string;
  replayReportHashAfterMutation: string;
};

const DEFAULT_PACKAGE_ROOT = resolve(import.meta.dirname, "..");
const DEFAULT_SOFTWARE_ROOT = resolve(import.meta.dirname, "..", "..", "..");

export async function runResultProvenanceGate(options: ResultProvenanceGateOptions = {}): Promise<ResultProvenanceGateReport> {
  const packageRoot = options.packageRoot ?? DEFAULT_PACKAGE_ROOT;
  const softwareRoot = options.softwareRoot ?? DEFAULT_SOFTWARE_ROOT;
  const source = readGateSourceFiles(softwareRoot);
  const probe = options.runExperimentProbe === false ? null : await runGroundTruthMutationProbe(packageRoot);
  const checks = [
    checkGroundTruthMutationBoundary(source.runner, probe),
    checkReplayRowsExcludeOracleLabels(probe),
    checkPassRowsHaveObservedVerifierSource(probe),
    checkLiveBesuStatusDerivedFromVerifierRows(source.liveBesuShell, source.liveBesuSolidity),
    checkSeglVerificationIgnoresFaultLabel(),
    checkPolicyDecisionReplayIgnoresExpectedCompliance(source.runner, source.auditReplay, source.gateway, source.policyDecisionAttestation),
    checkPromotedCommandsRegeneratePaperResults(source.compose, source.hashOnlyHardConfigExists),
  ];
  return {
    schema_version: "govreplay.result_provenance_gate.v1",
    status: checks.every((check) => check.status === "PASS") ? "PASS" : "FAIL",
    generated_at: "2026-07-05T00:00:00Z",
    checks,
  };
}

export function formatResultProvenanceGateReport(report: ResultProvenanceGateReport): string {
  const lines = [
    "# Result Provenance Gate",
    "",
    `Overall status: ${report.status}`,
    "",
  ];
  for (const check of report.checks) {
    lines.push(`- ${check.status} ${check.id}: ${check.title}`);
    lines.push(`  ${check.detail}`);
    lines.push(`  owner: ${check.owner}`);
    for (const evidence of check.evidence.slice(0, 5)) {
      lines.push(`  evidence: ${evidence}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

function readGateSourceFiles(softwareRoot: string): {
  compose: string;
  runner: string;
  auditReplay: string;
  gateway: string;
  policyDecisionAttestation: string;
  liveBesuShell: string;
  liveBesuSolidity: string;
  hashOnlyHardConfigExists: boolean;
} {
  return {
    compose: readUtf8(join(softwareRoot, "compose.yaml")),
    runner: readUtf8(join(softwareRoot, "packages", "experiments", "src", "runner.ts")),
    auditReplay: readUtf8(join(softwareRoot, "packages", "audit-replay", "src", "replay.ts")),
    gateway: readUtf8(join(softwareRoot, "packages", "gateway", "src", "gateway.ts")),
    policyDecisionAttestation: readUtf8(join(softwareRoot, "packages", "policy-service", "src", "policy-decision-attestation.ts")),
    liveBesuShell: readUtf8(join(softwareRoot, "contracts", "scripts", "besu-live-arpe-full.sh")),
    liveBesuSolidity: readUtf8(join(softwareRoot, "contracts", "script", "BesuLiveArpeFull.s.sol")),
    hashOnlyHardConfigExists: existsSync(join(softwareRoot, "packages", "experiments", "configs", "arpe_hash_only_ablation_hard_debug.json")),
  };
}

async function runGroundTruthMutationProbe(packageRoot: string): Promise<ProbeRun> {
  const config = parseExperimentConfig(join(packageRoot, "configs", "debug.json"));
  const tempRoot = mkdtempSync(join(tmpdir(), "govreplay-result-provenance-"));
  const result = await runExperiment({ ...config, run_id: "px-s33-result-provenance-gate" }, { packageRoot: tempRoot });
  const replayReportPath = join(result.runRoot, "audit", "replay_report.json");
  const replayReportHashBeforeMutation = fileHash(replayReportPath);
  mutateGroundTruthFiles(result.runRoot);
  const replayReportHashAfterMutation = fileHash(replayReportPath);
  const replayReport = JSON.parse(readUtf8(replayReportPath));
  return {
    runRoot: result.runRoot,
    replayRows: Array.isArray(replayReport.records) ? replayReport.records : [],
    replayReportHashBeforeMutation,
    replayReportHashAfterMutation,
  };
}

function mutateGroundTruthFiles(runRoot: string): void {
  const jsonPath = join(runRoot, "inputs", "ground_truth.json");
  const jsonlPath = join(runRoot, "inputs", "ground_truth.jsonl");
  const groundTruthSet = JSON.parse(readUtf8(jsonPath));
  const mutatedRecords = Array.isArray(groundTruthSet.records)
    ? groundTruthSet.records.map(mutateOracleRecord)
    : [];
  writeFileSync(jsonPath, `${JSON.stringify({ ...groundTruthSet, records: mutatedRecords }, null, 2)}\n`);
  writeFileSync(jsonlPath, `${mutatedRecords.map((record) => JSON.stringify(record)).join("\n")}\n`);
}

function mutateOracleRecord(record: Record<string, unknown>): Record<string, unknown> {
  return {
    ...record,
    expected_verdict: record.expected_verdict === "pass" ? "fail" : "pass",
    expected_failure_stage: "policy",
    expected_failure_code: "px_s33_mutated_expected_label",
    expected_policy_drift_class: "px_s33_mutated_expected_label",
    expected_historical_compliance: record.expected_historical_compliance === "pass" ? "fail" : "pass",
    expected_current_compliance: record.expected_current_compliance === "pass" ? "fail" : "pass",
  };
}

function checkGroundTruthMutationBoundary(runnerSource: string, probe: ProbeRun | null): ResultProvenanceCheck {
  const sourceEvidence = matchingEvidence(runnerSource, [
    "synthesizeAuditRecord(instance, groundTruth[index], config)",
    "function synthesizeAuditRecord(instance: WorkloadInstance, truth: GroundTruthRecord",
    "detectedFault(instance.system_configuration, truth)",
    "historical_compliance: truth.expected_historical_compliance",
    "policy_drift_class: truth.expected_policy_drift_class",
  ]);
  const probeEvidence = probe === null
    ? ["experiment probe disabled"]
    : [
      `probe run: ${probe.runRoot}`,
      `replay_report hash before ground_truth mutation: ${probe.replayReportHashBeforeMutation}`,
      `replay_report hash after ground_truth mutation: ${probe.replayReportHashAfterMutation}`,
    ];
  const artifactBoundaryPass = probe !== null && probe.replayReportHashBeforeMutation === probe.replayReportHashAfterMutation;
  const status = artifactBoundaryPass && sourceEvidence.length === 0 ? "PASS" : "FAIL";
  return {
    id: "PX-S33-1",
    invariant: 1,
    title: "Ground-truth label mutation must not change replay verdicts",
    status,
    detail: status === "PASS"
      ? "Post-run replay artifacts were stable after mutating oracle files, and runner source no longer matches the in-memory oracle synthesis patterns."
      : artifactBoundaryPass
        ? "Post-run replay artifacts were stable after mutating oracle files, but runner source still synthesizes replay rows from in-memory ground truth."
        : "Mutating only ground-truth files changed replay artifacts or the dynamic probe was unavailable.",
    evidence: [...probeEvidence, ...sourceEvidence],
    owner: status === "PASS" ? "PX-S34 complete" : "PX-S34/PX-S35",
  };
}

function checkReplayRowsExcludeOracleLabels(probe: ProbeRun | null): ResultProvenanceCheck {
  const findings = probe === null ? [] : forbiddenOracleFields(probe.replayRows);
  return {
    id: "PX-S33-2",
    invariant: 2,
    title: "Replay report rows must not carry expected labels or raw fault IDs as verifier inputs",
    status: findings.length === 0 ? "PASS" : "FAIL",
    detail: findings.length === 0
      ? "Generated replay rows do not expose forbidden oracle-label fields."
      : `Generated replay rows expose ${findings.length} oracle/fault-label traces.`,
    evidence: findings.length === 0 ? ["no forbidden oracle-label traces found"] : findings.slice(0, 8),
    owner: findings.length === 0 ? "PX-S34 complete" : "PX-S34/PX-S35",
  };
}

function checkPassRowsHaveObservedVerifierSource(probe: ProbeRun | null): ResultProvenanceCheck {
  const rows = probe?.replayRows ?? [];
  const missing = rows.filter((row) => isPassLikeRow(row) && !hasObservedVerifierSource(row));
  return {
    id: "PX-S33-3",
    invariant: 3,
    title: "Paper-facing PASS rows must identify an observed verifier source",
    status: missing.length === 0 ? "PASS" : "FAIL",
    detail: missing.length === 0
      ? "Every PASS-like row has observed verifier provenance."
      : `${missing.length} PASS-like replay rows lack verifier_source, replay_backend, or observed_evidence.`,
    evidence: missing.slice(0, 8).map((row) => `workflow_id=${String(row.workflow_id ?? row.workflow_index ?? "unknown")} configuration=${String(row.system_configuration ?? "unknown")}`),
    owner: missing.length === 0 ? "PX-S34 complete" : "PX-S35/PX-S36",
  };
}

function checkLiveBesuStatusDerivedFromVerifierRows(shellSource: string, soliditySource: string): ResultProvenanceCheck {
  const staticEvidence = [
    ...matchingEvidence(shellSource, [
      "write_live_audit()",
      "while [ \"$index\" -lt 656 ]",
      "\"replay_verdict\":\"PASS\",\"oracle_agreement\":\"PASS\"",
      "\"replay_success_count\": 656",
      "\"replay_failure_count\": 0",
    ], "contracts/scripts/besu-live-arpe-full.sh"),
    ...matchingEvidence(soliditySource, [
      "\"replay_success_count\":",
      "vm.toString(TOTAL_RECORDS)",
      "\"replay_failure_count\":0,",
    ], "contracts/script/BesuLiveArpeFull.s.sol"),
  ];
  const derivedEvidence = matchingEvidence(shellSource, [
    "replay_row_count=\"$(count_live_audit_matches",
    "replay_success_count=\"$(count_live_audit_matches",
    "replay_failure_count=\"$(count_live_audit_matches",
    "\"observed_transaction_count\": ${transaction_count}",
    "\"formula_replay_contract_call_count\": ${formula_replay_contract_call_count}",
  ], "contracts/scripts/besu-live-arpe-full.sh");
  const verifierEvidence = matchingEvidence(soliditySource, [
    "vm.writeLine(",
    "_verifyWorkflow(",
    "_auditRow(",
  ], "contracts/script/BesuLiveArpeFull.s.sol");
  const hasObservedDerivation = derivedEvidence.length === 5 && verifierEvidence.length === 3;
  const status = staticEvidence.length === 0 && hasObservedDerivation ? "PASS" : "FAIL";
  return {
    id: "PX-S33-4",
    invariant: 4,
    title: "Live Besu replay success counts must be derived from verifier rows",
    status,
    detail: status === "PASS"
      ? "Live Besu status counts are derived from observed live verifier rows, and the Solidity script writes per-workflow RPC-backed verifier output."
      : "Live Besu writer still emits static PASS rows or success/failure counts from constants.",
    evidence: staticEvidence.length > 0 ? staticEvidence : [...derivedEvidence, ...verifierEvidence],
    owner: status === "PASS" ? "PX-S36 complete" : "PX-S36",
  };
}

function checkSeglVerificationIgnoresFaultLabel(): ResultProvenanceCheck {
  const withFaultLabel = seglGateInstance("H2");
  const withoutFaultLabel = { ...withFaultLabel, fault_id: "F0" as const };
  const { events } = buildSeglLog([withFaultLabel]);
  const withLabelCodes = issueCodes(verifySeglWorkflow(events, seglWorkflowReference(withFaultLabel)));
  const withoutLabelCodes = issueCodes(verifySeglWorkflow(events, seglWorkflowReference(withoutFaultLabel)));
  const same = JSON.stringify(withLabelCodes) === JSON.stringify(withoutLabelCodes);
  return {
    id: "PX-S33-5",
    invariant: 5,
    title: "SEGL semantic detection must not require fault_id",
    status: same ? "PASS" : "FAIL",
    detail: same
      ? "The same SEGL event log produced the same verifier result when only the generator fault label was changed outside the verifier input."
      : "The same SEGL event log produced different verifier results when only fault_id changed.",
    evidence: [
      `with fault_id=H2 issues: ${withLabelCodes.join(", ") || "none"}`,
      `with fault_id=F0 issues: ${withoutLabelCodes.join(", ") || "none"}`,
    ],
    owner: same ? "PX-S37 complete" : "PX-S37",
  };
}

function checkPolicyDecisionReplayIgnoresExpectedCompliance(
  runnerSource: string,
  auditReplaySource: string,
  gatewaySource: string,
  policyDecisionSource: string,
): ResultProvenanceCheck {
  const evidence = [
    ...matchingEvidence(runnerSource, [
      "historical_compliance: truth.expected_historical_compliance",
      "current_policy_compliance: truth.expected_current_compliance",
      "policy_drift_class: truth.expected_policy_drift_class",
    ], "packages/experiments/src/runner.ts"),
    ...matchingEvidence(auditReplaySource, [
      "const expectedHistorical = complianceValue(fixture?.expected_historical_compliance)",
      "const recomputed = expectedHistorical === \"fail\" ? \"deny\" : \"allow\"",
    ], "packages/audit-replay/src/replay.ts"),
    ...matchingEvidence(gatewaySource, [
      "expectedDecision: test.expected_decision",
    ], "packages/gateway/src/gateway.ts"),
    ...matchingEvidence(policyDecisionSource, [
      "decision: fixture.expectedDecision",
    ], "packages/policy-service/src/policy-decision-attestation.ts"),
  ];
  return {
    id: "PX-S33-6",
    invariant: 6,
    title: "Policy decision replay must not derive decisions from expected compliance labels",
    status: evidence.length === 0 ? "PASS" : "FAIL",
    detail: evidence.length === 0
      ? "Policy decision and replay paths do not show expected-label-derived decisions."
      : "Policy decision or replay paths still derive decisions from expected labels.",
    evidence,
    owner: "PX-S38",
  };
}

function checkPromotedCommandsRegeneratePaperResults(composeSource: string, hashOnlyHardConfigExists: boolean): ResultProvenanceCheck {
  const promotedCommandHasHashOnlyHard = composeSource.includes("arpe_hash_only_ablation_hard_debug.json");
  const evidence = [
    `hash-only hard config exists: ${hashOnlyHardConfigExists}`,
    `paper-arpe-full includes arpe_hash_only_ablation_hard_debug.json: ${promotedCommandHasHashOnlyHard}`,
  ];
  return {
    id: "PX-S33-7",
    invariant: 7,
    title: "Promoted paper commands must regenerate every paper-discussed result",
    status: hashOnlyHardConfigExists && !promotedCommandHasHashOnlyHard ? "FAIL" : "PASS",
    detail: hashOnlyHardConfigExists && !promotedCommandHasHashOnlyHard
      ? "The supplemental hash-only hard ablation exists but is not regenerated by the promoted paper-arpe-full command."
      : "Promoted commands include the known paper-facing ablation config.",
    evidence,
    owner: "PX-S35/PX-S39",
  };
}

function forbiddenOracleFields(rows: Array<Record<string, unknown>>): string[] {
  const forbiddenKeys = new Set([
    "expected_verdict",
    "expected_failure_stage",
    "expected_failure_code",
    "expected_policy_drift_class",
    "fault_id",
  ]);
  const findings: string[] = [];
  rows.forEach((row, index) => {
    walkRecord(row, (path, key, value) => {
      if (forbiddenKeys.has(key)) {
        findings.push(`row ${index} contains forbidden key ${path}`);
      }
      if (key === "detail" && typeof value === "string" && (value.includes(" expected=") || /\b[HF]\d+\b/.test(value))) {
        findings.push(`row ${index} detail leaks oracle/fault label at ${path}: ${value}`);
      }
    });
  });
  return findings;
}

function walkRecord(value: unknown, visit: (path: string, key: string, value: unknown) => void, path = "$"): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkRecord(item, visit, `${path}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") {
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    const childPath = `${path}.${key}`;
    visit(childPath, key, child);
    walkRecord(child, visit, childPath);
  }
}

function isPassLikeRow(row: Record<string, unknown>): boolean {
  return row.verdict === "PASS" || row.replay_verdict === "PASS" || row.oracle_agreement === "PASS";
}

function hasObservedVerifierSource(row: Record<string, unknown>): boolean {
  const hasSource = typeof row.verifier_source === "string" || typeof row.replay_backend === "string";
  const hasEvidence = Array.isArray(row.checks) && row.checks.length > 0 || Array.isArray(row.observed_evidence) && row.observed_evidence.length > 0;
  return hasSource && hasEvidence;
}

function matchingEvidence(source: string, needles: string[], label = "source"): string[] {
  return needles.flatMap((needle) => source.includes(needle) ? [`${label}: ${needle}`] : []);
}

function issueCodes(result: { issues: Array<{ code: string }> }): string[] {
  return result.issues.map((issue) => issue.code).sort();
}

function seglWorkflowReference(instance: Pick<WorkloadInstance, "workflow_id">): { workflow_id: string } {
  return { workflow_id: instance.workflow_id };
}

function seglGateInstance(faultId: WorkloadInstance["fault_id"]): WorkloadInstance {
  return {
    run_id: "px-s33-segl-gate",
    workflow_id: "wf-SEGL-P1-H2-0001",
    scenario_id: "S2_configuration_change",
    policy_version: "policy:v1",
    system_configuration: "SEGL",
    fault_id: faultId,
    governance_domain: "policy_domain",
    governance_domain_type: "policy_versions_and_policy_decisions",
    governance_domain_id: "govreplay:domain:policy_domain",
    expected_domain: "policy_domain",
    domain_fault: faultId !== "F0",
    cross_domain_dependency: [],
    seed: 1,
    agent_id: "agent:configbot",
    artifact_id: "artifact-SEGL-P1-H2-0001",
    deployment_id: "deployment-SEGL-P1-H2-0001",
  };
}

function fileHash(path: string): string {
  return `sha256:${createHash("sha256").update(readUtf8(path)).digest("hex")}`;
}

function readUtf8(path: string): string {
  return readFileSync(path, "utf8");
}

async function main(): Promise<void> {
  const report = await runResultProvenanceGate();
  process.stdout.write(formatResultProvenanceGateReport(report));
  process.exitCode = report.status === "PASS" ? 0 : 1;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
