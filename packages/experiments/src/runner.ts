// Research fixture/demo code: embedded keys are public synthetic test vectors.
// Never use these keys or this fixture signer for production accounts. See SECURITY.md.
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { addressFromPrivateKey, signAttestation } from "../../attestations/src/signing.ts";
import { generateWorkload } from "./workload.ts";
import { GOVERNANCE_DOMAIN_TYPES, governanceDomainId, type GovernanceDomain, HARD_FAULT_BY_ID, HARD_FAULT_CATALOG, HARD_FAULT_IDS, type ExperimentConfig, type GroundTruthRecord, type HardFaultId, type SystemConfiguration, type WorkloadInstance } from "./model.ts";
import { scoreMetricRows, type ScoredMetricRow } from "./metrics.ts";
import { buildOracleRecords, type OracleRecord } from "./oracle.ts";
import { buildReplayInputRecords, type ReplayInputRecord } from "./replayInput.ts";
import { verifyReplayInputs, type ObservedVerifierOutputRecord } from "./replayOutput.ts";
import { buildSeglLog } from "./segl.ts";
import { ledgerStateRequirementForFault, loadArpeTaxonomy, type ArpeTaxonomy, type ArpeTestClass } from "./taxonomy.ts";

export type ExperimentRunResult = {
  runRoot: string;
  workload: WorkloadInstance[];
  groundTruth: OracleRecord[];
  replayInputs: ReplayInputRecord[];
  auditRecords: ObservedVerifierOutputRecord[];
  scoredMetricRows: ScoredMetricRow[];
};

const STANDARD_DIRS = [
  "inputs/policies",
  "inputs/evidence_templates",
  "inputs/artifact_templates",
  "baseline_logs",
  "objects/evidence",
  "objects/artifacts",
  "objects/attestations",
  "ledger",
  "telemetry",
  "faults",
  "audit/replay_traces",
  "results",
  "paper/figures",
] as const;

const MERKLE_LOG_PRIVATE_KEY = "0x0000000000000000000000000000000000000000000000000000000000000005";
const MERKLE_LOG_SIGNER = addressFromPrivateKey(MERKLE_LOG_PRIVATE_KEY);
const MERKLE_EVENT_TYPES = [
  "observation",
  "policy_decision",
  "action_proposal",
  "approval",
  "artifact",
  "deployment",
] as const;

export async function runExperiment(config: ExperimentConfig, options: { packageRoot: string }): Promise<ExperimentRunResult> {
  const runRoot = resolve(options.packageRoot, "runs", config.run_id);
  mkdirSync(runRoot, { recursive: true });
  for (const dir of STANDARD_DIRS) {
    mkdirSync(join(runRoot, dir), { recursive: true });
  }

  const workload = generateWorkload(config);
  const taxonomy = loadArpeTaxonomy();
  const groundTruth = buildOracleRecords(workload, config.current_policy_version, taxonomy);
  const replayInputs = buildReplayInputRecords(workload, config.current_policy_version);
  const auditRecords = verifyReplayInputs(replayInputs);
  const scoredMetricRows = scoreMetricRows(groundTruth, auditRecords);

  writeFileSync(join(runRoot, "config.yaml"), configYaml(config));
  writeJson(join(runRoot, "config.json"), config);
  writeJson(join(runRoot, "manifest.json"), runManifest(config, workload, groundTruth));
  writeJsonl(join(runRoot, "inputs", "workload.jsonl"), workload);
  writeJson(join(runRoot, "inputs", "arpe_test_classes.json"), taxonomyForOutput(taxonomy));
  writeJsonl(join(runRoot, "inputs", "ground_truth.jsonl"), groundTruth);
  writeJson(join(runRoot, "inputs", "ground_truth.json"), {
    schema_version: "govprov.ground_truth_set.v1",
    isolation_boundary: "Generated from workload and fault catalog before audit replay. Verifier code reads audit inputs, not this file.",
    record_count: groundTruth.length,
    records: groundTruth,
  });
  writeJson(join(runRoot, "inputs", "scenario.json"), scenarioSummary(config, workload));
  writeJson(join(runRoot, "inputs", "hard_fault_catalog.json"), {
    schema_version: "govprov.hard_fault_catalog.v1",
    matrix: config.matrix,
    selected_fault_ids: config.fault_ids.filter((faultId) => isHardFaultId(faultId)),
    deterministic_seeds: config.seeds,
    faults: HARD_FAULT_CATALOG,
  });
  writeJsonl(join(runRoot, "audit", "replay_inputs.jsonl"), replayInputs);
  writeJson(join(runRoot, "audit", "replay_inputs.json"), {
    schema_version: "govprov.replay_input_set.v1",
    separation_boundary: "Verifier input records omit oracle labels and fault identifiers. They are generated before observed verifier output.",
    record_count: replayInputs.length,
    records: replayInputs,
  });
  writeJsonl(join(runRoot, "baseline_logs", "structured_logs.jsonl"), workload.filter((item) => item.system_configuration === "baseline_structured_logs").map(baselineLog));
  const merkleLog = signedMerkleLog(workload.filter((item) => item.system_configuration === "baseline_signed_merkle_log"));
  writeJsonl(join(runRoot, "baseline_logs", "signed_merkle_log.jsonl"), merkleLog.events);
  writeJson(join(runRoot, "baseline_logs", "signed_merkle_manifest.json"), merkleLog.manifest);
  const seglLog = buildSeglLog(workload.filter((item) => item.system_configuration === "SEGL"));
  writeJsonl(join(runRoot, "baseline_logs", "segl_events.jsonl"), seglLog.events);
  writeJson(join(runRoot, "baseline_logs", "segl_manifest.json"), seglLog.manifest);
  writeJsonl(join(runRoot, "ledger", "hash_only_anchors.jsonl"), workload.filter((item) => item.system_configuration === "baseline_hash_only_ledger").map(hashOnlyAnchorEvent));
  writeJson(join(runRoot, "ledger", "hash_only_anchor_manifest.json"), hashOnlyAnchorManifest(workload.filter((item) => item.system_configuration === "baseline_hash_only_ledger")));
  writeJsonl(join(runRoot, "faults", "injection_log.jsonl"), groundTruth.filter((item) => item.fault_id !== "F0").map(faultLog));
  writeJson(join(runRoot, "faults", "fault_injection.json"), {
    schema_version: "govprov.fault_injection_set.v1",
    separation_boundary: "Fault plan and expected labels are emitted separately from verifier output.",
    record_count: groundTruth.filter((item) => item.fault_id !== "F0").length,
    records: groundTruth.filter((item) => item.fault_id !== "F0").map(faultLog),
  });
  writeJsonl(join(runRoot, "audit", "audit_results.jsonl"), auditRecords);
  writeJson(join(runRoot, "audit", "replay_report.json"), {
    schema_version: "govprov.audit_replay_report_set.v1",
    separation_boundary: "Verifier output only; ground truth remains under inputs/ and is consumed by metrics aggregation.",
    record_count: auditRecords.length,
    records: auditRecords,
  });
  writeJsonl(join(runRoot, "telemetry", "workflow_metrics.jsonl"), auditRecords.map((record) => ({
    workflow_id: record.workflow_id,
    system_configuration: record.system_configuration,
    workflow_total_ms: record.metrics.workflow_total_ms,
    verification_time_ms: record.metrics.verification_time_ms,
    storage_bytes: record.metrics.storage_bytes,
    ledger_transaction_count: record.metrics.ledger_transaction_count,
    gas_used: record.metrics.gas_used,
  })));
  writeJsonl(join(runRoot, "ledger", "events.jsonl"), auditRecords.filter((record) => record.system_configuration === "govreplay_besu" || record.system_configuration === "baseline_hash_only_ledger").map(ledgerEvent));
  writeJsonl(join(runRoot, "ledger", "transactions.jsonl"), auditRecords.filter((record) => record.system_configuration === "govreplay_besu" || record.system_configuration === "baseline_hash_only_ledger").map(ledgerTransaction));
  writeJson(join(runRoot, "ledger", "contract_addresses.json"), {
    boundary: "Phase 7 deterministic matrix sidecar; live Besu deployment remains in existing Besu Compose profiles.",
    chain_id: "1338",
    contract_set: "govprov:contract-set:phase7:v1",
  });
  const gasRows = gasUsageRows(auditRecords);
  writeJsonl(join(runRoot, "telemetry", "ledger_metrics.jsonl"), gasRows);

  writeMetricsAndPaperExports(runRoot, auditRecords, scoredMetricRows, taxonomy, gasRows, config);
  return { runRoot, workload, groundTruth, replayInputs, auditRecords, scoredMetricRows };
}

function writeMetricsAndPaperExports(
  runRoot: string,
  records: ObservedVerifierOutputRecord[],
  scoredRows: ScoredMetricRow[],
  taxonomy: ArpeTaxonomy,
  gasRows: GasUsageRow[],
  config: ExperimentConfig,
): void {
  const summary = metricsSummary(scoredRows);
  const byTestClass = taxonomyMetricRows(scoredRows, "test_class_id");
  const byArpeElement = taxonomyMetricRows(scoredRows, "arpe_property");
  const byExternalTradition = taxonomyMetricRows(scoredRows, "external_tradition");
  const byRequiredState = taxonomyMetricRows(scoredRows, "ledger_state_requirement");
  const byGovernanceDomain = byKey(scoredRows, "governance_domain");
  const byGovernanceDomainAndConfig = taxonomyMetricRows(scoredRows, "governance_domain");
  writeJsonl(join(runRoot, "results", "scored_metric_rows.jsonl"), scoredRows);
  writeJson(join(runRoot, "results", "metrics_summary.json"), summary);
  writeJson(join(runRoot, "results", "metrics.json"), {
    schema_version: "govprov.metrics_audit_bundle.v1",
    spec: "docs/metrics_spec.md",
    separation_boundary: "Metrics are derived after replay by joining oracle records to observed verifier output by replay_id.",
    summary,
    by_fault: byKey(scoredRows, "fault_id"),
    by_test_class: byTestClass,
    by_arpe_element: byArpeElement,
    by_external_tradition: byExternalTradition,
    by_required_state: byRequiredState,
    by_governance_domain: byGovernanceDomain,
    by_governance_domain_and_config: byGovernanceDomainAndConfig,
    by_policy: byKey(scoredRows, "policy_version"),
    by_scenario: byKey(scoredRows, "scenario_id"),
    scored_rows: "results/scored_metric_rows.jsonl",
    overhead: overheadRows(records),
    gas_summary: gasSummaryRows(gasRows),
  });
  writeJson(join(runRoot, "results", "matrix_summary.json"), matrixSummary(summary));
  writeCsv(join(runRoot, "results", "matrix_summary.csv"), matrixSummaryRows(summary));
  writeCsv(join(runRoot, "results", "metrics_by_fault.csv"), byKey(scoredRows, "fault_id"));
  const perFaultOracleRows = perFaultOracleAgreementRows(scoredRows);
  writeCsv(join(runRoot, "results", "per_fault_oracle_agreement.csv"), perFaultOracleRows);
  writeCsv(join(runRoot, "results", "metrics_by_test_class.csv"), byTestClass);
  writeCsv(join(runRoot, "results", "metrics_by_arpe_element.csv"), byArpeElement);
  writeCsv(join(runRoot, "results", "metrics_by_external_tradition.csv"), byExternalTradition);
  writeCsv(join(runRoot, "results", "metrics_by_required_state.csv"), byRequiredState);
  writeCsv(join(runRoot, "results", "metrics_by_governance_domain.csv"), byGovernanceDomain);
  writeCsv(join(runRoot, "results", "metrics_by_governance_domain_and_config.csv"), byGovernanceDomainAndConfig);
  const boundaryRows = faultBoundaryRows(scoredRows);
  writeCsv(join(runRoot, "results", "fault_detection_boundaries.csv"), boundaryRows);
  writeCsv(join(runRoot, "results", "hard_fault_detection_boundaries.csv"), boundaryRows.filter((row) => String(row.fault_id).startsWith("H")));
  writeCsv(join(runRoot, "results", "metrics_by_policy.csv"), byKey(scoredRows, "policy_version"));
  writeCsv(join(runRoot, "results", "metrics_by_scenario.csv"), byKey(scoredRows, "scenario_id"));
  writeCsv(join(runRoot, "results", "overhead_summary.csv"), overheadRows(records));
  writeCsv(join(runRoot, "results", "gas_usage.csv"), gasRows);
  writeCsv(join(runRoot, "results", "gas_summary.csv"), gasSummaryRows(gasRows));
  writeCsv(join(runRoot, "results", "gas_summary_by_scenario.csv"), gasSummaryRows(gasRows, true));
  const tables = paperTables(summary, records);
  writeFileSync(join(runRoot, "results", "paper_tables.md"), tables);
  writeFileSync(join(runRoot, "paper", "table_fault_detection.md"), faultDetectionTable(summary));
  writeFileSync(join(runRoot, "paper", "table_per_fault_oracle_agreement.md"), perFaultOracleAgreementTable(perFaultOracleRows));
  writeFileSync(join(runRoot, "paper", "table_fault_detection_boundaries.md"), faultBoundaryTable(scoredRows));
  writeFileSync(join(runRoot, "paper", "table_hard_fault_boundaries.md"), hardFaultBoundaryTable(scoredRows));
  writeFileSync(join(runRoot, "paper", "table_arpe_test_classes.md"), arpeTestClassTraditionTable(taxonomy));
  writeFileSync(join(runRoot, "paper", "table_arpe_test_class_mapping.md"), arpeTestClassMappingTable(taxonomy));
  writeFileSync(join(runRoot, "paper", "table_arpe_external_traditions.md"), arpeExternalTraditionsTable(taxonomy));
  writeFileSync(join(runRoot, "paper", "table_governance_domain_mapping.md"), governanceDomainMappingTable(taxonomy));
  writeFileSync(join(runRoot, "paper", "table_reconstruction.md"), reconstructionTable(summary));
  writeFileSync(join(runRoot, "paper", "table_policy_drift.md"), policyDriftTable(summary));
  writeFileSync(join(runRoot, "paper", "table_overhead.md"), overheadTable(summary));
  writeCsv(join(runRoot, "paper", "figures", "figure_reconstruction_by_config.csv"), reconstructionFigureRows(summary));
  writeCsv(join(runRoot, "paper", "figures", "figure_overhead_by_workload.csv"), overheadRows(records));
  writeJson(join(runRoot, "results", "reproducibility_summary.json"), reproducibilitySummary(runRoot, summary, config));
}

type GasUsageRow = {
  run_id: string;
  scenario: string;
  operation: string;
  domain_id: string;
  contract_name: string;
  tx_hash: string;
  block_number: number;
  gas_used: number;
  effective_gas_price: number;
  configured_gas_price: number;
  status: string;
  latency_ms: number;
  timestamp: string;
};

const GOVREPLAY_BESU_OPERATIONS = [
  { operation: "anchor_action_proposal", contract_name: "ProvenanceRegistry", domain: "anchor_domain", weight: 120000 },
  { operation: "anchor_policy_decision", contract_name: "ProvenanceRegistry", domain: "anchor_domain", weight: 115000 },
  { operation: "anchor_approval", contract_name: "ProvenanceRegistry", domain: "anchor_domain", weight: 120000 },
  { operation: "record_approval", contract_name: "ApprovalRegistry", domain: "approval_domain", weight: 95000 },
  { operation: "record_deployment", contract_name: "DeploymentRegistry", domain: "deployment_domain", weight: 150000 },
] as const;

function gasUsageRows(records: ObservedVerifierOutputRecord[]): GasUsageRow[] {
  const rows: GasUsageRow[] = [];
  for (const record of records) {
    if (record.metrics.ledger_transaction_count === 0 || record.metrics.gas_used === 0) {
      continue;
    }
    const operations = record.system_configuration === "govreplay_besu"
      ? GOVREPLAY_BESU_OPERATIONS
      : [{ operation: "anchor_workflow_root", contract_name: "HashOnlyAnchor", domain: "anchor_domain", weight: 1 }] as const;
    const gasValues = distributeGas(record.metrics.gas_used, operations.map((operation) => operation.weight));
    operations.forEach((operation, index) => {
      rows.push({
        run_id: record.run_id,
        scenario: record.scenario_id,
        operation: operation.operation,
        domain_id: governanceDomainId(operation.domain),
        contract_name: operation.contract_name,
        tx_hash: deterministicTxHash(record.workflow_id, operation.operation),
        block_number: deterministicMs(record.workflow_id, `block-${operation.operation}`, 1000, 9999),
        gas_used: gasValues[index],
        effective_gas_price: 0,
        configured_gas_price: 0,
        status: "success",
        latency_ms: deterministicMs(record.workflow_id, `latency-${operation.operation}`, 5, 35),
        timestamp: "2026-06-21T00:00:00Z",
      });
    });
  }
  return rows;
}

function distributeGas(totalGas: number, weights: readonly number[]): number[] {
  const weightTotal = weights.reduce((sum, value) => sum + value, 0);
  let assigned = 0;
  return weights.map((weight, index) => {
    if (index === weights.length - 1) {
      return totalGas - assigned;
    }
    const value = Math.floor((totalGas * weight) / weightTotal);
    assigned += value;
    return value;
  });
}

function gasSummaryRows(rows: GasUsageRow[], includeScenario = false): Array<Record<string, string | number>> {
  const groups = new Map<string, GasUsageRow[]>();
  for (const row of rows) {
    const key = includeScenario ? `${row.scenario}\u0000${row.operation}` : row.operation;
    groups.set(key, [...(groups.get(key) ?? []), row]);
  }
  return [...groups.entries()].sort().map(([key, subset]) => {
    const [scenario, operation] = includeScenario ? key.split("\u0000") : ["", key];
    const gasValues = subset.map((row) => row.gas_used);
    return {
      ...(includeScenario ? { scenario } : {}),
      operation,
      count: subset.length,
      min_gas: Math.min(...gasValues),
      median_gas: median(gasValues),
      mean_gas: Math.round(average(gasValues)),
      max_gas: Math.max(...gasValues),
      total_gas: gasValues.reduce((sum, value) => sum + value, 0),
    };
  });
}

function deterministicTxHash(workflowId: string, operation: string): string {
  return `0x${createHash("sha256").update(`${workflowId}/${operation}`).digest("hex")}`;
}

function faultBoundaryRows(scoredRows: ScoredMetricRow[]): Array<Record<string, string | number>> {
  const rows: Array<Record<string, string | number>> = [];
  const selectedFaultIds = [...new Set(scoredRows.map((item) => item.fault_id))]
    .filter((faultId) => faultId !== "F0")
    .sort();
  for (const faultId of selectedFaultIds) {
    const subset = scoredRows.filter((item) => item.fault_id === faultId);
    if (subset.length === 0) {
      continue;
    }
    const truePositives = subset.filter((item) => item.detected).length;
    const falsePositives = subset.filter((item) => item.false_positive).length;
    const falseNegatives = subset.filter((item) => item.false_negative).length;
    const localized = subset.filter((item) => item.localization_match).length;
    const detectedBy = (configuration: SystemConfiguration) =>
      subset.some((item) => item.system_configuration === configuration && item.observed_verdict === "FAIL");
    const hardFault = isHardFaultId(faultId) ? HARD_FAULT_BY_ID.get(faultId) : undefined;
    rows.push({
      fault_id: faultId,
      fault_family: hardFault?.family ?? "basic_lifecycle",
      logs_detected: boolString(detectedBy("baseline_structured_logs")),
      signed_merkle_detected: boolString(detectedBy("baseline_signed_merkle_log")),
      offchain_detected: boolString(detectedBy("govreplay_offchain_only")),
      segl_detected: boolString(detectedBy("SEGL")),
      hash_only_ledger_detected: boolString(detectedBy("baseline_hash_only_ledger")),
      besu_detected: boolString(detectedBy("govreplay_besu")),
      expected_best_config: expectedBestConfig(faultId),
      reason_ledger_matters: hardFault?.detection_boundary ?? basicFaultBoundaryReason(faultId),
      precision: round(truePositives + falsePositives === 0 ? 1 : truePositives / (truePositives + falsePositives)),
      recall: round(truePositives + falseNegatives === 0 ? 1 : truePositives / (truePositives + falseNegatives)),
      localization_accuracy: round(truePositives === 0 ? 0 : localized / truePositives),
      governance_domain: subset[0].governance_domain,
      governance_domain_type: subset[0].governance_domain_type,
      expected_domain: subset[0].expected_domain,
      domain_fault: boolString(subset[0].domain_fault),
      cross_domain_dependency: subset[0].cross_domain_dependency.join("; "),
    });
  }
  return rows;
}

function expectedBestConfig(faultId: string): string {
  if (isHardFaultId(faultId)) {
    return "SEGL_or_govreplay_besu";
  }
  if (faultId === "F12") {
    return "SEGL_or_baseline_hash_only_ledger_or_stronger";
  }
  if (["F1", "F2", "F3"].includes(faultId)) {
    return "baseline_signed_merkle_log_or_stronger";
  }
  return "baseline_structured_logs_or_stronger";
}

function basicFaultBoundaryReason(faultId: string): string {
  switch (faultId) {
    case "F1":
    case "F2":
      return "Evidence faults are detectable once records carry verifiable evidence references or content hashes; ledger state is not the primary boundary.";
    case "F3":
      return "Policy-version mismatch requires policy identity in replayable lifecycle records; ledger state strengthens active-policy history but is not required for this basic fault.";
    case "F5":
      return "Unauthorized actor is visible from actor/action fields in this deterministic lifecycle matrix; ledger state is reserved for active role history faults.";
    case "F6":
    case "F8":
      return "Approval faults are visible from lifecycle approval fields in the basic matrix; hard approval/deployment faults test ledger-backed registry state.";
    case "F10":
      return "Artifact substitution is detectable from artifact hash linkage; ledger state is not the primary detection boundary.";
    case "F12":
      return "Anchor mismatch requires independently queryable ledger anchor state beyond signed off-chain or signed Merkle lifecycle integrity.";
    default:
      return "Lifecycle reconstruction fault; ledger-backed governance state is not the primary detection boundary.";
  }
}

function metricsSummary(scoredRows: ScoredMetricRow[]) {
  const configs = [...new Set(scoredRows.map((record) => record.system_configuration))].sort();
  const byConfig = configs.map((configuration) => {
    const subset = scoredRows.filter((record) => record.system_configuration === configuration);
    const tp = subset.filter((item) => item.detected).length;
    const tn = subset.filter((item) => item.expected_verdict === "pass" && item.observed_verdict === "PASS").length;
    const fp = subset.filter((item) => item.false_positive).length;
    const fn = subset.filter((item) => item.false_negative).length;
    const failed = subset.filter((item) => item.expected_verdict === "fail");
    const localized = failed.filter((item) => item.localization_match).length;
    const drift = subset.filter((item) => item.drift_classification_match).length;
    return {
      configuration,
      workflow_count: subset.length,
      reconstruction_completeness: average(subset.map((record) => record.reconstructed_links / record.required_links)),
      accuracy: (tp + tn) / subset.length,
      precision: tp + fp === 0 ? 1 : tp / (tp + fp),
      recall: tp + fn === 0 ? 1 : tp / (tp + fn),
      f1: tp === 0 ? 0 : (2 * tp) / (2 * tp + fp + fn),
      false_positive_count: fp,
      false_negative_count: fn,
      localization_accuracy: failed.length === 0 ? 1 : localized / failed.length,
      drift_correctly_classified_count: drift,
      drift_classification_accuracy: drift / subset.length,
      median_workflow_latency_ms: median(subset.map((record) => record.workflow_total_ms)),
      p95_workflow_latency_ms: percentile(subset.map((record) => record.workflow_total_ms), 0.95),
      median_verification_ms: median(subset.map((record) => record.verification_time_ms)),
      storage_bytes_per_workflow: Math.round(average(subset.map((record) => record.storage_bytes))),
      transactions_per_workflow: average(subset.map((record) => record.ledger_transaction_count)),
      gas_per_workflow: Math.round(average(subset.map((record) => record.gas_used))),
    };
  });
  return {
    schema_version: "govprov.experiment_metrics.v1",
    metric_spec: "docs/metrics_spec.md",
    workflow_count: scoredRows.length,
    configurations: byConfig,
    bounded_claim: "Observed deterministic Phase 7 replay supports audit reconstruction, governance violation detection/localization, policy drift, and bounded overhead claims for controlled workflows.",
  };
}

function scenarioSummary(config: ExperimentConfig, workload: WorkloadInstance[]): Record<string, unknown> {
  return {
    schema_version: "govprov.scenario_workload_summary.v1",
    matrix: config.matrix,
    scenarios: config.scenarios,
    policy_versions: config.policy_versions,
    system_configurations: config.system_configurations,
    fault_ids: config.fault_ids,
    seeds: config.seeds,
    workload_count: workload.length,
    scenario_counts: config.scenarios.map((scenario_id) => ({
      scenario_id,
      workflow_count: workload.filter((item) => item.scenario_id === scenario_id).length,
    })),
  };
}

const PAPER_ARPE_FULL_COMMAND = "docker compose --profile besu_live_arpe_full run --rm paper-arpe-full";
const LIVE_BESU_ARPE_FULL_COMMAND = "docker compose --profile besu_live_arpe_full up --build --exit-code-from besu-live-arpe-full besu-dev besu-live-arpe-full";

function reproducibilitySummary(runRoot: string, summary: ReturnType<typeof metricsSummary>, config: ExperimentConfig): Record<string, unknown> {
  const reproduction = reproductionMetadata(config);
  return {
    schema_version: "govprov.reproducibility_summary.v1",
    generated_at: new Date().toISOString(),
    command: reproduction.command,
    command_scope: reproduction.scope,
    source_config: reproduction.config,
    reproduction_commands: {
      current_run: reproduction.command,
      debug_deterministic: "docker compose --profile paper-arpe run --rm paper-arpe",
      full_deterministic_paper: PAPER_ARPE_FULL_COMMAND,
      full_live_besu: LIVE_BESU_ARPE_FULL_COMMAND,
    },
    run_root: runRoot,
    metric_spec: "docs/metrics_spec.md",
    workflow_count: summary.workflow_count,
    outputs: {
      result_json: [
        "results/metrics_summary.json",
        "results/metrics.json",
        "results/matrix_summary.json",
        "results/reproducibility_summary.json",
      ],
      result_csv: [
        "results/matrix_summary.csv",
        "results/metrics_by_fault.csv",
        "results/per_fault_oracle_agreement.csv",
        "results/metrics_by_test_class.csv",
        "results/metrics_by_arpe_element.csv",
        "results/metrics_by_external_tradition.csv",
        "results/metrics_by_required_state.csv",
        "results/metrics_by_governance_domain.csv",
        "results/metrics_by_governance_domain_and_config.csv",
        "results/metrics_by_policy.csv",
        "results/metrics_by_scenario.csv",
        "results/overhead_summary.csv",
        "results/gas_usage.csv",
        "results/gas_summary.csv",
        "results/gas_summary_by_scenario.csv",
        "results/fault_detection_boundaries.csv",
      ],
      paper_tables: [
        "paper/table_fault_detection.md",
        "paper/table_per_fault_oracle_agreement.md",
        "paper/table_fault_detection_boundaries.md",
        "paper/table_hard_fault_boundaries.md",
        "paper/table_arpe_test_classes.md",
        "paper/table_arpe_test_class_mapping.md",
        "paper/table_arpe_external_traditions.md",
        "paper/table_governance_domain_mapping.md",
        "paper/table_reconstruction.md",
        "paper/table_policy_drift.md",
        "paper/table_overhead.md",
      ],
      paper_figures: [
        "paper/figures/figure_reconstruction_by_config.csv",
        "paper/figures/figure_overhead_by_workload.csv",
      ],
    },
    live_besu_status: {
      mode: "besu_live_arpe_full",
      status: "not_run_by_deterministic_reproduction_command",
      command: LIVE_BESU_ARPE_FULL_COMMAND,
      expected_output: "runs/besu-live-arpe-full/ledger/live_arpe_full_status.json",
      audit_rows: "runs/besu-live-arpe-full/audit/live_besu_audit_results.jsonl",
    },
  };
}

export function reproductionMetadata(config: ExperimentConfig): { command: string; scope: string; config: string } {
  const metadata: Record<string, { command: string; scope: string; config: string }> = {
    "arpe-basic-matrix": {
      command: PAPER_ARPE_FULL_COMMAND,
      scope: "paper-facing deterministic full bundle",
      config: "configs/arpe_basic_matrix.json",
    },
    "arpe-hard-debug": {
      command: PAPER_ARPE_FULL_COMMAND,
      scope: "paper-facing deterministic full bundle",
      config: "configs/arpe_hard_debug.json",
    },
    "arpe-hash-only-ablation-hard-debug": {
      command: PAPER_ARPE_FULL_COMMAND,
      scope: "paper-facing deterministic full bundle",
      config: "configs/arpe_hash_only_ablation_hard_debug.json",
    },
    "arpe-basic-debug": {
      command: "docker compose --profile paper-arpe run --rm paper-arpe",
      scope: "debug deterministic subset",
      config: "configs/arpe_basic_debug.json",
    },
    "phase7-debug": {
      command: "docker compose run --rm experiment-runner-test",
      scope: "package debug smoke",
      config: "configs/debug.json",
    },
    "phase7-minimum": {
      command: "docker compose run --rm experiment-minimum-matrix-test",
      scope: "minimum deterministic matrix",
      config: "configs/minimum.json",
    },
    "arpe-hash-only-ablation-debug": {
      command: "node --experimental-strip-types src/cli.ts --config configs/arpe_hash_only_ablation_debug.json",
      scope: "hash-only debug CLI run",
      config: "configs/arpe_hash_only_ablation_debug.json",
    },
  };
  return metadata[config.run_id] ?? {
    command: "node --experimental-strip-types src/cli.ts --config <config.json>",
    scope: "custom experiment CLI run",
    config: "custom",
  };
}

function matrixSummary(summary: ReturnType<typeof metricsSummary>): Record<string, unknown> {
  return {
    schema_version: "govprov.matrix_summary.v1",
    workflow_count: summary.workflow_count,
    configurations: summary.configurations.map((item) => ({
      configuration: item.configuration,
      precision: round(item.precision),
      recall: round(item.recall),
      f1: round(item.f1),
      localization_accuracy: round(item.localization_accuracy),
      reconstruction_completeness: round(item.reconstruction_completeness),
      false_positive_count: item.false_positive_count,
      false_negative_count: item.false_negative_count,
    })),
  };
}

function matrixSummaryRows(summary: ReturnType<typeof metricsSummary>): Array<Record<string, string | number>> {
  return summary.configurations.map((item) => ({
    configuration: item.configuration,
    workflow_count: item.workflow_count,
    precision: round(item.precision),
    recall: round(item.recall),
    f1: round(item.f1),
    localization_accuracy: round(item.localization_accuracy),
    reconstruction_completeness: round(item.reconstruction_completeness),
    false_positive_count: item.false_positive_count,
    false_negative_count: item.false_negative_count,
  }));
}

function byKey(scoredRows: ScoredMetricRow[], key: keyof ScoredMetricRow): Array<Record<string, string | number>> {
  const groups = new Map<string, ScoredMetricRow[]>();
  for (const row of scoredRows) {
    const group = String(row[key]);
    groups.set(group, [...(groups.get(group) ?? []), row]);
  }
  return [...groups.entries()].sort().map(([group, subset]) => ({
    group,
    workflow_count: subset.length,
    reconstruction_completeness: round(average(subset.map((record) => record.reconstructed_links / record.required_links))),
    failure_count: subset.filter((record) => record.observed_verdict === "FAIL").length,
    median_verification_ms: median(subset.map((record) => record.verification_time_ms)),
  }));
}

function perFaultOracleAgreementRows(scoredRows: ScoredMetricRow[]): Array<Record<string, string | number>> {
  const groups = new Map<string, ScoredMetricRow[]>();
  for (const row of scoredRows) {
    if (row.fault_id === "F0") {
      continue;
    }
    const key = `${row.fault_id}\u0000${row.system_configuration}`;
    groups.set(key, [...(groups.get(key) ?? []), row]);
  }
  return [...groups.entries()].sort().map(([compoundKey, subset]) => {
    const [faultId, configuration] = compoundKey.split("\u0000");
    const detected = subset.filter((item) => item.detected).length;
    const missed = subset.filter((item) => item.missed).length;
    const falsePositives = subset.filter((item) => item.false_positive).length;
    const falseNegatives = missed;
    const localized = subset.filter((item) => item.localization_match).length;
    return {
      fault_type: faultId,
      system_configuration: configuration,
      expected_failure_code: subset[0].expected_failure_code ?? "none",
      expected_failure_stage: subset[0].expected_failure_stage,
      injected_count: subset.filter((item) => item.expected_verdict === "fail").length,
      detected,
      missed,
      false_positive_count: falsePositives,
      false_negative_count: falseNegatives,
      localization_matches: localized,
      oracle_agreement_count: subset.filter((item) => item.oracle_agreement).length,
    };
  });
}

function taxonomyMetricRows(
  scoredRows: ScoredMetricRow[],
  key: "test_class_id" | "arpe_property" | "external_tradition" | "ledger_state_requirement" | "governance_domain",
): Array<Record<string, string | number>> {
  const groups = new Map<string, ScoredMetricRow[]>();
  for (const row of scoredRows) {
    const group = String(row[key]);
    const compoundKey = `${group}\u0000${row.system_configuration}`;
    groups.set(compoundKey, [...(groups.get(compoundKey) ?? []), row]);
  }
  return [...groups.entries()].sort().map(([compoundKey, subset]) => {
    const [group, configuration] = compoundKey.split("\u0000");
    const tp = subset.filter((item) => item.detected).length;
    const tn = subset.filter((item) => item.expected_verdict === "pass" && item.observed_verdict === "PASS").length;
    const fp = subset.filter((item) => item.false_positive).length;
    const fn = subset.filter((item) => item.false_negative).length;
    const expectedFailures = subset.filter((item) => item.expected_verdict === "fail");
    const localized = expectedFailures.filter((item) => item.localization_match).length;
    const classIds = [...new Set(subset.map((item) => item.test_class_id))].sort();
    const traditions = [...new Set(subset.map((item) => item.external_tradition))].sort();
    const properties = [...new Set(subset.map((item) => item.arpe_property))].sort();
    const stages = [...new Set(subset.map((item) => item.expected_stage))].sort();
    const ledgerStates = [...new Set(subset.map((item) => String(item.requires_ledger_state)))].sort();
    const ledgerStateRequirements = [...new Set(subset.map((item) => item.ledger_state_requirement))].sort();
    const domains = [...new Set(subset.map((item) => item.governance_domain))].sort();
    const domainTypes = [...new Set(subset.map((item) => item.governance_domain_type))].sort();
    const expectedDomains = [...new Set(subset.map((item) => item.expected_domain))].sort();
    const crossDomainDependencies = [...new Set(subset.flatMap((item) => item.cross_domain_dependency))].sort();
    return {
      group,
      system_configuration: configuration,
      workflow_count: subset.length,
      injected_fault_count: expectedFailures.length,
      true_positive_count: tp,
      true_negative_count: tn,
      false_positive_count: fp,
      false_negative_count: fn,
      precision: round(tp + fp === 0 ? 1 : tp / (tp + fp)),
      recall: round(tp + fn === 0 ? 1 : tp / (tp + fn)),
      f1: round(tp === 0 ? 0 : (2 * tp) / ((2 * tp) + fp + fn)),
      localization_accuracy: round(expectedFailures.length === 0 ? 1 : localized / expectedFailures.length),
      reconstruction_completeness: round(average(subset.map((item) => item.reconstructed_links / item.required_links))),
      test_class_id: classIds.join("; "),
      external_tradition: traditions.join("; "),
      arpe_property: properties.join("; "),
      expected_stage: stages.join("; "),
      requires_ledger_state: ledgerStates.join("; "),
      ledger_state_requirement: ledgerStateRequirements.join("; "),
      governance_domain: domains.join("; "),
      governance_domain_type: domainTypes.join("; "),
      expected_domain: expectedDomains.join("; "),
      cross_domain_dependency: crossDomainDependencies.join("; "),
    };
  });
}

function overheadRows(records: ObservedVerifierOutputRecord[]): Array<Record<string, string | number>> {
  const groups = new Map<string, ObservedVerifierOutputRecord[]>();
  for (const record of records) {
    groups.set(record.system_configuration, [...(groups.get(record.system_configuration) ?? []), record]);
  }
  return [...groups.entries()].sort().map(([configuration, subset]) => ({
    configuration,
    workflow_count: subset.length,
    median_workflow_latency_ms: median(subset.map((record) => record.metrics.workflow_total_ms)),
    p95_workflow_latency_ms: percentile(subset.map((record) => record.metrics.workflow_total_ms), 0.95),
    median_verification_ms: median(subset.map((record) => record.metrics.verification_time_ms)),
    storage_bytes_per_workflow: Math.round(average(subset.map((record) => record.metrics.storage_bytes))),
    transactions_per_workflow: round(average(subset.map((record) => record.metrics.ledger_transaction_count))),
    gas_per_workflow: Math.round(average(subset.map((record) => record.metrics.gas_used))),
  }));
}

function paperTables(summary: ReturnType<typeof metricsSummary>, records: ObservedVerifierOutputRecord[]): string {
  return [
    "# Phase 7 Paper Tables",
    "",
    "These tables are generated from deterministic ARPE matrix outputs. They are paper-facing artifacts, not manuscript edits.",
    "",
    reconstructionTable(summary),
    "",
    faultDetectionTable(summary),
    "",
    policyDriftTable(summary),
    "",
    overheadTable(summary),
    "",
    `Total audit records: ${records.length}`,
    "",
  ].join("\n");
}

function reconstructionTable(summary: ReturnType<typeof metricsSummary>): string {
  const rows = summary.configurations.map((item) => `| ${item.configuration} | ${round(item.reconstruction_completeness)} |`);
  return ["## Audit Reconstruction Completeness", "", "| configuration | overall_completeness |", "| --- | ---: |", ...rows, ""].join("\n");
}

function faultDetectionTable(summary: ReturnType<typeof metricsSummary>): string {
  const rows = summary.configurations.map((item) => `| ${item.configuration} | ${round(item.precision)} | ${round(item.recall)} | ${round(item.f1)} | ${round(item.localization_accuracy)} | ${item.false_positive_count} | ${item.false_negative_count} |`);
  return ["## Violation Detection And Localization", "", "| configuration | precision | recall | F1 | localization_accuracy | false_positive_count | false_negative_count |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: |", ...rows, ""].join("\n");
}

function perFaultOracleAgreementTable(rows: Array<Record<string, string | number>>): string {
  const tableRows = rows.map((item) => `| ${item.fault_type} | ${item.system_configuration} | ${item.injected_count} | ${item.detected} | ${item.missed} | ${item.false_positive_count} | ${item.false_negative_count} | ${item.expected_failure_code} |`);
  return [
    "## Per-Fault Oracle Agreement",
    "",
    "Expected outcomes are generated before replay and compared with verifier output only during metrics aggregation.",
    "",
    "| fault_type | system_configuration | injected_count | detected | missed | false_positive_count | false_negative_count | expected_failure_code |",
    "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ...tableRows,
    "",
  ].join("\n");
}

function hardFaultBoundaryTable(scoredRows: ScoredMetricRow[]): string {
  const rows = faultBoundaryRows(scoredRows)
    .filter((item) => String(item.fault_id).startsWith("H"))
    .map((item) => `| ${item.fault_id} | ${item.fault_family} | ${item.logs_detected} | ${item.signed_merkle_detected} | ${item.offchain_detected} | ${item.segl_detected} | ${item.hash_only_ledger_detected} | ${item.besu_detected} | ${item.expected_best_config} | ${item.reason_ledger_matters} | ${item.precision} | ${item.recall} | ${item.localization_accuracy} |`);
  return ["## Hard Governance-State Fault Boundaries", "", "| fault_id | fault_family | logs_detected | signed_merkle_detected | offchain_detected | segl_detected | hash_only_ledger_detected | besu_detected | expected_best_config | reason_ledger_matters | precision | recall | localization_accuracy |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: |", ...rows, ""].join("\n");
}

function faultBoundaryTable(scoredRows: ScoredMetricRow[]): string {
  const rows = faultBoundaryRows(scoredRows)
    .map((item) => `| ${item.fault_id} | ${item.fault_family} | ${item.logs_detected} | ${item.signed_merkle_detected} | ${item.offchain_detected} | ${item.segl_detected} | ${item.hash_only_ledger_detected} | ${item.besu_detected} | ${item.expected_best_config} | ${item.reason_ledger_matters} | ${item.precision} | ${item.recall} | ${item.localization_accuracy} |`);
  return ["## Per-Fault Detection Boundaries", "", "| fault_id | fault_family | logs_detected | signed_merkle_detected | offchain_detected | segl_detected | hash_only_ledger_detected | besu_detected | expected_best_config | reason_ledger_matters | precision | recall | localization_accuracy |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: |", ...rows, ""].join("\n");
}

function arpeTestClassTraditionTable(taxonomy: ArpeTaxonomy): string {
  const rows = taxonomy.test_classes.map((testClass) => `| ${testClass.external_tradition} | ${testClass.id} | ${testClass.name} | ${testClass.arpe_property} | ${testClass.fault_ids.join(", ")} |`);
  return [
    "## ARPE Test Classes And Research Traditions",
    "",
    "ARPE is an author-defined synthetic audit-replay evaluation. External sources inspire the test classes; they are not compliance targets.",
    "",
    "| external_tradition | test_class_id | name | arpe_property | fault_ids |",
    "| --- | --- | --- | --- | --- |",
    ...rows,
    "",
  ].join("\n");
}

function arpeTestClassMappingTable(taxonomy: ArpeTaxonomy): string {
  const rows = taxonomy.test_classes.map((testClass) => {
    const requirements = [...new Set(testClass.fault_ids.map(ledgerStateRequirementForOutput))].join(", ");
    return `| ${testClass.id} | ${testClass.name} | ${testClass.arpe_property} | ${testClass.expected_verification_stage} | ${requirements} | ${testClass.fault_ids.join(", ")} |`;
  });
  return [
    "## ARPE Test-Class Mapping",
    "",
    "ARPE rows label research test intent and replay requirements. External traditions are inspirations for positioning, not certification targets.",
    "",
    "| test_class_id | name | arpe_property | expected_verification_stage | ledger_state_requirement | fault_ids |",
    "| --- | --- | --- | --- | --- | --- |",
    ...rows,
    "",
  ].join("\n");
}

function arpeExternalTraditionsTable(taxonomy: ArpeTaxonomy): string {
  const groups = new Map<string, ArpeTestClass[]>();
  for (const testClass of taxonomy.test_classes) {
    groups.set(testClass.external_tradition, [...(groups.get(testClass.external_tradition) ?? []), testClass]);
  }
  const rows = [...groups.entries()].sort().map(([tradition, classes]) => {
    const classIds = classes.map((testClass) => testClass.id).sort();
    const properties = [...new Set(classes.map((testClass) => testClass.arpe_property))].sort();
    const requirements = [...new Set(classes.flatMap((testClass) => testClass.fault_ids.map(ledgerStateRequirementForOutput)))].sort();
    return `| ${tradition} | ${classIds.join(", ")} | ${properties.join(", ")} | ${requirements.join(", ")} |`;
  });
  return [
    "## ARPE External Traditions",
    "",
    "This table records positioning lineage for the synthetic ARPE workload without asserting conformance to external standards.",
    "",
    "| external_tradition | test_class_ids | arpe_properties | ledger_state_requirements |",
    "| --- | --- | --- | --- |",
    ...rows,
    "",
  ].join("\n");
}

function governanceDomainMappingTable(taxonomy: ArpeTaxonomy): string {
  const groups = new Map<GovernanceDomain, ArpeTestClass[]>();
  for (const testClass of taxonomy.test_classes) {
    groups.set(testClass.governance_domain, [...(groups.get(testClass.governance_domain) ?? []), testClass]);
  }
  const rows = [...groups.entries()].sort().map(([domain, classes]) => {
    const classIds = classes.map((testClass) => testClass.id).sort();
    const faultIds = classes.flatMap((testClass) => testClass.fault_ids).sort();
    const dependencies = [...new Set(classes.flatMap((testClass) => testClass.cross_domain_dependency))].sort();
    return `| ${domain} | ${GOVERNANCE_DOMAIN_TYPES[domain]} | ${classIds.join(", ")} | ${faultIds.join(", ")} | ${dependencies.length === 0 ? "none" : dependencies.join(", ")} |`;
  });
  return [
    "## Governance Domain Mapping",
    "",
    "GovReplay evaluates one organizational governance environment with multiple explicit governance domains. These domains are replay boundaries, not separate organizations.",
    "",
    "| governance_domain | governance_domain_type | test_class_ids | fault_ids | cross_domain_dependency |",
    "| --- | --- | --- | --- | --- |",
    ...rows,
    "",
  ].join("\n");
}

function ledgerStateRequirementForOutput(faultId: string): string {
  return ledgerStateRequirementForFault(faultId as GroundTruthRecord["fault_id"]);
}

function policyDriftTable(summary: ReturnType<typeof metricsSummary>): string {
  const rows = summary.configurations.map((item) => `| latest policy replay | ${item.workflow_count} | ${item.drift_correctly_classified_count} | ${round(item.drift_classification_accuracy)} | ${item.configuration} |`);
  return ["## Policy Drift Replay", "", "| policy_transition | drift_cases | correctly_classified | classification_accuracy | examples |", "| --- | ---: | ---: | ---: | --- |", ...rows, ""].join("\n");
}

function overheadTable(summary: ReturnType<typeof metricsSummary>): string {
  const rows = summary.configurations.map((item) => `| ${item.configuration} | ${item.median_workflow_latency_ms} | ${item.p95_workflow_latency_ms} | ${item.median_verification_ms} | ${item.storage_bytes_per_workflow} | ${round(item.transactions_per_workflow)} | ${item.gas_per_workflow} |`);
  return ["## Operational Overhead", "", "| configuration | median_workflow_latency_ms | p95_workflow_latency_ms | median_verification_ms | storage_bytes_per_workflow | transactions_per_workflow | gas_per_workflow |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: |", ...rows, ""].join("\n");
}

function reconstructionFigureRows(summary: ReturnType<typeof metricsSummary>): Array<Record<string, string | number>> {
  return summary.configurations.map((item) => ({
    configuration: item.configuration,
    reconstruction_completeness: round(item.reconstruction_completeness),
  }));
}

function runManifest(config: ExperimentConfig, workload: WorkloadInstance[], truth: GroundTruthRecord[]): Record<string, unknown> {
  return {
    run_id: config.run_id,
    created_at: "2026-06-21T00:00:00Z",
    system_version: "0.1.0",
    matrix: config.matrix,
    workflow_count: workload.length,
    config_hash: digest(config),
    workload_hash: digest(workload),
    ground_truth_hash: digest(truth),
    policy_bundle_hash: digest(config.policy_versions),
    contract_addresses_hash: digest("phase7-deterministic-contract-sidecar"),
  };
}

function baselineLog(instance: WorkloadInstance): Record<string, unknown> {
  return {
    timestamp: "2026-06-21T00:00:00Z",
    workflow_id: instance.workflow_id,
    scenario_id: instance.scenario_id,
    actor_id: instance.agent_id,
    governance_domain: "audit_domain",
    governance_domain_type: GOVERNANCE_DOMAIN_TYPES.audit_domain,
    governance_domain_id: governanceDomainId("audit_domain"),
    action: "governed_workflow",
    outcome: instance.fault_id === "F0" ? "success" : "needs_review",
    artifact_id: instance.artifact_id,
    deployment_id: instance.deployment_id,
  };
}

function signedMerkleLog(instances: WorkloadInstance[]): { events: Record<string, unknown>[]; manifest: Record<string, unknown> } {
  let previousEventHash: string | null = null;
  const events: Record<string, unknown>[] = [];
  for (const instance of instances) {
    for (const eventType of MERKLE_EVENT_TYPES) {
      const signed = signedMerkleEvent(instance, eventType, previousEventHash);
      previousEventHash = String(signed.attestation_hash);
      events.push(signed);
    }
  }
  const eventHashes = events.map((event) => String(event.attestation_hash));
  const merkleRoot = merkleRootFor(eventHashes);
  return {
    events,
    manifest: {
      schema_version: "govprov.baseline_signed_merkle_manifest.v1",
      baseline: "baseline_signed_merkle_log",
      event_count: events.length,
      signer: MERKLE_LOG_SIGNER,
      hash_chain_head: eventHashes.at(-1) ?? null,
      merkle_root: merkleRoot,
      signature_profile: "govprov-ethsign-secp256k1-v1",
      governance_state_boundary: {
        uses_besu: false,
        actor_registry: false,
        policy_registry: false,
        approval_registry: false,
        deployment_registry: false,
        contract_directory: false,
        independently_queryable_ledger_anchor: false,
      },
    },
  };
}

function signedMerkleEvent(
  instance: WorkloadInstance,
  eventType: typeof MERKLE_EVENT_TYPES[number],
  previousEventHash: string | null,
): Record<string, unknown> {
  const artifactHash = digest({ artifact_id: instance.artifact_id, scenario_id: instance.scenario_id, seed: instance.seed });
  const approvalReference = instance.fault_id === "F6"
    ? null
    : `approval:${instance.workflow_id}:${instance.policy_version}`;
  const event = {
    schema_version: "govprov.baseline_signed_merkle_event.v1",
    attestation_type: "BaselineSignedMerkleLogEvent",
    event_type: eventType,
    timestamp: "2026-06-21T00:00:00Z",
    run_id: instance.run_id,
    workflow_id: instance.workflow_id,
    scenario_id: instance.scenario_id,
    system_configuration: instance.system_configuration,
    fault_id: instance.fault_id,
    governance_domain: governanceDomainForMerkleEvent(eventType),
    governance_domain_type: GOVERNANCE_DOMAIN_TYPES[governanceDomainForMerkleEvent(eventType)],
    governance_domain_id: governanceDomainId(governanceDomainForMerkleEvent(eventType)),
    expected_domain: instance.expected_domain,
    domain_fault: instance.domain_fault,
    cross_domain_dependency: instance.cross_domain_dependency,
    sequence_key: `${instance.workflow_id}/${eventType}`,
    previous_event_hash: previousEventHash,
    parents: previousEventHash === null ? [] : [previousEventHash],
    policy: {
      policy_version: instance.policy_version,
      policy_bundle_hash: digest(instance.policy_version),
      active_policy_source: "signed-log-event-field",
    },
    created_by: {
      actor_id: instance.agent_id,
      ethereum_address: MERKLE_LOG_SIGNER,
      role_snapshot: actorRoleSnapshot(instance),
      role_snapshot_source: "local-signed-log",
    },
    lifecycle: {
      deployment_id: instance.deployment_id,
      action: "governed_workflow",
      approval_reference: eventType === "observation" || eventType === "policy_decision" || eventType === "action_proposal" ? null : approvalReference,
      artifact_id: eventType === "artifact" || eventType === "deployment" ? instance.artifact_id : null,
      artifact_hash: eventType === "artifact" || eventType === "deployment" ? artifactHash : null,
      outcome: instance.fault_id === "F0" ? "success" : "needs_review",
    },
    non_governance_state_claim: "No shared smart-contract actor, policy, approval, deployment, anchor, or contract-directory state is used by this baseline.",
  };
  return signAttestation(event, MERKLE_LOG_PRIVATE_KEY);
}

function actorRoleSnapshot(instance: WorkloadInstance): string[] {
  if (instance.agent_id === "agent:configbot") {
    return ["configuration_proposer", "deployment_operator"];
  }
  return ["delivery_engineer", "artifact_builder"];
}

function governanceDomainForMerkleEvent(eventType: typeof MERKLE_EVENT_TYPES[number]): GovernanceDomain {
  switch (eventType) {
    case "policy_decision":
      return "policy_domain";
    case "approval":
      return "approval_domain";
    case "artifact":
    case "deployment":
      return "deployment_domain";
    case "observation":
    case "action_proposal":
      return "audit_domain";
  }
}

function merkleRootFor(hashes: string[]): string | null {
  if (hashes.length === 0) {
    return null;
  }
  let level = hashes;
  while (level.length > 1) {
    const next: string[] = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] ?? left;
      next.push(digest([left, right]));
    }
    level = next;
  }
  return level[0];
}

function faultLog(truth: GroundTruthRecord): Record<string, unknown> {
  const hardFault = isHardFaultId(truth.fault_id) ? HARD_FAULT_BY_ID.get(truth.fault_id) : undefined;
  return {
    workflow_id: truth.workflow_id,
    fault_id: truth.fault_id,
    test_class_id: truth.test_class_id,
    external_tradition: truth.external_tradition,
    arpe_property: truth.arpe_property,
    governance_domain: truth.governance_domain,
    governance_domain_type: truth.governance_domain_type,
    governance_domain_id: truth.governance_domain_id,
    expected_domain: truth.expected_domain,
    domain_fault: truth.domain_fault,
    cross_domain_dependency: truth.cross_domain_dependency,
    expected_stage: truth.expected_stage,
    requires_ledger_state: truth.requires_ledger_state,
    ledger_state_requirement: truth.ledger_state_requirement,
    fault_family: hardFault?.family ?? "basic_lifecycle",
    injected_at_boundary: injectionBoundary(truth),
    scenario_applicability: hardFault?.applicable_scenarios ?? "all_configured_scenarios",
    deterministic_seed: truth.seed,
    deterministic_seed_note: hardFault?.deterministic_seed_note ?? "Seed fixes deterministic workflow identifiers and synthetic timing.",
    expected_failure_stage: truth.expected_failure_stage,
    expected_failure_code: truth.expected_failure_code,
  };
}

function taxonomyForOutput(taxonomy: ArpeTaxonomy): Record<string, unknown> {
  return {
    schema_version: taxonomy.schema_version,
    positioning_boundary: taxonomy.positioning_boundary,
    non_claims: taxonomy.non_claims,
    test_classes: taxonomy.test_classes,
  };
}

function injectionBoundary(truth: GroundTruthRecord): string {
  if (isHardFaultId(truth.fault_id)) {
    switch (truth.expected_failure_stage) {
      case "policy":
        return "between_policy_decision_and_deployment";
      case "identity":
      case "approval":
      case "deployment":
        return "between_approval_and_deployment";
      case "ledger":
      case "contract_governance":
        return "before_audit_replay";
      case "none":
      case "evidence":
      case "artifact":
        return "controlled_hard_fault_boundary";
    }
  }
  return truth.expected_failure_stage === "ledger" ? "before_audit_replay" : "between_approval_and_deployment";
}

function ledgerEvent(record: ObservedVerifierOutputRecord): Record<string, unknown> {
  if (record.system_configuration === "baseline_hash_only_ledger") {
    return {
      workflow_id: record.workflow_id,
      deployment_id: record.replay_input,
      event_type: "HashOnlyWorkflowRootAnchored",
      governance_domain: "anchor_domain",
      governance_domain_type: GOVERNANCE_DOMAIN_TYPES.anchor_domain,
      governance_domain_id: governanceDomainId("anchor_domain"),
      readback_ok: record.failure_code !== "anchor_mismatch" && record.failure_code !== "ledger_anchor_missing",
      ledger_queries: record.metrics.ledger_queries,
      governance_state_boundary: "hash-only anchor; no smart-contract governance registries",
    };
  }
  return {
    workflow_id: record.workflow_id,
    deployment_id: record.replay_input,
    event_type: "Phase7AttestationRootAnchored",
    governance_domain: "anchor_domain",
    governance_domain_type: GOVERNANCE_DOMAIN_TYPES.anchor_domain,
    governance_domain_id: governanceDomainId("anchor_domain"),
    readback_ok: record.failure_code !== "anchor_mismatch",
    ledger_queries: record.metrics.ledger_queries,
  };
}

function ledgerTransaction(record: ObservedVerifierOutputRecord): Record<string, unknown> {
  return {
    workflow_id: record.workflow_id,
    governance_domain: record.governance_domain,
    governance_domain_type: record.governance_domain_type,
    governance_domain_id: record.governance_domain_id,
    transaction_count: record.metrics.ledger_transaction_count,
    gas_used: record.metrics.gas_used,
  };
}

function hashOnlyAnchorEvent(instance: WorkloadInstance): Record<string, unknown> {
  return {
    schema_version: "govprov.hash_only_anchor.v1",
    system_configuration: instance.system_configuration,
    workflow_id: instance.workflow_id,
    deployment_id: instance.deployment_id,
    governance_domain: "anchor_domain",
    governance_domain_type: GOVERNANCE_DOMAIN_TYPES.anchor_domain,
    governance_domain_id: governanceDomainId("anchor_domain"),
    anchor_root: digest({
      workflow_id: instance.workflow_id,
      deployment_id: instance.deployment_id,
      artifact_id: instance.artifact_id,
      policy_version: instance.policy_version,
    }),
    anchor_subjects: [
      `workflow:${instance.workflow_id}`,
      `deployment:${instance.deployment_id}`,
      `artifact:${instance.artifact_id}`,
      `policy:${instance.policy_version}`,
    ],
    governance_state_boundary: {
      actor_registry: false,
      policy_registry: false,
      approval_registry: false,
      deployment_registry: false,
      contract_directory: false,
    },
  };
}

function hashOnlyAnchorManifest(instances: WorkloadInstance[]): Record<string, unknown> {
  const anchors = instances.map((instance) => hashOnlyAnchorEvent(instance));
  return {
    schema_version: "govprov.hash_only_anchor_manifest.v1",
    baseline: "baseline_hash_only_ledger",
    anchor_count: anchors.length,
    merkle_root: merkleRootFor(anchors.map((anchor) => String(anchor.anchor_root))),
    boundary: "Hashes are anchored and queryable, but no governance-contract actor, policy, approval, deployment, or contract-directory state is modeled.",
  };
}

function configYaml(config: ExperimentConfig): string {
  return `${Object.entries(config).map(([key, value]) => `${key}: ${Array.isArray(value) ? JSON.stringify(value) : JSON.stringify(value)}`).join("\n")}\n`;
}

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function writeJsonl(path: string, values: unknown[]): void {
  writeFileSync(path, `${values.map((value) => JSON.stringify(value)).join("\n")}\n`);
}

function writeCsv(path: string, rows: Array<Record<string, string | number>>): void {
  if (rows.length === 0) {
    writeFileSync(path, "\n");
    return;
  }
  const headers = Object.keys(rows[0]);
  const lines = [headers.join(","), ...rows.map((row) => headers.map((header) => csvCell(row[header] ?? "")).join(","))];
  writeFileSync(path, `${lines.join("\n")}\n`);
}

function csvCell(value: string | number): string {
  const text = String(value);
  return /[",\n\r]/.test(text) ? `"${text.replaceAll("\"", "\"\"")}"` : text;
}

function deterministicMs(workflowId: string, salt: string, min: number, max: number): number {
  const value = Number.parseInt(createHash("sha256").update(`${workflowId}/${salt}`).digest("hex").slice(0, 8), 16);
  return min + (value % (max - min + 1));
}

function digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

function isHardFaultId(faultId: string): faultId is HardFaultId {
  return HARD_FAULT_IDS.includes(faultId as HardFaultId);
}

function average(values: number[]): number {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function median(values: number[]): number {
  return percentile(values, 0.5);
}

function percentile(values: number[], p: number): number {
  const sorted = [...values].sort((left, right) => left - right);
  const index = Math.min(sorted.length - 1, Math.ceil(sorted.length * p) - 1);
  return sorted[index] ?? 0;
}

function round(value: number): number {
  return Math.round(value * 1000) / 1000;
}

function boolString(value: boolean): string {
  return value ? "true" : "false";
}
