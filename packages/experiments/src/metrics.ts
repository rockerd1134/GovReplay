import type { FailureStage, SystemConfiguration, Verdict } from "./model.ts";
import type { OracleRecord } from "./oracle.ts";
import type { ObservedVerifierOutputRecord } from "./replayOutput.ts";

export type ScoredMetricRow = {
  schema_version: "govprov.scored_metric_row.v1";
  replay_id: string;
  run_id: string;
  workflow_id: string;
  scenario_id: string;
  policy_version: string;
  system_configuration: SystemConfiguration;
  fault_id: string;
  test_class_id: string;
  external_tradition: string;
  arpe_property: string;
  expected_stage: FailureStage;
  requires_ledger_state: boolean;
  ledger_state_requirement: string;
  governance_domain: string;
  governance_domain_type: string;
  expected_domain: string;
  domain_fault: boolean;
  cross_domain_dependency: string[];
  expected_verdict: Verdict;
  expected_failure_stage: FailureStage;
  expected_failure_code: string | null;
  expected_policy_drift_class: string;
  observed_verdict: "PASS" | "FAIL";
  observed_failure_stage: FailureStage | null;
  observed_failure_code: string | null;
  observed_policy_drift_class: string;
  oracle_agreement: boolean;
  detected: boolean;
  missed: boolean;
  false_positive: boolean;
  false_negative: boolean;
  localization_match: boolean;
  drift_classification_match: boolean;
  required_links: number;
  reconstructed_links: number;
  verification_time_ms: number;
  workflow_total_ms: number;
  storage_bytes: number;
  ledger_transaction_count: number;
  gas_used: number;
};

export function scoreMetricRows(
  oracleRecords: OracleRecord[],
  verifierOutputs: ObservedVerifierOutputRecord[],
): ScoredMetricRow[] {
  const oracleByReplayId = new Map(oracleRecords.map((record) => [record.replay_id, record]));
  return verifierOutputs.map((output) => {
    const oracle = oracleByReplayId.get(output.replay_id);
    if (oracle === undefined) {
      throw new Error(`Missing oracle record for replay_id ${output.replay_id}`);
    }
    const expectedFailure = oracle.expected_verdict === "fail";
    const observedFailure = output.verdict === "FAIL";
    return {
      schema_version: "govprov.scored_metric_row.v1",
      replay_id: output.replay_id,
      run_id: output.run_id,
      workflow_id: output.workflow_id,
      scenario_id: output.scenario_id,
      policy_version: oracle.policy_version,
      system_configuration: output.system_configuration,
      fault_id: oracle.fault_id,
      test_class_id: oracle.test_class_id,
      external_tradition: oracle.external_tradition,
      arpe_property: oracle.arpe_property,
      expected_stage: oracle.expected_stage,
      requires_ledger_state: oracle.requires_ledger_state,
      ledger_state_requirement: oracle.ledger_state_requirement,
      governance_domain: oracle.governance_domain,
      governance_domain_type: oracle.governance_domain_type,
      expected_domain: oracle.expected_domain,
      domain_fault: oracle.domain_fault,
      cross_domain_dependency: oracle.cross_domain_dependency,
      expected_verdict: oracle.expected_verdict,
      expected_failure_stage: oracle.expected_failure_stage,
      expected_failure_code: oracle.expected_failure_code,
      expected_policy_drift_class: oracle.expected_policy_drift_class,
      observed_verdict: output.verdict,
      observed_failure_stage: output.failure_stage,
      observed_failure_code: output.failure_code,
      observed_policy_drift_class: output.policy_drift_class,
      oracle_agreement: expectedFailure === observedFailure,
      detected: expectedFailure && observedFailure,
      missed: expectedFailure && !observedFailure,
      false_positive: !expectedFailure && observedFailure,
      false_negative: expectedFailure && !observedFailure,
      localization_match: expectedFailure && output.failure_stage === oracle.expected_failure_stage,
      drift_classification_match: output.policy_drift_class === oracle.expected_policy_drift_class,
      required_links: output.metrics.required_links,
      reconstructed_links: output.metrics.reconstructed_links,
      verification_time_ms: output.metrics.verification_time_ms,
      workflow_total_ms: output.metrics.workflow_total_ms,
      storage_bytes: output.metrics.storage_bytes,
      ledger_transaction_count: output.metrics.ledger_transaction_count,
      gas_used: output.metrics.gas_used,
    };
  });
}
