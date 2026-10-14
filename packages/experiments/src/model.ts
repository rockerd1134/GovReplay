export const SYSTEM_CONFIGURATIONS = [
  "baseline_structured_logs",
  "baseline_signed_merkle_log",
  "govreplay_offchain_only",
  "SEGL",
  "baseline_hash_only_ledger",
  "govreplay_besu",
] as const;

export const SCENARIOS = [
  "S1_runbook_update",
  "S2_configuration_change",
  "S3_patch_proposal",
  "S4_policy_gated_deployment",
] as const;

export const POLICY_VERSIONS = ["policy:v1", "policy:v2", "policy:v3"] as const;
export const FAULT_IDS = ["F0", "F1", "F2", "F3", "F5", "F6", "F8", "F10", "F12"] as const;
export const HARD_FAULT_IDS = ["H1", "H2", "H3", "H4", "H5", "H6", "H7", "H8"] as const;
export const ALL_FAULT_IDS = [...FAULT_IDS, ...HARD_FAULT_IDS] as const;

export type SystemConfiguration = typeof SYSTEM_CONFIGURATIONS[number];
export type ScenarioId = typeof SCENARIOS[number];
export type PolicyVersion = typeof POLICY_VERSIONS[number];
export type BasicFaultId = typeof FAULT_IDS[number];
export type HardFaultId = typeof HARD_FAULT_IDS[number];
export type FaultId = typeof ALL_FAULT_IDS[number];
export type Verdict = "pass" | "fail";
export type FailureStage = "none" | "evidence" | "policy" | "identity" | "approval" | "artifact" | "deployment" | "ledger" | "contract_governance";
export type GovernanceDomain =
  | "identity_domain"
  | "policy_domain"
  | "approval_domain"
  | "deployment_domain"
  | "anchor_domain"
  | "contract_domain"
  | "audit_domain";

export const GOVERNANCE_DOMAINS: readonly GovernanceDomain[] = [
  "identity_domain",
  "policy_domain",
  "approval_domain",
  "deployment_domain",
  "anchor_domain",
  "contract_domain",
  "audit_domain",
] as const;

export const GOVERNANCE_DOMAIN_TYPES: Record<GovernanceDomain, string> = {
  identity_domain: "actor_registration_and_role_history",
  policy_domain: "policy_registration_activation_and_decision_binding",
  approval_domain: "approval_authority_and_separation_of_duties",
  deployment_domain: "deployment_registry_and_artifact_consistency",
  anchor_domain: "provenance_anchor_and_merkle_root_readback",
  contract_domain: "contract_directory_and_governance_contract_history",
  audit_domain: "audit_replay_reports_and_metrics",
};

export type ExperimentConfig = {
  run_id: string;
  matrix: "debug" | "minimum_publishable" | "arpe_basic_matrix" | "arpe_hard_matrix";
  system_configurations: SystemConfiguration[];
  scenarios: ScenarioId[];
  policy_versions: PolicyVersion[];
  fault_ids: FaultId[];
  seeds: number[];
  current_policy_version: PolicyVersion;
};

export type WorkloadInstance = {
  run_id: string;
  workflow_id: string;
  scenario_id: ScenarioId;
  policy_version: PolicyVersion;
  system_configuration: SystemConfiguration;
  fault_id: FaultId;
  governance_domain: GovernanceDomain;
  governance_domain_type: string;
  governance_domain_id: string;
  expected_domain: GovernanceDomain;
  domain_fault: boolean;
  cross_domain_dependency: GovernanceDomain[];
  seed: number;
  agent_id: string;
  artifact_id: string;
  deployment_id: string;
};

export type GroundTruthRecord = WorkloadInstance & {
  replay_id: string;
  test_class_id: string;
  external_tradition: string;
  arpe_property: string;
  expected_stage: FailureStage;
  requires_ledger_state: boolean;
  ledger_state_requirement: string;
  expected_verdict: Verdict;
  expected_failure_stage: FailureStage;
  expected_failure_code: string | null;
  expected_historical_compliance: Verdict;
  expected_current_compliance: Verdict;
  expected_policy_drift_class: string;
};

export type ExperimentAuditRecord = {
  schema_version: "govprov.audit_replay_report.v1";
  audit_profile: "govprov-arpe-phase7-v1";
  run_id: string;
  replay_id: string;
  workflow_id: string;
  scenario_id: ScenarioId;
  system_configuration: SystemConfiguration;
  verifier_source: string;
  replay_backend: string;
  governance_domain: GovernanceDomain;
  governance_domain_type: string;
  governance_domain_id: string;
  expected_domain: GovernanceDomain;
  domain_fault: boolean;
  cross_domain_dependency: GovernanceDomain[];
  replay_input_type: "deployment_id";
  replay_input: string;
  verdict: "PASS" | "FAIL";
  failure_stage: FailureStage | null;
  failure_code: string | null;
  historical_compliance: Verdict;
  current_policy_compliance: Verdict;
  policy_drift: boolean;
  policy_drift_class: string;
  reconstructed_links: Record<string, boolean>;
  input_provenance: Array<{
    artifact_type: string;
    source: string;
    digest: string;
    purpose: string;
  }>;
  checks: Array<{
    name: string;
    stage: string;
    status: "PASS" | "FAIL" | "NOT_EVALUATED";
    code: string | null;
    detail: string;
  }>;
  metrics: {
    required_links: number;
    reconstructed_links: number;
    records_loaded: number;
    offchain_artifacts_opened: number;
    ledger_queries: number;
    unresolved_references: number;
    verification_time_ms: number;
    workflow_total_ms: number;
    storage_bytes: number;
    ledger_transaction_count: number;
    gas_used: number;
  };
};

export function replayIdFor(item: { system_configuration: SystemConfiguration; workflow_id: string }): string {
  return `${item.system_configuration}/${item.workflow_id}`;
}

export const REQUIRED_LINKS = [
  "observation",
  "evidence",
  "policy_version",
  "policy_decision",
  "action_proposal",
  "approval_chain",
  "artifact",
  "deployment",
  "ledger_anchor",
] as const;

export const FAULT_TRUTH: Record<FaultId, { stage: FailureStage; code: string | null }> = {
  F0: { stage: "none", code: null },
  F1: { stage: "evidence", code: "evidence_missing" },
  F2: { stage: "evidence", code: "evidence_hash_mismatch" },
  F3: { stage: "policy", code: "policy_version_mismatch" },
  F5: { stage: "identity", code: "unauthorized_actor" },
  F6: { stage: "approval", code: "approval_missing" },
  F8: { stage: "approval", code: "separation_of_duties_violation" },
  F10: { stage: "artifact", code: "artifact_hash_mismatch" },
  F12: { stage: "ledger", code: "anchor_mismatch" },
  H1: { stage: "identity", code: "role_revoked_before_deployment" },
  H2: { stage: "policy", code: "policy_changed_between_decision_and_deployment" },
  H3: { stage: "policy", code: "conflicting_policy_activation" },
  H4: { stage: "ledger", code: "ledger_anchor_missing" },
  H5: { stage: "approval", code: "ledger_approval_offchain_omission" },
  H6: { stage: "deployment", code: "wrong_deployment_scope" },
  H7: { stage: "identity", code: "stale_actor_snapshot" },
  H8: { stage: "contract_governance", code: "contract_directory_mismatch" },
};

export function governanceDomainId(domain: GovernanceDomain): string {
  return `govreplay:domain:${domain}`;
}

export function governanceDomainForStage(stage: FailureStage): GovernanceDomain {
  switch (stage) {
    case "identity":
      return "identity_domain";
    case "policy":
      return "policy_domain";
    case "approval":
      return "approval_domain";
    case "artifact":
    case "deployment":
      return "deployment_domain";
    case "ledger":
      return "anchor_domain";
    case "contract_governance":
      return "contract_domain";
    case "none":
    case "evidence":
      return "audit_domain";
  }
}

export function governanceDomainForFault(faultId: FaultId): GovernanceDomain {
  return governanceDomainForStage(FAULT_TRUTH[faultId].stage);
}

export function crossDomainDependenciesForFault(faultId: FaultId): GovernanceDomain[] {
  switch (faultId) {
    case "H5":
      return ["approval_domain", "deployment_domain"];
    case "H6":
      return ["deployment_domain", "approval_domain"];
    case "H8":
      return ["contract_domain", "identity_domain", "policy_domain", "approval_domain", "deployment_domain", "anchor_domain"];
    case "F12":
    case "H4":
      return ["anchor_domain", "audit_domain"];
    default:
      return [];
  }
}

export function governanceDomainMetadataForFault(faultId: FaultId): {
  governance_domain: GovernanceDomain;
  governance_domain_type: string;
  governance_domain_id: string;
  expected_domain: GovernanceDomain;
  domain_fault: boolean;
  cross_domain_dependency: GovernanceDomain[];
} {
  const governanceDomain = governanceDomainForFault(faultId);
  return {
    governance_domain: governanceDomain,
    governance_domain_type: GOVERNANCE_DOMAIN_TYPES[governanceDomain],
    governance_domain_id: governanceDomainId(governanceDomain),
    expected_domain: governanceDomain,
    domain_fault: faultId !== "F0",
    cross_domain_dependency: crossDomainDependenciesForFault(faultId),
  };
}

export type HardFaultCatalogEntry = {
  fault_id: HardFaultId;
  fault_name: string;
  family: "actor_role" | "policy_activation" | "anchor" | "approval_deployment" | "contract_directory";
  applicable_scenarios: ScenarioId[];
  deterministic_seed_note: string;
  expected_failure_stage: FailureStage;
  expected_failure_code: string;
  detection_boundary: string;
};

export const HARD_FAULT_CATALOG: HardFaultCatalogEntry[] = [
  {
    fault_id: "H1",
    fault_name: "role_revoked_before_deployment",
    family: "actor_role",
    applicable_scenarios: ["S2_configuration_change", "S4_policy_gated_deployment"],
    deterministic_seed_note: "Seed selects actor; injector revokes its deployment-time role after approval and before deployment.",
    expected_failure_stage: "identity",
    expected_failure_code: "role_revoked_before_deployment",
    detection_boundary: "Requires actor registry role history at deployment time.",
  },
  {
    fault_id: "H2",
    fault_name: "policy_changed_between_decision_and_deployment",
    family: "policy_activation",
    applicable_scenarios: ["S1_runbook_update", "S2_configuration_change", "S3_patch_proposal", "S4_policy_gated_deployment"],
    deterministic_seed_note: "Seed fixes lifecycle timestamps; injector activates the next stricter policy after decision and before deployment.",
    expected_failure_stage: "policy",
    expected_failure_code: "policy_changed_between_decision_and_deployment",
    detection_boundary: "Requires policy activation history at both decision and deployment time.",
  },
  {
    fault_id: "H3",
    fault_name: "conflicting_policy_activation",
    family: "policy_activation",
    applicable_scenarios: ["S1_runbook_update", "S2_configuration_change", "S3_patch_proposal", "S4_policy_gated_deployment"],
    deterministic_seed_note: "Seed fixes activation ordering; injector emits overlapping active-policy records for the same scope.",
    expected_failure_stage: "policy",
    expected_failure_code: "conflicting_policy_activation",
    detection_boundary: "Requires independently queryable policy registry activation windows.",
  },
  {
    fault_id: "H4",
    fault_name: "internally_consistent_unanchored_bundle",
    family: "anchor",
    applicable_scenarios: ["S1_runbook_update", "S2_configuration_change", "S3_patch_proposal", "S4_policy_gated_deployment"],
    deterministic_seed_note: "Seed fixes attestation bundle; injector leaves signatures and hashes intact but omits the required ledger anchor.",
    expected_failure_stage: "ledger",
    expected_failure_code: "ledger_anchor_missing",
    detection_boundary: "Requires provenance anchor registry readback beyond off-chain bundle integrity.",
  },
  {
    fault_id: "H5",
    fault_name: "ledger_approval_offchain_omission",
    family: "approval_deployment",
    applicable_scenarios: ["S2_configuration_change", "S3_patch_proposal", "S4_policy_gated_deployment"],
    deterministic_seed_note: "Seed fixes approval ID; injector records ledger approval while omitting or changing the off-chain lifecycle reference.",
    expected_failure_stage: "approval",
    expected_failure_code: "ledger_approval_offchain_omission",
    detection_boundary: "Requires comparison between approval registry state and off-chain lifecycle links.",
  },
  {
    fault_id: "H6",
    fault_name: "wrong_deployment_scope",
    family: "approval_deployment",
    applicable_scenarios: ["S3_patch_proposal", "S4_policy_gated_deployment"],
    deterministic_seed_note: "Seed fixes artifact hash; injector preserves artifact identity but changes deployment environment or scope.",
    expected_failure_stage: "deployment",
    expected_failure_code: "wrong_deployment_scope",
    detection_boundary: "Requires approval scope and deployment registry state, not just artifact hash matching.",
  },
  {
    fault_id: "H7",
    fault_name: "stale_actor_snapshot",
    family: "actor_role",
    applicable_scenarios: ["S2_configuration_change", "S4_policy_gated_deployment"],
    deterministic_seed_note: "Seed fixes signed-log role snapshot; injector changes active ledger role state before the relevant lifecycle point.",
    expected_failure_stage: "identity",
    expected_failure_code: "stale_actor_snapshot",
    detection_boundary: "Requires actor registry state to check signed-log role snapshots.",
  },
  {
    fault_id: "H8",
    fault_name: "contract_directory_mismatch",
    family: "contract_directory",
    applicable_scenarios: ["S1_runbook_update", "S2_configuration_change", "S3_patch_proposal", "S4_policy_gated_deployment"],
    deterministic_seed_note: "Seed fixes contract-set version; injector supersedes the directory entry before the governed action.",
    expected_failure_stage: "contract_governance",
    expected_failure_code: "contract_directory_mismatch",
    detection_boundary: "Requires contract-directory history for replay against the active governance contract set.",
  },
];

export const HARD_FAULT_BY_ID = new Map(HARD_FAULT_CATALOG.map((entry) => [entry.fault_id, entry]));
