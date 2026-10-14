import { createHash } from "node:crypto";
import {
  HARD_FAULT_IDS,
  REQUIRED_LINKS,
  replayIdFor,
  type ExperimentConfig,
  type GovernanceDomain,
  type HardFaultId,
  type ScenarioId,
  type SystemConfiguration,
  type WorkloadInstance,
} from "./model.ts";
import type { ObservedReplayEvidence } from "./observedReplayVerifier.ts";

export type ReplayInputProvenance = {
  artifact_type: string;
  source: string;
  digest: string;
  purpose: string;
};

export type ReplayInputRecord = {
  schema_version: "govprov.replay_input.v1";
  run_id: string;
  replay_id: string;
  workflow_id: string;
  scenario_id: ScenarioId;
  system_configuration: SystemConfiguration;
  governance_domain: GovernanceDomain;
  governance_domain_type: string;
  governance_domain_id: string;
  expected_domain: GovernanceDomain;
  domain_fault: boolean;
  cross_domain_dependency: GovernanceDomain[];
  replay_input_type: "deployment_id";
  replay_input: string;
  subject: {
    deployment_id: string;
    artifact_id: string;
    agent_id: string;
  };
  scenario_metadata: {
    policy_version: string;
    seed: number;
  };
  observed_evidence: ObservedReplayEvidence;
  input_provenance: ReplayInputProvenance[];
};

export function buildReplayInputRecords(
  workload: WorkloadInstance[],
  currentPolicyVersion: ExperimentConfig["current_policy_version"],
): ReplayInputRecord[] {
  return workload.map((instance) => buildReplayInputRecord(instance, currentPolicyVersion));
}

export function buildReplayInputRecord(
  instance: WorkloadInstance,
  currentPolicyVersion: ExperimentConfig["current_policy_version"],
): ReplayInputRecord {
  const observedEvidence = observedEvidenceFor(instance, currentPolicyVersion);
  return {
    schema_version: "govprov.replay_input.v1",
    run_id: instance.run_id,
    replay_id: replayIdFor(instance),
    workflow_id: instance.workflow_id,
    scenario_id: instance.scenario_id,
    system_configuration: instance.system_configuration,
    governance_domain: instance.governance_domain,
    governance_domain_type: instance.governance_domain_type,
    governance_domain_id: instance.governance_domain_id,
    expected_domain: instance.expected_domain,
    domain_fault: instance.domain_fault,
    cross_domain_dependency: instance.cross_domain_dependency,
    replay_input_type: "deployment_id",
    replay_input: instance.deployment_id,
    subject: {
      deployment_id: instance.deployment_id,
      artifact_id: instance.artifact_id,
      agent_id: instance.agent_id,
    },
    scenario_metadata: {
      policy_version: instance.policy_version,
      seed: instance.seed,
    },
    observed_evidence: observedEvidence,
    input_provenance: inputProvenanceFor(instance, observedEvidence),
  };
}

function observedEvidenceFor(
  instance: WorkloadInstance,
  currentPolicyVersion: ExperimentConfig["current_policy_version"],
): ObservedReplayEvidence {
  const lifecycle = baselineLifecycleFor(instance.system_configuration);
  if (configurationCanObserveFault(instance.system_configuration, instance.fault_id)) {
    applyObservedMutation(lifecycle, instance.fault_id);
  }
  return {
    schema_version: "govprov.observed_replay_evidence.v1",
    source_profile: sourceProfileFor(instance.system_configuration),
    links: observedLinksFor(instance, lifecycle),
    policy: {
      historical_policy_version: instance.policy_version,
      current_policy_version: currentPolicyVersion,
    },
    lifecycle,
  };
}

function configurationCanObserveFault(systemConfiguration: SystemConfiguration, faultId: WorkloadInstance["fault_id"]): boolean {
  if (faultId === "F0") {
    return false;
  }
  if (systemConfiguration === "baseline_hash_only_ledger") {
    return faultId === "F12" || faultId === "H4";
  }
  if (isHardFaultId(faultId)) {
    return systemConfiguration === "govreplay_besu" || systemConfiguration === "SEGL";
  }
  if (systemConfiguration === "baseline_structured_logs") {
    return new Set(["F5", "F6", "F8", "F10"]).has(faultId);
  }
  if (systemConfiguration === "baseline_signed_merkle_log" && faultId === "F12") {
    return false;
  }
  if (systemConfiguration === "govreplay_offchain_only" && faultId === "F12") {
    return false;
  }
  return true;
}

function baselineLifecycleFor(configuration: SystemConfiguration): ObservedReplayEvidence["lifecycle"] {
  const notObserved: ObservedReplayEvidence["lifecycle"] = {
    evidence: "not_observed",
    policy_binding: "not_observed",
    actor_authority: "not_observed",
    approval: "not_observed",
    artifact: "not_observed",
    deployment_scope: "not_observed",
    anchor: "not_observed",
    contract_directory: "not_observed",
  };
  switch (configuration) {
    case "baseline_structured_logs":
      return {
        ...notObserved,
        actor_authority: "authorized",
        approval: "present",
        artifact: "matched",
      };
    case "baseline_signed_merkle_log":
    case "govreplay_offchain_only":
      return {
        ...notObserved,
        evidence: "present",
        policy_binding: "bound",
        actor_authority: "authorized",
        approval: "present",
        artifact: "matched",
      };
    case "baseline_hash_only_ledger":
      return {
        ...notObserved,
        anchor: "matched",
      };
    case "SEGL":
    case "govreplay_besu":
      return {
        evidence: "present",
        policy_binding: "bound",
        actor_authority: "authorized",
        approval: "present",
        artifact: "matched",
        deployment_scope: "matched",
        anchor: "matched",
        contract_directory: "current",
      };
  }
}

function applyObservedMutation(lifecycle: ObservedReplayEvidence["lifecycle"], faultId: WorkloadInstance["fault_id"]): void {
  switch (faultId) {
    case "F0":
      break;
    case "F1":
      lifecycle.evidence = "missing";
      break;
    case "F2":
      lifecycle.evidence = "digest_mismatch";
      break;
    case "F3":
      lifecycle.policy_binding = "version_mismatch";
      break;
    case "F5":
      lifecycle.actor_authority = "unauthorized";
      break;
    case "F6":
      lifecycle.approval = "missing";
      break;
    case "F8":
      lifecycle.approval = "separation_of_duties_violation";
      break;
    case "F10":
      lifecycle.artifact = "mismatch";
      break;
    case "F12":
      lifecycle.anchor = "mismatch";
      break;
    case "H1":
      lifecycle.actor_authority = "revoked_before_deployment";
      break;
    case "H2":
      lifecycle.policy_binding = "changed_before_deployment";
      break;
    case "H3":
      lifecycle.policy_binding = "conflicting_activation";
      break;
    case "H4":
      lifecycle.anchor = "missing";
      break;
    case "H5":
      lifecycle.approval = "ledger_offchain_mismatch";
      break;
    case "H6":
      lifecycle.deployment_scope = "mismatch";
      break;
    case "H7":
      lifecycle.actor_authority = "stale_snapshot";
      break;
    case "H8":
      lifecycle.contract_directory = "mismatch";
      break;
  }
}

function observedLinksFor(instance: WorkloadInstance, lifecycle: ObservedReplayEvidence["lifecycle"]): Record<string, boolean> {
  const all = Object.fromEntries(REQUIRED_LINKS.map((link) => [link, true])) as Record<string, boolean>;
  if (instance.system_configuration === "govreplay_besu" || instance.system_configuration === "SEGL") {
    return {
      ...all,
      evidence: lifecycle.evidence !== "missing",
      approval_chain: lifecycle.approval !== "missing" && lifecycle.approval !== "ledger_offchain_mismatch",
      ledger_anchor: lifecycle.anchor !== "missing",
    };
  }
  if (instance.system_configuration === "govreplay_offchain_only") {
    return {
      ...all,
      evidence: lifecycle.evidence !== "missing",
      approval_chain: lifecycle.approval !== "missing",
      ledger_anchor: false,
    };
  }
  if (instance.system_configuration === "baseline_hash_only_ledger") {
    return {
      observation: true,
      evidence: false,
      policy_version: true,
      policy_decision: false,
      action_proposal: false,
      approval_chain: false,
      artifact: true,
      deployment: true,
      ledger_anchor: lifecycle.anchor !== "missing",
    };
  }
  if (instance.system_configuration === "baseline_signed_merkle_log") {
    return {
      ...all,
      evidence: lifecycle.evidence !== "missing",
      approval_chain: lifecycle.approval !== "missing",
      ledger_anchor: false,
    };
  }
  return {
    observation: true,
    evidence: instance.fault_id !== "F1",
    policy_version: false,
    policy_decision: false,
    action_proposal: true,
    approval_chain: ["F6", "F8"].includes(instance.fault_id) ? false : true,
    artifact: true,
    deployment: true,
    ledger_anchor: false,
  };
}

function sourceProfileFor(configuration: SystemConfiguration): ObservedReplayEvidence["source_profile"] {
  switch (configuration) {
    case "baseline_structured_logs":
      return "structured_log";
    case "baseline_signed_merkle_log":
      return "signed_merkle_log";
    case "govreplay_offchain_only":
      return "signed_offchain_attestation_bundle";
    case "SEGL":
      return "signed_event_sourced_governance_log";
    case "baseline_hash_only_ledger":
      return "hash_only_anchor";
    case "govreplay_besu":
      return "deterministic_besu_state";
  }
}

function inputProvenanceFor(instance: WorkloadInstance, observedEvidence: ObservedReplayEvidence): ReplayInputProvenance[] {
  const replayId = replayIdFor(instance);
  return [
    {
      artifact_type: "workload_instance",
      source: `inputs/workload.jsonl#${replayId}`,
      digest: digest({
        replay_id: replayId,
        workflow_id: instance.workflow_id,
        scenario_id: instance.scenario_id,
        system_configuration: instance.system_configuration,
        policy_version: instance.policy_version,
        seed: instance.seed,
      }),
      purpose: "replay subject and scenario metadata",
    },
    {
      artifact_type: provenanceArtifactType(instance.system_configuration),
      source: provenanceSource(instance),
      digest: digest({
        replay_id: replayId,
        deployment_id: instance.deployment_id,
        artifact_id: instance.artifact_id,
        agent_id: instance.agent_id,
        observed_evidence: observedEvidence,
      }),
      purpose: "observed verifier input",
    },
  ];
}

function provenanceArtifactType(configuration: SystemConfiguration): string {
  switch (configuration) {
    case "baseline_structured_logs":
      return "structured_log";
    case "baseline_signed_merkle_log":
      return "signed_merkle_log";
    case "govreplay_offchain_only":
      return "signed_offchain_attestation_bundle";
    case "SEGL":
      return "signed_event_sourced_governance_log";
    case "baseline_hash_only_ledger":
      return "hash_only_anchor";
    case "govreplay_besu":
      return "deterministic_besu_sidecar";
  }
}

function provenanceSource(instance: WorkloadInstance): string {
  switch (instance.system_configuration) {
    case "baseline_structured_logs":
      return `baseline_logs/structured_logs.jsonl#${instance.workflow_id}`;
    case "baseline_signed_merkle_log":
      return `baseline_logs/signed_merkle_log.jsonl#${instance.workflow_id}`;
    case "govreplay_offchain_only":
      return `objects/attestations/${instance.workflow_id}.json`;
    case "SEGL":
      return `baseline_logs/segl_events.jsonl#${instance.workflow_id}`;
    case "baseline_hash_only_ledger":
      return `ledger/hash_only_anchors.jsonl#${instance.workflow_id}`;
    case "govreplay_besu":
      return `ledger/events.jsonl#${instance.workflow_id}`;
  }
}

function isHardFaultId(faultId: string): faultId is HardFaultId {
  return HARD_FAULT_IDS.includes(faultId as HardFaultId);
}

function digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}
