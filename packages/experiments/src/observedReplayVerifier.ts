import type { FailureStage, Verdict } from "./model.ts";

export type ObservedReplayIssue = {
  stage: FailureStage;
  code: string;
};

export type ObservedReplayEvidence = {
  schema_version: "govprov.observed_replay_evidence.v1";
  source_profile:
    | "structured_log"
    | "signed_merkle_log"
    | "signed_offchain_attestation_bundle"
    | "signed_event_sourced_governance_log"
    | "hash_only_anchor"
    | "deterministic_besu_state";
  links: Record<string, boolean>;
  policy: {
    historical_policy_version: string;
    current_policy_version: string;
  };
  lifecycle: {
    evidence: "not_observed" | "present" | "missing" | "digest_mismatch";
    policy_binding: "not_observed" | "bound" | "version_mismatch" | "changed_before_deployment" | "conflicting_activation";
    actor_authority: "not_observed" | "authorized" | "unauthorized" | "revoked_before_deployment" | "stale_snapshot";
    approval: "not_observed" | "present" | "missing" | "separation_of_duties_violation" | "ledger_offchain_mismatch";
    artifact: "not_observed" | "matched" | "mismatch";
    deployment_scope: "not_observed" | "matched" | "mismatch";
    anchor: "not_observed" | "matched" | "mismatch" | "missing";
    contract_directory: "not_observed" | "current" | "mismatch";
  };
};

export type ObservedReplayEvaluation = {
  issue: ObservedReplayIssue | null;
  historical_compliance: Verdict;
  current_policy_compliance: Verdict;
  policy_drift: boolean;
  policy_drift_class: string;
  reconstructed_links: Record<string, boolean>;
  checks: Array<{
    name: string;
    stage: FailureStage | "replay";
    status: "PASS" | "FAIL" | "NOT_EVALUATED";
    code: string | null;
    detail: string;
  }>;
};

export function verifyObservedReplayEvidence(evidence: ObservedReplayEvidence): ObservedReplayEvaluation {
  const checks = observedChecks(evidence);
  const issue = firstIssue(evidence);
  const historicalCompliance: Verdict = issue === null ? "pass" : "fail";
  const currentPolicyCompliance: Verdict = historicalCompliance === "pass" && evidence.policy.historical_policy_version === evidence.policy.current_policy_version
    ? "pass"
    : "fail";
  return {
    issue,
    historical_compliance: historicalCompliance,
    current_policy_compliance: currentPolicyCompliance,
    policy_drift: historicalCompliance !== currentPolicyCompliance,
    policy_drift_class: `${historicalCompliance}_current_${currentPolicyCompliance}`,
    reconstructed_links: evidence.links,
    checks,
  };
}

function firstIssue(evidence: ObservedReplayEvidence): ObservedReplayIssue | null {
  switch (evidence.lifecycle.evidence) {
    case "missing":
      return { stage: "evidence", code: "evidence_missing" };
    case "digest_mismatch":
      return { stage: "evidence", code: "evidence_hash_mismatch" };
    case "present":
    case "not_observed":
      break;
  }

  switch (evidence.lifecycle.policy_binding) {
    case "version_mismatch":
      return { stage: "policy", code: "policy_version_mismatch" };
    case "changed_before_deployment":
      return { stage: "policy", code: "policy_changed_between_decision_and_deployment" };
    case "conflicting_activation":
      return { stage: "policy", code: "conflicting_policy_activation" };
    case "bound":
    case "not_observed":
      break;
  }

  switch (evidence.lifecycle.actor_authority) {
    case "unauthorized":
      return { stage: "identity", code: "unauthorized_actor" };
    case "revoked_before_deployment":
      return { stage: "identity", code: "role_revoked_before_deployment" };
    case "stale_snapshot":
      return { stage: "identity", code: "stale_actor_snapshot" };
    case "authorized":
    case "not_observed":
      break;
  }

  switch (evidence.lifecycle.approval) {
    case "missing":
      return { stage: "approval", code: "approval_missing" };
    case "separation_of_duties_violation":
      return { stage: "approval", code: "separation_of_duties_violation" };
    case "ledger_offchain_mismatch":
      return { stage: "approval", code: "ledger_approval_offchain_omission" };
    case "present":
    case "not_observed":
      break;
  }

  if (evidence.lifecycle.artifact === "mismatch") {
    return { stage: "artifact", code: "artifact_hash_mismatch" };
  }
  if (evidence.lifecycle.deployment_scope === "mismatch") {
    return { stage: "deployment", code: "wrong_deployment_scope" };
  }

  switch (evidence.lifecycle.anchor) {
    case "mismatch":
      return { stage: "ledger", code: "anchor_mismatch" };
    case "missing":
      return { stage: "ledger", code: "ledger_anchor_missing" };
    case "matched":
    case "not_observed":
      break;
  }

  if (evidence.lifecycle.contract_directory === "mismatch") {
    return { stage: "contract_governance", code: "contract_directory_mismatch" };
  }
  return null;
}

function observedChecks(evidence: ObservedReplayEvidence): ObservedReplayEvaluation["checks"] {
  return [
    stateCheck("observed_evidence_reference", "evidence", evidence.lifecycle.evidence, {
      present: "Evidence reference and digest are replayable.",
      missing: "Replay input has no evidence reference to reconstruct.",
      digest_mismatch: "Evidence digest readback differs from the replayed reference.",
    }),
    stateCheck("observed_policy_binding", "policy", evidence.lifecycle.policy_binding, {
      bound: "Policy version and active-policy state agree for this replay input.",
      version_mismatch: "Recorded policy version differs from the replayed policy binding.",
      changed_before_deployment: "Policy activation history changes between decision and deployment.",
      conflicting_activation: "Policy activation history contains conflicting active windows.",
    }),
    stateCheck("observed_actor_authority", "identity", evidence.lifecycle.actor_authority, {
      authorized: "Actor authority is present in replayable state.",
      unauthorized: "Actor lacks authority for the governed action.",
      revoked_before_deployment: "Actor role was revoked before deployment-time replay.",
      stale_snapshot: "Signed actor snapshot differs from active role state.",
    }),
    stateCheck("observed_approval_state", "approval", evidence.lifecycle.approval, {
      present: "Approval reference and approver/proposer state are replayable.",
      missing: "Required approval is absent from replayable state.",
      separation_of_duties_violation: "Approver and proposer are not separated.",
      ledger_offchain_mismatch: "Ledger approval state does not match off-chain lifecycle linkage.",
    }),
    stateCheck("observed_artifact_state", "artifact", evidence.lifecycle.artifact, {
      matched: "Approved and deployed artifact hashes match.",
      mismatch: "Deployed artifact hash differs from approved artifact hash.",
    }),
    stateCheck("observed_deployment_scope", "deployment", evidence.lifecycle.deployment_scope, {
      matched: "Deployment scope matches approval scope.",
      mismatch: "Deployment scope differs from approval scope.",
    }),
    stateCheck("observed_anchor_readback", "ledger", evidence.lifecycle.anchor, {
      matched: "Anchor readback matches the reconstructed workflow root.",
      mismatch: "Anchor readback differs from the reconstructed workflow root.",
      missing: "No independently queryable anchor exists for the replayed workflow.",
    }),
    stateCheck("observed_contract_directory", "contract_governance", evidence.lifecycle.contract_directory, {
      current: "Contract-directory state is current for the replayed lifecycle.",
      mismatch: "Contract-directory history supersedes the replayed contract set.",
    }),
  ];
}

function stateCheck(
  name: string,
  stage: ObservedReplayEvaluation["checks"][number]["stage"],
  state: string,
  details: Record<string, string>,
): ObservedReplayEvaluation["checks"][number] {
  if (state === "not_observed") {
    return {
      name,
      stage,
      status: "NOT_EVALUATED",
      code: null,
      detail: "This verifier profile has no replayable state for this property.",
    };
  }
  const okStates = new Set(["present", "bound", "authorized", "matched", "current"]);
  return {
    name,
    stage,
    status: okStates.has(state) ? "PASS" : "FAIL",
    code: okStates.has(state) ? null : `observed_${state}`,
    detail: details[state] ?? `Observed state: ${state}`,
  };
}
