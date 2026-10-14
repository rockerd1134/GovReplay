import type { CasePlan, Step } from "./model.ts";

export type OracleCase = {
  case_id: string;
  ordered_events: Step[];
  attestation_actor: "actor";
  required_role_at_N: "DEPLOYER_ROLE";
  deployment_actor: "writer" | "actor";
  required_role_at_D: "LEDGER_WRITER_ROLE" | "DEPLOYER_ROLE";
  N_order: number;
  D_order: number;
  authority_at_N: boolean;
  authority_at_D: boolean;
  expected_write_disposition: { N: "accepted"; D: "accepted" | "reverted" };
  expected_replay_verdict: "PASS" | "FAIL";
  expected_besu_replay_verdict: "PASS" | "FAIL" | "NOT_APPLICABLE";
  expected_failure_boundary: "N" | "D" | null;
  violated_invariant: "I1" | "I3" | null;
  history_realizability_class: "REALIZABLE_VALID_HISTORY" | "REALIZABLE_INVALID_HISTORY" | "REJECTED_BY_WRITE_TIME_ENFORCEMENT";
  rationale: string;
};

// This module uses only the independently specified symbolic order and role rule.
// It never reads receipts, SEGL events, replay output, fault IDs, or verifier logic.
export function oracleFor(plan: CasePlan): OracleCase {
  let actorHasRole = true; // case-local authoritative setup grant
  let atN: boolean | undefined;
  let atD: boolean | undefined;
  for (const step of plan.ordered_events) {
    if (step === "R") actorHasRole = false;
    if (step === "G") actorHasRole = true;
    if (step === "N") atN = actorHasRole;
    if (step === "D") atD = plan.deployment_transaction_sender === "writer" ? true : actorHasRole;
  }
  if (atN === undefined || atD === undefined) throw new Error(`Case ${plan.case_id} has no N/D boundary`);
  const deploymentReverted = !atD;
  const verdict = atN && atD ? "PASS" : "FAIL";
  const failureBoundary = !atN ? "N" : deploymentReverted ? "D" : null;
  return {
    case_id: plan.case_id,
    ordered_events: plan.ordered_events,
    attestation_actor: "actor",
    required_role_at_N: "DEPLOYER_ROLE",
    deployment_actor: plan.deployment_transaction_sender,
    required_role_at_D: plan.deployment_transaction_sender === "writer" ? "LEDGER_WRITER_ROLE" : "DEPLOYER_ROLE",
    N_order: plan.ordered_events.indexOf("N") + 1,
    D_order: plan.ordered_events.indexOf("D") + 1,
    authority_at_N: atN,
    authority_at_D: atD,
    expected_write_disposition: { N: "accepted", D: deploymentReverted ? "reverted" : "accepted" },
    expected_replay_verdict: verdict,
    expected_besu_replay_verdict: deploymentReverted ? "NOT_APPLICABLE" : verdict,
    expected_failure_boundary: failureBoundary,
    violated_invariant: !atN ? "I1" : deploymentReverted ? "I3" : null,
    history_realizability_class: deploymentReverted ? "REJECTED_BY_WRITE_TIME_ENFORCEMENT" : atN ? "REALIZABLE_VALID_HISTORY" : "REALIZABLE_INVALID_HISTORY",
    rationale: !atN
      ? "The actor lacks DEPLOYER_ROLE at first authoritative commitment N; a claimed signature time cannot restore it."
      : deploymentReverted
        ? "The actor has authority at N but is the deployment sender after losing DEPLOYER_ROLE at D."
        : "The actor has authority at N and the deployment sender has its required role at D; later changes do not alter either historical boundary.",
  };
}
