import { addressFromPrivateKey, signAttestation } from "../../../attestations/src/signing.ts";
import { digestJson } from "../../../attestations/src/digest.ts";
import { seglEventHash, verifySeglLog, type SeglEvent } from "../../src/segl.ts";
import type { CasePlan, RunMetadata } from "./model.ts";

export type CaseHashes = {
  case_id: string;
  action_hash: string;
  approval_hash: string;
  deployment_attestation_hash: string;
  deployment_id_hash: string;
  artifact_hash: string;
};

export type TemporalReplay = {
  verdict: "PASS" | "FAIL";
  failure_boundary: "N" | "D" | "integrity" | null;
  authority_at_N: boolean;
  authority_at_D: boolean;
  policy_at_D: boolean;
  approval_at_D: boolean;
  N_order: number;
  D_order: number;
  integrity_issues: string[];
};

// The existing SEGL signature, hash-chain and append integrity verifier remains
// authoritative for the event stream. This narrow adapter only adds a historical
// role check at the experiment's N and D boundaries.
export function buildTemporalSeglEvents(plan: CasePlan, meta: RunMetadata, hashes: CaseHashes, logPrivateKey: string): SeglEvent[] {
  const signer = addressFromPrivateKey(logPrivateKey);
  const events: SeglEvent[] = [];
  const add = (
    event_type: SeglEvent["event_type"],
    domain: SeglEvent["domain"],
    subject: string,
    object: string,
    payload: Record<string, unknown>,
  ) => {
    const sequence = events.length + 1;
    const draft = {
      schema_version: "govprov.segl.event.v1" as const,
      attestation_type: "SignedEventSourcedGovernanceLogEvent" as const,
      event_id: `temporal:${meta.run_id}:${plan.case_id}:${sequence}:${event_type}`,
      sequence,
      domain,
      workflow_id: plan.case_id,
      event_type,
      subject,
      object,
      policy_version: meta.policy_hash,
      // Deliberately equal and caller controlled: neither field orders replay.
      timestamp: "2026-10-01T00:00:00Z",
      logical_time: "caller-selected-equal-time",
      payload,
      prev_event_hash: events.at(-1)?.event_hash ?? null,
      signer,
      created_by: { actor_id: "segl:temporal-log-operator", ethereum_address: signer, signing_profile: "experimental-deterministic-secp256k1" },
    };
    const withHash = { ...draft, event_hash: seglEventHash(draft) };
    const signed = signAttestation(withHash, logPrivateKey);
    events.push({ ...withHash, signature: signed.signature, attestation_hash: signed.attestation_hash });
  };

  add("actor_role_assigned", "identity_domain", meta.attestation_actor, plan.case_id, { roles: [meta.deployer_role] });
  add("actor_role_assigned", "identity_domain", meta.default_deployment_transaction_sender, plan.case_id, { roles: [meta.ledger_writer_role] });
  add("policy_activated", "policy_domain", meta.policy_hash, plan.case_id, { policy_hash: meta.policy_hash, scope: plan.case_id });
  for (const step of plan.ordered_events) {
    switch (step) {
      case "A":
        add("policy_decision_recorded", "policy_domain", meta.attestation_actor, plan.case_id, { policy_hash: meta.policy_hash });
        break;
      case "S":
      case "AUDIT":
        break;
      case "R":
        add("actor_role_revoked", "identity_domain", meta.attestation_actor, plan.case_id, { roles: [meta.deployer_role] });
        break;
      case "G":
        add("actor_role_assigned", "identity_domain", meta.attestation_actor, plan.case_id, { roles: [meta.deployer_role] });
        break;
      case "N":
        add("anchor_recorded", "anchor_domain", hashes.action_hash, plan.case_id, {
          anchor_id: hashes.action_hash,
          action_hash: hashes.action_hash,
          actor: meta.attestation_actor,
          workflow_root: digestJson(plan.case_id).value,
        });
        break;
      case "D":
        add("approval_recorded", "approval_domain", hashes.approval_hash, hashes.artifact_hash, {
          approval_id: hashes.approval_hash,
          approver: meta.approval_actor,
          proposer: meta.attestation_actor,
          artifact_hash: hashes.artifact_hash,
          deployment_scope: "temporal:staging",
          separation_of_duties_ok: true,
          offchain_lifecycle_reference: plan.case_id,
        });
        add("artifact_recorded", "deployment_domain", hashes.artifact_hash, plan.case_id, {
          artifact_id: hashes.artifact_hash,
          artifact_hash: hashes.artifact_hash,
          approved_artifact_hash: hashes.artifact_hash,
        });
        add("deployment_recorded", "deployment_domain", hashes.deployment_id_hash, hashes.artifact_hash, {
          deployment_id: hashes.deployment_id_hash,
          artifact_id: hashes.artifact_hash,
          artifact_hash: hashes.artifact_hash,
          approval_id: hashes.approval_hash,
          deployer: plan.deployment_transaction_sender === "writer" ? meta.default_deployment_transaction_sender : meta.attestation_actor,
          deployment_scope: "temporal:staging",
        });
        break;
    }
  }
  return events;
}

function hasRoleBefore(events: readonly SeglEvent[], actor: string, role: string, boundarySequence: number): boolean {
  let held = false;
  for (const event of events) {
    if (event.sequence >= boundarySequence) break;
    if (event.subject.toLowerCase() !== actor.toLowerCase()) continue;
    if (!Array.isArray(event.payload.roles) || !event.payload.roles.includes(role)) continue;
    if (event.event_type === "actor_role_assigned") held = true;
    if (event.event_type === "actor_role_revoked") held = false;
  }
  return held;
}

export function verifyTemporalSegl(events: SeglEvent[], meta: RunMetadata, hashes: CaseHashes): TemporalReplay {
  const integrity = verifySeglLog(events);
  const anchor = events.find((event) => event.event_type === "anchor_recorded" && event.payload.action_hash === hashes.action_hash);
  const deployment = events.find((event) => event.event_type === "deployment_recorded" && event.payload.deployment_id === hashes.deployment_id_hash);
  if (anchor === undefined || deployment === undefined) throw new Error(`Missing temporal N/D events for ${hashes.case_id}`);
  const authorityN = hasRoleBefore(events, meta.attestation_actor, meta.deployer_role, anchor.sequence);
  const deploymentActor = String(deployment.payload.deployer);
  const deploymentRole = deploymentActor.toLowerCase() === meta.attestation_actor.toLowerCase() ? meta.deployer_role : meta.ledger_writer_role;
  const authorityD = hasRoleBefore(events, deploymentActor, deploymentRole, deployment.sequence);
  const policyD = events.some((event) => event.event_type === "policy_activated" && event.payload.policy_hash === meta.policy_hash && event.sequence < deployment.sequence);
  const approvalD = events.some((event) => event.event_type === "approval_recorded" && event.payload.approval_id === hashes.approval_hash
    && event.payload.artifact_hash === hashes.artifact_hash && event.sequence < deployment.sequence);
  const failure: TemporalReplay["failure_boundary"] = !integrity.ok ? "integrity" : !authorityN ? "N" : !authorityD || !policyD || !approvalD ? "D" : null;
  return {
    verdict: failure === null ? "PASS" : "FAIL",
    failure_boundary: failure,
    authority_at_N: authorityN,
    authority_at_D: authorityD,
    policy_at_D: policyD,
    approval_at_D: approvalD,
    N_order: anchor.sequence,
    D_order: deployment.sequence,
    integrity_issues: integrity.issues.map((issue) => issue.code),
  };
}
