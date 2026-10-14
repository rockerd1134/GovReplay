// Research fixture/demo code: embedded keys are public synthetic test vectors.
// Never use these keys or this fixture signer for production accounts. See SECURITY.md.
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { canonicalJson } from "./canonical-json.ts";
import { digestAttestation, digestJson, type DigestObject } from "./digest.ts";
import {
  addressFromPrivateKey,
  signAttestation,
  type SignedAttestation,
} from "./signing.ts";

export const signedFixtureDir = join(import.meta.dirname, "..", "fixtures", "signed");

export const signedFixtureNames = [
  "observation-request.signed.attestation.json",
  "evidence-bundle.signed.attestation.json",
  "policy-decision.signed.attestation.json",
  "agent-action.signed.attestation.json",
  "artifact.signed.attestation.json",
  "approval.signed.attestation.json",
  "deployment.signed.attestation.json",
  "ledger-anchor.signed.attestation.json",
  "audit-replay-report.signed.attestation.json",
] as const;

export type SignedFixtureName = (typeof signedFixtureNames)[number];

interface FixtureActor {
  actor_id: string;
  actor_type: "agent" | "human" | "service";
  private_key: string;
}

interface ActorEnvelope {
  actor_id: string;
  actor_type: "agent" | "human" | "service";
  ethereum_address: string;
}

const actors = {
  agentAlpha: {
    actor_id: "govprov:actor:agent-alpha",
    actor_type: "agent",
    private_key: "0x0000000000000000000000000000000000000000000000000000000000000002",
  },
  policyService: {
    actor_id: "govprov:actor:policy-service",
    actor_type: "service",
    private_key: "0x0000000000000000000000000000000000000000000000000000000000000003",
  },
  securityApprover: {
    actor_id: "govprov:actor:security-approver",
    actor_type: "human",
    private_key: "0x0000000000000000000000000000000000000000000000000000000000000001",
  },
  deployer: {
    actor_id: "govprov:actor:deployer",
    actor_type: "human",
    private_key: "0x0000000000000000000000000000000000000000000000000000000000000004",
  },
  ledgerWriter: {
    actor_id: "govprov:actor:ledger-writer",
    actor_type: "service",
    private_key: "0x0000000000000000000000000000000000000000000000000000000000000005",
  },
  verifier: {
    actor_id: "govprov:actor:verifier",
    actor_type: "service",
    private_key: "0x0000000000000000000000000000000000000000000000000000000000000006",
  },
} satisfies Record<string, FixtureActor>;

const policy = {
  policy_id: "govprov:policy:delivery-v1",
  policy_hash: bytes32("22"),
  scope_hash: bytes32("33"),
};

export function generateSignedFixtureAttestations(): Record<SignedFixtureName, SignedAttestation> {
  const observation = sign(baseAttestation({
    attestation_type: "ObservationAttestation",
    predicate_type: "https://govprov.dev/predicate/observation/v1",
    subjectName: "ticket-1001",
    subjectDigest: digestText("ticket-1001:governed-staging-deployment"),
    parents: [],
    created_at: "2026-06-20T00:00:00Z",
    actor: actors.agentAlpha,
    predicate: {
      observation_id: "obs-1001",
      source: "incident-ticket",
      request_summary: "Prepare a governed staging deployment for service api.",
    },
  }), actors.agentAlpha);

  const evidence = sign(baseAttestation({
    attestation_type: "EvidenceBundleAttestation",
    predicate_type: "https://govprov.dev/predicate/evidence-bundle/v1",
    subjectName: "evidence-bundle-1001",
    subjectDigest: digestText("evidence-bundle-1001"),
    parents: [observation.attestation_hash],
    created_at: "2026-06-20T00:01:00Z",
    actor: actors.agentAlpha,
    predicate: {
      evidence_count: "2",
      evidence: [
        {
          name: "unit-test-report",
          digest: digestText("unit-test-report:pass"),
          uri: "cas://sha256/5555555555555555555555555555555555555555555555555555555555555555",
        },
        {
          name: "incident-summary",
          digest: digestText("incident-summary:medium-risk"),
          uri: "cas://sha256/6666666666666666666666666666666666666666666666666666666666666666",
        },
      ],
    },
  }), actors.agentAlpha);

  const policyDecision = sign(baseAttestation({
    attestation_type: "PolicyDecisionAttestation",
    predicate_type: "https://govprov.dev/predicate/policy-decision/v1",
    subjectName: "policy-decision-1001",
    subjectDigest: digestText("policy-decision-1001:allow"),
    parents: [evidence.attestation_hash],
    created_at: "2026-06-20T00:02:00Z",
    actor: actors.policyService,
    predicate: {
      decision: "allow",
      obligations: [
        "security-approval",
        "artifact-digest",
      ],
      policy_version: "delivery-v1",
      evidence_bundle_hash: evidence.attestation_hash,
    },
  }), actors.policyService);

  const action = sign(baseAttestation({
    attestation_type: "AgentActionAttestation",
    predicate_type: "https://govprov.dev/predicate/agent-action/v1",
    subjectName: "action-1001",
    subjectDigest: digestText("action-1001:staging-deployment"),
    parents: [
      observation.attestation_hash,
      evidence.attestation_hash,
      policyDecision.attestation_hash,
    ],
    created_at: "2026-06-20T00:03:00Z",
    actor: actors.agentAlpha,
    predicate: {
      action_id: "act-1001",
      action_type: "staging-deployment",
      risk: "medium",
      policy_decision_hash: policyDecision.attestation_hash,
      evidence_bundle_hash: evidence.attestation_hash,
    },
  }), actors.agentAlpha);

  const artifact = sign(baseAttestation({
    attestation_type: "ArtifactAttestation",
    predicate_type: "https://govprov.dev/predicate/artifact/v1",
    subjectName: "deployment-manifest.yaml",
    subjectDigest: digestText("deployment-manifest:api:staging:v1"),
    parents: [action.attestation_hash],
    created_at: "2026-06-20T00:04:00Z",
    actor: actors.agentAlpha,
    predicate: {
      artifact_id: "artifact-1001",
      artifact_type: "deployment-manifest",
      artifact_digest: digestText("deployment-manifest:api:staging:v1"),
      source_action: action.attestation_hash,
    },
  }), actors.agentAlpha);

  const approval = sign(baseAttestation({
    attestation_type: "ApprovalAttestation",
    predicate_type: "https://govprov.dev/predicate/approval/v1",
    subjectName: "approval-1001",
    subjectDigest: digestText("approval-1001:approved"),
    parents: [action.attestation_hash, artifact.attestation_hash],
    created_at: "2026-06-20T00:05:00Z",
    actor: actors.securityApprover,
    predicate: {
      approval_id: "apr-1001",
      decision: "approved",
      approval_role: "SECURITY_APPROVER_ROLE",
      action_hash: action.attestation_hash,
      artifact_hash: artifact.attestation_hash,
      policy_decision_hash: policyDecision.attestation_hash,
    },
  }), actors.securityApprover);

  const deployment = sign(baseAttestation({
    attestation_type: "DeploymentAttestation",
    predicate_type: "https://govprov.dev/predicate/deployment/v1",
    subjectName: "deployment-1001",
    subjectDigest: digestText("deployment-1001:staging"),
    parents: [approval.attestation_hash, artifact.attestation_hash],
    created_at: "2026-06-20T00:06:00Z",
    actor: actors.deployer,
    predicate: {
      deployment_id: "dep-1001",
      environment: "staging",
      artifact_hash: artifact.attestation_hash,
      approval_hash: approval.attestation_hash,
    },
  }), actors.deployer);

  const ledgerAnchor = sign(baseAttestation({
    attestation_type: "LedgerAnchorAttestation",
    predicate_type: "https://govprov.dev/predicate/ledger-anchor/v1",
    subjectName: "ledger-anchor-1001",
    subjectDigest: digestText("ledger-anchor-1001:deployment"),
    parents: [deployment.attestation_hash],
    created_at: "2026-06-20T00:07:00Z",
    actor: actors.ledgerWriter,
    predicate: {
      chain_id: "1338",
      transaction_hash: bytes32("ab"),
      contract_address: "0x0000000000000000000000000000000000001001",
      anchored_hash: deployment.attestation_hash,
    },
  }), actors.ledgerWriter);

  const auditReport = sign(baseAttestation({
    attestation_type: "AuditReplayReport",
    predicate_type: "https://govprov.dev/predicate/audit-replay-report/v1",
    subjectName: "audit-report-1001",
    subjectDigest: digestText("audit-report-1001:pass"),
    parents: [ledgerAnchor.attestation_hash],
    created_at: "2026-06-20T00:08:00Z",
    actor: actors.verifier,
    predicate: {
      audit_result: "pass",
      failure_codes: [],
      replay_duration_ms: "42",
      replay_target: deployment.attestation_hash,
    },
  }), actors.verifier);

  return {
    "observation-request.signed.attestation.json": observation,
    "evidence-bundle.signed.attestation.json": evidence,
    "policy-decision.signed.attestation.json": policyDecision,
    "agent-action.signed.attestation.json": action,
    "artifact.signed.attestation.json": artifact,
    "approval.signed.attestation.json": approval,
    "deployment.signed.attestation.json": deployment,
    "ledger-anchor.signed.attestation.json": ledgerAnchor,
    "audit-replay-report.signed.attestation.json": auditReport,
  };
}

export async function writeSignedFixtureAttestations(outputDir = signedFixtureDir): Promise<void> {
  await mkdir(outputDir, { recursive: true });
  const fixtures = generateSignedFixtureAttestations();
  await Promise.all(
    signedFixtureNames.map((name) => writeFile(join(outputDir, name), `${serializeFixture(fixtures[name])}\n`)),
  );
}

export function serializeFixture(attestation: SignedAttestation): string {
  return `${JSON.stringify(attestation, null, 2)}`;
}

function baseAttestation(input: {
  attestation_type: string;
  predicate_type: string;
  subjectName: string;
  subjectDigest: DigestObject;
  parents: string[];
  created_at: string;
  actor: FixtureActor;
  predicate: Record<string, unknown>;
}): Record<string, unknown> {
  return {
    _type: "https://govprov.dev/attestation/v1",
    schema_version: "govprov.attestation.v1",
    attestation_type: input.attestation_type,
    predicate_type: input.predicate_type,
    subject: [
      {
        name: input.subjectName,
        digest: input.subjectDigest,
        uri: digestToCasUri(input.subjectDigest),
      },
    ],
    parents: input.parents,
    created_at: input.created_at,
    created_by: actorEnvelope(input.actor),
    ...governanceDomainFields(input.attestation_type),
    policy,
    predicate: input.predicate,
  };
}

function governanceDomainFields(attestationType: string): Record<string, string> {
  const domain = governanceDomainForAttestation(attestationType);
  const domainTypes: Record<string, string> = {
    identity_domain: "actor_registration_and_role_history",
    policy_domain: "policy_registration_activation_and_decision_binding",
    approval_domain: "approval_authority_and_separation_of_duties",
    deployment_domain: "deployment_registry_and_artifact_consistency",
    anchor_domain: "provenance_anchor_and_merkle_root_readback",
    contract_domain: "contract_directory_and_governance_contract_history",
    audit_domain: "audit_replay_reports_and_metrics",
  };
  return {
    governance_domain: domain,
    governance_domain_type: domainTypes[domain],
    governance_domain_id: `govreplay:domain:${domain}`,
  };
}

function governanceDomainForAttestation(attestationType: string): string {
  switch (attestationType) {
    case "PolicyDecisionAttestation":
      return "policy_domain";
    case "ApprovalAttestation":
      return "approval_domain";
    case "ArtifactAttestation":
    case "DeploymentAttestation":
      return "deployment_domain";
    case "LedgerAnchorAttestation":
      return "anchor_domain";
    case "AuditReplayReport":
      return "audit_domain";
    case "ObservationAttestation":
    case "EvidenceBundleAttestation":
    case "AgentActionAttestation":
    default:
      return "audit_domain";
  }
}

function sign(attestation: Record<string, unknown>, actor: FixtureActor): SignedAttestation {
  return signAttestation(attestation, actor.private_key);
}

function actorEnvelope(actor: FixtureActor): ActorEnvelope {
  return {
    actor_id: actor.actor_id,
    actor_type: actor.actor_type,
    ethereum_address: addressFromPrivateKey(actor.private_key),
  };
}

function digestText(value: string): DigestObject {
  return digestJson(value);
}

function digestToCasUri(digest: DigestObject): string {
  return `cas://sha256/${digest.value.slice(2)}`;
}

function bytes32(byte: string): string {
  return `0x${byte.repeat(32)}`;
}

if (process.argv.includes("--write")) {
  await writeSignedFixtureAttestations();
}
