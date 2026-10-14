import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { sha256Hex } from "../../attestations/src/digest.ts";
import { type AttestationIndex, resolveInsideRun } from "../../attestations/src/run-layout.ts";
import { verifyAttestationSetLevel1 } from "../../attestations/src/verifier.ts";

export type ReplayInput =
  | { type: "deployment_id"; value: string }
  | { type: "action_id"; value: string }
  | { type: "attestation_hash"; value: string }
  | { type: "workflow_id"; value: string };

export type CheckStatus = "PASS" | "FAIL" | "INCOMPLETE" | "NOT_EVALUATED";

export type ReplayCheck = {
  name: string;
  stage: string;
  status: CheckStatus;
  code: string | null;
  detail: string;
};

export type ReplayNode = {
  attestation_hash: string;
  attestation_type: string;
  subject_name: string | null;
  created_at: string;
  parent_hashes: string[];
  path: string;
};

export type AuditReplayReport = {
  schema_version: "govprov.audit_replay_report.v1";
  audit_profile: "govprov-audit-replay-v1";
  run_id: string;
  workflow_id: string;
  scenario_id: string | null;
  system_configuration: "signed_offchain" | "govreplay_besu";
  governance_domain: string;
  governance_domain_type: string;
  governance_domain_id: string;
  expected_domain: string;
  domain_fault: boolean;
  cross_domain_dependency: string[];
  replay_input_type: ReplayInput["type"];
  replay_input: string;
  verdict: "PASS" | "FAIL" | "INCOMPLETE";
  failure_stage: string | null;
  failure_code: string | null;
  historical_compliance: "pass" | "fail" | "not_evaluated";
  current_policy_compliance: "pass" | "fail" | "not_evaluated";
  policy_drift: boolean;
  policy_drift_class: string;
  reconstructed_links: Record<string, boolean>;
  nodes: ReplayNode[];
  edges: Array<{ from: string; to: string }>;
  checks: ReplayCheck[];
  metrics: {
    required_links: number;
    reconstructed_links: number;
    valid_signatures: number;
    invalid_signatures: number;
    hash_mismatches: number;
    ledger_queries: number;
    verification_time_ms: number;
  };
};

export type ReplayOptions = {
  runRoot: string;
  input: ReplayInput;
  scenarioRoot?: string;
  ledgerSidecarPath?: string;
  currentPolicyVersion?: string;
  reportDir?: string;
};

type LoadedRun = {
  runRoot: string;
  index: AttestationIndex;
  replayFixture: Record<string, unknown> | null;
  records: Map<string, Record<string, unknown>>;
};

const REQUIRED_TYPES = [
  "ObservationAttestation",
  "EvidenceBundleAttestation",
  "PolicyDecisionAttestation",
  "AgentActionAttestation",
  "ApprovalAttestation",
  "ArtifactAttestation",
  "DeploymentAttestation",
] as const;

const TYPE_TO_LINK: Record<string, string> = {
  ObservationAttestation: "observation",
  EvidenceBundleAttestation: "evidence",
  PolicyDecisionAttestation: "policy_decision",
  AgentActionAttestation: "action_proposal",
  ApprovalAttestation: "approval_chain",
  ArtifactAttestation: "artifact",
  DeploymentAttestation: "deployment",
};

const BACKWARD_PARENT_PRIORITY: Record<string, Record<string, number>> = {
  DeploymentAttestation: { ArtifactAttestation: 0, ApprovalAttestation: 1 },
  ArtifactAttestation: { ApprovalAttestation: 0, AgentActionAttestation: 1 },
  ApprovalAttestation: { AgentActionAttestation: 0 },
  AgentActionAttestation: {
    PolicyDecisionAttestation: 0,
    EvidenceBundleAttestation: 1,
    ObservationAttestation: 2,
  },
  PolicyDecisionAttestation: { EvidenceBundleAttestation: 0 },
  EvidenceBundleAttestation: { ObservationAttestation: 0 },
};

export async function replayAudit(options: ReplayOptions): Promise<AuditReplayReport> {
  const started = Date.now();
  const loaded = loadRun(options.runRoot);
  currentRunRoot = loaded.runRoot;
  const startHash = resolveStartHash(loaded, options.input);
  const checks: ReplayCheck[] = [];
  if (startHash === null) {
    checks.push({
      name: "locate_start_record",
      stage: "replay",
      status: "INCOMPLETE",
      code: "F_LINK_BROKEN",
      detail: `Could not locate ${options.input.type} ${options.input.value}`,
    });
  }

  const traversal = startHash === null
    ? { hashes: [] as string[], missing: [] as string[] }
    : traverseBackward(loaded, startHash);
  const nodes = traversal.hashes.map((hash) => nodeFromRecord(loaded, hash));
  const nodeHashSet = new Set(nodes.map((node) => node.attestation_hash));
  const edges = nodes.flatMap((node) =>
    node.parent_hashes
      .filter((parentHash) => nodeHashSet.has(parentHash))
      .map((parentHash) => ({ from: node.attestation_hash, to: parentHash }))
  );

  checks.push(...lineageChecks(nodes, traversal.missing));

  const attestationReports = await verifyAttestationSetLevel1([...loaded.records.values()], {
    index: loaded.index,
    runRoot: loaded.runRoot,
  });
  checks.push(...attestationReports.map((report) => ({
    name: `verify_${report.attestation_type ?? "attestation"}`,
    stage: "crypto",
    status: report.status === "PASS" ? "PASS" as const : "FAIL" as const,
    code: report.failure_codes[0] ?? null,
    detail: report.status === "PASS"
      ? `${report.attestation_hash} signature and canonical hash verified`
      : `${report.attestation_hash} failed: ${report.failure_codes.join(", ")}`,
  })));

  const scenarioId = stringValue(loaded.replayFixture?.scenario_id);
  const scenarioRoot = options.scenarioRoot ?? inferScenarioRoot(loaded.runRoot, scenarioId);
  checks.push(...integrityChecks(nodes, scenarioRoot));
  const policyReplay = policyReplayFromNodes(nodes, options.currentPolicyVersion);
  checks.push(...policyReplay.checks);
  checks.push(...approvalChecks(nodes));

  const ledger = ledgerChecks({
    nodes,
    loaded,
    sidecarPath: options.ledgerSidecarPath ?? inferLedgerSidecar(loaded.runRoot, scenarioId),
  });
  checks.push(...ledger.checks);

  const reconstructed = reconstructedLinks(nodes, ledger.status === "PASS");
  const incomplete = checks.find((check) => check.status === "INCOMPLETE");
  const hardFailure = checks.find((check) => check.status === "FAIL");
  const verdict = incomplete !== undefined ? "INCOMPLETE" : hardFailure !== undefined ? "FAIL" : "PASS";
  const failure = incomplete ?? hardFailure ?? null;
  const signatureFailures = attestationReports.filter((report) => report.status === "FAIL");
  const hashMismatches = checks.filter((check) =>
    check.code === "F_HASH_OBJECT_MISMATCH"
    || check.code === "F_DEPLOYMENT_ARTIFACT_MISMATCH"
    || check.code === "F_APPROVAL_ARTIFACT_MISMATCH"
  );

  const report: AuditReplayReport = {
    schema_version: "govprov.audit_replay_report.v1",
    audit_profile: "govprov-audit-replay-v1",
    run_id: loaded.index.run_id,
    workflow_id: stringValue(loaded.replayFixture?.workflow_id) ?? loaded.index.run_id,
    scenario_id: scenarioId,
    system_configuration: ledger.status === "PASS" ? "govreplay_besu" : "signed_offchain",
    governance_domain: stringValue(loaded.replayFixture?.governance_domain) ?? "audit_domain",
    governance_domain_type: stringValue(loaded.replayFixture?.governance_domain_type) ?? "audit_replay_reports_and_metrics",
    governance_domain_id: stringValue(loaded.replayFixture?.governance_domain_id) ?? "govreplay:domain:audit_domain",
    expected_domain: stringValue(loaded.replayFixture?.expected_domain) ?? "audit_domain",
    domain_fault: Boolean(loaded.replayFixture?.domain_fault),
    cross_domain_dependency: arrayOfStrings(loaded.replayFixture?.cross_domain_dependency),
    replay_input_type: options.input.type,
    replay_input: options.input.value,
    verdict,
    failure_stage: failure?.stage ?? null,
    failure_code: failure?.code ?? null,
    historical_compliance: policyReplay.historical_compliance,
    current_policy_compliance: policyReplay.current_policy_compliance,
    policy_drift: policyReplay.historical_compliance !== "not_evaluated"
      && policyReplay.current_policy_compliance !== "not_evaluated"
      && policyReplay.historical_compliance !== policyReplay.current_policy_compliance,
    policy_drift_class: `${policyReplay.historical_compliance}_current_${policyReplay.current_policy_compliance}`,
    reconstructed_links: reconstructed,
    nodes,
    edges,
    checks,
    metrics: {
      required_links: REQUIRED_TYPES.length,
      reconstructed_links: Object.values(reconstructed).filter(Boolean).length,
      valid_signatures: attestationReports.length - signatureFailures.length,
      invalid_signatures: signatureFailures.length,
      hash_mismatches: hashMismatches.length,
      ledger_queries: ledger.queries,
      verification_time_ms: Date.now() - started,
    },
  };

  if (options.reportDir !== undefined) {
    writeReports(report, options.reportDir);
  }

  return report;
}

export function writeReports(report: AuditReplayReport, reportDir: string): { jsonl: string; markdown: string } {
  mkdirSync(reportDir, { recursive: true });
  const safeName = report.workflow_id.replaceAll(/[^A-Za-z0-9._-]/g, "_");
  const jsonl = join(reportDir, "audit_results.jsonl");
  const markdown = join(reportDir, `audit_${safeName}.md`);
  writeFileSync(jsonl, `${JSON.stringify(report)}\n`);
  writeFileSync(markdown, markdownReport(report));
  return { jsonl, markdown };
}

export function markdownReport(report: AuditReplayReport): string {
  const checks = report.checks
    .map((check) => `| ${check.stage} | ${check.name} | ${check.status} | ${check.code ?? ""} | ${check.detail.replaceAll("|", "\\|")} |`)
    .join("\n");
  const nodes = report.nodes
    .map((node, index) => `${index + 1}. ${node.attestation_type} ${node.subject_name ?? ""} (${node.attestation_hash})`)
    .join("\n");
  return [
    `# Audit Replay ${report.workflow_id}`,
    "",
    `Verdict: ${report.verdict}`,
    `Governance domain: ${report.governance_domain}`,
    `Failure: ${report.failure_code ?? "none"}`,
    `Historical compliance: ${report.historical_compliance}`,
    `Current policy compliance: ${report.current_policy_compliance}`,
    `Policy drift: ${String(report.policy_drift)}`,
    "",
    "## Reconstructed Chain",
    "",
    nodes,
    "",
    "## Checks",
    "",
    "| Stage | Check | Status | Code | Detail |",
    "| --- | --- | --- | --- | --- |",
    checks,
    "",
  ].join("\n");
}

function loadRun(runRootInput: string): LoadedRun {
  const runRoot = resolve(runRootInput);
  const index = readJson(resolveInsideRun(runRoot, "manifests/attestation_index.json")) as unknown as AttestationIndex;
  const replayFixturePath = resolveInsideRun(runRoot, "manifests/local_replay_fixture.json");
  const replayFixture = existsSync(replayFixturePath) ? readJson(replayFixturePath) : null;
  const records = new Map<string, Record<string, unknown>>();
  for (const entry of index.attestations) {
    const path = resolveInsideRun(runRoot, entry.path);
    if (existsSync(path)) {
      records.set(entry.attestation_hash, readJson(path));
    }
  }
  return { runRoot, index, replayFixture, records };
}

function resolveStartHash(loaded: LoadedRun, input: ReplayInput): string | null {
  if (input.type === "attestation_hash") {
    return loaded.records.has(input.value) ? input.value : null;
  }
  if (input.type === "workflow_id") {
    const deployment = [...loaded.records.values()].find((record) =>
      record.attestation_type === "DeploymentAttestation" && predicateString(record, "workflow_id") === input.value
    );
    return stringValue(deployment?.attestation_hash) ?? null;
  }

  if (input.type === "action_id") {
    const deployment = [...loaded.records.values()].find((record) =>
      record.attestation_type === "DeploymentAttestation" && predicateString(record, "action_id") === input.value
    );
    if (deployment !== undefined) {
      return stringValue(deployment.attestation_hash) ?? null;
    }
  }

  const field = input.type === "deployment_id" ? "deployment_id" : "action_id";
  const wantedType = input.type === "deployment_id" ? "DeploymentAttestation" : "AgentActionAttestation";
  const match = [...loaded.records.values()].find((record) =>
    record.attestation_type === wantedType
    && (predicateString(record, field) === input.value || subjectName(record) === input.value)
  );
  return stringValue(match?.attestation_hash) ?? null;
}

function traverseBackward(loaded: LoadedRun, startHash: string): { hashes: string[]; missing: string[] } {
  const visited = new Set<string>();
  const output: string[] = [];
  const missing: string[] = [];

  function visit(hash: string): void {
    if (visited.has(hash)) {
      return;
    }
    const record = loaded.records.get(hash);
    if (record === undefined) {
      missing.push(hash);
      return;
    }
    visited.add(hash);
    output.push(hash);
    for (const parentHash of sortedParentHashes(record, loaded)) {
      visit(parentHash);
    }
  }

  visit(startHash);
  return { hashes: output, missing };
}

function sortedParentHashes(record: Record<string, unknown>, loaded: LoadedRun): string[] {
  const parents = arrayOfStrings(record.parents);
  const priority = BACKWARD_PARENT_PRIORITY[String(record.attestation_type)] ?? {};
  return [...parents].sort((left, right) => {
    const leftType = String(loaded.records.get(left)?.attestation_type ?? "");
    const rightType = String(loaded.records.get(right)?.attestation_type ?? "");
    return (priority[leftType] ?? 99) - (priority[rightType] ?? 99)
      || leftType.localeCompare(rightType)
      || left.localeCompare(right);
  });
}

function nodeFromRecord(loaded: LoadedRun, hash: string): ReplayNode {
  const record = loaded.records.get(hash);
  if (record === undefined) {
    throw new Error(`Missing traversed record: ${hash}`);
  }
  const entry = loaded.index.attestations.find((item) => item.attestation_hash === hash);
  return {
    attestation_hash: hash,
    attestation_type: String(record.attestation_type),
    subject_name: subjectName(record),
    created_at: String(record.created_at),
    parent_hashes: arrayOfStrings(record.parents),
    path: entry?.path ?? "",
  };
}

function lineageChecks(nodes: ReplayNode[], missing: string[]): ReplayCheck[] {
  const checks: ReplayCheck[] = [];
  const seenTypes = new Set(nodes.map((node) => node.attestation_type));
  for (const type of REQUIRED_TYPES) {
    checks.push({
      name: `lineage_${TYPE_TO_LINK[type]}`,
      stage: "replay",
      status: seenTypes.has(type) ? "PASS" : "INCOMPLETE",
      code: seenTypes.has(type) ? null : "F_LINK_MISSING",
      detail: seenTypes.has(type) ? `${type} reconstructed` : `${type} missing from lineage`,
    });
  }
  for (const hash of missing) {
    checks.push({
      name: "resolve_parent",
      stage: "replay",
      status: "INCOMPLETE",
      code: "F_LINK_BROKEN",
      detail: `Parent attestation ${hash} is not resolvable`,
    });
  }
  return checks;
}

function integrityChecks(nodes: ReplayNode[], scenarioRoot: string | null): ReplayCheck[] {
  const records = recordsByType(nodes);
  const checks: ReplayCheck[] = [];
  const evidence = records.get("EvidenceBundleAttestation")?.predicate as Record<string, unknown> | undefined;
  if (evidence !== undefined) {
    for (const item of Array.isArray(evidence.evidence) ? evidence.evidence : []) {
      if (!isRecord(item)) {
        continue;
      }
      const path = stringValue(item.path);
      const expected = digestValue(item.content_digest);
      if (scenarioRoot === null || path === undefined || expected === null) {
        checks.push(check("verify_evidence_digest", "evidence", "NOT_EVALUATED", null, "Evidence source path is unavailable"));
        continue;
      }
      const fullPath = join(scenarioRoot, path);
      if (!existsSync(fullPath)) {
        checks.push(check("verify_evidence_digest", "evidence", "FAIL", "F_HASH_OBJECT_MISMATCH", `${path} is missing`));
        continue;
      }
      const actual = sha256Hex(readFileSync(fullPath));
      checks.push(check(
        "verify_evidence_digest",
        "evidence",
        actual === expected ? "PASS" : "FAIL",
        actual === expected ? null : "F_HASH_OBJECT_MISMATCH",
        `${path} expected ${expected}, observed ${actual}`,
      ));
    }
  }

  const artifact = records.get("ArtifactAttestation")?.predicate as Record<string, unknown> | undefined;
  if (artifact !== undefined) {
    const path = stringValue(artifact.path);
    const expected = digestValue(artifact.content_digest);
    const fullPath = scenarioRoot !== null && path !== undefined ? join(scenarioRoot, path) : null;
    const status = fullPath !== null && expected !== null && existsSync(fullPath) && sha256Hex(readFileSync(fullPath)) === expected
      ? "PASS"
      : "FAIL";
    checks.push(check(
      "verify_artifact_digest",
      "artifact",
      status,
      status === "PASS" ? null : "F_HASH_OBJECT_MISMATCH",
      path ?? "Artifact source path is unavailable",
    ));
  }

  const approvalDigest = digestValue((records.get("ApprovalAttestation")?.predicate as Record<string, unknown> | undefined)?.approved_artifact_digest);
  const artifactDigest = digestValue(artifact?.content_digest);
  const deployment = records.get("DeploymentAttestation")?.predicate as Record<string, unknown> | undefined;
  const deployedDigest = digestValue(deployment?.deployed_artifact_digest);
  const approvedDeploymentDigest = digestValue(deployment?.approved_artifact_digest);
  if (approvalDigest !== null && artifactDigest !== null) {
    checks.push(check(
      "approval_artifact_digest_match",
      "approval",
      approvalDigest === artifactDigest ? "PASS" : "FAIL",
      approvalDigest === artifactDigest ? null : "F_APPROVAL_ARTIFACT_MISMATCH",
      `approval=${approvalDigest} artifact=${artifactDigest}`,
    ));
  }
  if (deployedDigest !== null && approvedDeploymentDigest !== null) {
    checks.push(check(
      "deployment_artifact_digest_match",
      "deployment",
      deployedDigest === approvedDeploymentDigest ? "PASS" : "FAIL",
      deployedDigest === approvedDeploymentDigest ? null : "F_DEPLOYMENT_ARTIFACT_MISMATCH",
      `approved=${approvedDeploymentDigest} deployed=${deployedDigest}`,
    ));
  }
  return checks;
}

function policyReplayFromNodes(
  nodes: ReplayNode[],
  currentPolicyVersion: string | undefined,
): {
  historical_compliance: "pass" | "fail" | "not_evaluated";
  current_policy_compliance: "pass" | "fail" | "not_evaluated";
  checks: ReplayCheck[];
} {
  const records = recordsByType(nodes);
  const policy = records.get("PolicyDecisionAttestation")?.predicate as Record<string, unknown> | undefined;
  const recorded = stringValue(policy?.decision);
  const historical = complianceFromDecision(recorded);
  const historicalVersion = stringValue(policy?.policy_version);
  const recomputedHash = recomputePolicyDecisionHash(policy);
  const recordedHash = stringValue(policy?.policy_decision_hash);
  const hashMatches = recordedHash === undefined || recomputedHash === null || recordedHash === recomputedHash;
  const checks = [
    check(
      "historical_policy_decision_recompute",
      "policy",
      recorded === undefined ? "INCOMPLETE" : hashMatches ? "PASS" : "FAIL",
      recorded === undefined ? "F_POLICY_DECISION_MISSING" : hashMatches ? null : "F_POLICY_DECISION_MISMATCH",
      recomputedHash === null
        ? `recorded=${recorded ?? "unknown"} recomputed_from=signed_policy_decision_predicate`
        : `recorded=${recorded ?? "unknown"} decision_hash=${recordedHash ?? "absent"} recomputed_hash=${recomputedHash}`,
    ),
  ];
  const current = currentPolicyCompliance(historical, historicalVersion, currentPolicyVersion);
  if (currentPolicyVersion !== undefined) {
    checks.push(check(
      "current_policy_drift_classification",
      "policy",
      "PASS",
      null,
      `historical=${historicalVersion ?? "unknown"} current=${currentPolicyVersion}`,
    ));
  }
  return {
    historical_compliance: historical,
    current_policy_compliance: current,
    checks,
  };
}

function approvalChecks(nodes: ReplayNode[]): ReplayCheck[] {
  const records = recordsByType(nodes);
  const action = records.get("AgentActionAttestation")?.predicate as Record<string, unknown> | undefined;
  const approval = records.get("ApprovalAttestation")?.predicate as Record<string, unknown> | undefined;
  const deployment = records.get("DeploymentAttestation")?.predicate as Record<string, unknown> | undefined;
  if (approval === undefined) {
    return [check("approval_present", "approval", "FAIL", "F_APPROVAL_MISSING", "Approval attestation is absent")];
  }
  const checks = [
    check(
      "approval_present",
      "approval",
      "PASS",
      null,
      String(approval.approval_id ?? "approval attestation reconstructed"),
    ),
  ];
  const decision = stringValue(approval.decision);
  checks.push(check(
    "approval_decision",
    "approval",
    decision === undefined ? "INCOMPLETE" : "PASS",
    decision === undefined ? "F_APPROVAL_MISSING" : null,
    `decision=${decision ?? "unknown"}; governance validity is localized by role, SOD, and artifact checks`,
  ));
  const approver = stringValue(approval.approver_actor_id);
  const proposer = stringValue(action?.actor_id);
  checks.push(check(
    "approval_separation_of_duties",
    "approval",
    approver !== undefined && proposer !== undefined && approver !== proposer ? "PASS" : "FAIL",
    approver !== undefined && proposer !== undefined && approver !== proposer ? null : "F_APPROVAL_SOD",
    `approver=${approver ?? "unknown"} proposer=${proposer ?? "unknown"}`,
  ));
  const deploymentApprovalId = stringValue(deployment?.approval_id);
  const approvalId = stringValue(approval.approval_id);
  if (deploymentApprovalId !== undefined && approvalId !== undefined) {
    checks.push(check(
      "deployment_approval_reference",
      "approval",
      deploymentApprovalId === approvalId ? "PASS" : "FAIL",
      deploymentApprovalId === approvalId ? null : "F_APPROVAL_MISSING",
      `deployment=${deploymentApprovalId} approval=${approvalId}`,
    ));
  }
  return checks;
}

function ledgerChecks(input: {
  nodes: ReplayNode[];
  loaded: LoadedRun;
  sidecarPath: string | null;
}): { checks: ReplayCheck[]; queries: number; status: CheckStatus } {
  if (input.sidecarPath === null || !existsSync(input.sidecarPath)) {
    return {
      checks: [check("ledger_sidecar_present", "ledger", "NOT_EVALUATED", null, "Besu sidecar not present for this local replay")],
      queries: 0,
      status: "NOT_EVALUATED",
    };
  }
  const sidecar = readJson(input.sidecarPath);
  const records = recordsByType(input.nodes);
  const pairs: Array<[string, string | undefined, string | undefined]> = [
    ["observation_attestation_hash", sidecar.observation_attestation_hash as string | undefined, records.get("ObservationAttestation")?.attestation_hash as string | undefined],
    ["evidence_attestation_hash", sidecar.evidence_attestation_hash as string | undefined, records.get("EvidenceBundleAttestation")?.attestation_hash as string | undefined],
    ["policy_decision_attestation_hash", sidecar.policy_decision_attestation_hash as string | undefined, records.get("PolicyDecisionAttestation")?.attestation_hash as string | undefined],
    ["action_attestation_hash", sidecar.action_attestation_hash as string | undefined, records.get("AgentActionAttestation")?.attestation_hash as string | undefined],
    ["approval_attestation_hash", sidecar.approval_attestation_hash as string | undefined, records.get("ApprovalAttestation")?.attestation_hash as string | undefined],
    ["artifact_attestation_hash", sidecar.artifact_attestation_hash as string | undefined, records.get("ArtifactAttestation")?.attestation_hash as string | undefined],
    ["deployment_attestation_hash", sidecar.deployment_attestation_hash as string | undefined, records.get("DeploymentAttestation")?.attestation_hash as string | undefined],
  ];
  const checks = [
    check(
      "ledger_readback",
      "ledger",
      sidecar.readback_ok === true ? "PASS" : "FAIL",
      sidecar.readback_ok === true ? null : "F_LEDGER_ANCHOR_MISSING",
      `readback_ok=${String(sidecar.readback_ok)}`,
    ),
    ...pairs.map(([name, observed, expected]) => check(
      `ledger_${name}`,
      "ledger",
      observed === expected ? "PASS" : "FAIL",
      observed === expected ? null : "F_LEDGER_EVENT_MISMATCH",
      `observed=${observed ?? "missing"} expected=${expected ?? "missing"}`,
    )),
  ];
  return {
    checks,
    queries: checks.length,
    status: checks.every((item) => item.status === "PASS") ? "PASS" : "FAIL",
  };
}

function recordsByType(nodes: ReplayNode[]): Map<string, Record<string, unknown>> {
  const map = new Map<string, Record<string, unknown>>();
  for (const node of nodes) {
    map.set(node.attestation_type, readJson(nodePathFromNode(node)));
  }
  return map;
}

function nodePathFromNode(node: ReplayNode): string {
  const root = findRunRootFromPath(node.path);
  return root === null ? node.path : resolveInsideRun(root, node.path);
}

function findRunRootFromPath(_path: string): string | null {
  return currentRunRoot;
}

let currentRunRoot: string | null = null;

function reconstructedLinks(nodes: ReplayNode[], ledgerOk: boolean): Record<string, boolean> {
  const types = new Set(nodes.map((node) => node.attestation_type));
  return {
    observation: types.has("ObservationAttestation"),
    evidence: types.has("EvidenceBundleAttestation"),
    policy_version: types.has("PolicyDecisionAttestation"),
    policy_decision: types.has("PolicyDecisionAttestation"),
    action_proposal: types.has("AgentActionAttestation"),
    approval_chain: types.has("ApprovalAttestation"),
    artifact: types.has("ArtifactAttestation"),
    deployment: types.has("DeploymentAttestation"),
    ledger_anchor: ledgerOk,
  };
}

function inferScenarioRoot(runRoot: string, scenarioId: string | null): string | null {
  if (scenarioId === null) {
    return null;
  }
  const packageRoot = resolve(runRoot, "..", "..", "..");
  const candidate = join(packageRoot, "examples", "scenarios", scenarioId);
  return existsSync(candidate) ? candidate : null;
}

function inferLedgerSidecar(runRoot: string, scenarioId: string | null): string | null {
  if (scenarioId === null) {
    return null;
  }
  const packageRoot = resolve(runRoot, "..", "..", "..");
  const candidate = join(packageRoot, "runs", "besu-dev", "scenarios", scenarioId, "govreplay_besu.json");
  return existsSync(candidate) ? candidate : null;
}

function readJson(path: string): Record<string, unknown> {
  const value = JSON.parse(readFileSync(path, "utf8"));
  if (!isRecord(value)) {
    throw new TypeError(`Expected JSON object: ${path}`);
  }
  return value;
}

function subjectName(record: Record<string, unknown>): string | null {
  const subject = record.subject;
  if (!Array.isArray(subject) || !isRecord(subject[0])) {
    return null;
  }
  return stringValue(subject[0].name) ?? null;
}

function predicateString(record: Record<string, unknown> | undefined, field: string): string | undefined {
  if (record === undefined || !isRecord(record.predicate)) {
    return undefined;
  }
  return stringValue(record.predicate[field]);
}

function digestValue(value: unknown): string | null {
  return isRecord(value) && typeof value.value === "string" ? value.value : null;
}

function check(name: string, stage: string, status: CheckStatus, code: string | null, detail: string): ReplayCheck {
  return { name, stage, status, code, detail };
}

function complianceFromDecision(value: unknown): "pass" | "fail" | "not_evaluated" {
  if (value === "allow") {
    return "pass";
  }
  if (value === "deny") {
    return "fail";
  }
  return "not_evaluated";
}

function currentPolicyCompliance(
  historical: "pass" | "fail" | "not_evaluated",
  historicalVersion: string | undefined,
  currentPolicyVersion: string | undefined,
): "pass" | "fail" | "not_evaluated" {
  if (currentPolicyVersion === undefined || historical === "not_evaluated") {
    return "not_evaluated";
  }
  if (historical === "fail") {
    return "fail";
  }
  return historicalVersion === currentPolicyVersion ? "pass" : "fail";
}

function recomputePolicyDecisionHash(policy: Record<string, unknown> | undefined): string | null {
  if (policy === undefined) {
    return null;
  }
  const policyBundleHash = stringValue(policy.policy_bundle_hash);
  const policyBundleVersion = stringValue(policy.policy_bundle_version);
  const policyInputHash = stringValue(policy.policy_input_hash);
  const decision = stringValue(policy.decision);
  const obligationsHash = stringValue(policy.obligations_hash);
  const evaluatorIdentity = stringValue(policy.evaluator_identity);
  const evaluatorVersion = stringValue(policy.evaluator_version);
  if (
    policyBundleHash === undefined
    || policyBundleVersion === undefined
    || policyInputHash === undefined
    || decision === undefined
    || obligationsHash === undefined
    || evaluatorIdentity === undefined
    || evaluatorVersion === undefined
  ) {
    return null;
  }
  return sha256Hex(JSON.stringify({
    schema_version: "govprov.policy_evaluation.v1",
    policy_bundle_hash: policyBundleHash,
    policy_bundle_version: policyBundleVersion,
    policy_input_hash: policyInputHash,
    decision,
    obligations_hash: obligationsHash,
    evaluator_identity: evaluatorIdentity,
    evaluator_version: evaluatorVersion,
    matched_policy_ids: arrayOfStrings(policy.matched_policy_ids),
  }));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function arrayOfStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function setCurrentRunRootForTest(runRoot: string): void {
  currentRunRoot = runRoot;
}

export function prepareReplayRunRoot(runRoot: string): void {
  currentRunRoot = resolve(runRoot);
}
