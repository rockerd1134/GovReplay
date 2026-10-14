import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parseExperimentConfig } from "../src/config.ts";
import { ALL_FAULT_IDS, type WorkloadInstance } from "../src/model.ts";
import { reproductionMetadata, runExperiment } from "../src/runner.ts";
import { buildSeglLog, seglEventHash, verifySeglWorkflow, type SeglEvent, type SeglVerificationResult } from "../src/segl.ts";
import { ARPE_PROPERTIES, loadArpeTaxonomy } from "../src/taxonomy.ts";
import { generateWorkload, groundTruthFor } from "../src/workload.ts";

const packageRoot = join(import.meta.dirname, "..");

test("P7-S1 parses debug config and creates standard run layout", async () => {
  const config = parseExperimentConfig(join(packageRoot, "configs", "debug.json"));
  const tempRoot = mkdtempSync(join(tmpdir(), "govprov-p7-"));
  const result = await runExperiment({ ...config, run_id: "test-debug" }, { packageRoot: tempRoot });

  assert.equal(result.workload.length, 60);
  assert.ok(existsSync(join(result.runRoot, "manifest.json")));
  assert.ok(existsSync(join(result.runRoot, "config.json")));
  assert.ok(existsSync(join(result.runRoot, "inputs", "workload.jsonl")));
  assert.ok(existsSync(join(result.runRoot, "inputs", "scenario.json")));
  assert.ok(existsSync(join(result.runRoot, "inputs", "arpe_test_classes.json")));
  assert.ok(existsSync(join(result.runRoot, "inputs", "ground_truth.json")));
  assert.ok(existsSync(join(result.runRoot, "inputs", "ground_truth.jsonl")));
  assert.ok(existsSync(join(result.runRoot, "inputs", "hard_fault_catalog.json")));
  assert.ok(existsSync(join(result.runRoot, "audit", "replay_inputs.json")));
  assert.ok(existsSync(join(result.runRoot, "audit", "replay_inputs.jsonl")));
  assert.ok(existsSync(join(result.runRoot, "faults", "fault_injection.json")));
  assert.ok(existsSync(join(result.runRoot, "audit", "replay_report.json")));
  assert.ok(existsSync(join(result.runRoot, "audit", "audit_results.jsonl")));
  assert.ok(existsSync(join(result.runRoot, "baseline_logs", "signed_merkle_log.jsonl")));
  assert.ok(existsSync(join(result.runRoot, "baseline_logs", "signed_merkle_manifest.json")));
  assert.ok(existsSync(join(result.runRoot, "baseline_logs", "segl_events.jsonl")));
  assert.ok(existsSync(join(result.runRoot, "baseline_logs", "segl_manifest.json")));
  assert.ok(existsSync(join(result.runRoot, "ledger", "hash_only_anchors.jsonl")));
  assert.ok(existsSync(join(result.runRoot, "ledger", "hash_only_anchor_manifest.json")));
  assert.ok(existsSync(join(result.runRoot, "results", "metrics.json")));
  assert.ok(existsSync(join(result.runRoot, "results", "metrics_summary.json")));
  assert.ok(existsSync(join(result.runRoot, "results", "scored_metric_rows.jsonl")));
  assert.ok(existsSync(join(result.runRoot, "results", "reproducibility_summary.json")));
  assert.ok(existsSync(join(result.runRoot, "results", "matrix_summary.json")));
  assert.ok(existsSync(join(result.runRoot, "results", "matrix_summary.csv")));
  assert.ok(existsSync(join(result.runRoot, "results", "fault_detection_boundaries.csv")));
  assert.ok(existsSync(join(result.runRoot, "results", "hard_fault_detection_boundaries.csv")));
  assert.ok(existsSync(join(result.runRoot, "results", "per_fault_oracle_agreement.csv")));
  assert.ok(existsSync(join(result.runRoot, "results", "metrics_by_test_class.csv")));
  assert.ok(existsSync(join(result.runRoot, "results", "metrics_by_arpe_element.csv")));
  assert.ok(existsSync(join(result.runRoot, "results", "metrics_by_external_tradition.csv")));
  assert.ok(existsSync(join(result.runRoot, "results", "metrics_by_required_state.csv")));
  assert.ok(existsSync(join(result.runRoot, "results", "metrics_by_governance_domain.csv")));
  assert.ok(existsSync(join(result.runRoot, "results", "metrics_by_governance_domain_and_config.csv")));
  assert.ok(existsSync(join(result.runRoot, "results", "gas_usage.csv")));
  assert.ok(existsSync(join(result.runRoot, "results", "gas_summary.csv")));
  assert.ok(existsSync(join(result.runRoot, "results", "gas_summary_by_scenario.csv")));
  assert.ok(existsSync(join(result.runRoot, "telemetry", "ledger_metrics.jsonl")));
  assert.ok(existsSync(join(result.runRoot, "paper", "table_fault_detection.md")));
  assert.ok(existsSync(join(result.runRoot, "paper", "table_per_fault_oracle_agreement.md")));
  assert.ok(existsSync(join(result.runRoot, "paper", "table_fault_detection_boundaries.md")));
  assert.ok(existsSync(join(result.runRoot, "paper", "table_hard_fault_boundaries.md")));
  assert.ok(existsSync(join(result.runRoot, "paper", "table_arpe_test_classes.md")));
  assert.ok(existsSync(join(result.runRoot, "paper", "table_arpe_test_class_mapping.md")));
  assert.ok(existsSync(join(result.runRoot, "paper", "table_arpe_external_traditions.md")));
  assert.ok(existsSync(join(result.runRoot, "paper", "table_governance_domain_mapping.md")));
  const groundTruth = JSON.parse(readFileSync(join(result.runRoot, "inputs", "ground_truth.json"), "utf8"));
  const replayInputs = JSON.parse(readFileSync(join(result.runRoot, "audit", "replay_inputs.json"), "utf8"));
  const replayReport = JSON.parse(readFileSync(join(result.runRoot, "audit", "replay_report.json"), "utf8"));
  const metrics = JSON.parse(readFileSync(join(result.runRoot, "results", "metrics.json"), "utf8"));
  assert.equal(groundTruth.schema_version, "govprov.ground_truth_set.v1");
  assert.equal(replayInputs.schema_version, "govprov.replay_input_set.v1");
  assert.equal(replayReport.schema_version, "govprov.audit_replay_report_set.v1");
  assert.equal(metrics.schema_version, "govprov.metrics_audit_bundle.v1");
  assert.equal(groundTruth.record_count, 60);
  assert.equal(replayInputs.record_count, 60);
  assert.equal(replayReport.record_count, 60);
  assert.equal(metrics.separation_boundary.includes("replay_id"), true);
  const replayInputText = JSON.stringify(replayInputs);
  assert.equal(replayInputText.includes("fault_id"), false);
  assert.equal(replayInputText.includes("expected_verdict"), false);
  assert.equal(replayInputText.includes("expected_failure_stage"), false);
  assert.equal(replayInputText.includes("expected_failure_code"), false);
  assert.equal(replayInputText.includes("expected_policy_drift_class"), false);
  assert.equal(replayReport.records.every((record: Record<string, unknown>) => typeof record.replay_id === "string"), true);
  assert.equal(replayReport.records.every((record: Record<string, unknown>) => typeof record.verifier_source === "string"), true);
  assert.equal(replayReport.records.every((record: Record<string, unknown>) => typeof record.replay_backend === "string"), true);
  assert.equal(replayReport.records.some((record: Record<string, unknown>) => "fault_id" in record), false);
  assert.equal(JSON.stringify(replayReport).includes("expected="), false);
  assert.equal(readFileSync(join(result.runRoot, "results", "scored_metric_rows.jsonl"), "utf8").trim().split("\n").length, 60);
});

test("P12-S2 ARPE taxonomy maps every configured fault exactly once and covers all ARPE properties", () => {
  const taxonomy = loadArpeTaxonomy();
  for (const faultId of ALL_FAULT_IDS) {
    const matches = taxonomy.test_classes.filter((testClass) => testClass.fault_ids.includes(faultId));
    assert.equal(matches.length, 1, `${faultId} should map to exactly one ARPE test class`);
  }
  for (const property of ARPE_PROPERTIES) {
    assert.ok(taxonomy.test_classes.some((testClass) => testClass.arpe_property === property), `${property} should be covered`);
  }
  assert.ok(taxonomy.positioning_boundary.includes("not standards-compliance claims"));
  assert.ok(taxonomy.non_claims.some((claim) => claim.includes("not SLSA-compliant")));
  assert.ok(taxonomy.non_claims.some((claim) => claim.includes("not in-toto-compliant")));
});

test("P7-S2 workload and ground truth cover policy drift and faults", () => {
  const config = parseExperimentConfig(join(packageRoot, "configs", "minimum.json"));
  const workload = generateWorkload(config);
  assert.equal(workload.length, 2700);
  const drift = groundTruthFor(workload.find((item) => item.fault_id === "F0" && item.policy_version === "policy:v1")!, config.current_policy_version);
  assert.equal(drift.expected_policy_drift_class, "pass_current_fail");
  const approval = groundTruthFor(workload.find((item) => item.fault_id === "F8")!, config.current_policy_version);
  assert.equal(approval.expected_failure_code, "separation_of_duties_violation");
  assert.equal(approval.test_class_id, "TC-APPROVAL-SEPARATION");
  assert.equal(approval.arpe_property, "approval authority and separation of duties");
  assert.equal(approval.expected_stage, "approval");
  assert.equal(approval.requires_ledger_state, false);
});

test("P12-S3 generated ground-truth and fault records include taxonomy metadata", async () => {
  const config = parseExperimentConfig(join(packageRoot, "configs", "arpe_hard_debug.json"));
  const tempRoot = mkdtempSync(join(tmpdir(), "govprov-p12-s3-"));
  const result = await runExperiment(config, { packageRoot: tempRoot });
  const groundTruth = JSON.parse(readFileSync(join(result.runRoot, "inputs", "ground_truth.json"), "utf8"));
  const faultInjection = JSON.parse(readFileSync(join(result.runRoot, "faults", "fault_injection.json"), "utf8"));
  const h1Truth = groundTruth.records.find((item: { fault_id: string }) => item.fault_id === "H1");
  assert.equal(h1Truth.test_class_id, "TC-ACTOR-AUTHORITY");
  assert.equal(h1Truth.external_tradition.includes("delegated-functionary"), true);
  assert.equal(h1Truth.arpe_property, "approval authority and separation of duties");
  assert.equal(h1Truth.expected_stage, "identity");
  assert.equal(h1Truth.requires_ledger_state, true);
  assert.equal(h1Truth.ledger_state_requirement, "ledger_backed_governance_state");
  assert.equal(h1Truth.governance_domain, "identity_domain");
  assert.equal(h1Truth.expected_domain, "identity_domain");
  assert.equal(h1Truth.domain_fault, true);
  const h8Fault = faultInjection.records.find((item: { fault_id: string }) => item.fault_id === "H8");
  assert.equal(h8Fault.test_class_id, "TC-GOVERNANCE-STATE-REPLAY");
  assert.equal(h8Fault.arpe_property, "ledger-backed governance-state replay");
  assert.equal(h8Fault.expected_stage, "contract_governance");
  assert.equal(h8Fault.requires_ledger_state, true);
  assert.equal(h8Fault.ledger_state_requirement, "ledger_backed_governance_state");
  assert.equal(h8Fault.governance_domain, "contract_domain");
  assert.deepEqual(h8Fault.cross_domain_dependency, ["identity_domain", "policy_domain", "approval_domain", "deployment_domain", "anchor_domain"]);
});

test("P12-S4 taxonomy metrics exports reconcile to matrix totals", async () => {
  const config = parseExperimentConfig(join(packageRoot, "configs", "arpe_hard_debug.json"));
  const tempRoot = mkdtempSync(join(tmpdir(), "govprov-p12-s4-"));
  const result = await runExperiment(config, { packageRoot: tempRoot });
  const metrics = JSON.parse(readFileSync(join(result.runRoot, "results", "metrics.json"), "utf8"));
  const summary = JSON.parse(readFileSync(join(result.runRoot, "results", "metrics_summary.json"), "utf8"));

  assert.equal(sumWorkflowCount(metrics.by_test_class), summary.workflow_count);
  assert.equal(sumWorkflowCount(metrics.by_arpe_element), summary.workflow_count);
  assert.equal(sumWorkflowCount(metrics.by_external_tradition), summary.workflow_count);
  assert.equal(sumWorkflowCount(metrics.by_required_state), summary.workflow_count);
  assert.equal(sumWorkflowCount(metrics.by_governance_domain), summary.workflow_count);
  assert.equal(sumWorkflowCount(metrics.by_governance_domain_and_config), summary.workflow_count);
  assert.equal(metrics.by_required_state.some((row: { group: string; false_negative_count: number }) => row.group === "ledger_backed_governance_state" && row.false_negative_count > 0), true);

  const classCsv = readFileSync(join(result.runRoot, "results", "metrics_by_test_class.csv"), "utf8");
  assert.ok(classCsv.startsWith("group,system_configuration,workflow_count,injected_fault_count,true_positive_count,true_negative_count,false_positive_count,false_negative_count"));
  assert.ok(classCsv.includes("TC-GOVERNANCE-STATE-REPLAY,baseline_signed_merkle_log"));
  assert.ok(classCsv.includes("TC-GOVERNANCE-STATE-REPLAY,SEGL"));
  const arpeElementCsv = readFileSync(join(result.runRoot, "results", "metrics_by_arpe_element.csv"), "utf8");
  assert.ok(arpeElementCsv.includes("ledger-backed governance-state replay,baseline_signed_merkle_log"));
  const requiredStateCsv = readFileSync(join(result.runRoot, "results", "metrics_by_required_state.csv"), "utf8");
  assert.ok(requiredStateCsv.includes("ledger_backed_governance_state,baseline_signed_merkle_log"));
  const governanceDomainCsv = readFileSync(join(result.runRoot, "results", "metrics_by_governance_domain.csv"), "utf8");
  assert.ok(governanceDomainCsv.includes("identity_domain"));
  const governanceDomainConfigCsv = readFileSync(join(result.runRoot, "results", "metrics_by_governance_domain_and_config.csv"), "utf8");
  assert.ok(governanceDomainConfigCsv.includes("contract_domain,baseline_signed_merkle_log"));
  const traditionTable = readFileSync(join(result.runRoot, "paper", "table_arpe_test_classes.md"), "utf8");
  assert.ok(traditionTable.includes("author-defined synthetic audit-replay evaluation"));
  assert.ok(traditionTable.includes("TC-GOVERNANCE-STATE-REPLAY"));
  const mappingTable = readFileSync(join(result.runRoot, "paper", "table_arpe_test_class_mapping.md"), "utf8");
  assert.ok(mappingTable.includes("ledger_backed_governance_state"));
  assert.ok(mappingTable.includes("TC-GOVERNANCE-STATE-REPLAY"));
  const externalTraditionsTable = readFileSync(join(result.runRoot, "paper", "table_arpe_external_traditions.md"), "utf8");
  assert.ok(externalTraditionsTable.includes("without asserting conformance"));
  const governanceDomainTable = readFileSync(join(result.runRoot, "paper", "table_governance_domain_mapping.md"), "utf8");
  assert.ok(governanceDomainTable.includes("one organizational governance environment"));
  assert.ok(governanceDomainTable.includes("contract_domain"));
  assertGeneratedTableAvoidsComplianceClaims(mappingTable);
  assertGeneratedTableAvoidsComplianceClaims(externalTraditionsTable);
});

test("P7-S3 through P11-S2 emit baselines, ablation, full reports, metrics, and paper exports", async () => {
  const config = parseExperimentConfig(join(packageRoot, "configs", "debug.json"));
  const tempRoot = mkdtempSync(join(tmpdir(), "govprov-p7-"));
  const result = await runExperiment({ ...config, run_id: "test-outputs" }, { packageRoot: tempRoot });
  const auditLines = readFileSync(join(result.runRoot, "audit", "audit_results.jsonl"), "utf8").trim().split("\n");
  assert.equal(auditLines.length, 60);
  assert.ok(auditLines.some((line) => line.includes("\"system_configuration\":\"baseline_structured_logs\"")));
  assert.ok(auditLines.some((line) => line.includes("\"system_configuration\":\"baseline_signed_merkle_log\"")));
  assert.ok(auditLines.some((line) => line.includes("\"system_configuration\":\"govreplay_offchain_only\"")));
  assert.ok(auditLines.some((line) => line.includes("\"system_configuration\":\"SEGL\"")));
  assert.ok(auditLines.some((line) => line.includes("\"system_configuration\":\"govreplay_besu\"")));
  const merkleEvents = readFileSync(join(result.runRoot, "baseline_logs", "signed_merkle_log.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(merkleEvents.length, 72);
  assert.equal(merkleEvents[0].schema_version, "govprov.baseline_signed_merkle_event.v1");
  assert.equal(merkleEvents[0].previous_event_hash, null);
  assert.equal(merkleEvents[1].previous_event_hash, merkleEvents[0].attestation_hash);
  assert.equal(merkleEvents[0].signature.profile, "govprov-ethsign-secp256k1-v1");
  assert.ok(merkleEvents.some((event) => event.lifecycle.artifact_hash !== null));
  assert.ok(merkleEvents.some((event) => event.lifecycle.approval_reference !== null));
  const merkleManifest = JSON.parse(readFileSync(join(result.runRoot, "baseline_logs", "signed_merkle_manifest.json"), "utf8"));
  assert.equal(merkleManifest.baseline, "baseline_signed_merkle_log");
  assert.equal(merkleManifest.event_count, 72);
  assert.equal(merkleManifest.governance_state_boundary.uses_besu, false);
  assert.equal(merkleManifest.governance_state_boundary.policy_registry, false);
  const seglEvents = readFileSync(join(result.runRoot, "baseline_logs", "segl_events.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(seglEvents.length, 104);
  assert.equal(seglEvents[0].schema_version, "govprov.segl.event.v1");
  assert.equal(seglEvents[0].system_configuration, undefined);
  assert.equal(seglEvents[0].prev_event_hash, null);
  assert.equal(seglEvents[1].prev_event_hash, seglEvents[0].event_hash);
  assert.equal(seglEvents[0].signature.profile, "govprov-ethsign-secp256k1-v1");
  assert.ok(seglEvents.some((event) => event.event_type === "policy_activated"));
  assert.ok(seglEvents.some((event) => event.event_type === "approval_recorded"));
  assert.ok(seglEvents.some((event) => event.event_type === "anchor_recorded"));
  const seglManifest = JSON.parse(readFileSync(join(result.runRoot, "baseline_logs", "segl_manifest.json"), "utf8"));
  assert.equal(seglManifest.system_configuration, "SEGL");
  assert.equal(seglManifest.event_count, 104);
  assert.equal(seglManifest.state_equivalence.policy_activation_history, true);
  assert.equal(seglManifest.state_equivalence.uses_besu, false);
  const hashOnlyManifest = JSON.parse(readFileSync(join(result.runRoot, "ledger", "hash_only_anchor_manifest.json"), "utf8"));
  assert.equal(hashOnlyManifest.baseline, "baseline_hash_only_ledger");
  assert.equal(hashOnlyManifest.anchor_count, 0);
  assert.ok(readFileSync(join(result.runRoot, "results", "paper_tables.md"), "utf8").includes("Violation Detection"));
  assert.ok(existsSync(join(result.runRoot, "paper", "figures", "figure_reconstruction_by_config.csv")));
});

test("PX-S27 SEGL verifies signed event-source integrity and adversarial mutations", () => {
  const instance = seglInstance("F0");
  const { events } = buildSeglLog([instance]);
  assert.equal(verifySeglWorkflow(events, seglReference(instance)).ok, true);

  const tamperedPayload = cloneEvents(events);
  tamperedPayload[3].payload.evidence_hash = "sha256:tampered";
  assertHasIssue(verifySeglWorkflow(tamperedPayload, seglReference(instance)), "event_hash_mismatch");

  const badSignature = cloneEvents(events);
  badSignature[0].signature.signature = "0x00".padEnd(132, "0");
  assertHasIssue(verifySeglWorkflow(badSignature, seglReference(instance)), "invalid_signature");

  const removedRole = cloneEvents(events).filter((event) => event.event_type !== "actor_role_assigned");
  assertHasIssue(verifySeglWorkflow(removedRole, seglReference(instance)), "missing_role_assignment_event");

  const removedPolicy = cloneEvents(events).filter((event) => event.event_type !== "policy_activated");
  assertHasIssue(verifySeglWorkflow(removedPolicy, seglReference(instance)), "missing_policy_activation_event");

  const removedApproval = cloneEvents(events).filter((event) => event.event_type !== "approval_recorded");
  assertHasIssue(verifySeglWorkflow(removedApproval, seglReference(instance)), "missing_approval_event");

  const reordered = cloneEvents(events);
  [reordered[1], reordered[2]] = [reordered[2], reordered[1]];
  assertHasIssue(verifySeglWorkflow(reordered, seglReference(instance)), "missing_or_reordered_event");

  const brokenChain = cloneEvents(events);
  brokenChain[1].prev_event_hash = "0x".padEnd(66, "0");
  assertHasIssue(verifySeglWorkflow(brokenChain, seglReference(instance)), "broken_hash_chain");

  const conflictingSequence = cloneEvents(events);
  conflictingSequence.push({ ...structuredClone(conflictingSequence[1]), event_id: "segl:conflicting", event_hash: seglEventHash({ ...conflictingSequence[1], event_id: "segl:conflicting" }) });
  assertHasIssue(verifySeglWorkflow(conflictingSequence, seglReference(instance)), "conflicting_sequence");

  assertHasIssue(verifySeglWorkflowFor(seglInstance("F8")), "separation_of_duties_violation");
  assertHasIssue(verifySeglWorkflowFor(seglInstance("F10")), "artifact_deployment_mismatch");
  assertHasIssue(verifySeglWorkflowFor(seglInstance("F12")), "anchor_mismatch");
  assertHasIssue(verifySeglWorkflowFor(seglInstance("H1")), "stale_actor_role_state");
  assertHasIssue(verifySeglWorkflowFor(seglInstance("H2")), "policy_changed_between_decision_and_deployment");
  assertHasIssue(verifySeglWorkflowFor(seglInstance("H3")), "conflicting_policy_activation");
  assertHasIssue(verifySeglWorkflowFor(seglInstance("H4")), "anchor_mismatch");
  assertHasIssue(verifySeglWorkflowFor(seglInstance("H5")), "ledger_approval_offchain_omission");
  assertHasIssue(verifySeglWorkflowFor(seglInstance("H6")), "deployment_scope_mismatch");
  assertHasIssue(verifySeglWorkflowFor(seglInstance("H7")), "stale_actor_role_state");
  assertHasIssue(verifySeglWorkflowFor(seglInstance("H8")), "contract_directory_mismatch");
});

test("PX-S37 SEGL verifier ignores generator fault labels after event generation", () => {
  const faulted = seglInstance("H2");
  const relabeled = { ...faulted, fault_id: "F0" as const };
  const { events } = buildSeglLog([faulted]);
  const fromFaultedReference = verifySeglWorkflow(events, seglReference(faulted));
  const fromRelabeledReference = verifySeglWorkflow(events, seglReference(relabeled));

  assert.deepEqual(issueCodes(fromFaultedReference), issueCodes(fromRelabeledReference));
  assertHasIssue(fromRelabeledReference, "policy_changed_between_decision_and_deployment");
});

test("PX-S13 emits per-transaction gas rows and operation summaries", async () => {
  const config = parseExperimentConfig(join(packageRoot, "configs", "arpe_hash_only_ablation_debug.json"));
  const tempRoot = mkdtempSync(join(tmpdir(), "govprov-px-s13-"));
  const result = await runExperiment(config, { packageRoot: tempRoot });

  const usage = readFileSync(join(result.runRoot, "results", "gas_usage.csv"), "utf8").trim().split("\n");
  assert.equal(
    usage[0],
    "run_id,scenario,operation,domain_id,contract_name,tx_hash,block_number,gas_used,effective_gas_price,configured_gas_price,status,latency_ms,timestamp",
  );
  assert.ok(usage.some((line) => line.includes(",anchor_action_proposal,govreplay:domain:anchor_domain,ProvenanceRegistry,")));
  assert.ok(usage.some((line) => line.includes(",record_approval,govreplay:domain:approval_domain,ApprovalRegistry,")));
  assert.ok(usage.some((line) => line.includes(",record_deployment,govreplay:domain:deployment_domain,DeploymentRegistry,")));
  assert.ok(usage.some((line) => line.includes(",anchor_workflow_root,govreplay:domain:anchor_domain,HashOnlyAnchor,")));
  assert.ok(usage.every((line, index) => index === 0 || line.includes(",0,0,success,")));

  const summary = readFileSync(join(result.runRoot, "results", "gas_summary.csv"), "utf8");
  assert.ok(summary.includes("operation,count,min_gas,median_gas,mean_gas,max_gas,total_gas"));
  assert.ok(summary.includes("record_deployment,"));
  const scenarioSummary = readFileSync(join(result.runRoot, "results", "gas_summary_by_scenario.csv"), "utf8");
  assert.ok(scenarioSummary.startsWith("scenario,operation,count,min_gas,median_gas,mean_gas,max_gas,total_gas"));

  const metrics = JSON.parse(readFileSync(join(result.runRoot, "results", "metrics.json"), "utf8"));
  assert.ok(metrics.gas_summary.some((row: { operation: string; total_gas: number }) => row.operation === "record_deployment" && row.total_gas > 0));
});

test("P11-S2 minimum matrix path represents 4x4x3x9x5 workflow executions", async () => {
  const config = parseExperimentConfig(join(packageRoot, "configs", "arpe_basic_matrix.json"));
  assert.equal(config.matrix, "arpe_basic_matrix");
  const tempRoot = mkdtempSync(join(tmpdir(), "govprov-p7-"));
  const result = await runExperiment({ ...config, run_id: "test-minimum" }, { packageRoot: tempRoot });
  assert.equal(result.workload.length, 2700);
  const summary = JSON.parse(readFileSync(join(result.runRoot, "results", "metrics_summary.json"), "utf8"));
  assert.equal(summary.workflow_count, 2700);
  assert.equal(summary.configurations.length, 5);
  const signedMerkle = summary.configurations.find((item: { configuration: string }) => item.configuration === "baseline_signed_merkle_log");
  const segl = summary.configurations.find((item: { configuration: string }) => item.configuration === "SEGL");
  const besu = summary.configurations.find((item: { configuration: string }) => item.configuration === "govreplay_besu");
  assert.equal(signedMerkle.recall, 0.875);
  assert.equal(signedMerkle.f1, (2 * 840) / ((2 * 840) + 0 + 120));
  assert.equal(segl.recall, 1);
  assert.equal(segl.precision, 1);
  assert.equal(segl.f1, 1);
  assert.equal(segl.transactions_per_workflow, 0);
  assert.equal(besu.recall, 1);
  assert.equal(besu.precision, 1);
  assert.equal(besu.f1, 1);
  const boundaryCsv = readFileSync(join(result.runRoot, "results", "fault_detection_boundaries.csv"), "utf8");
  assert.ok(boundaryCsv.startsWith("fault_id,fault_family,logs_detected,signed_merkle_detected,offchain_detected,segl_detected,hash_only_ledger_detected,besu_detected,expected_best_config,reason_ledger_matters,precision,recall,localization_accuracy"));
  assert.ok(boundaryCsv.includes("F12,basic_lifecycle,false,false,false,true,false,true,SEGL_or_baseline_hash_only_ledger_or_stronger"));
  const policyDriftTable = readFileSync(join(result.runRoot, "paper", "table_policy_drift.md"), "utf8");
  assert.ok(policyDriftTable.includes("| latest policy replay | 540 | 300 | 0.556 | baseline_structured_logs |"));
  assert.ok(policyDriftTable.includes("| latest policy replay | 540 | 480 | 0.889 | baseline_signed_merkle_log |"));
  assert.ok(policyDriftTable.includes("| latest policy replay | 540 | 480 | 0.889 | govreplay_offchain_only |"));
  assert.ok(policyDriftTable.includes("| latest policy replay | 540 | 540 | 1 | govreplay_besu |"));
  const oracleCsv = readFileSync(join(result.runRoot, "results", "per_fault_oracle_agreement.csv"), "utf8");
  assert.ok(oracleCsv.startsWith("fault_type,system_configuration,expected_failure_code,expected_failure_stage,injected_count,detected,missed,false_positive_count,false_negative_count"));
  assert.ok(oracleCsv.includes("F12,govreplay_besu,anchor_mismatch,ledger,60,60,0,0,0"));
  assert.ok(oracleCsv.includes("F12,baseline_signed_merkle_log,anchor_mismatch,ledger,60,0,60,0,60"));
  const oracleTable = readFileSync(join(result.runRoot, "paper", "table_per_fault_oracle_agreement.md"), "utf8");
  assert.ok(oracleTable.includes("Expected outcomes are generated before replay"));
});

test("P11-S3 hard matrix covers H-series governance-state faults with independent labels", async () => {
  const config = parseExperimentConfig(join(packageRoot, "configs", "arpe_hard_debug.json"));
  const workload = generateWorkload(config);
  assert.equal(workload.length, 580);
  assert.equal(workload.filter((item) => item.fault_id === "H6").length, 40);
  assert.equal(workload.some((item) => item.fault_id === "H6" && item.scenario_id === "S1_runbook_update"), false);

  const tempRoot = mkdtempSync(join(tmpdir(), "govprov-p11-"));
  const result = await runExperiment({ ...config, run_id: "test-hard" }, { packageRoot: tempRoot });
  assert.equal(result.groundTruth.length, 580);
  const hardTruth = result.groundTruth.find((item) => item.fault_id === "H8")!;
  assert.equal(hardTruth.expected_failure_stage, "contract_governance");
  assert.equal(hardTruth.expected_failure_code, "contract_directory_mismatch");

  const catalog = JSON.parse(readFileSync(join(result.runRoot, "inputs", "hard_fault_catalog.json"), "utf8"));
  assert.equal(catalog.schema_version, "govprov.hard_fault_catalog.v1");
  assert.deepEqual(catalog.selected_fault_ids, ["H1", "H2", "H3", "H4", "H5", "H6", "H7", "H8"]);
  assert.deepEqual(catalog.deterministic_seeds, [11, 12]);

  const auditRows = readFileSync(join(result.runRoot, "audit", "audit_results.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const h1Besu = auditRows.find((item) => item.fault_id === undefined && item.workflow_id.includes("H1") && item.system_configuration === "govreplay_besu");
  assert.equal(h1Besu.verdict, "FAIL");
  assert.equal(h1Besu.failure_code, "role_revoked_before_deployment");
  const h1Merkle = auditRows.find((item) => item.workflow_id.includes("H1") && item.system_configuration === "baseline_signed_merkle_log");
  assert.equal(h1Merkle.verdict, "PASS");

  const h1Segl = auditRows.find((item) => item.workflow_id.includes("H1") && item.system_configuration === "SEGL");
  assert.equal(h1Segl.verdict, "FAIL");
  assert.equal(h1Segl.failure_code, "role_revoked_before_deployment");

  const boundaryCsv = readFileSync(join(result.runRoot, "results", "hard_fault_detection_boundaries.csv"), "utf8");
  assert.ok(boundaryCsv.startsWith("fault_id,fault_family,logs_detected,signed_merkle_detected,offchain_detected,segl_detected,hash_only_ledger_detected,besu_detected,expected_best_config,reason_ledger_matters,precision,recall,localization_accuracy"));
  assert.ok(boundaryCsv.includes("H8,contract_directory,false,false,false,true,false,true,SEGL_or_govreplay_besu"));
  assert.ok(boundaryCsv.includes("Requires contract-directory history"));
  const policyDriftTable = readFileSync(join(result.runRoot, "paper", "table_policy_drift.md"), "utf8");
  assert.ok(policyDriftTable.includes("| latest policy replay | 116 | 16 | 0.138 | baseline_structured_logs |"));
  assert.ok(policyDriftTable.includes("| latest policy replay | 116 | 16 | 0.138 | baseline_signed_merkle_log |"));
  assert.ok(policyDriftTable.includes("| latest policy replay | 116 | 16 | 0.138 | govreplay_offchain_only |"));
  assert.ok(policyDriftTable.includes("| latest policy replay | 116 | 116 | 1 | govreplay_besu |"));
});

test("P11-S4 named debug matrices produce separate run directories and summaries", async () => {
  const basicConfig = parseExperimentConfig(join(packageRoot, "configs", "arpe_basic_debug.json"));
  const hardConfig = parseExperimentConfig(join(packageRoot, "configs", "arpe_hard_debug.json"));
  const tempRoot = mkdtempSync(join(tmpdir(), "govprov-p11-s4-"));
  const basic = await runExperiment(basicConfig, { packageRoot: tempRoot });
  const hard = await runExperiment(hardConfig, { packageRoot: tempRoot });

  assert.equal(basicConfig.matrix, "arpe_basic_matrix");
  assert.equal(hardConfig.matrix, "arpe_hard_matrix");
  assert.ok(basic.runRoot.endsWith(join("runs", "arpe-basic-debug")));
  assert.ok(hard.runRoot.endsWith(join("runs", "arpe-hard-debug")));
  assert.ok(existsSync(join(basic.runRoot, "results", "matrix_summary.csv")));
  assert.ok(existsSync(join(hard.runRoot, "results", "matrix_summary.csv")));
  assert.ok(readFileSync(join(basic.runRoot, "results", "fault_detection_boundaries.csv"), "utf8").includes("F10,basic_lifecycle,true,true,true,true,false,true"));
  assert.ok(readFileSync(join(hard.runRoot, "results", "fault_detection_boundaries.csv"), "utf8").includes("H1,actor_role,false,false,false,true,false,true"));
});

test("ST-S1 hash-only ledger ablation anchors hashes without governance-contract state", async () => {
  const config = parseExperimentConfig(join(packageRoot, "configs", "arpe_hash_only_ablation_debug.json"));
  const tempRoot = mkdtempSync(join(tmpdir(), "govprov-st-s1-"));
  const result = await runExperiment(config, { packageRoot: tempRoot });
  assert.equal(result.workload.length, 80);

  const summary = JSON.parse(readFileSync(join(result.runRoot, "results", "metrics_summary.json"), "utf8"));
  assert.equal(summary.workflow_count, 80);
  assert.deepEqual(summary.configurations.map((item: { configuration: string }) => item.configuration), [
    "SEGL",
    "baseline_hash_only_ledger",
    "baseline_structured_logs",
    "govreplay_besu",
    "govreplay_offchain_only",
  ]);
  const hashOnly = summary.configurations.find((item: { configuration: string }) => item.configuration === "baseline_hash_only_ledger");
  assert.equal(hashOnly.recall, 1 / 3);
  assert.equal(hashOnly.false_negative_count, 8);
  assert.equal(hashOnly.transactions_per_workflow, 1);
  assert.equal(hashOnly.gas_per_workflow > 0, true);

  const manifest = JSON.parse(readFileSync(join(result.runRoot, "ledger", "hash_only_anchor_manifest.json"), "utf8"));
  assert.equal(manifest.baseline, "baseline_hash_only_ledger");
  assert.equal(manifest.anchor_count, 16);
  assert.ok(manifest.boundary.includes("no governance-contract"));

  const anchors = readFileSync(join(result.runRoot, "ledger", "hash_only_anchors.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(anchors.length, 16);
  assert.equal(anchors[0].governance_state_boundary.actor_registry, false);
  assert.equal(anchors[0].governance_state_boundary.contract_directory, false);

  const auditRows = readFileSync(join(result.runRoot, "audit", "audit_results.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const f12HashOnly = auditRows.find((item) => item.workflow_id.includes("F12") && item.system_configuration === "baseline_hash_only_ledger");
  assert.equal(f12HashOnly.verdict, "FAIL");
  assert.equal(f12HashOnly.failure_code, "anchor_mismatch");
  const f12Offchain = auditRows.find((item) => item.workflow_id.includes("F12") && item.system_configuration === "govreplay_offchain_only");
  assert.equal(f12Offchain.verdict, "PASS");

  const boundaryCsv = readFileSync(join(result.runRoot, "results", "fault_detection_boundaries.csv"), "utf8");
  assert.ok(boundaryCsv.includes("F12,basic_lifecycle,false,false,false,true,true,true,SEGL_or_baseline_hash_only_ledger_or_stronger"));
});

test("ST-S1 hash-only ledger ablation detects anchors but not full governance-state faults", async () => {
  const config = parseExperimentConfig(join(packageRoot, "configs", "arpe_hash_only_ablation_hard_debug.json"));
  const tempRoot = mkdtempSync(join(tmpdir(), "govprov-st-s1-hard-"));
  const result = await runExperiment(config, { packageRoot: tempRoot });
  assert.equal(result.workload.length, 580);

  const summary = JSON.parse(readFileSync(join(result.runRoot, "results", "metrics_summary.json"), "utf8"));
  const hashOnly = summary.configurations.find((item: { configuration: string }) => item.configuration === "baseline_hash_only_ledger");
  assert.equal(hashOnly.false_negative_count, 84);
  assert.equal(hashOnly.recall, 0.16);

  const auditRows = readFileSync(join(result.runRoot, "audit", "audit_results.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const h4HashOnly = auditRows.find((item) => item.workflow_id.includes("H4") && item.system_configuration === "baseline_hash_only_ledger");
  assert.equal(h4HashOnly.verdict, "FAIL");
  assert.equal(h4HashOnly.failure_code, "ledger_anchor_missing");
  const h8HashOnly = auditRows.find((item) => item.workflow_id.includes("H8") && item.system_configuration === "baseline_hash_only_ledger");
  assert.equal(h8HashOnly.verdict, "PASS");

  const boundaryCsv = readFileSync(join(result.runRoot, "results", "hard_fault_detection_boundaries.csv"), "utf8");
  assert.ok(boundaryCsv.includes("H4,anchor,false,false,false,true,true,true,SEGL_or_govreplay_besu"));
  assert.ok(boundaryCsv.includes("H8,contract_directory,false,false,false,true,false,true,SEGL_or_govreplay_besu"));
});

test("reproducibility summary inventories paper-facing exports", async () => {
  const config = parseExperimentConfig(join(packageRoot, "configs", "arpe_basic_debug.json"));
  const tempRoot = mkdtempSync(join(tmpdir(), "govprov-p11-s5-"));
  const result = await runExperiment(config, { packageRoot: tempRoot });
  const summary = JSON.parse(readFileSync(join(result.runRoot, "results", "reproducibility_summary.json"), "utf8"));

  assert.equal(summary.schema_version, "govprov.reproducibility_summary.v1");
  assert.equal(summary.command, "docker compose --profile paper-arpe run --rm paper-arpe");
  assert.equal(summary.command_scope, "debug deterministic subset");
  assert.equal(summary.source_config, "configs/arpe_basic_debug.json");
  assert.equal(summary.reproduction_commands.current_run, "docker compose --profile paper-arpe run --rm paper-arpe");
  assert.equal(summary.reproduction_commands.full_deterministic_paper, "docker compose --profile besu_live_arpe_full run --rm paper-arpe-full");
  assert.equal(
    summary.reproduction_commands.full_live_besu,
    "docker compose --profile besu_live_arpe_full up --build --exit-code-from besu-live-arpe-full besu-dev besu-live-arpe-full",
  );
  assert.ok(summary.outputs.result_json.includes("results/metrics.json"));
  assert.ok(summary.outputs.result_csv.includes("results/metrics_by_fault.csv"));
  assert.ok(summary.outputs.result_csv.includes("results/per_fault_oracle_agreement.csv"));
  assert.ok(summary.outputs.result_csv.includes("results/metrics_by_test_class.csv"));
  assert.ok(summary.outputs.result_csv.includes("results/metrics_by_arpe_element.csv"));
  assert.ok(summary.outputs.result_csv.includes("results/metrics_by_external_tradition.csv"));
  assert.ok(summary.outputs.result_csv.includes("results/metrics_by_required_state.csv"));
  assert.ok(summary.outputs.result_csv.includes("results/metrics_by_governance_domain.csv"));
  assert.ok(summary.outputs.result_csv.includes("results/metrics_by_governance_domain_and_config.csv"));
  assert.ok(summary.outputs.result_csv.includes("results/gas_usage.csv"));
  assert.ok(summary.outputs.result_csv.includes("results/gas_summary.csv"));
  assert.ok(summary.outputs.result_csv.includes("results/gas_summary_by_scenario.csv"));
  assert.ok(summary.outputs.paper_tables.includes("paper/table_fault_detection_boundaries.md"));
  assert.ok(summary.outputs.paper_tables.includes("paper/table_per_fault_oracle_agreement.md"));
  assert.ok(summary.outputs.paper_tables.includes("paper/table_arpe_test_classes.md"));
  assert.ok(summary.outputs.paper_tables.includes("paper/table_arpe_test_class_mapping.md"));
  assert.ok(summary.outputs.paper_tables.includes("paper/table_arpe_external_traditions.md"));
  assert.ok(summary.outputs.paper_tables.includes("paper/table_governance_domain_mapping.md"));
  assert.ok(summary.outputs.paper_figures.includes("paper/figures/figure_reconstruction_by_config.csv"));
  assert.equal(summary.live_besu_status.mode, "besu_live_arpe_full");
  assert.equal(summary.live_besu_status.status, "not_run_by_deterministic_reproduction_command");
  assert.equal(summary.live_besu_status.command, "docker compose --profile besu_live_arpe_full up --build --exit-code-from besu-live-arpe-full besu-dev besu-live-arpe-full");
  assert.equal(summary.live_besu_status.expected_output, "runs/besu-live-arpe-full/ledger/live_arpe_full_status.json");
});

test("paper-facing full matrix summaries point to the promoted reproduction command", async () => {
  const config = parseExperimentConfig(join(packageRoot, "configs", "arpe_hash_only_ablation_hard_debug.json"));
  const metadata = reproductionMetadata(config);

  assert.equal(metadata.command, "docker compose --profile besu_live_arpe_full run --rm paper-arpe-full");
  assert.equal(metadata.scope, "paper-facing deterministic full bundle");
  assert.equal(metadata.config, "configs/arpe_hash_only_ablation_hard_debug.json");
});

function sumWorkflowCount(rows: Array<{ workflow_count: number }>): number {
  return rows.reduce((sum, row) => sum + row.workflow_count, 0);
}

function seglInstance(faultId: WorkloadInstance["fault_id"]): WorkloadInstance {
  return {
    run_id: "test-segl",
    workflow_id: `wf-SEGL-P1-${faultId}-0001`,
    scenario_id: "S2_configuration_change",
    policy_version: "policy:v1",
    system_configuration: "SEGL",
    fault_id: faultId,
    governance_domain: "audit_domain",
    governance_domain_type: "audit_replay_reports_and_metrics",
    governance_domain_id: "govreplay:domain:audit_domain",
    expected_domain: "audit_domain",
    domain_fault: faultId !== "F0",
    cross_domain_dependency: [],
    seed: 1,
    agent_id: "agent:configbot",
    artifact_id: `artifact-SEGL-P1-${faultId}-0001`,
    deployment_id: `deployment-SEGL-P1-${faultId}-0001`,
  };
}

function cloneEvents(events: SeglEvent[]): SeglEvent[] {
  return structuredClone(events);
}

function seglReference(instance: Pick<WorkloadInstance, "workflow_id">): { workflow_id: string } {
  return { workflow_id: instance.workflow_id };
}

function verifySeglWorkflowFor(instance: WorkloadInstance): SeglVerificationResult {
  return verifySeglWorkflow(buildSeglLog([instance]).events, seglReference(instance));
}

function issueCodes(result: SeglVerificationResult): string[] {
  return result.issues.map((issue) => issue.code).sort();
}

function assertHasIssue(result: SeglVerificationResult, code: string): void {
  assert.equal(result.issues.some((issue) => issue.code === code), true, `${code} should be reported; saw ${result.issues.map((issue) => issue.code).join(", ")}`);
}

function assertGeneratedTableAvoidsComplianceClaims(table: string): void {
  assert.equal(table.includes("SLSA-compliant"), false);
  assert.equal(table.includes("in-toto-compliant"), false);
}
