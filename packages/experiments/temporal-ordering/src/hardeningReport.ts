import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { recoverSignerAddressFromBytes } from "../../../attestations/src/signing.ts";
import { buildTemporalSeglEvents, verifyTemporalSegl, type CaseHashes } from "./seglTemporal.ts";
import { loadBesuObservation, verifyBesuCase, type BesuObservation, type Receipt } from "./besuTemporal.ts";
import { compareOrder, orderOfReceipt, roleAt, type CaseManifest, type CasePlan, type RunMetadata } from "./model.ts";
import { oracleFor } from "./oracle.ts";

type HardenedRow = {
  case_id: string;
  ordering: string;
  authority_at_N: boolean;
  N_write: "ACCEPT" | "REVERT";
  D_write: "ACCEPT" | "REVERT" | "NOT_ATTEMPTED";
  besu_replay: "PASS" | "FAIL" | "NOT_APPLICABLE";
  segl_replay: "PASS" | "FAIL";
  segl_failure_boundary: "N" | "D" | "integrity" | null;
  expected_N: "ACCEPT" | "REVERT";
  expected_D: "ACCEPT" | "REVERT" | "NOT_ATTEMPTED";
  expected_replay: "PASS" | "NOT_APPLICABLE";
  prediction_agrees: boolean;
  parity: "agree" | "disagree" | "not_comparable";
  N_transaction_hash: string;
  D_transaction_hash: string | null;
  signature_valid: boolean;
};

function readJson<T>(path: string): T { return JSON.parse(readFileSync(path, "utf8")) as T; }
function readJsonl<T>(path: string): T[] {
  return readFileSync(path, "utf8").trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line) as T);
}
function receiptFor(observation: BesuObservation, caseId: string, step: string): Receipt | undefined {
  return observation.receipts.find(row => row.case_id === caseId && row.step === step)?.receipt;
}
function orderedReceipts(plan: CasePlan, observation: BesuObservation): void {
  const steps: Record<string, string> = { R: "revoke", G: "regrant", N: "anchor_N", D: "deployment_D" };
  let prior: Receipt | undefined;
  let revokes = 0;
  let regrants = 0;
  for (const event of plan.ordered_events) {
    let step = steps[event];
    if (event === "R" && ++revokes > 1) step = `revoke_${revokes}`;
    if (event === "G" && ++regrants > 1) step = `regrant_${regrants}`;
    if (!step) continue;
    const receipt = receiptFor(observation, plan.case_id, step);
    if (!receipt) {
      if (event === "D" && receiptFor(observation, plan.case_id, "anchor_N")?.status === "0x0") continue;
      throw new Error(`Missing ${plan.case_id}/${step} receipt`);
    }
    if (prior && compareOrder(orderOfReceipt(prior), orderOfReceipt(receipt)) >= 0) {
      throw new Error(`Wrong committed order in ${plan.case_id}/${step}`);
    }
    prior = receipt;
  }
}
function main(): Promise<void> {
  return run();
}
async function run(): Promise<void> {
  const arg = process.argv.indexOf("--run-root");
  if (arg < 0 || !process.argv[arg + 1]) throw new Error("Usage: hardeningReport.ts --run-root <path>");
  const runRoot = resolve(process.argv[arg + 1]!);
  const meta = readJson<RunMetadata>(join(runRoot, "run_metadata.json"));
  const hardening = readJson<{ implementation: string; contract_version: string }>(join(runRoot, "hardening_metadata.json"));
  if (hardening.implementation !== "hardened" || hardening.contract_version !== "HardenedProvenanceRegistry.v1") {
    throw new Error("Run does not declare the hardened contract version");
  }
  const manifest = readJson<CaseManifest>(join(runRoot, "cases.json"));
  const hashes = readJsonl<CaseHashes>(join(runRoot, "case_hashes.jsonl"));
  const signatures = readJsonl<{ case_id: string; message: string; signature: string }>(join(runRoot, "signatures.jsonl"));
  const skipped = readJsonl<{ case_id: string; step: string; disposition: string; reason: string }>(join(runRoot, "skipped_steps.jsonl"));
  const signingKey = process.env.GOVPROV_DEV_DEPLOYER_PRIVATE_KEY;
  if (!signingKey) throw new Error("Set the local development signing key");
  const observation = await loadBesuObservation(runRoot, meta, process.env.GOVPROV_TEMPORAL_RPC_URL ?? "http://127.0.0.1:8545");
  const rows: HardenedRow[] = [];
  const seglCases = [];
  for (const plan of manifest.cases) {
    const h = hashes.find(value => value.case_id === plan.case_id);
    const signature = signatures.find(value => value.case_id === plan.case_id);
    if (!h || !signature || signature.message.toLowerCase() !== h.action_hash.toLowerCase()) {
      throw new Error(`Missing or mismatched signed action for ${plan.case_id}`);
    }
    const signatureValid = recoverSignerAddressFromBytes(Buffer.from(signature.message.slice(2), "hex"), signature.signature)
      .toLowerCase() === meta.attestation_actor.toLowerCase();
    if (!signatureValid) throw new Error(`Signature invalid for ${plan.case_id}`);
    orderedReceipts(plan, observation);
    const nReceipt = receiptFor(observation, plan.case_id, "anchor_N");
    const dReceipt = receiptFor(observation, plan.case_id, "deployment_D");
    if (!nReceipt) throw new Error(`Missing N receipt for ${plan.case_id}`);
    const nWrite = nReceipt.status === "0x1" ? "ACCEPT" : nReceipt.status === "0x0" ? "REVERT" : undefined;
    if (!nWrite) throw new Error(`Unknown N status for ${plan.case_id}`);
    const dWrite = !dReceipt ? "NOT_ATTEMPTED" : dReceipt.status === "0x1" ? "ACCEPT" : dReceipt.status === "0x0" ? "REVERT" : undefined;
    if (!dWrite) throw new Error(`Unknown D status for ${plan.case_id}`);
    const skip = skipped.find(value => value.case_id === plan.case_id && value.step === "D");
    if ((dWrite === "NOT_ATTEMPTED") !== Boolean(skip) || (skip && (skip.disposition !== "NOT_ATTEMPTED" || skip.reason !== "N_REVERTED"))) {
      throw new Error(`D skip record disagrees in ${plan.case_id}`);
    }
    if (nWrite === "REVERT" && dWrite !== "NOT_ATTEMPTED") throw new Error(`D attempted after rejected N in ${plan.case_id}`);
    if (nWrite === "ACCEPT" && dWrite === "NOT_ATTEMPTED") throw new Error(`D missing after accepted N in ${plan.case_id}`);
    const expected = oracleFor(plan);
    const authorityN = roleAt(observation.role_transitions, meta.attestation_actor, meta.deployer_role, orderOfReceipt(nReceipt));
    if (authorityN !== expected.authority_at_N) throw new Error(`Observed N role differs from symbolic case state: ${plan.case_id}`);
    if (nWrite === "REVERT" && nReceipt.logs.some(log => log.address.toLowerCase() === meta.contracts.ProvenanceRegistry.toLowerCase())) {
      throw new Error(`Rejected N emitted a provenance event in ${plan.case_id}`);
    }
    const events = buildTemporalSeglEvents(plan, meta, h, signingKey);
    const segl = verifyTemporalSegl(events, meta, h);
    if (segl.integrity_issues.length) throw new Error(`SEGL integrity failed in ${plan.case_id}`);
    const besu = dWrite === "NOT_ATTEMPTED" ? null : verifyBesuCase(observation, meta, h);
    const besuReplay = besu?.verdict ?? "NOT_APPLICABLE";
    const expectedN = expected.authority_at_N ? "ACCEPT" : "REVERT";
    const expectedD = !expected.authority_at_N ? "NOT_ATTEMPTED" : expected.authority_at_D ? "ACCEPT" : "REVERT";
    const expectedReplay = expectedD === "ACCEPT" ? "PASS" : "NOT_APPLICABLE";
    const parity = dWrite !== "ACCEPT" ? "not_comparable" : segl.verdict === besuReplay ? "agree" : "disagree";
    rows.push({
      case_id: plan.case_id,
      ordering: plan.ordered_events.join("→"),
      authority_at_N: authorityN,
      N_write: nWrite,
      D_write: dWrite,
      besu_replay: besuReplay,
      segl_replay: segl.verdict,
      segl_failure_boundary: segl.failure_boundary,
      expected_N: expectedN,
      expected_D: expectedD,
      expected_replay: expectedReplay,
      prediction_agrees: nWrite === expectedN && dWrite === expectedD && besuReplay === expectedReplay,
      parity,
      N_transaction_hash: nReceipt.transactionHash,
      D_transaction_hash: dReceipt?.transactionHash ?? null,
      signature_valid: signatureValid,
    });
    seglCases.push({ case_id: plan.case_id, events, replay: segl });
  }
  if (rows.length !== manifest.cases.length) throw new Error(`Expected ${manifest.cases.length} cases, got ${rows.length}`);
  const output = {
    schema_version: "govprov.temporal_hardening_results.v1",
    run_id: meta.run_id,
    hardening,
    contract_addresses: meta.contracts,
    chain_id: meta.chain_id,
    rows,
    summary: {
      cases: rows.length,
      prediction_agreements: rows.filter(row => row.prediction_agrees).length,
      invalid_at_N_prevented: rows.filter(row => !row.authority_at_N && row.N_write === "REVERT").length,
      invalid_at_N_admitted: rows.filter(row => !row.authority_at_N && row.N_write === "ACCEPT").length,
      valid_at_N_accepted: rows.filter(row => row.authority_at_N && row.N_write === "ACCEPT").length,
      expected_valid_histories_passing: rows.filter(row => row.expected_replay === "PASS" && row.besu_replay === "PASS").length,
      comparable_histories: rows.filter(row => row.parity !== "not_comparable").length,
      parity_disagreements: rows.filter(row => row.parity === "disagree").length,
      receipt_count: observation.receipts.length,
    },
  };
  writeFileSync(join(runRoot, "hardened_run_results.json"), JSON.stringify(output, null, 2) + "\n");
  writeFileSync(join(runRoot, "hardened_segl_events.json"), JSON.stringify({ cases: seglCases }, null, 2) + "\n");
  writeFileSync(join(runRoot, "hardened_besu_receipts.json"), JSON.stringify(observation, null, 2) + "\n");
  process.stdout.write(JSON.stringify(output.summary, null, 2) + "\n");
  if (output.summary.prediction_agreements !== manifest.cases.length || output.summary.parity_disagreements !== 0) process.exitCode = 1;
}
main().catch(error => { process.stderr.write(String(error?.stack ?? error) + "\n"); process.exitCode = 1; });
