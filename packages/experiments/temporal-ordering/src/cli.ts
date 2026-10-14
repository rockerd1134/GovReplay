import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { recoverSignerAddressFromBytes } from "../../../attestations/src/signing.ts";
import { compareOrder, orderOfReceipt, type CaseManifest, type CasePlan, type RunMetadata } from "./model.ts";
import { oracleFor } from "./oracle.ts";
import { buildTemporalSeglEvents, verifyTemporalSegl, type CaseHashes } from "./seglTemporal.ts";
import { loadBesuObservation, verifyBesuCase, type BesuObservation, type BesuReplay, type Receipt } from "./besuTemporal.ts";

type Row = {
  case_id: string;
  ordering: string;
  authority_N: boolean;
  authority_D: boolean;
  segl_write: "accepted";
  segl_replay: "PASS" | "FAIL";
  expected_N_write: "accepted";
  expected_D_write: "accepted" | "reverted";
  besu_N_write: "accepted" | "reverted";
  besu_D_write: "accepted" | "reverted";
  besu_replay: "PASS" | "FAIL" | "NOT_APPLICABLE";
  expected: "PASS" | "FAIL";
  failure_boundary: "N" | "D" | null;
  classification: string;
  parity: "agree" | "disagree" | "not_applicable";
  signature_valid: boolean;
};

function readJson<T>(path: string): T { return JSON.parse(readFileSync(path, "utf8")) as T; }
function readJsonl<T>(path: string): T[] { return readFileSync(path, "utf8").trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line) as T); }
function saveJson(path: string, value: unknown): void { writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`); }
function csvCell(value: unknown): string {
  const text = value === null || value === undefined ? "" : String(value);
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}
function saveCsv(path: string, rows: Record<string, unknown>[], columns: string[]): void {
  writeFileSync(path, `${[columns.join(","), ...rows.map((row) => columns.map((column) => csvCell(row[column])).join(","))].join("\n")}\n`);
}

function receiptFor(observation: BesuObservation, caseId: string, step: string): Receipt {
  const result = observation.receipts.find((item) => item.case_id === caseId && item.step === step);
  if (result === undefined) throw new Error(`Missing receipt ${caseId}/${step}`);
  return result.receipt;
}

function verifyCommittedOrder(plan: CasePlan, observation: BesuObservation): void {
  const authoritative = plan.ordered_events.filter((step) => ["R", "G", "N", "D"].includes(step));
  const receiptStep: Record<string, string> = { R: "revoke", G: "regrant", N: "anchor_N", D: "deployment_D" };
  let previous: Receipt | undefined;
  let revokes = 0;
  let regrants = 0;
  for (const step of authoritative) {
    let name = receiptStep[step]!;
    if (step === "R" && ++revokes > 1) name = `revoke_${revokes}`;
    if (step === "G" && ++regrants > 1) name = `regrant_${regrants}`;
    const receipt = receiptFor(observation, plan.case_id, name);
    if (previous !== undefined && compareOrder(orderOfReceipt(previous), orderOfReceipt(receipt)) >= 0) {
      throw new Error(`Besu receipt order contradicts ${plan.case_id}: ${step}`);
    }
    previous = receipt;
  }
}

function markdownTable(headers: string[], values: Array<Array<string | number | boolean | null>>): string {
  return [`| ${headers.join(" | ")} |`, `| ${headers.map(() => "---").join(" | ")} |`, ...values.map((row) => `| ${row.map((item) => item === null ? "—" : String(item)).join(" | ")} |`)].join("\n");
}

function classify(besu: BesuReplay): string {
  if (besu.write_D === "reverted") return "PREVENTED_AT_WRITE";
  if (!besu.authority_at_N && besu.write_N === "accepted") return "WRITE_TIME_ENFORCEMENT_GAP";
  if (besu.verdict === "FAIL") return "ACCEPTED_BUT_REPLAY_INVALID";
  return "VALID";
}

function writeReports(runRoot: string, rows: Row[], observation: BesuObservation): void {
  saveJson(join(runRoot, "temporal_ordering_results.json"), { rows });
  const acceptedN = rows.filter((row) => row.besu_N_write === "accepted").length;
  const acceptedD = rows.filter((row) => row.besu_D_write === "accepted").length;
  const rejectedD = rows.length - acceptedD;
  const replayInvalid = rows.filter((row) => row.besu_D_write === "accepted" && row.expected === "FAIL" && row.besu_replay === "FAIL").length;
  const validPass = rows.filter((row) => row.expected === "PASS" && row.besu_replay === "PASS").length;
  const writeDisagreements = rows.filter((row) => row.besu_N_write !== row.expected_N_write || row.besu_D_write !== row.expected_D_write).length;
  const oracleDisagreements = rows.filter((row) => row.besu_N_write !== row.expected_N_write || row.besu_D_write !== row.expected_D_write
    || row.besu_D_write === "accepted" && row.besu_replay !== row.expected || row.segl_replay !== row.expected).length;
  const comparable = rows.filter((row) => row.parity !== "not_applicable");
  const parityDisagreements = comparable.filter((row) => row.parity === "disagree").length;
  const table = markdownTable(
    ["Case", "Ordering", "Authority@N", "Authority@D", "SEGL Write", "SEGL Replay", "Besu N Write", "Besu D Write", "Besu Replay", "Expected", "Failure Boundary", "Classification"],
    rows.map((row) => [row.case_id, row.ordering, row.authority_N, row.authority_D, row.segl_write, row.segl_replay,
      row.besu_N_write, row.besu_D_write, row.besu_replay, row.expected, row.failure_boundary, row.classification]),
  );
  const security = markdownTable(
    ["Security condition", "Knowable at N?", "Knowable at D?", "Currently enforced at write?", "Detected at replay?", "Required historical state"],
    [
      ["Attestation actor has required role at N", "Yes", "Yes", "No: active actor only", "Yes", "Role grants/revocations before N"],
      ["Deployment sender has deployer or writer role at D", "No", "Yes", "Yes", "Yes for committed D", "Role grants/revocations before D"],
      ["Approval for action and artifact at D", "No", "Yes", "Yes", "Yes", "Approval record before D"],
      ["Policy hash exists at D", "Yes if registered", "Yes", "Yes", "Yes", "Policy registration before D"],
      ["Claimed S preceded R", "No", "No", "No", "Not used", "A trusted pre-R witness would be needed"],
    ],
  );
  const caseNotes = rows.map((row) => {
    const nReason = row.besu_N_write === "accepted"
      ? "ProvenanceRegistry accepted the active ledger-writer sender and active header actor; it does not check the header actor's DEPLOYER_ROLE."
      : "The anchor transaction reverted; inspect its receipt and contract inputs.";
    const dReason = row.besu_D_write === "accepted"
      ? "DeploymentRegistry accepted the sender's role, registered policy, action/deployment anchors, and valid approval."
      : "DeploymentRegistry reverted the actor-submitted transaction; the receipt has status 0x0 and no committed D. Source inspection points to the sender-role check; RPC did not supply a decoded revert reason.";
    return `- **${row.case_id}:** N ${row.besu_N_write} (${nReason}) D ${row.besu_D_write} (${dReason}) Historical replay ${row.besu_replay}${row.failure_boundary ? ` at ${row.failure_boundary}` : ""}. ${!row.authority_N ? "The missing actor role was knowable from authoritative state at N." : "No N role violation was present."}`;
  });
  writeFileSync(join(runRoot, "temporal_ordering_results.md"), [
    "# Temporal Authorization Ordering Results", "",
    `Run: \`${runRoot}\`. Local version-pinned single-node Besu dev profile (chain 1337); SEGL uses signed append events. The actor's claimed signature time is not used as order evidence.`, "",
    table, "", "## Case write and replay observations", "", ...caseNotes, "", "## Security boundaries", "", security, "", "## Counts", "",
    `- ${rows.length} cases; SEGL accepted ${rows.length}/${rows.length} append histories.`,
    `- Besu accepted ${acceptedN}/${rows.length} N anchors and ${acceptedD}/${rows.length} D records; ${rejectedD}/${rows.length} D attempts reverted.`,
    `- Accepted invalid Besu histories detected at replay: ${replayInvalid}/${rows.filter((row) => row.besu_D_write === "accepted" && row.expected === "FAIL").length}.`,
    `- Expected-valid Besu histories passing replay: ${validPass}/${rows.filter((row) => row.expected === "PASS").length}.`,
    `- Oracle disagreements: ${oracleDisagreements}/${rows.length}; SEGL/Besu replay disagreements on equivalent committed histories: ${parityDisagreements}/${comparable.length}.`,
    `- Besu write-disposition disagreements with the independent case specification: ${writeDisagreements}/${rows.length}.`,
    `- Semantically underspecified cases under the adopted model: 0/${rows.length}. Verification latency: not evaluated.`,
    "", "## Interpretation and limits", "",
    "Write dispositions come from saved transaction receipts refetched from Besu RPC; role state comes from ordered ActorRegistry events. SEGL verdicts come from signed append order in a stream generated from the same tracked case manifest after the Besu run. This is controlled semantic parity, not evidence of independently operated SEGL administration. A reverted Besu D has no committed deployment history and is excluded from parity counts. The role experiment uses one stable registered policy and an administrator-issued approval; it does not test policy-version ordering, multi-administrator trust, or timestamp authenticity. The dev chain placed the experiment transactions in separate blocks; same-block ordering is handled by the adapter and unit test but was not exercised live. The contract-level cause recorded for a revert is a source-level attribution, not an RPC-decoded revert reason.", "",
  ].join("\n"));
  saveCsv(join(runRoot, "temporal_ordering_results.csv"), rows as unknown as Record<string, unknown>[], [
    "case_id", "ordering", "authority_N", "authority_D", "segl_write", "segl_replay", "expected_N_write", "expected_D_write", "besu_N_write", "besu_D_write", "besu_replay", "expected", "failure_boundary", "classification", "parity", "signature_valid",
  ]);
  writeFileSync(join(runRoot, "temporal_ordering_security_boundaries.md"), `# Security Boundaries\n\n${security}\n`);
  const notes = [
    "# Temporal Ordering Paper Notes", "",
    `We evaluated ${rows.length} controlled role-order cases with signed SEGL append histories and live local Besu contract writes. The cases place revocation before or after first attestation commitment N and deployment record D, with a regrant case and a post-deployment audit case.`, "",
    `Besu accepted ${acceptedN}/${rows.length} action-attestation anchors and ${acceptedD}/${rows.length} deployment attempts; ${rejectedD}/${rows.length} deployment attempts reverted. Historical replay detected ${replayInvalid} accepted invalid histories, while ${validPass}/${rows.filter((row) => row.expected === "PASS").length} expected-valid Besu histories passed. The independent oracle disagreed in ${oracleDisagreements}/${rows.length} cases, and equivalent committed SEGL/Besu histories disagreed in ${parityDisagreements}/${comparable.length} cases.`, "",
    "A cryptographically valid signature establishes authorship and content integrity, but its caller-supplied time does not establish pre-revocation authorization. The experiment evaluates the attestation actor's historical role at first authoritative commitment N and the deployment sender's historical role at D. Anchoring does not itself confer the actor's required deployer role.", "",
    "The current ProvenanceRegistry accepts an anchor naming an active actor without checking that actor's required deployer role. Such accepted invalid histories can be identified by later historical replay. DeploymentRegistry checks the transaction sender's deployer or writer role and other write-time prerequisites; the actor-submitted post-revocation D attempt was rejected. These are separate contract-write and replay boundaries.", "",
    "SEGL and GovReplay-Besu use equivalent historical role semantics for comparable committed histories in this controlled experiment. Besu's distinctive potential value is independently administered state and implemented contract-side write checks, not an observed replay-detection advantage in these cases.", "",
    "The result uses a single-node local QBFT development chain, deterministic signers, one stable policy, and controlled synthetic lifecycle events. The SEGL stream was generated from the tracked case manifest after the Besu run; parity therefore concerns the modeled transition order, not independent administration. The live transactions occupied separate blocks, so same-block ordering was tested in unit logic but not live. The result does not establish trusted signing time, multi-party administration security, operational detection rates, or latency at scale. A Besu-rejected deployment is excluded from replay-semantic parity counts.", "",
    "## Proposed reviewer response", "",
    "In the stated scenario, a signature created locally before revocation does not independently prove its creation time. We evaluate the attestation actor's role when the attestation is first committed to ordered governance history. If revocation precedes that commitment, the prior signature does not preserve authorization, even when the contract accepts the anchor. Deployment is evaluated separately against the deployment sender's authority and required policy and approval state at its own ordered boundary. Replay reconstructs those historical boundaries, so a later revocation does not retroactively invalidate an action that was valid when committed.", "",
  ];
  if (oracleDisagreements === 0 && parityDisagreements === 0) writeFileSync(join(runRoot, "temporal_ordering_paper_notes.md"), notes.join("\n"));
  saveJson(join(runRoot, "temporal_ordering_summary.json"), {
    run_id: readJson<RunMetadata>(join(runRoot, "run_metadata.json")).run_id,
    case_count: rows.length,
    segl_append_accepted: rows.length,
    besu_N_accepted: acceptedN,
    besu_D_accepted: acceptedD,
    besu_D_rejected: rejectedD,
    accepted_invalid_detected: replayInvalid,
    expected_valid_passing: validPass,
    oracle_disagreements: oracleDisagreements,
    write_disagreements: writeDisagreements,
    parity_disagreements: parityDisagreements,
    comparable_histories: comparable.length,
    receipt_count: observation.receipts.length,
  });
}

async function main(): Promise<void> {
  const runRootArg = process.argv[process.argv.indexOf("--run-root") + 1];
  if (process.argv.indexOf("--run-root") < 0 || !runRootArg) throw new Error("Usage: cli.ts --run-root <runs/<run_id>/temporal_ordering>");
  const runRoot = resolve(runRootArg);
  const sourceRoot = dirname(dirname(fileURLToPath(import.meta.url)));
  const manifest = readJson<CaseManifest>(join(runRoot, "cases.json"));
  const meta = readJson<RunMetadata>(join(runRoot, "run_metadata.json"));
  const hashes = readJsonl<CaseHashes>(join(runRoot, "case_hashes.jsonl"));
  const signatures = readJsonl<{ case_id: string; message: string; signature: string; claimed_created_at: string }>(join(runRoot, "signatures.jsonl"));
  const signingKey = process.env.GOVPROV_DEV_DEPLOYER_PRIVATE_KEY;
  if (!signingKey) throw new Error("Set GOVPROV_DEV_DEPLOYER_PRIVATE_KEY for the local SEGL signing profile");
  const besu = await loadBesuObservation(runRoot, meta, process.env.GOVPROV_TEMPORAL_RPC_URL ?? "http://127.0.0.1:8545");
  const oracle = manifest.cases.map(oracleFor);
  const seglCases = [];
  const rows: Row[] = [];
  for (const plan of manifest.cases) {
    const caseHashes = hashes.find((item) => item.case_id === plan.case_id);
    const signature = signatures.find((item) => item.case_id === plan.case_id);
    if (caseHashes === undefined || signature === undefined) throw new Error(`Missing case data: ${plan.case_id}`);
    if (signature.message.toLowerCase() !== caseHashes.action_hash.toLowerCase()) {
      throw new Error(`Local signature is not bound to anchored action hash: ${plan.case_id}`);
    }
    const signatureValid = recoverSignerAddressFromBytes(Buffer.from(signature.message.slice(2), "hex"), signature.signature).toLowerCase() === meta.attestation_actor.toLowerCase();
    if (!signatureValid) throw new Error(`Invalid local actor signature: ${plan.case_id}`);
    verifyCommittedOrder(plan, besu);
    const events = buildTemporalSeglEvents(plan, meta, caseHashes, signingKey);
    const segl = verifyTemporalSegl(events, meta, caseHashes);
    const observed = verifyBesuCase(besu, meta, caseHashes);
    const expected = oracle.find((item) => item.case_id === plan.case_id)!;
    if (segl.integrity_issues.length) throw new Error(`SEGL event integrity failed in ${plan.case_id}: ${segl.integrity_issues.join(",")}`);
    const parity = observed.write_D === "reverted" ? "not_applicable" : segl.verdict === observed.verdict ? "agree" : "disagree";
    rows.push({
      case_id: plan.case_id,
      ordering: plan.ordered_events.join("→"),
      authority_N: observed.authority_at_N,
      authority_D: observed.authority_at_D,
      segl_write: "accepted",
      segl_replay: segl.verdict,
      expected_N_write: expected.expected_write_disposition.N,
      expected_D_write: expected.expected_write_disposition.D,
      besu_N_write: observed.write_N,
      besu_D_write: observed.write_D,
      besu_replay: observed.verdict,
      expected: expected.expected_replay_verdict,
      failure_boundary: observed.failure_boundary,
      classification: classify(observed),
      parity,
      signature_valid: signatureValid,
    });
    seglCases.push({ case_id: plan.case_id, events, replay: segl });
  }
  const oracleWithIdentities = oracle.map((expected) => ({
    ...expected,
    attestation_actor: meta.attestation_actor,
    anchor_transaction_sender: meta.anchor_transaction_sender,
    deployment_transaction_sender: expected.deployment_actor === "actor"
      ? meta.attestation_actor : meta.default_deployment_transaction_sender,
    approval_actor: meta.approval_actor,
  }));
  saveJson(join(runRoot, "temporal_ordering_oracle.json"), {
    schema_version: "govprov.temporal_oracle.v1",
    generated_from: "tracked symbolic case order and adopted invariants, without replay inputs; case identities resolved from run metadata only for output",
    cases: oracleWithIdentities,
  });
  saveJson(join(runRoot, "temporal_ordering_segl_events.json"), { schema_version: "govprov.temporal_segl_events.v1", cases: seglCases });
  saveJson(join(runRoot, "temporal_ordering_besu_receipts.json"), { schema_version: "govprov.temporal_besu_receipts.v1", ...besu });
  writeReports(runRoot, rows, besu);
  const summary = readJson<Record<string, unknown>>(join(runRoot, "temporal_ordering_summary.json"));
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  if (Number(summary.oracle_disagreements) > 0 || Number(summary.parity_disagreements) > 0) process.exitCode = 1;
}

main().catch((error: unknown) => { process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`); process.exitCode = 1; });
