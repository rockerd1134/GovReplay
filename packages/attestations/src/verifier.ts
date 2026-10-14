import { readFile } from "node:fs/promises";
import { canonicalJson } from "./canonical-json.ts";
import { assertBytes32Hex, digestAttestation } from "./digest.ts";
import {
  type AttestationIndex,
  type AttestationIndexEntry,
  resolveInsideRun,
} from "./run-layout.ts";
import { parseCasUri } from "./storage.ts";
import {
  recoverAttestationSigner,
  SIGNATURE_PROFILE,
} from "./signing.ts";

export type VerificationLevel = "LEVEL_0" | "LEVEL_1";
export type VerificationStatus = "PASS" | "FAIL";

export type VerificationFailureCode =
  | "F_SCHEMA_REQUIRED_FIELD"
  | "F_SCHEMA_ENUM"
  | "F_SCHEMA_DIGEST"
  | "F_SCHEMA_TIMESTAMP"
  | "F_SCHEMA_LINK_SHAPE"
  | "F_SCHEMA_SIGNATURE"
  | "F_HASH_ATTESTATION_MISMATCH"
  | "F_HASH_OBJECT_MISMATCH"
  | "F_SIGNATURE_INVALID"
  | "F_SIGNATURE_ACTOR_MISMATCH"
  | "F_LINK_BROKEN"
  | "F_INDEX_PATH_UNSAFE";

export interface VerificationFailure {
  code: VerificationFailureCode;
  field: string;
  message: string;
}

export interface VerificationReport {
  level: VerificationLevel;
  status: VerificationStatus;
  attestation_hash: string | null;
  attestation_type: string | null;
  failure_codes: VerificationFailureCode[];
  failures: VerificationFailure[];
}

export interface VerifyLevel1Options {
  records?: Record<string, unknown>[];
  index?: AttestationIndex;
  runRoot?: string;
}

const SUPPORTED_SCHEMA_VERSION = "govprov.attestation.v1";
const SUPPORTED_ENVELOPE_TYPE = "https://govprov.dev/attestation/v1";
const SUPPORTED_ATTESTATION_TYPES = new Set([
  "ObservationAttestation",
  "EvidenceBundleAttestation",
  "PolicyDecisionAttestation",
  "AgentActionAttestation",
  "ArtifactAttestation",
  "ApprovalAttestation",
  "DeploymentAttestation",
  "LedgerAnchorAttestation",
  "AuditReplayReport",
]);

export function verifyLevel0(attestation: unknown): VerificationReport {
  const failures: VerificationFailure[] = [];
  if (!isRecord(attestation)) {
    return report("LEVEL_0", null, null, [
      failure("F_SCHEMA_REQUIRED_FIELD", "$", "Attestation must be a JSON object"),
    ]);
  }

  requireString(attestation, "_type", failures);
  requireString(attestation, "schema_version", failures);
  requireString(attestation, "attestation_type", failures);
  requireString(attestation, "predicate_type", failures);
  requireString(attestation, "attestation_hash", failures);
  requireString(attestation, "created_at", failures);
  requireObject(attestation, "created_by", failures);
  requireArray(attestation, "subject", failures);
  requireArray(attestation, "parents", failures);
  requireObject(attestation, "predicate", failures);
  requireObject(attestation, "signature", failures);

  const envelopeType = stringValue(attestation._type);
  if (envelopeType !== undefined && envelopeType !== SUPPORTED_ENVELOPE_TYPE) {
    failures.push(failure("F_SCHEMA_ENUM", "_type", `Unsupported envelope type: ${envelopeType}`));
  }

  const schemaVersion = stringValue(attestation.schema_version);
  if (schemaVersion !== undefined && schemaVersion !== SUPPORTED_SCHEMA_VERSION) {
    failures.push(failure("F_SCHEMA_ENUM", "schema_version", `Unsupported schema version: ${schemaVersion}`));
  }

  const attestationType = stringValue(attestation.attestation_type);
  if (attestationType !== undefined && !SUPPORTED_ATTESTATION_TYPES.has(attestationType)) {
    failures.push(failure("F_SCHEMA_ENUM", "attestation_type", `Unsupported attestation type: ${attestationType}`));
  }

  validateBytes32(attestation.attestation_hash, "attestation_hash", failures);
  validateTimestamp(attestation.created_at, "created_at", failures);
  validateActor(attestation.created_by, failures);
  validateSubject(attestation.subject, failures);
  validateParents(attestation.parents, failures);
  validateSignature(attestation.signature, failures);

  return report(
    "LEVEL_0",
    stringValue(attestation.attestation_hash) ?? null,
    attestationType ?? null,
    failures,
  );
}

export async function verifyLevel1(
  attestation: unknown,
  options: VerifyLevel1Options = {},
): Promise<VerificationReport> {
  const level0 = verifyLevel0(attestation);
  if (level0.status === "FAIL") {
    return report("LEVEL_1", level0.attestation_hash, level0.attestation_type, level0.failures);
  }

  const record = attestation as Record<string, unknown>;
  const failures: VerificationFailure[] = [];
  const claimedHash = record.attestation_hash as string;
  const actualHash = digestAttestation(record).value;
  if (actualHash !== claimedHash) {
    failures.push(failure(
      "F_HASH_ATTESTATION_MISMATCH",
      "attestation_hash",
      `Expected ${claimedHash}, recomputed ${actualHash}`,
    ));
  }

  verifySignature(record, failures);
  verifyParents(record, options, failures);
  await verifyIndexReferences(record, options, failures);

  return report("LEVEL_1", claimedHash, record.attestation_type as string, failures);
}

export async function verifyAttestationSetLevel1(
  attestations: Record<string, unknown>[],
  options: Omit<VerifyLevel1Options, "records"> = {},
): Promise<VerificationReport[]> {
  const records = attestations.map((item) => structuredClone(item) as Record<string, unknown>);
  const reports = [];
  for (const attestation of records) {
    reports.push(await verifyLevel1(attestation, { ...options, records }));
  }
  return reports.sort(compareReports);
}

function report(
  level: VerificationLevel,
  attestationHash: string | null,
  attestationType: string | null,
  failures: VerificationFailure[],
): VerificationReport {
  const sortedFailures = [...failures].sort(compareFailures);
  return {
    level,
    status: sortedFailures.length === 0 ? "PASS" : "FAIL",
    attestation_hash: attestationHash,
    attestation_type: attestationType,
    failure_codes: [...new Set(sortedFailures.map((item) => item.code))],
    failures: sortedFailures,
  };
}

function verifySignature(record: Record<string, unknown>, failures: VerificationFailure[]): void {
  let recovered: string;
  try {
    recovered = recoverAttestationSigner(record).toLowerCase();
  } catch (error) {
    failures.push(failure("F_SIGNATURE_INVALID", "signature", messageFromError(error)));
    return;
  }

  const signature = record.signature as Record<string, unknown>;
  const signer = String(signature.signer).toLowerCase();
  const actor = record.created_by as Record<string, unknown>;
  const actorAddress = String(actor.ethereum_address).toLowerCase();

  if (recovered !== signer) {
    failures.push(failure("F_SIGNATURE_INVALID", "signature.signer", "Recovered signer does not match claimed signer"));
  }
  if (recovered !== actorAddress) {
    failures.push(failure(
      "F_SIGNATURE_ACTOR_MISMATCH",
      "created_by.ethereum_address",
      "Recovered signer does not match attesting actor",
    ));
  }
}

function verifyParents(
  record: Record<string, unknown>,
  options: VerifyLevel1Options,
  failures: VerificationFailure[],
): void {
  const parentHashes = record.parents as string[];
  if (parentHashes.length === 0) {
    return;
  }

  const known = new Set<string>();
  for (const item of options.records ?? []) {
    const hash = stringValue(item.attestation_hash);
    if (hash !== undefined) {
      known.add(hash);
    }
  }
  for (const entry of options.index?.attestations ?? []) {
    known.add(entry.attestation_hash);
  }

  for (const parentHash of parentHashes) {
    if (!known.has(parentHash)) {
      failures.push(failure("F_LINK_BROKEN", "parents", `Parent hash is not resolvable: ${parentHash}`));
    }
  }
}

async function verifyIndexReferences(
  record: Record<string, unknown>,
  options: VerifyLevel1Options,
  failures: VerificationFailure[],
): Promise<void> {
  if (options.index === undefined && options.runRoot === undefined) {
    return;
  }
  if (options.index === undefined || options.runRoot === undefined) {
    failures.push(failure("F_INDEX_PATH_UNSAFE", "index", "Both index and runRoot are required to verify run paths"));
    return;
  }

  const entry = options.index.attestations.find((item) => item.attestation_hash === record.attestation_hash);
  if (entry === undefined) {
    failures.push(failure("F_LINK_BROKEN", "index.attestations", "Attestation hash is not present in the index"));
    return;
  }

  validateIndexEntryShape(entry, failures);

  let typedPath: string;
  try {
    typedPath = resolveInsideRun(options.runRoot, entry.path);
  } catch (error) {
    failures.push(failure("F_INDEX_PATH_UNSAFE", "index.path", messageFromError(error)));
    return;
  }

  const casDigest = safeParseCas(entry.cas_uri, failures);
  if (casDigest !== null && casDigest.value !== record.attestation_hash) {
    failures.push(failure("F_HASH_OBJECT_MISMATCH", "index.cas_uri", "CAS URI digest does not match attestation hash"));
  }

  try {
    const typedContent = await readFile(typedPath, "utf8");
    if (typedContent !== `${canonicalJson(record)}\n`) {
      failures.push(failure("F_HASH_OBJECT_MISMATCH", "index.path", "Indexed typed attestation content differs"));
    }
  } catch (error) {
    failures.push(failure("F_HASH_OBJECT_MISMATCH", "index.path", messageFromError(error)));
  }
}

function validateIndexEntryShape(entry: AttestationIndexEntry, failures: VerificationFailure[]): void {
  validateBytes32(entry.attestation_hash, "index.attestation_hash", failures);
  if (!SUPPORTED_ATTESTATION_TYPES.has(entry.attestation_type)) {
    failures.push(failure("F_SCHEMA_ENUM", "index.attestation_type", "Index attestation type is unsupported"));
  }
  validateTimestamp(entry.created_at, "index.created_at", failures);
  if (!/^0x[0-9a-f]{40}$/.test(entry.actor_address)) {
    failures.push(failure("F_SCHEMA_DIGEST", "index.actor_address", "Index actor address is malformed"));
  }
}

function safeParseCas(uri: string, failures: VerificationFailure[]) {
  try {
    return parseCasUri(uri);
  } catch (error) {
    failures.push(failure("F_HASH_OBJECT_MISMATCH", "index.cas_uri", messageFromError(error)));
    return null;
  }
}

function validateActor(value: unknown, failures: VerificationFailure[]): void {
  if (!isRecord(value)) {
    return;
  }
  requireString(value, "actor_id", failures, "created_by.actor_id");
  requireString(value, "actor_type", failures, "created_by.actor_type");
  requireString(value, "ethereum_address", failures, "created_by.ethereum_address");
  if (!["agent", "human", "service"].includes(String(value.actor_type))) {
    failures.push(failure("F_SCHEMA_ENUM", "created_by.actor_type", "Actor type is unsupported"));
  }
  if (stringValue(value.ethereum_address) !== undefined && !/^0x[0-9a-fA-F]{40}$/.test(String(value.ethereum_address))) {
    failures.push(failure("F_SCHEMA_DIGEST", "created_by.ethereum_address", "Actor address is malformed"));
  }
}

function validateSubject(value: unknown, failures: VerificationFailure[]): void {
  if (!Array.isArray(value)) {
    return;
  }
  if (value.length === 0) {
    failures.push(failure("F_SCHEMA_REQUIRED_FIELD", "subject", "Subject must contain at least one item"));
  }
  value.forEach((item, index) => {
    const field = `subject[${index}]`;
    if (!isRecord(item)) {
      failures.push(failure("F_SCHEMA_REQUIRED_FIELD", field, "Subject item must be a JSON object"));
      return;
    }
    requireString(item, "name", failures, `${field}.name`);
    const digest = requireObject(item, "digest", failures, `${field}.digest`);
    if (digest !== undefined) {
      validateDigestObject(digest, `${field}.digest`, failures);
    }
  });
}

function validateParents(value: unknown, failures: VerificationFailure[]): void {
  if (!Array.isArray(value)) {
    return;
  }
  value.forEach((item, index) => {
    if (typeof item !== "string") {
      failures.push(failure("F_SCHEMA_LINK_SHAPE", `parents[${index}]`, "Parent hash must be a string"));
      return;
    }
    try {
      assertBytes32Hex(item);
    } catch {
      failures.push(failure("F_SCHEMA_LINK_SHAPE", `parents[${index}]`, "Parent hash must be lowercase bytes32 hex"));
    }
  });
}

function validateSignature(value: unknown, failures: VerificationFailure[]): void {
  if (!isRecord(value)) {
    return;
  }
  requireString(value, "profile", failures, "signature.profile");
  requireString(value, "signature", failures, "signature.signature");
  requireString(value, "signer", failures, "signature.signer");
  if (value.profile !== undefined && value.profile !== SIGNATURE_PROFILE) {
    failures.push(failure("F_SCHEMA_SIGNATURE", "signature.profile", "Signature profile is unsupported"));
  }
  if (stringValue(value.signature) !== undefined && !/^0x[0-9a-fA-F]{130}$/.test(String(value.signature))) {
    failures.push(failure("F_SCHEMA_SIGNATURE", "signature.signature", "Signature value is malformed"));
  }
  if (stringValue(value.signer) !== undefined && !/^0x[0-9a-fA-F]{40}$/.test(String(value.signer))) {
    failures.push(failure("F_SCHEMA_SIGNATURE", "signature.signer", "Signature signer is malformed"));
  }
}

function validateDigestObject(value: Record<string, unknown>, field: string, failures: VerificationFailure[]): void {
  requireString(value, "algorithm", failures, `${field}.algorithm`);
  requireString(value, "value", failures, `${field}.value`);
  if (value.algorithm !== undefined && value.algorithm !== "sha256") {
    failures.push(failure("F_SCHEMA_DIGEST", `${field}.algorithm`, "Digest algorithm is unsupported"));
  }
  validateBytes32(value.value, `${field}.value`, failures);
}

function validateBytes32(value: unknown, field: string, failures: VerificationFailure[]): void {
  if (value === undefined || typeof value !== "string") {
    return;
  }
  try {
    assertBytes32Hex(value);
  } catch {
    failures.push(failure("F_SCHEMA_DIGEST", field, "Value must be lowercase 0x-prefixed bytes32 hex"));
  }
}

function validateTimestamp(value: unknown, field: string, failures: VerificationFailure[]): void {
  if (value === undefined || typeof value !== "string") {
    return;
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) {
    failures.push(failure("F_SCHEMA_TIMESTAMP", field, "Timestamp must be an ISO-8601 UTC instant"));
  }
}

function requireString(
  record: Record<string, unknown>,
  field: string,
  failures: VerificationFailure[],
  label = field,
): string | undefined {
  if (record[field] === undefined || record[field] === null) {
    failures.push(failure("F_SCHEMA_REQUIRED_FIELD", label, "Required string field is missing"));
    return undefined;
  }
  if (typeof record[field] !== "string" || record[field] === "") {
    failures.push(failure("F_SCHEMA_REQUIRED_FIELD", label, "Required field must be a non-empty string"));
    return undefined;
  }
  return record[field];
}

function requireObject(
  record: Record<string, unknown>,
  field: string,
  failures: VerificationFailure[],
  label = field,
): Record<string, unknown> | undefined {
  if (record[field] === undefined || record[field] === null) {
    failures.push(failure("F_SCHEMA_REQUIRED_FIELD", label, "Required object field is missing"));
    return undefined;
  }
  if (!isRecord(record[field])) {
    failures.push(failure("F_SCHEMA_REQUIRED_FIELD", label, "Required field must be a JSON object"));
    return undefined;
  }
  return record[field];
}

function requireArray(
  record: Record<string, unknown>,
  field: string,
  failures: VerificationFailure[],
): unknown[] | undefined {
  if (record[field] === undefined || record[field] === null) {
    failures.push(failure("F_SCHEMA_REQUIRED_FIELD", field, "Required array field is missing"));
    return undefined;
  }
  if (!Array.isArray(record[field])) {
    failures.push(failure("F_SCHEMA_REQUIRED_FIELD", field, "Required field must be an array"));
    return undefined;
  }
  return record[field];
}

function failure(code: VerificationFailureCode, field: string, message: string): VerificationFailure {
  return { code, field, message };
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function messageFromError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function compareFailures(left: VerificationFailure, right: VerificationFailure): number {
  return left.code.localeCompare(right.code)
    || left.field.localeCompare(right.field)
    || left.message.localeCompare(right.message);
}

function compareReports(left: VerificationReport, right: VerificationReport): number {
  return String(left.attestation_hash).localeCompare(String(right.attestation_hash));
}
