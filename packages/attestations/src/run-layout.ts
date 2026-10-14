import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { canonicalJson } from "./canonical-json.ts";
import { assertBytes32Hex, digestAttestation, type DigestObject } from "./digest.ts";
import { digestToCasUri } from "./storage.ts";

export const ATTESTATION_INDEX_SCHEMA_VERSION = "govprov.attestation_index.v1";

export interface AttestationIndex {
  schema_version: typeof ATTESTATION_INDEX_SCHEMA_VERSION;
  run_id: string;
  attestation_count: string;
  attestations: AttestationIndexEntry[];
}

export interface AttestationIndexEntry {
  attestation_hash: string;
  attestation_type: string;
  actor_address: string;
  created_at: string;
  parent_hashes: string[];
  subject_digests: DigestObject[];
  path: string;
  cas_uri: string;
}

export interface WriteRunLayoutOptions {
  runRoot: string;
  runId: string;
  attestations: Record<string, unknown>[];
}

export interface WriteRunLayoutResult {
  index: AttestationIndex;
  indexPath: string;
  runRoot: string;
}

export class AttestationRunLayoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttestationRunLayoutError";
  }
}

export async function writeAttestationRunLayout(options: WriteRunLayoutOptions): Promise<WriteRunLayoutResult> {
  const runRoot = resolveRunRoot(options.runRoot);
  const runId = validateRunId(options.runId);
  const records = options.attestations.map((attestation) => ({
    attestation: attestationObject(attestation),
    metadata: validateSignedAttestation(attestation),
  }));
  const seen = new Set<string>();
  const entries: AttestationIndexEntry[] = [];

  await mkdir(resolveInsideRun(runRoot, "attestations"), { recursive: true });
  await mkdir(resolveInsideRun(runRoot, "objects"), { recursive: true });
  await mkdir(resolveInsideRun(runRoot, "manifests"), { recursive: true });

  for (const record of records) {
    if (seen.has(record.metadata.attestation_hash)) {
      throw new AttestationRunLayoutError(`Duplicate attestation hash: ${record.metadata.attestation_hash}`);
    }
    seen.add(record.metadata.attestation_hash);

    const entry = indexEntryFromMetadata(record.metadata);
    const attestationPath = resolveInsideRun(runRoot, entry.path);
    const objectPath = casObjectPath(runRoot, record.metadata.attestation_hash);
    const content = `${canonicalJson(record.attestation)}\n`;

    await writeStableFile(attestationPath, content);
    await writeStableFile(objectPath, content);
    entries.push(entry);
  }

  entries.sort(compareIndexEntries);

  const index: AttestationIndex = {
    schema_version: ATTESTATION_INDEX_SCHEMA_VERSION,
    run_id: runId,
    attestation_count: String(entries.length),
    attestations: entries,
  };
  const indexPath = resolveInsideRun(runRoot, "manifests/attestation_index.json");
  await writeStableFile(indexPath, `${canonicalJson(index)}\n`);

  return { index, indexPath, runRoot };
}

export function indexEntryForAttestation(attestation: Record<string, unknown>): AttestationIndexEntry {
  return indexEntryFromMetadata(validateSignedAttestation(attestation));
}

function indexEntryFromMetadata(record: ReturnType<typeof validateSignedAttestation>): AttestationIndexEntry {
  const hashNoPrefix = record.attestation_hash.slice(2);
  return {
    attestation_hash: record.attestation_hash,
    attestation_type: record.attestation_type,
    actor_address: record.actor_address,
    created_at: record.created_at,
    parent_hashes: record.parent_hashes,
    subject_digests: record.subject_digests,
    path: `attestations/${attestationTypePath(record.attestation_type)}/${hashNoPrefix}.json`,
    cas_uri: digestToCasUri({ algorithm: "sha256", value: record.attestation_hash }),
  };
}

export function casObjectPath(runRoot: string, attestationHash: string): string {
  assertBytes32Hex(attestationHash);
  const hex = attestationHash.slice(2);
  return resolveInsideRun(resolveRunRoot(runRoot), `objects/sha256/${hex.slice(0, 2)}/${hex.slice(2, 4)}/${hex}.json`);
}

export function validateSignedAttestation(attestation: unknown): {
  attestation_hash: string;
  attestation_type: string;
  actor_address: string;
  created_at: string;
  parent_hashes: string[];
  subject_digests: DigestObject[];
} {
  const record = attestationObject(attestation);
  const attestationHash = stringField(record, "attestation_hash");
  assertBytes32Hex(attestationHash);

  const actual = digestAttestation(record);
  if (actual.value !== attestationHash) {
    throw new AttestationRunLayoutError(
      `Attestation digest mismatch for ${attestationHash}: recomputed ${actual.value}`,
    );
  }

  const createdBy = objectField(record, "created_by");
  const actorAddress = stringField(createdBy, "ethereum_address").toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(actorAddress)) {
    throw new AttestationRunLayoutError(`Malformed actor address: ${actorAddress}`);
  }

  return {
    attestation_hash: attestationHash,
    attestation_type: stringField(record, "attestation_type"),
    actor_address: actorAddress,
    created_at: stringField(record, "created_at"),
    parent_hashes: hashArrayField(record, "parents"),
    subject_digests: subjectDigests(record),
  };
}

function attestationObject(attestation: unknown): Record<string, unknown> {
  if (attestation === null || typeof attestation !== "object" || Array.isArray(attestation)) {
    throw new AttestationRunLayoutError("Attestation must be a JSON object");
  }
  return attestation as Record<string, unknown>;
}

export function resolveInsideRun(runRoot: string, relativePath: string): string {
  const root = resolveRunRoot(runRoot);
  const cleanRelativePath = validateRelativePath(relativePath);
  const absolute = resolve(root, cleanRelativePath);
  const rel = relative(root, absolute);
  if (rel === "" || rel.startsWith("..") || resolve(root, rel) !== absolute) {
    throw new AttestationRunLayoutError(`Resolved path escapes run root: ${relativePath}`);
  }
  return absolute;
}

function resolveRunRoot(runRoot: string): string {
  if (typeof runRoot !== "string" || runRoot.trim() === "") {
    throw new AttestationRunLayoutError("Run root must be a non-empty path");
  }
  return resolve(runRoot);
}

function validateRunId(runId: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(runId)) {
    throw new AttestationRunLayoutError(`Malformed run id: ${runId}`);
  }
  return runId;
}

function validateRelativePath(relativePath: string): string {
  if (
    typeof relativePath !== "string"
    || relativePath.trim() === ""
    || relativePath.includes("\\")
    || relativePath.startsWith("/")
    || /^[A-Za-z]:/.test(relativePath)
    || relativePath.split("/").some((segment) => segment === "" || segment === "." || segment === "..")
  ) {
    throw new AttestationRunLayoutError(`Unsafe relative path: ${relativePath}`);
  }
  return relativePath;
}

async function writeStableFile(path: string, content: string): Promise<void> {
  try {
    const existing = await readFile(path, "utf8");
    if (existing === content) {
      return;
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }

  await mkdir(dirname(path), { recursive: true });
  const tempPath = `${path}.tmp-${process.pid}-${Date.now()}`;
  try {
    await writeFile(tempPath, content, { flag: "wx" });
    await rename(tempPath, path);
  } catch (error) {
    await rm(tempPath, { force: true });
    throw error;
  }
}

function compareIndexEntries(left: AttestationIndexEntry, right: AttestationIndexEntry): number {
  return left.created_at.localeCompare(right.created_at)
    || left.attestation_type.localeCompare(right.attestation_type)
    || left.attestation_hash.localeCompare(right.attestation_hash);
}

function attestationTypePath(attestationType: string): string {
  if (!/^[A-Za-z][A-Za-z0-9]*$/.test(attestationType)) {
    throw new AttestationRunLayoutError(`Unsafe attestation type: ${attestationType}`);
  }
  return attestationType
    .replace(/Attestation$/, "")
    .replace(/Report$/, "_report")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase();
}

function subjectDigests(record: Record<string, unknown>): DigestObject[] {
  const subject = record.subject;
  if (!Array.isArray(subject)) {
    throw new AttestationRunLayoutError("Attestation subject must be an array");
  }
  return subject.map((item, index) => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      throw new AttestationRunLayoutError(`Subject ${index} must be a JSON object`);
    }
    const digest = objectField(item as Record<string, unknown>, "digest");
    const algorithm = stringField(digest, "algorithm");
    if (algorithm !== "sha256") {
      throw new AttestationRunLayoutError(`Unsupported subject digest algorithm: ${algorithm}`);
    }
    const value = stringField(digest, "value");
    assertBytes32Hex(value);
    return { algorithm, value };
  });
}

function hashArrayField(record: Record<string, unknown>, field: string): string[] {
  const value = record[field];
  if (!Array.isArray(value)) {
    throw new AttestationRunLayoutError(`Attestation ${field} must be an array`);
  }
  return value.map((item, index) => {
    if (typeof item !== "string") {
      throw new AttestationRunLayoutError(`Attestation ${field}[${index}] must be a string`);
    }
    assertBytes32Hex(item);
    return item;
  });
}

function objectField(record: Record<string, unknown>, field: string): Record<string, unknown> {
  const value = record[field];
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AttestationRunLayoutError(`Attestation ${field} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function stringField(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new AttestationRunLayoutError(`Attestation ${field} must be a non-empty string`);
  }
  return value;
}
