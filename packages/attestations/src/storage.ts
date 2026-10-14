import { createHash } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { canonicalJson } from "./canonical-json.ts";
import {
  assertBytes32Hex,
  attestationContentForDigest,
  digestAttestation,
  type DigestAlgorithm,
  type DigestObject,
} from "./digest.ts";

export interface StoredObject {
  algorithm: DigestAlgorithm;
  digest: string;
  uri: string;
  path: string;
  bytes: number;
}

export interface RetrievedAttestation {
  digest: DigestObject;
  uri: string;
  attestation: Record<string, unknown>;
}

export interface RetrievedBlob {
  digest: DigestObject;
  uri: string;
  bytes: Uint8Array;
}

export class ContentAddressMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ContentAddressMismatchError";
  }
}

export class LocalContentAddressedStore {
  readonly root: string;

  constructor(root: string) {
    if (!root || root.trim() === "") {
      throw new TypeError("Store root must be a non-empty path");
    }
    this.root = resolve(root);
  }

  async putAttestation(attestation: unknown): Promise<StoredObject> {
    const digest = digestAttestation(attestation);
    const content = `${canonicalJson(attestation)}\n`;
    const bytes = new TextEncoder().encode(content);
    const path = this.objectPath("attestations", digest, ".json");

    await this.writeVerified(path, bytes, async (existing) => {
      const parsed = JSON.parse(new TextDecoder().decode(existing)) as unknown;
      const existingDigest = digestAttestation(parsed);
      assertDigestMatches(digest, existingDigest, "stored attestation");
    });

    return {
      algorithm: digest.algorithm,
      digest: digest.value,
      uri: digestToCasUri(digest),
      path,
      bytes: bytes.byteLength,
    };
  }

  async getAttestation(digestOrUri: DigestObject | string): Promise<RetrievedAttestation> {
    const digest = normalizeDigestReference(digestOrUri);
    const path = this.objectPath("attestations", digest, ".json");
    const content = await readFile(path);
    const parsed = JSON.parse(new TextDecoder().decode(content)) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new TypeError("Stored attestation must be a JSON object");
    }

    const actual = digestAttestation(parsed);
    assertDigestMatches(digest, actual, "stored attestation");

    return {
      digest,
      uri: digestToCasUri(digest),
      attestation: parsed as Record<string, unknown>,
    };
  }

  async putBlob(bytes: string | Uint8Array): Promise<StoredObject> {
    const data = toBytes(bytes);
    const digest: DigestObject = {
      algorithm: "sha256",
      value: sha256Bytes(data),
    };
    const path = this.objectPath("objects", digest, ".blob");

    await this.writeVerified(path, data, async (existing) => {
      const existingDigest: DigestObject = {
        algorithm: "sha256",
        value: sha256Bytes(existing),
      };
      assertDigestMatches(digest, existingDigest, "stored blob");
    });

    return {
      algorithm: digest.algorithm,
      digest: digest.value,
      uri: digestToCasUri(digest),
      path,
      bytes: data.byteLength,
    };
  }

  async getBlob(digestOrUri: DigestObject | string): Promise<RetrievedBlob> {
    const digest = normalizeDigestReference(digestOrUri);
    const path = this.objectPath("objects", digest, ".blob");
    const bytes = await readFile(path);
    const actual: DigestObject = {
      algorithm: "sha256",
      value: sha256Bytes(bytes),
    };
    assertDigestMatches(digest, actual, "stored blob");

    return {
      digest,
      uri: digestToCasUri(digest),
      bytes,
    };
  }

  attestationPath(digestOrUri: DigestObject | string): string {
    return this.objectPath("attestations", normalizeDigestReference(digestOrUri), ".json");
  }

  blobPath(digestOrUri: DigestObject | string): string {
    return this.objectPath("objects", normalizeDigestReference(digestOrUri), ".blob");
  }

  private objectPath(kind: "attestations" | "objects", digest: DigestObject, extension: ".json" | ".blob"): string {
    const hex = digestPathSegment(digest);
    const path = resolve(this.root, kind, digest.algorithm, hex.slice(0, 2), hex.slice(2, 4), `${hex}${extension}`);
    assertPathWithinRoot(path, this.root);
    return path;
  }

  private async writeVerified(
    path: string,
    bytes: Uint8Array,
    verifyExisting: (existing: Uint8Array) => Promise<void>,
  ): Promise<void> {
    try {
      const existing = await readFile(path);
      await verifyExisting(existing);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
    }

    await mkdir(dirname(path), { recursive: true });
    const tempPath = `${path}.tmp-${process.pid}-${Date.now()}`;
    try {
      await writeFile(tempPath, bytes, { flag: "wx" });
      await rename(tempPath, path);
    } catch (error) {
      await rm(tempPath, { force: true });
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
        throw error;
      }
      const existing = await readFile(path);
      await verifyExisting(existing);
    }
  }
}

export function digestToCasUri(digest: DigestObject): string {
  return `cas://${assertSupportedAlgorithm(digest.algorithm)}/${digestPathSegment(digest)}`;
}

export function parseCasUri(uri: string): DigestObject {
  const match = /^cas:\/\/([^/]+)\/([^/]+)$/.exec(uri);
  if (!match) {
    throw new TypeError(`Malformed CAS URI: ${uri}`);
  }

  const algorithm = assertSupportedAlgorithm(match[1]);
  const hex = match[2];
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new TypeError(`Malformed CAS digest: ${hex}`);
  }

  return {
    algorithm,
    value: `0x${hex}`,
  };
}

export function normalizeDigestReference(digestOrUri: DigestObject | string): DigestObject {
  if (typeof digestOrUri === "string") {
    if (digestOrUri.startsWith("cas://")) {
      return parseCasUri(digestOrUri);
    }
    assertBytes32Hex(digestOrUri);
    return {
      algorithm: "sha256",
      value: digestOrUri,
    };
  }

  const algorithm = assertSupportedAlgorithm(digestOrUri.algorithm);
  assertBytes32Hex(digestOrUri.value);
  return {
    algorithm,
    value: digestOrUri.value,
  };
}

function digestPathSegment(digest: DigestObject): string {
  const normalized = normalizeDigestReference(digest);
  return normalized.value.slice(2);
}

function assertSupportedAlgorithm(algorithm: string): DigestAlgorithm {
  if (algorithm !== "sha256") {
    throw new TypeError(`Unsupported digest algorithm: ${algorithm}`);
  }
  return algorithm;
}

function assertDigestMatches(expected: DigestObject, actual: DigestObject, label: string): void {
  if (expected.algorithm !== actual.algorithm || expected.value !== actual.value) {
    throw new ContentAddressMismatchError(
      `${label} digest mismatch: expected ${expected.algorithm}:${expected.value}, got ${actual.algorithm}:${actual.value}`,
    );
  }
}

function assertPathWithinRoot(path: string, root: string): void {
  const rel = relative(root, path);
  if (rel === "" || rel.startsWith("..") || resolve(root, rel) !== path) {
    throw new TypeError(`Resolved storage path escapes root: ${path}`);
  }
}

function sha256Bytes(input: Uint8Array): string {
  return `0x${createHash("sha256").update(input).digest("hex")}`;
}

function toBytes(input: string | Uint8Array): Uint8Array {
  if (typeof input === "string") {
    return new TextEncoder().encode(input);
  }
  return input;
}

export function verifyAttestationDigest(attestation: unknown, expected: DigestObject): void {
  const actual = {
    algorithm: "sha256" as const,
    value: sha256Bytes(new TextEncoder().encode(canonicalJson(attestationContentForDigest(attestation)))),
  };
  assertDigestMatches(normalizeDigestReference(expected), actual, "attestation");
}
