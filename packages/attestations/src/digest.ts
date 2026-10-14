import { createHash } from "node:crypto";
import { canonicalJson } from "./canonical-json.ts";

export type DigestAlgorithm = "sha256";

export interface DigestObject {
  algorithm: DigestAlgorithm;
  value: string;
}

export function sha256Hex(input: string | Uint8Array): string {
  return `0x${createHash("sha256").update(input).digest("hex")}`;
}

export function digestJson(value: unknown): DigestObject {
  return {
    algorithm: "sha256",
    value: sha256Hex(canonicalJson(value)),
  };
}

export function bytes32FromDigest(digest: DigestObject): string {
  if (digest.algorithm !== "sha256") {
    throw new TypeError(`Unsupported digest algorithm for bytes32: ${digest.algorithm}`);
  }
  assertBytes32Hex(digest.value);
  return digest.value;
}

export function attestationContentForDigest(attestation: unknown): unknown {
  if (attestation === null || typeof attestation !== "object" || Array.isArray(attestation)) {
    throw new TypeError("Attestation must be a JSON object");
  }

  const copy = structuredClone(attestation) as Record<string, unknown>;
  delete copy.signature;
  delete copy.attestation_hash;
  return copy;
}

export function digestAttestation(attestation: unknown): DigestObject {
  return digestJson(attestationContentForDigest(attestation));
}

export function attestationBytes32(attestation: unknown): string {
  return bytes32FromDigest(digestAttestation(attestation));
}

export function assertBytes32Hex(value: string): void {
  if (!/^0x[0-9a-f]{64}$/.test(value)) {
    throw new TypeError(`Expected lowercase 0x-prefixed bytes32 hex string: ${value}`);
  }
}
