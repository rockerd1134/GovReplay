import { createHmac } from "node:crypto";
import { digestAttestation, digestJson, type DigestObject } from "./digest.ts";

export const SIGNATURE_PROFILE = "govprov-ethsign-secp256k1-v1";

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const HALF_N = N >> 1n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

export interface AttestationSignature {
  profile: typeof SIGNATURE_PROFILE;
  signature: string;
  signer: string;
}

export interface AttestationSigningPayload {
  profile: typeof SIGNATURE_PROFILE;
  schema_version: string;
  attestation_type: string;
  attestation_hash: DigestObject;
  signing_input: string;
  signing_input_digest: DigestObject;
}

export interface SignedAttestation extends Record<string, unknown> {
  attestation_hash: string;
  signature: AttestationSignature;
}

type Point = { x: bigint; y: bigint } | null;

export function signingPayloadForAttestation(attestation: Record<string, unknown>): AttestationSigningPayload {
  const schemaVersion = stringField(attestation, "schema_version");
  const attestationType = stringField(attestation, "attestation_type");
  const attestationHash = digestAttestation(attestation);
  const signingInput = [
    "GovReplay Attestation v1",
    `schema_version=${schemaVersion}`,
    `attestation_type=${attestationType}`,
    `attestation_hash=${attestationHash.value}`,
  ].join("\n");

  return {
    profile: SIGNATURE_PROFILE,
    schema_version: schemaVersion,
    attestation_type: attestationType,
    attestation_hash: attestationHash,
    signing_input: signingInput,
    signing_input_digest: digestJson(signingInput),
  };
}

export function signAttestation(
  attestation: Record<string, unknown>,
  privateKeyHex: string,
): SignedAttestation {
  const payload = signingPayloadForAttestation(attestation);
  const privateKey = parsePrivateKey(privateKeyHex);
  const signer = addressFromPrivateKey(privateKeyHex);
  const messageHash = personalSignMessageHash(payload.signing_input);
  const signature = signMessageHash(messageHash, privateKey);

  return {
    ...structuredClone(attestation),
    attestation_hash: payload.attestation_hash.value,
    signature: {
      profile: SIGNATURE_PROFILE,
      signature,
      signer,
    },
  };
}

export function recoverAttestationSigner(attestation: Record<string, unknown>): string {
  const signature = signatureObject(attestation.signature);
  const payload = signingPayloadForAttestation(attestation);
  return recoverSignerAddress(payload.signing_input, signature.signature);
}

export function verifyAttestationSignature(
  attestation: Record<string, unknown>,
  expectedAddress = actorAddress(attestation),
): boolean {
  const signature = signatureObject(attestation.signature);
  if (signature.profile !== SIGNATURE_PROFILE) {
    throw new TypeError(`Unsupported signature profile: ${signature.profile}`);
  }

  const attestationHash = digestAttestation(attestation).value;
  const claimedHash = attestation.attestation_hash;
  if (typeof claimedHash === "string" && claimedHash !== attestationHash) {
    return false;
  }

  const recovered = recoverAttestationSigner(attestation);
  return normalizeAddress(recovered) === normalizeAddress(signature.signer)
    && normalizeAddress(recovered) === normalizeAddress(expectedAddress);
}

export function recoverSignerAddress(message: string, signatureHex: string): string {
  return recoverSignerAddressFromBytes(new TextEncoder().encode(message), signatureHex);
}

export function recoverSignerAddressFromBytes(messageBytes: Uint8Array, signatureHex: string): string {
  const messageHash = personalSignMessageHashBytes(messageBytes);
  const { r, s, recovery } = parseSignature(signatureHex);
  const publicKey = recoverPublicKey(messageHash, r, s, recovery);
  return addressFromPublicKey(publicKey);
}

export function addressFromPrivateKey(privateKeyHex: string): string {
  const privateKey = parsePrivateKey(privateKeyHex);
  const publicKey = scalarMultiply(privateKey, { x: GX, y: GY });
  if (publicKey === null) {
    throw new TypeError("Invalid private key");
  }
  return addressFromPublicKey(publicKey);
}

function signMessageHash(messageHash: Uint8Array, privateKey: bigint): string {
  const z = bytesToBigInt(messageHash);

  for (let attempt = 0; attempt < 1024; attempt += 1) {
    const k = deterministicK(privateKey, messageHash, attempt);
    const point = scalarMultiply(k, { x: GX, y: GY });
    if (point === null) {
      continue;
    }

    const r = mod(point.x, N);
    if (r === 0n) {
      continue;
    }

    const candidateS = mod(invert(k, N) * (z + r * privateKey), N);
    if (candidateS === 0n) {
      continue;
    }

    const useLowS = candidateS > HALF_N;
    const s = useLowS ? N - candidateS : candidateS;
    const yParity = Number(point.y & 1n) ^ (useLowS ? 1 : 0);
    return `0x${hex32(r)}${hex32(s)}${(27 + yParity).toString(16).padStart(2, "0")}`;
  }

  throw new Error("Unable to produce deterministic signature");
}

function recoverPublicKey(messageHash: Uint8Array, r: bigint, s: bigint, recovery: number): Exclude<Point, null> {
  if (r <= 0n || r >= N || s <= 0n || s > HALF_N) {
    throw new TypeError("Malformed ECDSA signature");
  }

  const x = r + BigInt(Math.floor(recovery / 2)) * N;
  if (x >= P) {
    throw new TypeError("Signature recovery point is out of range");
  }

  const y = yFromX(x, recovery % 2);
  const rPoint = { x, y };
  if (scalarMultiply(N, rPoint) !== null) {
    throw new TypeError("Invalid signature recovery point");
  }

  const z = bytesToBigInt(messageHash);
  const rInv = invert(r, N);
  const u1 = mod(-z * rInv, N);
  const u2 = mod(s * rInv, N);
  const publicKey = pointAdd(scalarMultiply(u1, { x: GX, y: GY }), scalarMultiply(u2, rPoint));
  if (publicKey === null) {
    throw new TypeError("Invalid recovered public key");
  }
  return publicKey;
}

function personalSignMessageHash(message: string): Uint8Array {
  return personalSignMessageHashBytes(new TextEncoder().encode(message));
}

function personalSignMessageHashBytes(messageBytes: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${messageBytes.length}`);
  const input = new Uint8Array(prefix.length + messageBytes.length);
  input.set(prefix);
  input.set(messageBytes, prefix.length);
  return keccak256(input);
}

function addressFromPublicKey(publicKey: Exclude<Point, null>): string {
  const encoded = new Uint8Array(64);
  encoded.set(bigIntToBytes(publicKey.x, 32), 0);
  encoded.set(bigIntToBytes(publicKey.y, 32), 32);
  return `0x${bytesToHex(keccak256(encoded).slice(-20))}`;
}

function deterministicK(privateKey: bigint, messageHash: Uint8Array, attempt: number): bigint {
  let k = new Uint8Array(32);
  let v = new Uint8Array(32).fill(1);
  const key = bigIntToBytes(privateKey, 32);
  const attemptBytes = new Uint8Array([attempt >> 8, attempt & 0xff]);

  k = hmac(k, concat(v, new Uint8Array([0]), key, messageHash, attemptBytes));
  v = hmac(k, v);
  k = hmac(k, concat(v, new Uint8Array([1]), key, messageHash, attemptBytes));
  v = hmac(k, v);

  for (;;) {
    v = hmac(k, v);
    const candidate = bytesToBigInt(v);
    if (candidate > 0n && candidate < N) {
      return candidate;
    }
    k = hmac(k, concat(v, new Uint8Array([0])));
    v = hmac(k, v);
  }
}

function parsePrivateKey(privateKeyHex: string): bigint {
  const value = parseHex(privateKeyHex, 32, "private key");
  const key = bytesToBigInt(value);
  if (key <= 0n || key >= N) {
    throw new TypeError("Private key is out of secp256k1 range");
  }
  return key;
}

function parseSignature(signatureHex: string): { r: bigint; s: bigint; recovery: number } {
  const signature = parseHex(signatureHex, 65, "signature");
  const v = signature[64];
  if (v !== 27 && v !== 28) {
    throw new TypeError(`Unsupported recovery id: ${v}`);
  }
  return {
    r: bytesToBigInt(signature.slice(0, 32)),
    s: bytesToBigInt(signature.slice(32, 64)),
    recovery: v - 27,
  };
}

function signatureObject(value: unknown): AttestationSignature {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Attestation signature is required");
  }
  const signature = value as Record<string, unknown>;
  if (signature.profile !== SIGNATURE_PROFILE) {
    throw new TypeError(`Unsupported signature profile: ${String(signature.profile)}`);
  }
  if (typeof signature.signature !== "string") {
    throw new TypeError("Signature value is required");
  }
  if (typeof signature.signer !== "string") {
    throw new TypeError("Signature signer is required");
  }
  return {
    profile: signature.profile,
    signature: signature.signature,
    signer: signature.signer,
  };
}

function actorAddress(attestation: Record<string, unknown>): string {
  const createdBy = attestation.created_by;
  if (createdBy === null || typeof createdBy !== "object" || Array.isArray(createdBy)) {
    throw new TypeError("Attestation created_by actor is required");
  }
  return stringField(createdBy as Record<string, unknown>, "ethereum_address");
}

function stringField(value: Record<string, unknown>, field: string): string {
  const item = value[field];
  if (typeof item !== "string" || item.length === 0) {
    throw new TypeError(`Attestation ${field} must be a non-empty string`);
  }
  return item;
}

function normalizeAddress(address: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new TypeError(`Malformed Ethereum address: ${address}`);
  }
  return address.toLowerCase();
}

function pointAdd(left: Point, right: Point): Point {
  if (left === null) {
    return right;
  }
  if (right === null) {
    return left;
  }
  if (left.x === right.x) {
    if (mod(left.y + right.y, P) === 0n) {
      return null;
    }
    return pointDouble(left);
  }
  const slope = mod((right.y - left.y) * invert(right.x - left.x, P), P);
  const x = mod(slope * slope - left.x - right.x, P);
  const y = mod(slope * (left.x - x) - left.y, P);
  return { x, y };
}

function pointDouble(point: Exclude<Point, null>): Point {
  if (point.y === 0n) {
    return null;
  }
  const slope = mod(3n * point.x * point.x * invert(2n * point.y, P), P);
  const x = mod(slope * slope - 2n * point.x, P);
  const y = mod(slope * (point.x - x) - point.y, P);
  return { x, y };
}

function scalarMultiply(scalar: bigint, point: Exclude<Point, null>): Point {
  let n = mod(scalar, N);
  let result: Point = null;
  let addend: Point = point;
  while (n > 0n) {
    if ((n & 1n) === 1n) {
      result = pointAdd(result, addend);
    }
    addend = addend === null ? null : pointDouble(addend);
    n >>= 1n;
  }
  return result;
}

function yFromX(x: bigint, parity: number): bigint {
  const alpha = mod(x ** 3n + 7n, P);
  const beta = powMod(alpha, (P + 1n) >> 2n, P);
  const y = Number(beta & 1n) === parity ? beta : P - beta;
  if (mod(y * y, P) !== alpha) {
    throw new TypeError("Signature recovery point is not on the curve");
  }
  return y;
}

function invert(value: bigint, modulo: bigint): bigint {
  let a = mod(value, modulo);
  let b = modulo;
  let x = 0n;
  let y = 1n;
  let u = 1n;
  let v = 0n;

  while (a !== 0n) {
    const q = b / a;
    [x, u] = [u, x - u * q];
    [y, v] = [v, y - v * q];
    [b, a] = [a, b - a * q];
  }
  if (b !== 1n) {
    throw new TypeError("Value has no modular inverse");
  }
  return mod(x, modulo);
}

function powMod(base: bigint, exponent: bigint, modulo: bigint): bigint {
  let result = 1n;
  let b = mod(base, modulo);
  let e = exponent;
  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = mod(result * b, modulo);
    }
    b = mod(b * b, modulo);
    e >>= 1n;
  }
  return result;
}

function mod(value: bigint, modulo: bigint): bigint {
  const result = value % modulo;
  return result >= 0n ? result : result + modulo;
}

function parseHex(value: string, byteLength: number, label: string): Uint8Array {
  const pattern = new RegExp(`^0x[0-9a-fA-F]{${byteLength * 2}}$`);
  if (!pattern.test(value)) {
    throw new TypeError(`Malformed ${label}`);
  }
  const bytes = new Uint8Array(byteLength);
  for (let index = 0; index < byteLength; index += 1) {
    bytes[index] = Number.parseInt(value.slice(2 + index * 2, 4 + index * 2), 16);
  }
  return bytes;
}

function bigIntToBytes(value: bigint, byteLength: number): Uint8Array {
  const hex = value.toString(16).padStart(byteLength * 2, "0");
  return parseHex(`0x${hex}`, byteLength, "integer");
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt(`0x${bytesToHex(bytes)}`);
}

function hex32(value: bigint): string {
  return value.toString(16).padStart(64, "0");
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(arrays.reduce((sum, item) => sum + item.length, 0));
  let offset = 0;
  for (const array of arrays) {
    output.set(array, offset);
    offset += array.length;
  }
  return output;
}

function hmac(key: Uint8Array, data: Uint8Array): Uint8Array {
  return createHmac("sha256", key).update(data).digest();
}

function keccak256(input: Uint8Array): Uint8Array {
  const state = new BigUint64Array(25);
  const rate = 136;
  let offset = 0;

  while (offset + rate <= input.length) {
    absorbBlock(state, input.slice(offset, offset + rate));
    keccakF1600(state);
    offset += rate;
  }

  const block = new Uint8Array(rate);
  block.set(input.slice(offset));
  block[input.length - offset] = 0x01;
  block[rate - 1] |= 0x80;
  absorbBlock(state, block);
  keccakF1600(state);

  const output = new Uint8Array(32);
  let outputOffset = 0;
  while (outputOffset < output.length) {
    const blockBytes = stateToBytes(state, rate);
    const count = Math.min(rate, output.length - outputOffset);
    output.set(blockBytes.slice(0, count), outputOffset);
    outputOffset += count;
    if (outputOffset < output.length) {
      keccakF1600(state);
    }
  }
  return output;
}

function absorbBlock(state: BigUint64Array, block: Uint8Array): void {
  for (let index = 0; index < block.length / 8; index += 1) {
    state[index] ^= bytesToLane(block, index * 8);
  }
}

function stateToBytes(state: BigUint64Array, byteLength: number): Uint8Array {
  const output = new Uint8Array(byteLength);
  for (let index = 0; index < byteLength / 8; index += 1) {
    laneToBytes(state[index], output, index * 8);
  }
  return output;
}

function bytesToLane(bytes: Uint8Array, offset: number): bigint {
  let lane = 0n;
  for (let index = 0; index < 8; index += 1) {
    lane |= BigInt(bytes[offset + index] ?? 0) << BigInt(8 * index);
  }
  return lane;
}

function laneToBytes(lane: bigint, output: Uint8Array, offset: number): void {
  for (let index = 0; index < 8; index += 1) {
    output[offset + index] = Number((lane >> BigInt(8 * index)) & 0xffn);
  }
}

const ROUND_CONSTANTS = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

const ROTATION_OFFSETS = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];

function keccakF1600(state: BigUint64Array): void {
  for (const roundConstant of ROUND_CONSTANTS) {
    const c = new Array<bigint>(5);
    for (let x = 0; x < 5; x += 1) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    const d = new Array<bigint>(5);
    for (let x = 0; x < 5; x += 1) {
      d[x] = c[(x + 4) % 5] ^ rotateLeft64(c[(x + 1) % 5], 1);
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        state[x + 5 * y] = mask64(state[x + 5 * y] ^ d[x]);
      }
    }

    const b = new Array<bigint>(25);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotateLeft64(state[x + 5 * y], ROTATION_OFFSETS[x + 5 * y]);
      }
    }

    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        state[x + 5 * y] = mask64(b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & b[((x + 2) % 5) + 5 * y]));
      }
    }

    state[0] = mask64(state[0] ^ roundConstant);
  }
}

function rotateLeft64(value: bigint, shift: number): bigint {
  const n = BigInt(shift % 64);
  if (n === 0n) {
    return mask64(value);
  }
  return mask64((value << n) | (value >> (64n - n)));
}

function mask64(value: bigint): bigint {
  return value & 0xffffffffffffffffn;
}
