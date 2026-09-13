/**
 * Ed25519 over the charter/1 signing profile (§1.2): rejects noncanonical
 * encodings, small-order public keys and R points, S >= L, bad lengths.
 * Node's OpenSSL verify is RFC 8032-compatible; the strictness checks below
 * close the remaining permissive corners.
 */
import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import { CharterError } from "../errors.ts";

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

/** Known small-order point encodings (canonical forms), libsodium-style. */
const SMALL_ORDER = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]);

function leInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]!);
  return v;
}

/** Canonicality + small-order checks on a compressed point encoding. */
function checkPoint(bytes: Uint8Array, what: string): void {
  if (bytes.length !== 32) throw new CharterError("SCHEMA", `${what}: bad length`);
  const hex = Buffer.from(bytes).toString("hex");
  if (SMALL_ORDER.has(hex)) throw new CharterError("SIGNATURE_INVALID", `${what}: small-order point`);
  const y = leInt(bytes) & ((1n << 255n) - 1n);
  if (y >= P) throw new CharterError("SIGNATURE_INVALID", `${what}: noncanonical encoding`);
}

export function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new CharterError("SCHEMA", "seed must be 32 bytes");
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const priv = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const pub = createPublicKey(priv).export({ format: "der", type: "spki" });
  return new Uint8Array(pub.subarray(-32));
}

export function publicKeyHexFromSeed(seed: Uint8Array): string {
  return Buffer.from(publicKeyFromSeed(seed)).toString("hex");
}

/** Sign message bytes with a 32-byte seed → 64-byte signature. */
export function signBytes(message: Uint8Array, seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new CharterError("SCHEMA", "seed must be 32 bytes");
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const priv = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  return new Uint8Array(nodeSign(null, message, priv));
}

/**
 * Strict verification. Returns false (not throw) for bad signatures after the
 * structural checks; malformed encodings throw SIGNATURE_INVALID/SCHEMA.
 */
export function verifyBytes(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  if (publicKey.length !== 32) throw new CharterError("SCHEMA", "public key length");
  if (signature.length !== 64) return false;
  const R = signature.subarray(0, 32);
  const S = signature.subarray(32, 64);
  checkPoint(R, "R");
  checkPoint(publicKey, "public key");
  if (leInt(S) >= L) return false; // noncanonical S
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicKey]);
  const pub = createPublicKey({ key: spki, format: "der", type: "spki" });
  return nodeVerify(null, message, pub, signature);
}
