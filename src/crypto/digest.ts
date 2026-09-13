/** §1.2 domain-separated digests and signature envelopes. */
import { createHash } from "node:crypto";
import { canonicalize } from "../json/jcs.ts";
import type { Hash, Json } from "../types.ts";

export const DIGEST_KINDS = [
  "manifest", "policy", "pin", "input", "request",
  "clause", "audit", "checkpoint", "control",
] as const;
export type DigestKind = (typeof DIGEST_KINDS)[number];

export const SIGN_KINDS = ["policy", "pin", "audit", "checkpoint"] as const;
export type SignKind = (typeof SIGN_KINDS)[number];

export function sha256Hex(data: string | Uint8Array): Hash {
  return createHash("sha256").update(data).digest("hex");
}

/** D(k,x) = hex(SHA256(UTF8("LAGI-CHARTER/" + k + "/1\n") || J(x))). */
export function digest(kind: DigestKind, value: Json): Hash {
  return sha256Hex(`LAGI-CHARTER/${kind}/1\n` + canonicalize(value));
}

/** S(k,x): ASCII bytes an Ed25519 signature covers — "…sign/k/1\n" + D(k,x). */
export function signMessage(kind: SignKind, value: Json): Uint8Array {
  return new TextEncoder().encode(`LAGI-CHARTER/sign/${kind}/1\n` + digest(kind, value));
}
