/** verifyBundle (§3.7): historical cryptographic validity + authority continuity. */
import { CharterError } from "../errors.ts";
import { digest, signMessage } from "../crypto/digest.ts";
import { verifyBytes } from "../crypto/ed25519.ts";
import { timeMs } from "../scalars.ts";
import { vBundle } from "../schema/validate.ts";
import { compile } from "./compile.ts";
import { pinFor } from "./cite.ts";
import type {
  Authority, Bundle, Detached, RootFile, Time, Validated, Warning,
} from "../types.ts";
import { ENGINE } from "../types.ts";

const DAY_MS = 86_400_000;

function authorityFor(bundle: Bundle, root: RootFile, predecessors: Bundle[], seen: Set<number>): Authority {
  const { policy } = bundle;
  if (policy.version === 1) {
    if (policy.previous_hash !== null) {
      throw new CharterError("SCHEMA", "genesis requires previous_hash=null");
    }
    return root.bootstrap;
  }
  const prev = predecessors.find((b) => b.policy.version === policy.version - 1);
  if (!prev) throw new CharterError("VERSION_CONFLICT", "missing predecessor bundle");
  if (!seen.has(prev.policy.version)) {
    seen.add(prev.policy.version);
    // Recursively establish the predecessor's own authority chain.
    verifyBundle(prev, root, predecessors, undefined, seen);
  }
  const prevHash = digest("policy", prev.policy);
  if (prevHash !== policy.previous_hash) {
    throw new CharterError("VERSION_CONFLICT", "previous_hash does not bind predecessor");
  }
  if (prev.policy.charter_id !== policy.charter_id || prev.policy.tenant_id !== policy.tenant_id) {
    throw new CharterError("SCHEMA", "predecessor identity mismatch");
  }
  return prev.policy.next_authority;
}

export function verifyBundle(
  rawBundle: Bundle,
  root: RootFile,
  predecessors: Bundle[],
  at?: Time,
  _seen?: Set<number>,
): Validated {
  const bundle = vBundle(rawBundle, "$.bundle");
  const { policy, manifest } = bundle;

  // Identity vs independently pinned root.
  if (policy.tenant_id !== root.tenant_id || policy.charter_id !== root.charter_id) {
    throw new CharterError("SCHEMA", "policy identity does not match root");
  }
  if (manifest.gateway_id !== root.gateway_id) {
    throw new CharterError("SCHEMA", "manifest gateway does not match root");
  }

  // Manifest digest before signature work.
  if (digest("manifest", manifest) !== policy.manifest_hash) {
    throw new CharterError("HASH_MISMATCH", "manifest digest mismatch");
  }

  const authority = authorityFor(bundle, root, predecessors, _seen ?? new Set([policy.version]));

  // Permanent key_id↔public_key binding across the provided chain.
  const keyBytes = new Map<string, string>();
  for (const b of [bundle, ...predecessors]) {
    for (const k of b.policy.next_authority.keys) {
      const prev = keyBytes.get(k.key_id);
      if (prev !== undefined && prev !== k.public_key) {
        throw new CharterError("SCHEMA", `key ${k.key_id} rebound to different public bytes`);
      }
      keyBytes.set(k.key_id, k.public_key);
    }
  }
  for (const k of root.bootstrap.keys) {
    const prev = keyBytes.get(k.key_id);
    if (prev !== undefined && prev !== k.public_key) {
      throw new CharterError("SCHEMA", `key ${k.key_id} rebound vs bootstrap`);
    }
    keyBytes.set(k.key_id, k.public_key);
  }

  // Duplicate key_id in the submitted set.
  const seen = new Set<string>();
  for (const s of bundle.signatures) {
    if (seen.has(s.key_id)) throw new CharterError("SIGNATURE_DUPLICATE", s.key_id);
    seen.add(s.key_id);
  }

  // Unknown signer.
  const authKeys = new Map(authority.keys.map((k) => [k.key_id, k.public_key]));
  for (const s of bundle.signatures) {
    if (!authKeys.has(s.key_id)) throw new CharterError("KEY_UNKNOWN", s.key_id);
  }

  // Every submitted signature must verify — invalid extras fail the bundle.
  const msg = signMessage("policy", policy);
  let valid = 0;
  for (const s of bundle.signatures) {
    const ok = verifyBytes(msg, Buffer.from(s.signature, "base64url"), Buffer.from(authKeys.get(s.key_id)!, "hex"));
    if (!ok) throw new CharterError("SIGNATURE_INVALID", s.key_id);
    valid++;
  }

  // Quorum.
  if (valid < authority.threshold) throw new CharterError("QUORUM", `${valid} < ${authority.threshold}`);

  // Semantic compiler (also rechecks manifest digest and time consistency).
  compile(policy, manifest);

  // Warnings relative to reference time (default issued_at); never affect validity.
  const ref = at !== undefined ? timeMs(at) : timeMs(policy.issued_at);
  const warnings = new Set<Warning>();
  if (policy.scope_rules.length === 0) warnings.add("NO_ALLOW_RULES");
  if (authority.threshold === 1) warnings.add("SINGLE_SIGNER");
  const na = timeMs(policy.not_after);
  if (na > ref && na - ref <= DAY_MS) warnings.add("EXPIRY_WITHIN_24H");

  const pin = { ...pinFor(bundle), engine: ENGINE };
  return {
    valid: true,
    pin,
    signatures: valid,
    required: authority.threshold,
    warnings: [...warnings].sort(),
  };
}

/** Signature-set check shared with pin verification (duplicate → SIGNATURE_DUPLICATE). */
export function checkSignatureSet(signatures: Detached[], authority: Authority, message: Uint8Array): number {
  const seen2 = new Set<string>();
  for (const s of signatures) {
    if (seen2.has(s.key_id)) throw new CharterError("SIGNATURE_DUPLICATE", s.key_id);
    seen2.add(s.key_id);
  }
  const authKeys = new Map(authority.keys.map((k) => [k.key_id, k.public_key]));
  for (const s of signatures) {
    if (!authKeys.has(s.key_id)) throw new CharterError("KEY_UNKNOWN", s.key_id);
  }
  let valid = 0;
  for (const s of signatures) {
    if (!verifyBytes(message, Buffer.from(s.signature, "base64url"), Buffer.from(authKeys.get(s.key_id)!, "hex"))) {
      throw new CharterError("SIGNATURE_INVALID", s.key_id);
    }
    valid++;
  }
  if (valid < authority.threshold) throw new CharterError("QUORUM", `${valid} < ${authority.threshold}`);
  return valid;
}
