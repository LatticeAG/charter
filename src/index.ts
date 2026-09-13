/**
 * CharterCore — the §3.7 pure SDK surface. Parser/compiler throw exact
 * ErrorCode values and never return partial policy objects.
 */
import { CharterError } from "./errors.ts";
import { digest as digestImpl, signMessage } from "./crypto/digest.ts";
import { signBytes } from "./crypto/ed25519.ts";
import { canonicalize as canon } from "./json/jcs.ts";
import { parseJsonBytes, parseJsonText } from "./json/strict.ts";
import { parseYamlSubset } from "./yaml/subset.ts";
import { vBundle, vCheckpoint, vPinCommand, vPolicy, vRootFile } from "./schema/validate.ts";
import { compile as compileImpl } from "./core/compile.ts";
import { evaluate as evaluateImpl } from "./core/evaluate.ts";
import { cite as citeImpl } from "./core/cite.ts";
import { diff as diffImpl } from "./core/diff.ts";
import { verifyBundle as verifyBundleImpl } from "./core/verify-bundle.ts";
import { verifyEvidence as verifyEvidenceImpl } from "./core/verify-evidence.ts";
import { secretRef } from "./config.ts";
import type {
  Bundle, Checkpoint, Compiled, Decision, Detached, Diff, Evidence, EvalInput,
  Hash, Json, Linted, Manifest, PinCommand, Policy, RootFile, Time, Validated, Verification,
} from "./types.ts";

export type { Compiled, Decision, Detached, Diff, Evidence, EvalInput, Linted, Manifest, Policy, Validated, Verification };
export { CharterError } from "./errors.ts";

/** Strict parse of a policy source. Throws CharterError with exact code. */
export function parsePolicy(bytes: Uint8Array, format: "json" | "yaml"): Policy {
  const text = new TextDecoder().decode(bytes);
  const v = format === "json" ? parseJsonText(text) : (parseYamlSubset(text) as Json);
  return vPolicy(v, "$");
}

/** Canonical JCS bytes of a validated policy. */
export function canonicalize(policy: Policy): Uint8Array {
  return new TextEncoder().encode(canon(policy as unknown as Json));
}

export function digest(
  kind: "manifest" | "policy" | "pin" | "input" | "request" | "clause" | "audit" | "checkpoint" | "control",
  value: Json,
): Hash {
  return digestImpl(kind, value);
}

export function verifyBundle(bundle: Bundle, root: RootFile, predecessors: Bundle[], at?: Time): Validated {
  return verifyBundleImpl(
    vBundle(bundle, "$.bundle"), vRootFile(root, "$.root"),
    predecessors.map((b, i) => vBundle(b, `$.predecessors[${i}]`)), at);
}

export function compile(policy: Policy, manifest: Manifest): Compiled {
  return compileImpl(policy, manifest);
}

export function evaluate(input: EvalInput): Decision {
  return evaluateImpl(input);
}

export function cite(bundle: Bundle, rule_id: import("./types.ts").RuleId): import("./types.ts").Citation {
  return citeImpl(bundle, rule_id);
}

export function diff(oldPolicy: Policy, newPolicy: Policy): Diff {
  return diffImpl(oldPolicy, newPolicy);
}

/**
 * Detached signature over a Policy or PinCommand. `key_handle` is a §5 secret
 * reference (`env:NAME`); the test harness additionally maps `fixture:N` to
 * the public RFC 8032 seed list — production handles cannot name fixtures.
 */
export function sign(kind: "policy" | "pin", value: Policy | PinCommand, key_id: import("./types.ts").KeyId, key_handle: string): Detached {
  const seed = resolveHandle(key_handle);
  const checked = kind === "policy" ? vPolicy(value, "$") : vPinCommand(value, "$");
  return {
    key_id,
    signature: Buffer.from(signBytes(signMessage(kind, checked), seed)).toString("base64url"),
  };
}

function resolveHandle(handle: string): Uint8Array {
  if (/^fixture:[0-2]$/.test(handle)) {
    // Test-only handle: public fixture seeds, rejected by production config.
    const seeds = [
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    ];
    return new Uint8Array(Buffer.from(seeds[Number(handle.slice(8))]!, "hex"));
  }
  const raw = new TextDecoder().decode(secretRef(handle));
  const seed = Buffer.from(raw, "base64url");
  if (seed.length !== 32 || seed.toString("base64url") !== raw) {
    throw new CharterError("SCHEMA", "key handle does not resolve to 32-byte base64url seed");
  }
  return new Uint8Array(seed);
}

export function verifyEvidence(
  evidence: Evidence,
  trusted_root: RootFile,
  end_checkpoint: Checkpoint | null,
  replay: boolean,
): Verification {
  const root = vRootFile(trusted_root, "$.trusted_root");
  const end = end_checkpoint === null ? null : vCheckpoint(end_checkpoint, "$.end_checkpoint");
  return verifyEvidenceImpl(evidence, root, end, replay);
}

/** Strict-JSON bytes → value helper for offline tooling. */
export function parseJson(bytes: Uint8Array): Json {
  return parseJsonBytes(bytes) as Json;
}
