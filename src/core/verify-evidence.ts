/**
 * §9 offline stream verifier: trusted-root integrity, bundle verification,
 * audit-chain hashes/signatures, checkpoint verification, control-artifact
 * binding, and deterministic replay of recorded decisions.
 *
 * verifyEvidence(evidence, trusted_root, end_checkpoint, replay):
 *   - trusted_root is the externally pinned RootFile; the embedded evidence
 *     root must equal it byte-for-byte (no trust-on-first-use).
 *   - end_checkpoint is the externally held head, or null.
 *   - integrity: VALID = internally sound and anchored; INCOMPLETE = sound
 *     prefix that cannot reach the declared end; INVALID = corruption.
 */
import { CharterError } from "../errors.ts";
import { digest, signMessage, sha256Hex } from "../crypto/digest.ts";
import { verifyBytes } from "../crypto/ed25519.ts";
import { jsonEqual } from "../json/jcs.ts";
import { timeMs } from "../scalars.ts";
import { vAuditEntry, vBundle, vCheckpoint, vRootFile } from "../schema/validate.ts";
import { compile } from "./compile.ts";
import { evaluate } from "./evaluate.ts";
import { checkSignatureSet } from "./verify-bundle.ts";
import type {
  AuditEntry, AuditEvent, Authority, Bundle, Checkpoint, ControlArtifact,
  DecisionData, Evidence, Hash, Json, Pin, RootFile, Verification,
} from "../types.ts";
import { ENGINE } from "../types.ts";

const ZERO_HASH = "0".repeat(64);

export function verifyEvidence(
  ev: Evidence,
  trustedRoot: RootFile,
  endCheckpoint: Checkpoint | null,
  replay: boolean,
): Verification {
  try {
    return verifyInner(ev, trustedRoot, endCheckpoint, replay);
  } catch (e) {
    if (e instanceof CharterError) return bad();
    throw e;
  }
}

function verifyInner(
  ev: Evidence,
  trustedRoot: RootFile,
  endCheckpoint: Checkpoint | null,
  wantReplay: boolean,
): Verification {
  const root = vRootFile(trustedRoot, "$.trusted_root");
  // Embedded root is data, not trust: it must equal the externally pinned root.
  if (!jsonEqual(ev.root as unknown as Json, root as unknown as Json)) return bad();

  // --- structural validation of every element -------------------------
  const bundles = ev.bundles.map((b, i) => vBundle(b, `$.bundles[${i}]`));
  const entries = ev.entries.map((e, i) => vAuditEntry(e, `$.entries[${i}]`));
  const start = ev.start === null ? null : vCheckpoint(ev.start, "$.start");
  const end = vCheckpoint(ev.end, "$.end");
  const controls = ev.controls.map((c, i) => vControlArtifact(c, `$.controls[${i}]`));

  // --- bundle verification ---------------------------------------------
  const bundleByVersion = new Map<number, Bundle>();
  const bundleByHash = new Map<Hash, Bundle>();
  for (const b of bundles) {
    if (digest("manifest", b.manifest) !== b.policy.manifest_hash) return bad();
    if (b.manifest.engine !== ENGINE || b.policy.engine !== ENGINE) return bad();
    if (b.policy.tenant_id !== root.tenant_id || b.policy.charter_id !== root.charter_id ||
        b.manifest.gateway_id !== root.gateway_id) return bad();
    if (bundleByVersion.has(b.policy.version) || bundleByHash.has(digest("policy", b.policy))) return bad();
    if (b.policy.version > 1) {
      const prev = bundleByVersion.get(b.policy.version - 1);
      if (!prev || b.policy.previous_hash !== digest("policy", prev.policy)) return bad();
    } else if (b.policy.previous_hash !== null) {
      return bad();
    }
    const authority: Authority = b.policy.version === 1
      ? root.bootstrap
      : bundleByVersion.get(b.policy.version - 1)!.policy.next_authority;
    try {
      checkSignatureSet(b.signatures, authority, signMessage("policy", b.policy));
      compile(b.policy, b.manifest);
    } catch (e) {
      if (e instanceof CharterError) return bad();
      throw e;
    }
    bundleByVersion.set(b.policy.version, b);
    bundleByHash.set(digest("policy", b.policy), b);
  }

  // --- audit chain -------------------------------------------------------
  const firstWant = (start?.body.through_seq ?? 0) + 1;
  let prevHash = start === null ? ZERO_HASH : start.body.head_hash;
  if (start !== null) {
    if (start.body.tenant_id !== root.tenant_id || start.body.log_id !== root.log_id) return bad();
    if (!verifyCheckpoint(start, root)) return bad();
  }
  let lastMs = -Infinity;
  let expectSeq = firstWant;
  for (const e of entries) {
    const b = e.body;
    if (b.tenant_id !== root.tenant_id || b.log_id !== root.log_id) return bad();
    if (b.seq !== expectSeq) return bad();
    if (b.prev_hash !== prevHash) return bad();
    if (digest("audit", b) !== e.hash) return bad();
    const key = root.audit_keys.find((k) => k.from_seq <= b.seq && (k.through_seq === null || b.seq <= k.through_seq));
    if (!key || key.key_id !== e.key_id) return bad();
    if (!verifyBytes(signMessage("audit", b), Buffer.from(e.signature, "base64url"), Buffer.from(key.public_key, "hex"))) {
      return bad();
    }
    const ms = timeMs(b.time);
    if (ms < lastMs) return bad();
    lastMs = ms;
    prevHash = e.hash;
    expectSeq++;
  }
  const through = entries.length > 0 ? entries[entries.length - 1]!.body.seq : (start?.body.through_seq ?? 0);

  // Control artifacts bound to referencing events, in referencing order.
  const controlBySeq = new Map<number, ControlArtifact>();
  for (const e of entries) {
    const ch = controlHashOf(e.body.event);
    if (ch === null) continue;
    const artifact = controls[controlBySeq.size];
    if (artifact === undefined) {
      return { integrity: "INCOMPLETE", replay: "NOT_REQUESTED", through_seq: e.body.seq, checkpoint_match: false, truth: "NOT_ATTESTED" };
    }
    if (digest("control", artifact as unknown as Json) !== ch) return bad();
    controlBySeq.set(e.body.seq, artifact);
  }

  // --- end checkpoint ------------------------------------------------------
  // The declared end must cover the stream exactly: fewer entries than the
  // claimed head means a missing suffix (INCOMPLETE); more entries than the
  // claimed head, or a bad checkpoint signature, means corruption (INVALID).
  if (!verifyCheckpoint(end, root)) return bad();
  if (through < end.body.through_seq) {
    return { integrity: "INCOMPLETE", replay: "NOT_REQUESTED", through_seq: through, checkpoint_match: false, truth: "NOT_ATTESTED" };
  }
  if (through > end.body.through_seq) return bad();
  const checkpointMatch =
    end.body.tenant_id === root.tenant_id &&
    end.body.log_id === root.log_id &&
    end.body.head_hash === prevHash &&
    (endCheckpoint === null || jsonEqual(end as unknown as Json, endCheckpoint as unknown as Json));
  if (!checkpointMatch) return bad();

  // --- replay ----------------------------------------------------------------
  let replayResult: Verification["replay"] = "NOT_REQUESTED";
  if (wantReplay) {
    if (start !== null) {
      // A checkpoint-started interval cannot reconstruct deployment context.
      replayResult = "CONTEXT_MISSING";
    } else {
      const inputs = new Map(ev.inputs.map((i) => [i.request.request_id, i]));
      replayResult = replayWithInputs(root, bundleByHash, entries, inputs);
    }
  }

  return {
    integrity: "VALID",
    replay: replayResult,
    through_seq: through,
    checkpoint_match: true,
    truth: "NOT_ATTESTED",
  };
}

function verifyCheckpoint(cp: Checkpoint, root: RootFile): boolean {
  const key = root.audit_keys.find((k) =>
    k.from_seq <= cp.body.through_seq && (k.through_seq === null || cp.body.through_seq <= k.through_seq));
  if (!key || key.key_id !== cp.key_id) return false;
  return verifyBytes(signMessage("checkpoint", cp.body),
    Buffer.from(cp.signature, "base64url"), Buffer.from(key.public_key, "hex"));
}

/** Replay every decision event with reconstructed deployment context. */
export function replayWithInputs(
  root: RootFile,
  bundleByHash: Map<Hash, Bundle>,
  entries: AuditEntry[],
  inputs: Map<string, { request: import("../types.ts").CallRequest; principal: import("../types.ts").Principal }>,
): Verification["replay"] {
  let activePin: Pin | null = null;
  for (const e of entries) {
    const b = e.body;
    const ev = b.event;
    if (ev.type === "PinActivated") {
      activePin = ev.value.pin;
    } else if (ev.type === "CheckEvaluated" || ev.type === "CallDenied" || ev.type === "CallCommitted") {
      const dd = ev.value as DecisionData;
      const input = inputs.get(dd.request_id);
      if (!input) return "INPUTS_MISSING";
      if (activePin === null) return "CONTEXT_MISSING";
      const bundle = bundleByHash.get(activePin.policy_hash);
      if (!bundle) return "CONTEXT_MISSING";
      // Reconstruct revocation context bounded by the recorded epoch.
      const revPolicies = new Set<Hash>();
      const revKeys = new Set<string>();
      for (const e2 of entries) {
        if (e2.body.seq >= b.seq) break;
        if (e2.body.event.type === "TargetRevoked" &&
            e2.body.event.value.epoch <= dd.revocation_epoch) {
          const t = e2.body.event.value.target;
          if (t.kind === "policy") revPolicies.add(t.policy_hash);
          else if (t.kind === "policy_key") revKeys.add(t.key_id);
        }
      }
      const authority: Authority | undefined = bundle.policy.version === 1 ? root.bootstrap
        : bundleByHash.get(bundle.policy.previous_hash!)?.policy.next_authority;
      if (!authority) return "CONTEXT_MISSING";
      const authKeys = new Set(authority.keys.map((k) => k.key_id));
      const seen = new Set<string>();
      let eligible = 0;
      for (const s of bundle.signatures) {
        if (revKeys.has(s.key_id) || seen.has(s.key_id) || !authKeys.has(s.key_id)) continue;
        seen.add(s.key_id);
        eligible++;
      }
      const recomputed = evaluate({
        policy: bundle.policy, manifest: bundle.manifest, active_pin: activePin,
        request: input.request, principal: input.principal, now: dd.evaluated_at,
        policy_revoked: revPolicies.has(activePin.policy_hash),
        policy_signatures_valid: eligible >= authority.threshold,
      });
      if (!jsonEqual(recomputed as unknown as Json, dd.decision as unknown as Json)) {
        return "MISMATCH";
      }
    }
  }
  return "MATCH";
}

function controlHashOf(event: AuditEvent): Hash | null {
  const v = event.value as { control_hash?: Hash };
  return v !== null && typeof v === "object" && "control_hash" in v ? v.control_hash! : null;
}

function vControlArtifact(v: unknown, path: string): ControlArtifact {
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new CharterError("SCHEMA", path);
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length !== 2 || !keys.includes("kind") || !keys.includes("value")) throw new CharterError("SCHEMA", path);
  if (o.kind !== "pin" && o.kind !== "pause" && o.kind !== "revoke") throw new CharterError("SCHEMA", path);
  return v as ControlArtifact;
}

function bad(): Verification {
  return { integrity: "INVALID", replay: "NOT_REQUESTED", through_seq: 0, checkpoint_match: false, truth: "NOT_ATTESTED" };
}

export { ZERO_HASH, sha256Hex as _sha256Hex };
