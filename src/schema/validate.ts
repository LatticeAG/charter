/**
 * Closed-schema validators (§1.1): every declared field required including
 * nullables; unknown properties rejected; set arrays sorted and unique on
 * arrival. All failures are CharterError(SCHEMA).
 */
import { CharterError, ERROR_CODES } from "../errors.ts";
import { canonicalize } from "../json/jcs.ts";
import {
  isHash, isId, isInt, isLabel, isNfc, isPublic, isRepository, isResource,
  isScalar, isSignature, isTime, isToolName, require, utf8Bytes,
  type IdPrefix,
} from "../scalars.ts";
import type {
  AdapterRequest, AdapterResponse, AuditEntry, AuditEvent, AuditKey,
  AuditPage, Authority, AuthFile, AuthRecord, Bundle, CallRequest, CallResult,
  CheckResult, Checkpoint, Citation, Compiled, Config, ControlArtifact,
  ControlResult, Deployment, Detached, Dispute, DisputeRequest, EncryptionKeys, Evidence,
  ExportBundle, ExportControl, ExportEntry, ExportHeader, ExportInput,
  ExportTrailer, Field, Fleet, Heartbeat, HeartbeatResult, InstanceView, Json,
  Key, Manifest, MetricSnapshot, PauseRequest, Pin, PinCommand, Policy,
  Predicate, Principal, ProofLink, Revocation, RevokeRequest, RevokeResult,
  RevokeTarget, RootFile, Rule, Scalar, Selector, SignedPin, Source, Time,
  Tool, Validated, Verification,
} from "../types.ts";
import { ENGINE } from "../types.ts";

type V<T> = (v: unknown, path: string) => T;

function fail(path: string, what: string): never {
  throw new CharterError("SCHEMA", `${path}: ${what}`);
}

export function obj<T>(v: unknown, path: string, spec: Record<string, (x: unknown, p: string) => unknown>): T {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail(path, "not an object");
  const o = v as Record<string, unknown>;
  const want = Object.keys(spec).sort();
  const got = Object.keys(o).sort();
  if (want.length !== got.length || !want.every((k, i) => k === got[i])) {
    const missing = want.filter((k) => !(k in o));
    const extra = got.filter((k) => !(k in spec));
    fail(path, `closed object violation (missing: ${missing.join(",") || "-"}; unknown: ${extra.join(",") || "-"})`);
  }
  const out: Record<string, unknown> = {};
  for (const k of want) out[k] = spec[k]!(o[k], `${path}.${k}`);
  return out as T;
}

export function arr<T>(v: unknown, path: string, item: V<T>, opts: {
  min?: number; max?: number; sortCmp?: (a: T, b: T) => number; uniqueCmp?: (a: T, b: T) => number;
} = {}): T[] {
  if (!Array.isArray(v)) fail(path, "not an array");
  if (opts.min !== undefined && v.length < opts.min) fail(path, `fewer than ${opts.min} elements`);
  if (opts.max !== undefined && v.length > opts.max) fail(path, `more than ${opts.max} elements`);
  const out = v.map((x, i) => item(x, `${path}[${i}]`));
  const cmp = opts.sortCmp ?? opts.uniqueCmp;
  if (cmp) {
    for (let i = 1; i < out.length; i++) {
      const c = cmp(out[i - 1]!, out[i]!);
      if (opts.uniqueCmp && c === 0) fail(path, "duplicate set member");
      if (opts.sortCmp && c >= 0) fail(path, "set not strictly sorted");
    }
  }
  return out;
}

function byteCmp(a: string, b: string): number {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return Buffer.compare(ab, bb);
}

function canonCmp(a: unknown, b: unknown): number {
  return byteCmp(canonicalize(a as Json), canonicalize(b as Json));
}

const int: V<number> = (v, p) => (isInt(v) ? v : fail(p, "not Int"));
const boundedInt = (min: number, max: number): V<number> => (v, p) =>
  isInt(v) && v >= min && v <= max ? v : fail(p, `int outside [${min},${max}]`);
const str: V<string> = (v, p) => (typeof v === "string" && isNfc(v) ? v : fail(p, "not NFC string"));
const bool: V<boolean> = (v, p) => (typeof v === "boolean" ? v : fail(p, "not boolean"));
const nul: V<null> = (v, p) => (v === null ? null : fail(p, "not null"));
const hash: V<string> = (v, p) => (isHash(v) ? v : fail(p, "not Hash"));
const pub: V<string> = (v, p) => (isPublic(v) ? v : fail(p, "not Public"));
const sig: V<string> = (v, p) => (isSignature(v) ? v : fail(p, "not Signature"));
const time: V<Time> = (v, p) => (isTime(v) ? v : fail(p, "not Time"));
const label: V<string> = (v, p) => (isLabel(v) ? v : fail(p, "not Label"));
const toolName: V<string> = (v, p) => (isToolName(v) ? v : fail(p, "not ToolName"));
const resource: V<string> = (v, p) => (isResource(v) ? v : fail(p, "not Resource"));
const idOf = (prefix: IdPrefix): V<string> => (v, p) => (isId(v, prefix) ? v : fail(p, `not ID<${prefix}>`));
const scalar: V<Scalar> = (v, p) => (isScalar(v) && (typeof v !== "string" || isNfc(v)) ? v : fail(p, "not Scalar"));
const nullable = <T>(inner: V<T>): V<T | null> => (v, p) => (v === null ? null : inner(v, p));
const oneOf = <T extends string>(...xs: T[]): V<T> => (v, p) =>
  (xs as readonly string[]).includes(v as string) ? (v as T) : fail(p, `not one of ${xs.join("|")}`);
const maxBytesStr = (n: number): V<string> => (v, p) =>
  typeof v === "string" && isNfc(v) && utf8Bytes(v) <= n ? v : fail(p, `string > ${n} bytes`);
const rangedStr = (min: number, max: number): V<string> => (v, p) =>
  typeof v === "string" && isNfc(v) && utf8Bytes(v) >= min && utf8Bytes(v) <= max
    ? v : fail(p, `string outside ${min}..${max} bytes`);

export const vJson: V<Json> = (v, p) => {
  if (v === null || typeof v === "boolean") return v;
  if (typeof v === "number") return isInt(v) ? v : fail(p, "not Int");
  if (typeof v === "string") return isNfc(v) ? v : fail(p, "not NFC");
  if (Array.isArray(v)) {
    if (v.length > 256) fail(p, "array > 256");
    return v.map((x, i) => vJson(x, `${p}[${i}]`)) as Json;
  }
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o);
    if (keys.length > 256) fail(p, "members > 256");
    const out: Record<string, Json> = {};
    for (const k of keys) {
      if (!isNfc(k)) fail(p, "non-NFC member name");
      out[k] = vJson(o[k], `${p}.${k}`);
    }
    return out;
  }
  return fail(p, "not Json");
};

/* ---------- §1.3 objects ---------- */

export const vKey: V<Key> = (v, p) => obj<Key>(v, p, { key_id: idOf("cky"), public_key: pub });

export const vAuthority: V<Authority> = (v, p) => {
  const a = obj<Authority>(v, p, {
    threshold: boundedInt(1, 8),
    keys: (x, pp) => arr(x, pp, vKey, { min: 1, max: 8, sortCmp: (a2, b2) => byteCmp(a2.key_id, b2.key_id), uniqueCmp: (a2, b2) => byteCmp(a2.key_id, b2.key_id) }),
  });
  if (a.threshold > a.keys.length) fail(`${p}.threshold`, "exceeds key count");
  const pubs = new Set(a.keys.map((k) => k.public_key));
  if (pubs.size !== a.keys.length) fail(`${p}.keys`, "public-key alias");
  return a;
};

export const vDetached: V<Detached> = (v, p) => obj<Detached>(v, p, { key_id: idOf("cky"), signature: sig });

/**
 * Detached signature set: 1–8 entries in non-decreasing key_id order. An
 * out-of-order set is SCHEMA; repeated key_id stays structurally valid so the
 * signature stage can report SIGNATURE_DUPLICATE (§2 error ordering).
 */
export const vDetachedSet: V<Detached[]> = (v, p) => {
  const out = arr(v, p, vDetached, { min: 1, max: 8 });
  for (let i = 1; i < out.length; i++) {
    if (byteCmp(out[i - 1]!.key_id, out[i]!.key_id) > 0) fail(p, "unsorted signature set");
  }
  return out;
};

export const vSource: V<Source> = (v, p) => obj<Source>(v, p, {
  repository: (x, pp) => (isRepository(x) ? x : fail(pp, "not repository")),
  pull_request: boundedInt(1, 2147483647),
  commit: (x, pp) => (typeof x === "string" && /^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(x) ? x : fail(pp, "not 40|64 hex commit")),
});

export const vSelector: V<Selector> = (v, p) => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail(p, "not object");
  const m = (v as Record<string, unknown>).match;
  if (m === "all") return obj<Selector>(v, p, { match: oneOf("all") });
  return obj<Selector>(v, p, { match: oneOf("exact", "segment_prefix"), value: resource });
};

export const vPredicate: V<Predicate> = (v, p) => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail(p, "not object");
  const op = (v as Record<string, unknown>).op;
  if (op === "eq") return obj<Predicate>(v, p, { arg: label, op: oneOf("eq"), value: scalar });
  if (op === "int_lte") return obj<Predicate>(v, p, { arg: label, op: oneOf("int_lte"), value: int });
  fail(p, "unknown predicate op");
};

const principalOrStar = (v: unknown, p: string): string =>
  v === "*" ? "*" : isId(v, "cpr") ? v : fail(p, "not PrincipalId|*");

const scopeOrStar = (v: unknown, p: string): string =>
  v === "*" ? "*" : isLabel(v) ? v : fail(p, "not Label|*");

export function vRule(hard: boolean): V<Rule> {
  return (v, p) => {
    const r = obj<Rule>(v, p, {
      id: idOf("crl"),
      text: rangedStr(1, 512),
      principals: (x, pp) => arr(x, pp, principalOrStar, { min: 1, max: 32, sortCmp: byteCmp, uniqueCmp: byteCmp }),
      tools: (x, pp) => arr(x, pp, toolName, { min: 1, max: 32, sortCmp: byteCmp, uniqueCmp: byteCmp }),
      scopes: (x, pp) => arr(x, pp, scopeOrStar, { min: 1, max: 32, sortCmp: byteCmp, uniqueCmp: byteCmp }),
      resources: (x, pp) => arr(x, pp, vSelector, { min: 1, max: 16, sortCmp: canonCmp, uniqueCmp: canonCmp }),
      when: (x, pp) => arr(x, pp, vPredicate, { min: 0, max: 16, sortCmp: canonCmp, uniqueCmp: canonCmp }),
    });
    if (r.principals.includes("*") && r.principals.length !== 1) fail(`${p}.principals`, "'*' must stand alone");
    if (r.scopes.includes("*") && r.scopes.length !== 1) fail(`${p}.scopes`, "'*' must stand alone");
    if (!hard) {
      if (r.scopes.includes("*")) fail(`${p}.scopes`, "wildcard scope in allow rule");
      if (r.resources.some((s) => s.match === "all")) fail(`${p}.resources`, "selector 'all' in allow rule");
    }
    return r;
  };
}

export const vField: V<Field> = (v, p) => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail(p, "not object");
  const kind = (v as Record<string, unknown>).kind;
  if (kind === "string") return obj<Field>(v, p, { name: label, kind: oneOf("string"), max_bytes: int });
  if (kind === "integer") {
    const f = obj<Field>(v, p, { name: label, kind: oneOf("integer"), min: int, max: int });
    if (f.kind === "integer" && f.min > f.max) fail(p, "min > max");
    return f;
  }
  if (kind === "boolean") return obj<Field>(v, p, { name: label, kind: oneOf("boolean") });
  fail(p, "unknown field kind");
};

export const vTool: V<Tool> = (v, p) =>
  obj<Tool>(v, p, {
    tool: toolName,
    binding: oneOf("RECORDS"),
    operation: oneOf("get", "put", "delete", "list", "export"),
    args: (x, pp) => arr(x, pp, vField, { max: 16, sortCmp: (a, b) => byteCmp(a.name, b.name), uniqueCmp: (a, b) => byteCmp(a.name, b.name) }),
  });

export const vManifest: V<Manifest> = (v, p) =>
  obj<Manifest>(v, p, {
    schema: oneOf("charter.manifest/1"),
    gateway_id: idOf("cgw"),
    engine: oneOf(ENGINE),
    resource_grammar: oneOf("segments/1"),
    adapter_build_hash: hash,
    tools: (x, pp) => arr(x, pp, vTool, { min: 1, max: 32, sortCmp: (a, b) => byteCmp(a.tool, b.tool), uniqueCmp: (a, b) => byteCmp(a.tool, b.tool) }),
  });

export const vPolicy: V<Policy> = (v, p) => {
  const pol = obj<Policy>(v, p, {
    schema: oneOf("charter.policy/1"),
    tenant_id: idOf("cte"),
    charter_id: idOf("cch"),
    version: boundedInt(1, 9007199254740991),
    previous_hash: nullable(hash),
    engine: oneOf(ENGINE),
    manifest_hash: hash,
    issued_at: time,
    not_before: time,
    not_after: time,
    source: vSource,
    description: rangedStr(1, 2048),
    next_authority: vAuthority,
    hard_denies: (x, pp) => arr(x, pp, vRule(true), { max: 128, sortCmp: (a, b) => byteCmp(a.id, b.id), uniqueCmp: (a, b) => byteCmp(a.id, b.id) }),
    scope_rules: (x, pp) => arr(x, pp, vRule(false), { max: 128, sortCmp: (a, b) => byteCmp(a.id, b.id), uniqueCmp: (a, b) => byteCmp(a.id, b.id) }),
  });
  if (pol.hard_denies.length + pol.scope_rules.length > 128) fail(p, "more than 128 rules");
  const ids = new Set([...pol.hard_denies.map((r) => r.id), ...pol.scope_rules.map((r) => r.id)]);
  if (ids.size !== pol.hard_denies.length + pol.scope_rules.length) fail(p, "rule id reused across lists");
  if (pol.version === 1 ? pol.previous_hash !== null : !isHash(pol.previous_hash)) {
    fail(`${p}.previous_hash`, "genesis requires null; successor requires hash");
  }
  return pol;
};

export const vBundle: V<Bundle> = (v, p) =>
  obj<Bundle>(v, p, { policy: vPolicy, manifest: vManifest, signatures: vDetachedSet });

export const vPin: V<Pin> = (v, p) =>
  obj<Pin>(v, p, {
    charter_id: idOf("cch"), version: boundedInt(1, 9007199254740991),
    policy_hash: hash, manifest_hash: hash, engine: oneOf(ENGINE),
  });

export const vCitation: V<Citation> = (v, p) => {
  const c = obj<Citation>(v, p, {
    schema: oneOf("charter.citation/1"), pin: vPin, rule_id: idOf("crl"),
    pointer: (x, pp) => (typeof x === "string" && /^\/(hard_denies|scope_rules)\/(0|[1-9][0-9]*)$/.test(x) ? x : fail(pp, "bad pointer")),
    clause_hash: hash,
    rule: vRule(true),
  });
  return c;
};

/* ---------- §1.4 control/identity ---------- */

export const vPinCommand: V<PinCommand> = (v, p) =>
  obj<PinCommand>(v, p, {
    schema: oneOf("charter.pin/1"), tenant_id: idOf("cte"), gateway_id: idOf("cgw"),
    request_id: idOf("crq"), expected_revision: int, expected_revocation_epoch: int,
    authority_policy_hash: hash, target: vPin, expires_at: time,
  });

export const vSignedPin: V<SignedPin> = (v, p) =>
  obj<SignedPin>(v, p, { command: vPinCommand, signatures: vDetachedSet });

export const vPauseRequest: V<PauseRequest> = (v, p) =>
  obj<PauseRequest>(v, p, { request_id: idOf("crq"), expected_revision: int, reason: rangedStr(1, 256) });

export const vRevokeTarget: V<RevokeTarget> = (v, p) => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail(p, "not object");
  const kind = (v as Record<string, unknown>).kind;
  if (kind === "policy") return obj<RevokeTarget>(v, p, { kind: oneOf("policy"), policy_hash: hash });
  if (kind === "credential") return obj<RevokeTarget>(v, p, { kind: oneOf("credential"), credential_id: idOf("ccr") });
  if (kind === "policy_key") return obj<RevokeTarget>(v, p, { kind: oneOf("policy_key"), key_id: idOf("cky") });
  fail(p, "unknown revoke target kind");
};

export const vRevokeRequest: V<RevokeRequest> = (v, p) =>
  obj<RevokeRequest>(v, p, {
    request_id: idOf("crq"), expected_revocation_epoch: int,
    target: vRevokeTarget, reason: rangedStr(1, 256),
  });

export const vRevocation: V<Revocation> = (v, p) =>
  obj<Revocation>(v, p, {
    request_id: idOf("crq"), expected_revocation_epoch: int, target: vRevokeTarget,
    reason: rangedStr(1, 256), epoch: boundedInt(1, 9007199254740991),
    actor_id: idOf("cpr"), effective_seq: int, recorded_at: time,
  });

export const vDeployment: V<Deployment> = (v, p) =>
  obj<Deployment>(v, p, {
    gateway_id: idOf("cgw"), revision: int, revocation_epoch: int,
    state: oneOf("UNPINNED", "ACTIVE", "PAUSED"), pin: nullable(vPin),
    installed_manifest_hash: hash, in_flight: int,
  });

export const vPrincipal: V<Principal> = (v, p) =>
  obj<Principal>(v, p, {
    principal_id: idOf("cpr"), credential_id: idOf("ccr"), instance_id: idOf("cin"),
    scopes: (x, pp) => arr(x, pp, label, { max: 32, sortCmp: byteCmp, uniqueCmp: byteCmp }),
  });

export const vCallRequest: V<CallRequest> = (v, p) =>
  obj<CallRequest>(v, p, {
    request_id: idOf("crq"), pin: vPin, scope: label, tool: toolName,
    resource: resource,
    args: (x, pp) => {
      if (x === null || typeof x !== "object" || Array.isArray(x)) fail(pp, "not object");
      const o = x as Record<string, unknown>;
      if (Object.keys(o).length > 256) fail(pp, "args members > 256");
      const out: Record<string, Scalar> = {};
      for (const [k, av] of Object.entries(o)) {
        if (!isLabel(k)) fail(pp, "arg name not Label");
        out[k] = scalar(av, `${pp}.${k}`);
      }
      return out;
    },
    deadline: time,
  });

const REASONS = [
  "ALLOW_SCOPE", "HARD_DENY", "NO_SCOPE", "PIN_MISMATCH", "MANIFEST_MISMATCH",
  "POLICY_REVOKED", "POLICY_KEY_REVOKED", "POLICY_NOT_YET_VALID", "POLICY_EXPIRED",
  "DEADLINE", "PRINCIPAL_SCOPE", "UNKNOWN_TOOL",
] as const;

export const vDecision: V<import("../types.ts").Decision> = (v, p) =>
  obj(v, p, {
    verdict: oneOf("ALLOW", "DENY"), reason: oneOf(...REASONS),
    rule_ids: (x: unknown, pp: string) => arr(x, pp, idOf("crl"), { max: 128, sortCmp: byteCmp, uniqueCmp: byteCmp }),
  });

export const vCallResult: V<CallResult> = (v, p) =>
  obj<CallResult>(v, p, {
    request_id: idOf("crq"),
    state: oneOf("DENIED", "COMMITTED", "SUCCEEDED", "FAILED", "INDETERMINATE", "NOT_SENT"),
    decision: vDecision, input_hash: hash, output: vJson, output_available: bool,
    output_hash: nullable(hash),
    audit_seqs: (x, pp) => arr(x, pp, int, { min: 1, max: 4 }),
  });

export const vCheckResult: V<CheckResult> = (v, p) =>
  obj<CheckResult>(v, p, { decision: vDecision, input_hash: hash, enforcement: (x, pp) => (x === false ? false : fail(pp, "not false")), audit_seq: int });

export const vControlResult: V<ControlResult> = (v, p) =>
  obj<ControlResult>(v, p, { deployment: vDeployment, audit_seq: int });

export const vRevokeResult: V<RevokeResult> = (v, p) =>
  obj<RevokeResult>(v, p, { revocation: vRevocation, deployment: vDeployment });

/* ---------- §1.5 fleet/disputes/audit/evidence ---------- */

export const vHeartbeat: V<Heartbeat> = (v, p) =>
  obj<Heartbeat>(v, p, {
    request_id: idOf("crq"), instance_id: idOf("cin"), counter: boundedInt(1, 9007199254740991),
    observed_pin: nullable(vPin), manifest_hash: hash,
  });

export const vInstanceView: V<InstanceView> = (v, p) =>
  obj<InstanceView>(v, p, {
    instance_id: idOf("cin"), counter: int, received_at: nullable(time),
    expires_at: nullable(time), observed_pin: nullable(vPin), manifest_hash: nullable(hash),
    state: oneOf("MISSING", "MATCHED", "MISMATCH"),
  });

export const vFleet: V<Fleet> = (v, p) =>
  obj<Fleet>(v, p, {
    as_of: time, desired_pin: nullable(vPin), status: oneOf("EMPTY", "HEALTHY", "SPLIT", "MISSING"),
    instances: (x, pp) => arr(x, pp, vInstanceView, { max: 32, sortCmp: (a, b) => byteCmp(a.instance_id, b.instance_id), uniqueCmp: (a, b) => byteCmp(a.instance_id, b.instance_id) }),
  });

export const vHeartbeatResult: V<HeartbeatResult> = (v, p) =>
  obj<HeartbeatResult>(v, p, { counter: int, expires_at: time, state: oneOf("MISSING", "MATCHED", "MISMATCH"), audit_seq: int });

export const vDisputeRequest: V<DisputeRequest> = (v, p) =>
  obj<DisputeRequest>(v, p, {
    request_id: idOf("crq"), dispute_id: idOf("cds"), pin: vPin, cited_seq: int,
    category: oneOf("POLICY_TEXT", "SCOPE_MATCH", "EXECUTION", "VERSION_SPLIT"),
    statement: rangedStr(1, 4096),
    evidence_hashes: (x, pp) => arr(x, pp, hash, { max: 16, sortCmp: byteCmp, uniqueCmp: byteCmp }),
  });

export const vDispute: V<Dispute> = (v, p) =>
  obj<Dispute>(v, p, {
    request_id: idOf("crq"), dispute_id: idOf("cds"), pin: vPin, cited_seq: int,
    category: oneOf("POLICY_TEXT", "SCOPE_MATCH", "EXECUTION", "VERSION_SPLIT"),
    statement: rangedStr(1, 4096),
    evidence_hashes: (x, pp) => arr(x, pp, hash, { max: 16, sortCmp: byteCmp, uniqueCmp: byteCmp }),
    actor_id: idOf("cpr"), recorded_at: time, status: oneOf("RECORDED_ADVISORY"), receipt_seq: int,
  });

export const vAuditEvent: V<AuditEvent> = (v, p) => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail(p, "not object");
  const type = (v as Record<string, unknown>).type;
  const val = (x: unknown, pp: string) => x;
  const decisionData: V<import("../types.ts").DecisionData> = (x, pp) =>
    obj(x, pp, {
      request_id: idOf("crq"), input_hash: hash, evaluated_at: time, decision: vDecision,
      revision: int, revocation_epoch: int, instance_counter: int,
    });
  switch (type) {
    case "PolicyPublished":
      return obj<AuditEvent>(v, p, { type: oneOf("PolicyPublished"), value: (x, pp) => obj(x, pp, { pin: vPin, source: vSource }) });
    case "PinActivated":
      return obj<AuditEvent>(v, p, { type: oneOf("PinActivated"), value: (x, pp) => obj(x, pp, { revision: int, revocation_epoch: int, previous_pin: nullable(vPin), pin: vPin, control_hash: hash, in_flight: int }) });
    case "GatewayPaused":
      return obj<AuditEvent>(v, p, { type: oneOf("GatewayPaused"), value: (x, pp) => obj(x, pp, { revision: int, control_hash: hash, in_flight: int }) });
    case "TargetRevoked":
      return obj<AuditEvent>(v, p, { type: oneOf("TargetRevoked"), value: (x, pp) => obj(x, pp, { epoch: int, target: vRevokeTarget, control_hash: hash, in_flight: int }) });
    case "CheckEvaluated":
    case "CallDenied":
    case "CallCommitted":
      return obj<AuditEvent>(v, p, { type: oneOf(type), value: decisionData });
    case "CallFinished":
      return obj<AuditEvent>(v, p, { type: oneOf("CallFinished"), value: (x, pp) => obj(x, pp, { request_id: idOf("crq"), state: oneOf("SUCCEEDED", "FAILED", "INDETERMINATE", "NOT_SENT"), output_hash: nullable(hash) }) });
    case "InstanceObserved":
      return obj<AuditEvent>(v, p, { type: oneOf("InstanceObserved"), value: (x, pp) => obj(x, pp, { heartbeat: vHeartbeat, expires_at: time }) });
    case "DisputeRecorded":
      return obj<AuditEvent>(v, p, { type: oneOf("DisputeRecorded"), value: (x, pp) => obj(x, pp, { dispute_id: idOf("cds"), cited_seq: int, category: oneOf("POLICY_TEXT", "SCOPE_MATCH", "EXECUTION", "VERSION_SPLIT"), statement_hash: hash }) });
    case "CommandRejected":
      return obj<AuditEvent>(v, p, { type: oneOf("CommandRejected"), value: (x, pp) => obj(x, pp, { operation: str, request_hash: hash, code: oneOf(...ERROR_CODES) }) });
    case "StorageMigrated":
      return obj<AuditEvent>(v, p, { type: oneOf("StorageMigrated"), value: (x, pp) => obj(x, pp, { from_version: int, to_version: int, migration_hash: hash }) });
    default:
      fail(p, `unknown audit event type ${String(type)}`);
  }
};

export const vAuditBody: V<import("../types.ts").AuditBody> = (v, p) =>
  obj(v, p, {
    schema: oneOf("charter.audit/1"), tenant_id: idOf("cte"), log_id: idOf("clg"),
    seq: boundedInt(1, 9007199254740991), prev_hash: hash, time: time,
    actor_id: idOf("cpr"), policy_pin: nullable(vPin), event: vAuditEvent,
  });

export const vAuditEntry: V<AuditEntry> = (v, p) =>
  obj<AuditEntry>(v, p, { body: vAuditBody, hash: hash, key_id: idOf("cky"), signature: sig });

export const vCheckpointBody: V<import("../types.ts").CheckpointBody> = (v, p) =>
  obj(v, p, {
    schema: oneOf("charter.checkpoint/1"), tenant_id: idOf("cte"), log_id: idOf("clg"),
    through_seq: int, head_hash: hash, time: time,
  });

export const vCheckpoint: V<Checkpoint> = (v, p) =>
  obj<Checkpoint>(v, p, { body: vCheckpointBody, key_id: idOf("cky"), signature: sig });

export const vControlArtifact: V<ControlArtifact> = (v, p) => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail(p, "not object");
  const kind = (v as Record<string, unknown>).kind;
  if (kind === "pin") return obj<ControlArtifact>(v, p, { kind: oneOf("pin"), value: vSignedPin });
  if (kind === "pause") return obj<ControlArtifact>(v, p, { kind: oneOf("pause"), value: vPauseRequest });
  if (kind === "revoke") return obj<ControlArtifact>(v, p, { kind: oneOf("revoke"), value: vRevokeRequest });
  fail(p, "unknown control kind");
};

export const vAuditPage: V<AuditPage> = (v, p) =>
  obj<AuditPage>(v, p, {
    entries: (x, pp) => arr(x, pp, vAuditEntry, { max: 100 }),
    controls: (x, pp) => arr(x, pp, vControlArtifact, { max: 256 }),
    through_seq: int, next_after: nullable(int),
  });

export const vEvidence: V<Evidence> = (v, p) =>
  obj<Evidence>(v, p, {
    schema: oneOf("charter.evidence/1"), root: (x, pp) => vRootFile(x, pp),
    bundles: (x, pp) => arr(x, pp, vBundle, { max: 256 }),
    start: nullable(vCheckpoint),
    entries: (x, pp) => arr(x, pp, vAuditEntry, { max: 256 }),
    controls: (x, pp) => arr(x, pp, vControlArtifact, { max: 256 }),
    end: vCheckpoint,
    inputs: (x, pp) => arr(x, pp, (xi, ppi) => obj(xi, ppi, { request: vCallRequest, principal: vPrincipal }), { max: 256 }),
  });

export const vVerification: V<Verification> = (v, p) =>
  obj<Verification>(v, p, {
    integrity: oneOf("VALID", "INVALID", "INCOMPLETE"),
    replay: oneOf("MATCH", "MISMATCH", "NOT_REQUESTED", "INPUTS_MISSING", "CONTEXT_MISSING"),
    through_seq: int, checkpoint_match: bool, truth: oneOf("NOT_ATTESTED"),
  });

/* ---------- §5 config/root/auth ---------- */

export const vAuditKey: V<AuditKey> = (v, p) => {
  const k = obj<AuditKey>(v, p, { key_id: idOf("cky"), public_key: pub, from_seq: boundedInt(1, 9007199254740991), through_seq: nullable(int) });
  if (k.through_seq !== null && k.through_seq < k.from_seq) fail(p, "through_seq < from_seq");
  return k;
};

export const vRootFile: V<RootFile> = (v, p) => {
  const r = obj<RootFile>(v, p, {
    schema: oneOf("charter.root/1"), tenant_id: idOf("cte"), charter_id: idOf("cch"),
    gateway_id: idOf("cgw"), log_id: idOf("clg"), bootstrap: vAuthority,
    audit_keys: (x, pp) => arr(x, pp, vAuditKey, { min: 1, max: 16, sortCmp: (a, b) => a.from_seq - b.from_seq, uniqueCmp: (a, b) => a.from_seq - b.from_seq }),
  });
  // exactly one active signer per sequence: contiguous non-overlapping ranges
  for (let i = 1; i < r.audit_keys.length; i++) {
    const prev = r.audit_keys[i - 1]!;
    if (prev.through_seq === null) fail(`${p}.audit_keys`, "non-final open range");
    if (prev.through_seq + 1 !== r.audit_keys[i]!.from_seq) fail(`${p}.audit_keys`, "gap/overlap in ranges");
  }
  const bootPubs = new Set(r.bootstrap.keys.map((k) => k.public_key));
  const bootIds = new Set(r.bootstrap.keys.map((k) => k.key_id));
  for (const ak of r.audit_keys) {
    if (bootPubs.has(ak.public_key) || bootIds.has(ak.key_id)) fail(`${p}.audit_keys`, "audit key overlaps bootstrap");
  }
  return r;
};

export const vAuthRecord: V<AuthRecord> = (v, p) => {
  const r = obj<AuthRecord>(v, p, {
    credential_id: idOf("ccr"), token_hash: hash, tenant_id: idOf("cte"),
    principal_id: idOf("cpr"),
    role: oneOf("reader", "publisher", "operator", "agent", "instance"),
    scopes: (x, pp) => arr(x, pp, label, { max: 32, sortCmp: byteCmp, uniqueCmp: byteCmp }),
    instance_id: nullable(idOf("cin")), expires_at: time,
  });
  if (r.role === "agent" || r.role === "instance") {
    if (r.instance_id === null) fail(`${p}.instance_id`, "agent/instance requires bound installation");
    if (r.role === "agent" && (r.scopes.length < 1 || r.scopes.length > 32)) fail(`${p}.scopes`, "agent needs 1-32 scopes");
  } else {
    if (r.instance_id !== null) fail(`${p}.instance_id`, "non-agent role must have null instance");
    if (r.scopes.length !== 0) fail(`${p}.scopes`, "non-agent roles must have empty scopes");
  }
  return r;
};

export const vAuthFile: V<AuthFile> = (v, p) => {
  const f = obj<AuthFile>(v, p, {
    schema: oneOf("charter.auth/1"),
    records: (x, pp) => arr(x, pp, vAuthRecord, { min: 1, max: 256 }),
  });
  const ids = new Set(f.records.map((r) => r.credential_id));
  const hashes = new Set(f.records.map((r) => r.token_hash));
  if (ids.size !== f.records.length || hashes.size !== f.records.length) fail(`${p}.records`, "duplicate credential id/hash");
  return f;
};

const vEncKey: V<{ key_id: string; key_base64url: string }> = (x, pp) =>
  obj<{ key_id: string; key_base64url: string }>(x, pp, {
    key_id: label,
    key_base64url: (xv, ppp) => {
      if (typeof xv !== "string") fail(ppp, "not string");
      const raw = Buffer.from(xv, "base64url");
      if (raw.length !== 32 || raw.toString("base64url") !== xv) fail(ppp, "not canonical base64url(32)");
      return xv;
    },
  });

export const vEncryptionKeys: V<EncryptionKeys> = (v, p) => {
  const e = obj<EncryptionKeys>(v, p, {
    active_key_id: label,
    keys: (x, pp) => arr(x, pp, vEncKey, {
      min: 1, max: 8,
      sortCmp: (a, b) => byteCmp(a.key_id, b.key_id),
      uniqueCmp: (a, b) => byteCmp(a.key_id, b.key_id),
    }),
  });
  if (!e.keys.some((k) => k.key_id === e.active_key_id)) fail(`${p}.active_key_id`, "absent from keys");
  return e;
};

const RE_SECRET_REF = /^env:[A-Z][A-Z0-9_]{0,63}$/;

export const vConfig: V<Config> = (v, p) => {
  const c = obj<Config>(v, p, {
    schema: oneOf("charter.config/1"),
    environment: oneOf("local", "production"),
    endpoint: str,
    tenant_id: idOf("cte"), gateway_id: idOf("cgw"), instance_id: idOf("cin"),
    system_principal_id: idOf("cpr"), root_file: str, manifest_file: str,
    instance_inventory: (x, pp) => arr(x, pp, idOf("cin"), { min: 1, max: 32, sortCmp: byteCmp, uniqueCmp: byteCmp }),
    client_credential_ref: (x, pp) => (typeof x === "string" && RE_SECRET_REF.test(x) ? x : fail(pp, "not env:NAME")),
    auth_records_ref: (x, pp) => (typeof x === "string" && RE_SECRET_REF.test(x) ? x : fail(pp, "not env:NAME")),
    audit_seed_ref: (x, pp) => (typeof x === "string" && RE_SECRET_REF.test(x) ? x : fail(pp, "not env:NAME")),
    audit_key_id: idOf("cky"),
    response_keys_ref: (x, pp) => (typeof x === "string" && RE_SECRET_REF.test(x) ? x : fail(pp, "not env:NAME")),
    storage_soft_limit_bytes: boundedInt(67108864, 8589934592),
    max_in_flight: boundedInt(1, 32),
    metrics_enabled: bool,
  });
  if (!c.instance_inventory.includes(c.instance_id)) fail(`${p}.instance_inventory`, "must contain instance_id");
  if (c.environment === "local") {
    if (!/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d{1,5})?\/?$/.test(c.endpoint)) {
      fail(`${p}.endpoint`, "local profile is HTTP loopback only");
    }
  } else {
    if (!/^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?\/?$/.test(c.endpoint)) {
      fail(`${p}.endpoint`, "production endpoint must be bare HTTPS origin");
    }
  }
  return c;
};

/* ---------- §3.7 adapter ---------- */

export const vAdapterRequest: V<AdapterRequest> = (v, p) =>
  obj<AdapterRequest>(v, p, {
    request_id: idOf("crq"), principal_id: idOf("cpr"), scope: label, pin: vPin,
    input_hash: hash, operation: oneOf("get", "put", "delete", "list", "export"),
    resource: resource,
    args: (x, pp) => {
      if (x === null || typeof x !== "object" || Array.isArray(x)) fail(pp, "not object");
      const out: Record<string, Scalar> = {};
      for (const [k, av] of Object.entries(x as Record<string, unknown>)) out[k] = scalar(av, `${pp}.${k}`);
      return out;
    },
    deadline: time,
  });

export const vAdapterResponse: V<AdapterResponse> = (v, p) => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail(p, "not object");
  const status = (v as Record<string, unknown>).status;
  if (status === "ok" || status === "error") {
    return obj<AdapterResponse>(v, p, { status: oneOf("ok", "error"), output: vJson });
  }
  if (status === "unknown") return obj<AdapterResponse>(v, p, { status: oneOf("unknown") });
  fail(p, "unknown adapter status");
};

/* ---------- §9 observability + export stream ---------- */

export const vMetricSnapshot: V<MetricSnapshot> = (v, p) =>
  obj<MetricSnapshot>(v, p, {
    window_seconds: (x, pp) => (x === 60 ? 60 : fail(pp, "not 60")),
    calls: int, allows: int, denies: int, indeterminate: int, not_sent: int,
    audit_failures: int, pin_revision: int, revocation_epoch: int,
    instances_matched: int, instances_missing: int, instances_mismatch: int,
  });

export const vValidated: V<Validated> = (v, p) =>
  obj<Validated>(v, p, {
    valid: (x, pp) => (x === true ? true : fail(pp, "not true")),
    pin: vPin, signatures: int, required: int,
    warnings: (x, pp) => arr(x, pp, oneOf("NO_ALLOW_RULES", "SINGLE_SIGNER", "EXPIRY_WITHIN_24H"), { max: 3, sortCmp: byteCmp, uniqueCmp: byteCmp }),
  });

export const vCompiled: V<Compiled> = (v, p) =>
  obj<Compiled>(v, p, { policy_hash: hash, manifest_hash: hash, engine: oneOf(ENGINE) });

export const vProofLink: V<ProofLink> = (v, p) =>
  obj<ProofLink>(v, p, {
    schema: oneOf("charter.proof-link/1"), tenant_id: idOf("cte"), log_id: idOf("clg"),
    seq: int, audit_hash: hash, policy_pin: nullable(vPin), input_hash: nullable(hash),
    parent_hashes: (x, pp) => arr(x, pp, hash, { max: 3, sortCmp: byteCmp, uniqueCmp: byteCmp }),
    evidence_profile: oneOf("charter.stream/1"), execution_truth: oneOf("NOT_ATTESTED"),
  });

export const vExportHeader: V<ExportHeader> = (v, p) =>
  obj<ExportHeader>(v, p, {
    record: oneOf("header"), schema: oneOf("charter.stream/1"), root: vRootFile,
    start: nullable(vCheckpoint), end: vCheckpoint,
  });
export const vExportBundle: V<ExportBundle> = (v, p) =>
  obj<ExportBundle>(v, p, { record: oneOf("bundle"), bundle: vBundle });
export const vExportControl: V<ExportControl> = (v, p) =>
  obj<ExportControl>(v, p, { record: oneOf("control"), control: vControlArtifact });
export const vExportEntry: V<ExportEntry> = (v, p) =>
  obj<ExportEntry>(v, p, { record: oneOf("entry"), entry: vAuditEntry });
export const vExportInput: V<ExportInput> = (v, p) =>
  obj<ExportInput>(v, p, { record: oneOf("input"), input: (x, pp) => obj(x, pp, { request: vCallRequest, principal: vPrincipal }) });
export const vExportTrailer: V<ExportTrailer> = (v, p) =>
  obj<ExportTrailer>(v, p, { record: oneOf("trailer"), bundles: int, controls: int, entries: int, inputs: int, through_seq: int });

/** Value must be one of the export stream record types. */
export const vExportRecord: V<ExportHeader | ExportBundle | ExportControl | ExportEntry | ExportInput | ExportTrailer> = (v, p) => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail(p, "not object");
  const rec = (v as Record<string, unknown>).record;
  switch (rec) {
    case "header": return vExportHeader(v, p);
    case "bundle": return vExportBundle(v, p);
    case "control": return vExportControl(v, p);
    case "entry": return vExportEntry(v, p);
    case "input": return vExportInput(v, p);
    case "trailer": return vExportTrailer(v, p);
    default: fail(p, "unknown stream record");
  }
};
