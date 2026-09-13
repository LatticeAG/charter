/**
 * TenantEngine — the local SQLite-backed realization of CharterTenantDO:
 * one serialization barrier, single-tenant durable state, the §7.1 admission
 * algorithm, audit chain, fleet observation, revocations, disputes, metrics.
 */
import { CharterError, retryable, statusFor } from "../errors.ts";
import { digest, sha256Hex, signMessage } from "../crypto/digest.ts";
import { publicKeyFromSeed, signBytes, verifyBytes } from "../crypto/ed25519.ts";
import { canonicalBytes, canonicalize, jsonEqual } from "../json/jcs.ts";
import { parseJsonText } from "../json/strict.ts";
import { msTime, timeMs } from "../scalars.ts";
import {
  vBundle, vCallRequest, vDisputeRequest, vHeartbeat, vPauseRequest,
  vRevokeRequest, vSignedPin,
} from "../schema/validate.ts";
import { compile } from "../core/compile.ts";
import { evaluate, installedTool } from "../core/evaluate.ts";
import { checkSignatureSet } from "../core/verify-bundle.ts";
import { cite, pinFor } from "../core/cite.ts";
import type {
  AdapterRequest, AdapterResponse, AuditBody, AuditEntry, AuditEvent,
  AuthFile, AuthRecord, Bundle, CallRequest, CallResult, CallState,
  Checkpoint, CheckResult, Config, ControlArtifact, Decision, DecisionData,
  Deployment, Dispute, EncryptionKeys, Evidence, Fleet, Hash, HeartbeatResult,
  InstanceState, InstanceView, Json, Manifest, MetricSnapshot, Pin, Policy,
  Principal, Revocation, RevokeTarget, RootFile, SignedPin, Time, Validated,
  Warning,
} from "../types.ts";
import { ENGINE } from "../types.ts";
import { Clock } from "./clock.ts";
import { Encrypter } from "./encryption.ts";
import { RateLimiter } from "./ratelimit.ts";
import { Store } from "./store.ts";

const ZERO_HASH = "0".repeat(64);
const DAY_MS = 86_400_000;
const RESPONSE_TTL_MS = DAY_MS;
const HEARTBEAT_FRESH_MS = 180_000;
const PIN_MAX_AHEAD_MS = 300_000;
const RESERVE_BYTES = 16 * 1024 * 1024;
const PER_CALL_RESERVE = 256 * 1024;
const MAX_WAITING = 64;
const MAX_IN_FLIGHT = 32;

export interface FaultHooks {
  /** Fail the next durable commit (tx rolls back → AUDIT_UNAVAILABLE). */
  failNextCommit?: boolean;
  /** Crash after durable CallCommitted, before step-6 recheck/initiation. */
  crashAfterMarker?: boolean;
  /** Worker↔DO partition: everything fails AUDIT_UNAVAILABLE. */
  partitioned?: boolean;
  /** Advance the injected clock to this ms after the durable commit, before
   *  the step-6 recheck (TV-C-37/65). Consumed once. */
  advanceClockToMs?: number | undefined;
}

export class CrashFault extends Error {
  constructor() {
    super("simulated crash");
    this.name = "CrashFault";
  }
}

export interface EngineOptions {
  store: Store;
  config: Config;
  root: RootFile;
  manifest: Manifest;
  auth: AuthFile;
  encryptionKeys: EncryptionKeys;
  auditSeed: Uint8Array;
  adapter: { run(req: AdapterRequest): Promise<AdapterResponse> | AdapterResponse };
  adapterTimeoutCapMs?: number;
  hooks?: FaultHooks;
  /** Test hook: deterministic clock source installed before recovery. */
  clockInject?: () => number;
}

type Caller = AuthRecord;
export type StoredResponse = { status: number; body: Json };

function errorBody(code: import("../errors.ts").ErrorCode, auditSeq: number | null): Json {
  return { error: { code, retryable: retryable(code), audit_seq: auditSeq } } as unknown as Json;
}

export class TenantEngine {
  readonly store: Store;
  readonly config: Config;
  readonly root: RootFile;
  readonly manifest: Manifest;
  readonly clock: Clock;
  private enc: Encrypter;
  private limiter = new RateLimiter();
  private authByHash = new Map<string, AuthRecord>();
  private auditSeed: Uint8Array;
  private adapter: EngineOptions["adapter"];
  private capMs: number | undefined;
  hooks: FaultHooks;
  private tail: Promise<unknown> = Promise.resolve();
  private crashed = false;
  private waiting = 0;
  private metrics = { windowStart: 0, calls: 0, allows: 0, denies: 0, indeterminate: 0, not_sent: 0, audit_failures: 0 };

  private constructor(opts: EngineOptions) {
    this.store = opts.store;
    this.config = opts.config;
    this.root = opts.root;
    this.manifest = opts.manifest;
    this.clock = new Clock(opts.store);
    this.enc = new Encrypter(opts.store, opts.config.tenant_id, opts.encryptionKeys);
    this.auditSeed = opts.auditSeed;
    this.adapter = opts.adapter;
    this.capMs = opts.adapterTimeoutCapMs;
    this.hooks = opts.hooks ?? {};
    if (opts.clockInject) this.clock.inject = opts.clockInject;
    for (const r of opts.auth.records) this.authByHash.set(r.token_hash, r);
  }

  /** Provision a fresh tenant store (genesis meta row). */
  static provision(opts: EngineOptions): TenantEngine {
    const { store, config, root, manifest, auth, auditSeed } = opts;
    if (root.tenant_id !== config.tenant_id || root.gateway_id !== config.gateway_id) {
      throw new CharterError("SCHEMA", "root does not match config tenant/gateway");
    }
    if (manifest.gateway_id !== config.gateway_id) {
      throw new CharterError("SCHEMA", "manifest gateway does not match config");
    }
    for (const r of auth.records) {
      if (r.tenant_id !== config.tenant_id) throw new CharterError("SCHEMA", "auth record tenant mismatch");
      if (r.principal_id === config.system_principal_id) {
        throw new CharterError("SCHEMA", "system_principal_id must not appear in AuthFile");
      }
    }
    const auditKey = root.audit_keys.find((k) => k.key_id === config.audit_key_id);
    if (!auditKey) throw new CharterError("SCHEMA", "audit_key_id not in root.audit_keys");
    const derivedPub = Buffer.from(publicKeyFromSeed(auditSeed)).toString("hex");
    if (derivedPub !== auditKey.public_key) {
      throw new CharterError("SCHEMA", "audit seed does not match audit_key_id public key");
    }
    const e = new TenantEngine(opts);
    const dep: Deployment = {
      gateway_id: config.gateway_id, revision: 0, revocation_epoch: 0,
      state: "UNPINNED", pin: null, installed_manifest_hash: digest("manifest", manifest), in_flight: 0,
    };
    store.tx(() => {
      store.run(
        "INSERT INTO meta(singleton,storage_version,deployment_jcs,head_version,next_seq,head_hash,last_time_ms,root_hash) VALUES(1,1,?,0,1,?,0,?)",
        canonicalize(dep as unknown as Json), ZERO_HASH, sha256Hex(canonicalBytes(root as unknown as Json)),
      );
    });
    return e;
  }

  /** Open an existing store and recover orphan COMMITTED calls. */
  static open(opts: EngineOptions): TenantEngine {
    const e = new TenantEngine(opts);
    e.recover();
    return e;
  }

  /* ================= plumbing ================= */

  private meta(): { deployment_jcs: string; head_version: number; next_seq: number; head_hash: string } {
    const m = this.store.get<{ deployment_jcs: string; head_version: number; next_seq: number; head_hash: string }>(
      "SELECT deployment_jcs,head_version,next_seq,head_hash FROM meta WHERE singleton=1");
    if (!m) throw new CharterError("AUDIT_UNAVAILABLE", "meta missing");
    return m;
  }

  deployment(): Deployment {
    const dep = JSON.parse(this.meta().deployment_jcs) as Deployment;
    dep.in_flight = this.store.get<{ n: number }>("SELECT COUNT(*) AS n FROM calls WHERE state='COMMITTED'")!.n;
    return dep;
  }

  private saveDeployment(dep: Deployment): void {
    this.store.run("UPDATE meta SET deployment_jcs=? WHERE singleton=1",
      canonicalize({ ...dep, in_flight: 0 } as unknown as Json));
  }

  /** One explicit serialization barrier across all decisions. */
  private async barrier<T>(fn: () => Promise<T> | T): Promise<T> {
    const run = this.tail.then(() => fn());
    this.tail = run.catch(() => undefined);
    return run;
  }

  private checkLive(): void {
    if (this.crashed) throw new CrashFault();
    if (this.hooks.partitioned) throw new CharterError("AUDIT_UNAVAILABLE", "partitioned from durable state");
  }

  /* ================= auth ================= */

  /** Bearer-token authentication: exact encoding, hash lookup, expiry, revocation. */
  authenticate(token: string): AuthRecord {
    this.checkLive();
    const raw = Buffer.from(token, "base64url");
    if (raw.length !== 32 || raw.toString("base64url") !== token) {
      throw new CharterError("AUTH_REQUIRED");
    }
    const rec = this.authByHash.get(sha256Hex(raw));
    if (!rec) throw new CharterError("AUTH_REQUIRED");
    const now = this.clock.sample();
    if (now >= timeMs(rec.expires_at)) throw new CharterError("AUTH_REQUIRED");
    if (this.isRevoked({ kind: "credential", credential_id: rec.credential_id })) {
      throw new CharterError("AUTH_REQUIRED");
    }
    // Serving installation must equal the credential's bound installation.
    if ((rec.role === "agent" || rec.role === "instance") && rec.instance_id !== this.config.instance_id) {
      throw new CharterError("FORBIDDEN", "serving instance mismatch");
    }
    return rec;
  }

  private principal(rec: AuthRecord): Principal {
    return {
      principal_id: rec.principal_id, credential_id: rec.credential_id,
      instance_id: rec.instance_id ?? this.config.instance_id, scopes: rec.scopes,
    };
  }

  /* ================= audit ================= */

  private auditKeyAt(seq: number): { key_id: string; public_key: string } | undefined {
    return this.root.audit_keys.find(
      (k) => k.from_seq <= seq && (k.through_seq === null || seq <= k.through_seq));
  }

  /** Append a signed audit entry; must run inside store.tx. Returns seq. */
  private appendAudit(actorId: string, policyPin: Pin | null, event: AuditEvent, time: Time): number {
    const meta = this.meta();
    const seq = meta.next_seq;
    const key = this.auditKeyAt(seq);
    if (!key || key.key_id !== this.config.audit_key_id) {
      throw new CharterError("AUDIT_UNAVAILABLE", "no eligible configured audit key");
    }
    const body: AuditBody = {
      schema: "charter.audit/1", tenant_id: this.root.tenant_id, log_id: this.root.log_id,
      seq, prev_hash: meta.head_hash, time, actor_id: actorId as AuditBody["actor_id"],
      policy_pin: policyPin, event,
    };
    const hash = digest("audit", body);
    const signature = Buffer.from(signBytes(signMessage("audit", body), this.auditSeed)).toString("base64url");
    this.store.run("INSERT INTO audit(seq,hash,body_jcs,key_id,signature) VALUES(?,?,?,?,?)",
      seq, hash, canonicalize(body as unknown as Json), key.key_id, signature);
    this.store.run("UPDATE meta SET next_seq=?,head_hash=? WHERE singleton=1", seq + 1, hash);
    return seq;
  }

  private insertControl(auditSeq: number, artifact: ControlArtifact): void {
    const ch = digest("control", artifact as unknown as Json);
    this.store.run("INSERT INTO controls(audit_seq,control_hash,artifact_jcs) VALUES(?,?,?)",
      auditSeq, ch, canonicalize(artifact as unknown as Json));
  }

  /* ================= idempotency ================= */

  private requestHash(method: string, path: string, body: Json): Hash {
    return digest("request", { method, path, body });
  }

  private storeResponse(requestId: string, owner: string, op: string, bodyHash: Hash,
    resp: StoredResponse, nowMs: number, auditSeq: number | null, kind: string): void {
    const enc = this.enc.encrypt("requests", requestId, "response_enc", canonicalize(resp.body));
    this.store.run(
      "INSERT INTO requests(request_id,owner_id,operation,body_hash,response_enc,response_until_ms,result_jcs) VALUES(?,?,?,?,?,?,?)",
      requestId, owner, op, bodyHash, enc, nowMs + RESPONSE_TTL_MS,
      canonicalize({ status: resp.status, audit_seq: auditSeq, kind }));
  }

  private updateStoredResponse(requestId: string, resp: StoredResponse, nowMs: number): void {
    const enc = this.enc.encrypt("requests", requestId, "response_enc", canonicalize(resp.body));
    this.store.run("UPDATE requests SET response_enc=? WHERE request_id=?", enc, requestId);
    const row = this.store.get<{ result_jcs: string }>("SELECT result_jcs FROM requests WHERE request_id=?", requestId);
    if (row) {
      const meta = JSON.parse(row.result_jcs) as { status: number };
      meta.status = resp.status;
      this.store.run("UPDATE requests SET result_jcs=? WHERE request_id=?", canonicalize(meta), requestId);
    }
  }

  /** Exact-retry resolution; throws mapped conflicts. */
  private resolveRetry(requestId: string, owner: string, op: string, bodyHash: Hash,
    nowMs: number, isCall: boolean): StoredResponse | undefined {
    const row = this.store.get<{
      owner_id: string; operation: string; body_hash: string;
      response_enc: string | null; response_until_ms: number; result_jcs: string;
    }>("SELECT owner_id,operation,body_hash,response_enc,response_until_ms,result_jcs FROM requests WHERE request_id=?", requestId);
    if (!row) return undefined;
    if (row.owner_id !== owner) throw new CharterError("NOT_FOUND", "invisible request id");
    if (row.operation !== op || row.body_hash !== bodyHash) {
      const seq = this.recordRejection(op, bodyHash, "IDEMPOTENCY_CONFLICT", owner, requestId, nowMs);
      throw new CharterError("IDEMPOTENCY_CONFLICT", undefined, seq);
    }
    if (isCall) {
      // Call state is the authoritative response; output bytes live only
      // within the 24-hour response window.
      const call = this.callRow(requestId);
      if (!call) throw new CharterError("NOT_FOUND");
      const live = nowMs < row.response_until_ms;
      return { status: statusForCall(call.state as CallState), body: this.callResult(requestId, live) };
    }
    if (nowMs < row.response_until_ms && row.response_enc !== null) {
      const body = parseJsonText(this.enc.decrypt("requests", requestId, "response_enc", row.response_enc));
      const meta = JSON.parse(row.result_jcs) as { status: number };
      return { status: meta.status, body };
    }
    const meta = JSON.parse(row.result_jcs) as { audit_seq: number | null };
    throw new CharterError("REQUEST_ID_REUSED", undefined, meta.audit_seq);
  }

  /**
   * CommandRejected event; nonretryable codes also reserve the tombstone and
   * error response when the request ID is fresh. Returns the event seq.
   */
  private recordRejection(op: string, reqHash: Hash, code: import("../errors.ts").ErrorCode,
    actorId: string, requestId: string | null, nowMs: number): number {
    return this.store.tx(() => {
      const seq = this.appendAudit(actorId, this.deployment().pin,
        { type: "CommandRejected", value: { operation: op, request_hash: reqHash, code } }, msTime(this.clock.sample()));
      if (requestId !== null && !retryable(code)) {
        const exists = this.store.get<{ request_id: string }>(
          "SELECT request_id FROM requests WHERE request_id=?", requestId);
        if (!exists) {
          const resp: StoredResponse = { status: statusFor(code), body: errorBody(code, seq) };
          this.storeResponse(requestId, actorId, op, reqHash, resp, nowMs, seq, "error");
        }
      }
      return seq;
    });
  }

  /**
   * Recordable rejection helper — only safe OUTSIDE store.tx. Work bodies
   * inside command()'s tx must instead throw a plain CharterError; the
   * command() catch records CommandRejected in a fresh tx.
   */
  private reject(op: string, reqHash: Hash, requestId: string, code: import("../errors.ts").ErrorCode,
    rec: AuthRecord, nowMs: number): CharterError {
    const seq = this.recordRejection(op, reqHash, code, rec.principal_id, requestId, nowMs);
    return new CharterError(code, undefined, seq);
  }

  /* ================= shared state ================= */

  private revokedSet(kind: RevokeTarget["kind"]): Set<string> {
    const rows = this.store.all<{ target_id: string }>("SELECT target_id FROM revocations WHERE target_kind=?", kind);
    return new Set(rows.map((r) => r.target_id));
  }

  isRevoked(t: RevokeTarget): boolean {
    const id = t.kind === "policy" ? t.policy_hash : t.kind === "credential" ? t.credential_id : t.key_id;
    return this.store.get<{ epoch: number }>(
      "SELECT epoch FROM revocations WHERE target_kind=? AND target_id=?", t.kind, id) !== undefined;
  }

  private capacityCheck(nowMs: number, restrictive: boolean): void {
    const used = this.store.usedBytes();
    const cap = this.config.storage_soft_limit_bytes;
    if (restrictive) {
      if (used >= cap) throw new CharterError("STORAGE_FULL", "capacity exhausted");
      return;
    }
    const dep = this.deployment();
    if (used + RESERVE_BYTES + dep.in_flight * PER_CALL_RESERVE >= cap) {
      throw new CharterError("STORAGE_FULL", "capacity reached (reserve held)");
    }
  }

  private fleetFor(instanceId: string, nowMs: number): { state: InstanceState; counter: number; receivedMs: number | null } {
    const row = this.store.get<{ counter: number; received_ms: number | null; observation_jcs: string }>(
      "SELECT counter,received_ms,observation_jcs FROM instances WHERE instance_id=?", instanceId);
    const dep = this.deployment();
    if (!row || row.received_ms === null || nowMs >= row.received_ms + HEARTBEAT_FRESH_MS) {
      return { state: "MISSING", counter: row?.counter ?? 0, receivedMs: row?.received_ms ?? null };
    }
    const obs = JSON.parse(row.observation_jcs) as { observed_pin: Pin | null; manifest_hash: Hash };
    const matched = jsonEqual(obs.observed_pin, dep.pin) && obs.manifest_hash === dep.installed_manifest_hash;
    return { state: matched ? "MATCHED" : "MISMATCH", counter: row.counter, receivedMs: row.received_ms };
  }

  private currentAuthority(): { authority: import("../types.ts").Authority; head: { version: number; policy_hash: string } } {
    const headV = this.meta().head_version;
    if (headV === 0) throw new CharterError("PIN_NOT_HEAD", "no published head");
    const row = this.store.get<{ policy_hash: string; bundle_jcs: string }>(
      "SELECT policy_hash,bundle_jcs FROM policies WHERE version=?", headV);
    if (!row) throw new CharterError("AUDIT_UNAVAILABLE", "head policy missing");
    const bundle = parseJsonText(row.bundle_jcs) as unknown as Bundle;
    const revokedKeys = this.revokedSet("policy_key");
    const keys = bundle.policy.next_authority.keys.filter((k) => !revokedKeys.has(k.key_id));
    return { authority: { threshold: bundle.policy.next_authority.threshold, keys }, head: { version: headV, policy_hash: row.policy_hash } };
  }

  /** Stored-bundle eligibility: original signatures minus revoked keys vs threshold. */
  private bundleEligible(bundle: Bundle): { revoked: boolean; signaturesValid: boolean } {
    const policyHash = digest("policy", bundle.policy);
    const revoked = this.revokedSet("policy").has(policyHash);
    let authority: import("../types.ts").Authority;
    if (bundle.policy.version === 1) {
      authority = this.root.bootstrap;
    } else {
      const prev = this.store.get<{ bundle_jcs: string }>(
        "SELECT bundle_jcs FROM policies WHERE version=?", bundle.policy.version - 1);
      if (!prev) throw new CharterError("AUDIT_UNAVAILABLE", "predecessor missing");
      authority = (parseJsonText(prev.bundle_jcs) as unknown as Bundle).policy.next_authority;
    }
    const revokedKeys = this.revokedSet("policy_key");
    const authKeys = new Map(authority.keys.map((k) => [k.key_id, k.public_key]));
    const msg = signMessage("policy", bundle.policy);
    const counted = new Set<string>();
    let eligible = 0;
    for (const s of bundle.signatures) {
      if (revokedKeys.has(s.key_id) || counted.has(s.key_id)) continue;
      const pub = authKeys.get(s.key_id);
      if (!pub) continue;
      if (!verifyBytes(msg, Buffer.from(s.signature, "base64url"), Buffer.from(pub, "hex"))) {
        throw new CharterError("AUDIT_UNAVAILABLE", "stored signature corrupt");
      }
      counted.add(s.key_id);
      eligible++;
    }
    return { revoked, signaturesValid: eligible >= authority.threshold };
  }

  private loadBundle(version: number): Bundle {
    const row = this.store.get<{ bundle_jcs: string }>("SELECT bundle_jcs FROM policies WHERE version=?", version);
    if (!row) throw new CharterError("NOT_FOUND", `policy version ${version} absent`);
    return vBundle(parseJsonText(row.bundle_jcs), "$.bundle");
  }

  /* ================= mutation scaffold ================= */

  /**
   * Shared mutation path inside the barrier: opportunistic schema validity for
   * FORBIDDEN logging → role → idempotency → bounds → rate → clock → tx(work).
   * Every recordable rejection appends CommandRejected; nonretryable new-ID
   * rejections also reserve the tombstone + error response.
   */
  private async command<T extends { request_id: string }>(
    op: string, path: string, rec: AuthRecord, roles: string[],
    rawBody: Json, validate: (b: Json) => T, work: (parsed: T, nowMs: number) => StoredResponse,
    opts: { clockExempt?: boolean; operatorBucket?: boolean; restrictiveCap?: boolean } = {},
  ): Promise<StoredResponse> {
    return this.barrier(() => {
      this.checkLive();
      const nowMs = this.clock.sample();
      // Role gate — FORBIDDEN is recordable when the body is schema-valid.
      if (!roles.includes(rec.role)) {
        let parsed: T | null = null;
        try { parsed = validate(rawBody); } catch { /* not schema-valid */ }
        if (parsed) {
          const h = this.requestHash("POST", path, rawBody);
          throw this.reject(op, h, parsed.request_id, "FORBIDDEN", rec, nowMs);
        }
        throw new CharterError("FORBIDDEN");
      }
      const parsed = validate(rawBody); // SCHEMA — never recorded
      const reqHash = this.requestHash("POST", path, rawBody);
      const replay = this.resolveRetry(parsed.request_id, rec.principal_id, op, reqHash, nowMs, false);
      if (replay) return replay;
      this.capacityCheck(nowMs, opts.restrictiveCap ?? false);
      if (opts.operatorBucket) this.limiter.operatorControl(rec.principal_id, nowMs);
      else this.limiter.mutation(this.config.tenant_id, rec.principal_id, nowMs);
      if (!opts.clockExempt && this.clock.isUnsafe()) {
        throw this.reject(op, reqHash, parsed.request_id, "CLOCK_UNSAFE", rec, nowMs);
      }
      try {
        return this.store.tx(() => {
          if (this.hooks.failNextCommit) {
            this.hooks.failNextCommit = false;
            throw new CharterError("AUDIT_UNAVAILABLE", "injected commit failure");
          }
          const resp = work(parsed, nowMs);
          this.storeResponse(parsed.request_id, rec.principal_id, op, reqHash, resp, nowMs,
            (resp.body as { audit_seq?: number }).audit_seq ?? null, "mutation");
          return resp;
        });
      } catch (e) {
        if (e instanceof CharterError && e.auditSeq !== null) throw e;
        if (e instanceof CharterError && recordable(e.code)) {
          const seq = this.recordRejection(op, reqHash, e.code, rec.principal_id, parsed.request_id, nowMs);
          throw new CharterError(e.code, undefined, seq);
        }
        if (e instanceof CharterError && e.code === "AUDIT_UNAVAILABLE") this.metrics.audit_failures++;
        throw e;
      }
    });
  }

  /* ================= publications ================= */

  /** POST /v1/charters */
  async publish(rec: AuthRecord, rawBody: Json): Promise<StoredResponse> {
    return this.command("POST /v1/charters", "/v1/charters", rec, ["publisher", "operator"], rawBody,
      (b) => {
        if (b === null || typeof b !== "object" || Array.isArray(b)) throw new CharterError("SCHEMA");
        const o = b as Record<string, unknown>;
        const keys = Object.keys(o).sort();
        if (keys.length !== 2 || keys[0] !== "bundle" || keys[1] !== "request_id") throw new CharterError("SCHEMA");
        if (!isIdStr(o.request_id, "crq")) throw new CharterError("SCHEMA");
        const bundle = vBundle(o.bundle, "$.bundle");
        if (utf8Size(canonicalBytes(bundle as unknown as Json)) > 256 * 1024) throw new CharterError("LIMIT");
        return { request_id: o.request_id as string, bundle };
      },
      (parsed, nowMs) => {
        const bundle = parsed.bundle;
        const headV = this.meta().head_version;
        // manifest digest
        if (digest("manifest", bundle.manifest) !== bundle.policy.manifest_hash) {
          throw new CharterError("HASH_MISMATCH");
        }
        // identity vs root
        if (bundle.policy.tenant_id !== this.root.tenant_id ||
            bundle.policy.charter_id !== this.root.charter_id ||
            bundle.manifest.gateway_id !== this.root.gateway_id) {
          throw new CharterError("SCHEMA", "identity mismatch vs root");
        }
        // signature set under the applicable authority
        const revokedKeys = this.revokedSet("policy_key");
        let authority: import("../types.ts").Authority;
        if (bundle.policy.version === 1) {
          authority = this.root.bootstrap;
        } else {
          const prev = this.store.get<{ bundle_jcs: string }>(
            "SELECT bundle_jcs FROM policies WHERE version=?", bundle.policy.version - 1);
          if (!prev) throw new CharterError("VERSION_CONFLICT", "predecessor not published");
          authority = (parseJsonText(prev.bundle_jcs) as unknown as Bundle).policy.next_authority;
        }
        const eff = { threshold: authority.threshold, keys: authority.keys.filter((k) => !revokedKeys.has(k.key_id)) };
        checkSignatureSet(bundle.signatures, eff, signMessage("policy", bundle.policy));
        compile(bundle.policy, bundle.manifest);
        // predecessor CAS / republish
        const policyHash = digest("policy", bundle.policy);
        const existing = this.store.get<{ policy_hash: string; published_seq: number; bundle_jcs: string }>(
          "SELECT policy_hash,published_seq,bundle_jcs FROM policies WHERE version=?", bundle.policy.version);
        if (existing) {
          if (existing.policy_hash === policyHash) {
            const orig = parseJsonText(existing.bundle_jcs) as unknown as Bundle;
            return { status: 201, body: { pin: pinFor(orig), head_version: orig.policy.version, audit_seq: existing.published_seq } as unknown as Json };
          }
          throw new CharterError("VERSION_CONFLICT", "version exists with different hash");
        }
        if (bundle.policy.version !== headV + 1) throw new CharterError("VERSION_CONFLICT", "version gap");
        if (headV > 0) {
          const headRow = this.store.get<{ policy_hash: string }>("SELECT policy_hash FROM policies WHERE version=?", headV);
          if (bundle.policy.previous_hash !== headRow!.policy_hash) {
            throw new CharterError("VERSION_CONFLICT", "previous_hash does not bind head");
          }
        } else if (bundle.policy.previous_hash !== null) {
          throw new CharterError("VERSION_CONFLICT");
        }
        // publication time bounds
        if (!(timeMs(bundle.policy.issued_at) <= nowMs && nowMs < timeMs(bundle.policy.not_after))) {
          throw new CharterError("POLICY_INELIGIBLE");
        }
        const pin = pinFor(bundle);
        const seq = this.appendAudit(rec.principal_id, pin,
          { type: "PolicyPublished", value: { pin, source: bundle.policy.source } }, msTime(nowMs));
        this.store.run(
          "INSERT INTO policies(version,policy_hash,previous_hash,bundle_jcs,published_seq) VALUES(?,?,?,?,?)",
          bundle.policy.version, policyHash, bundle.policy.previous_hash,
          canonicalBytes(bundle as unknown as Json), seq);
        this.store.run("UPDATE meta SET head_version=? WHERE singleton=1", bundle.policy.version);
        return { status: 201, body: { pin, head_version: bundle.policy.version, audit_seq: seq } as unknown as Json };
      });
  }

  /** POST /v1/charters/validate — full publication order minus predecessor CAS. */
  async validateBundleRoute(rec: AuthRecord, rawBody: Json): Promise<StoredResponse> {
    this.checkLive();
    const nowMs = this.clock.sample();
    if (rec.role !== "publisher" && rec.role !== "operator") throw new CharterError("FORBIDDEN");
    this.limiter.validation(this.config.tenant_id, nowMs);
    if (this.clock.isUnsafe()) throw new CharterError("CLOCK_UNSAFE");
    const b = rawBody as Record<string, unknown>;
    if (b === null || typeof b !== "object" || Array.isArray(b)) throw new CharterError("SCHEMA");
    const keys = Object.keys(b).sort();
    if (keys.length !== 1 || keys[0] !== "bundle") throw new CharterError("SCHEMA");
    const bundle = vBundle(b.bundle, "$.bundle");
    if (digest("manifest", bundle.manifest) !== bundle.policy.manifest_hash) throw new CharterError("HASH_MISMATCH");
    let authority: import("../types.ts").Authority;
    if (bundle.policy.version === 1) {
      authority = this.root.bootstrap;
    } else {
      const prev = this.store.get<{ bundle_jcs: string }>(
        "SELECT bundle_jcs FROM policies WHERE version=?", bundle.policy.version - 1);
      if (!prev) throw new CharterError("VERSION_CONFLICT", "predecessor not published");
      authority = (parseJsonText(prev.bundle_jcs) as unknown as Bundle).policy.next_authority;
    }
    const revokedKeys = this.revokedSet("policy_key");
    const eff = { threshold: authority.threshold, keys: authority.keys.filter((k) => !revokedKeys.has(k.key_id)) };
    const sigs = checkSignatureSet(bundle.signatures, eff, signMessage("policy", bundle.policy));
    compile(bundle.policy, bundle.manifest);
    if (!(timeMs(bundle.policy.issued_at) <= nowMs && nowMs < timeMs(bundle.policy.not_after))) {
      throw new CharterError("POLICY_INELIGIBLE");
    }
    const warnings = new Set<Warning>();
    if (bundle.policy.scope_rules.length === 0) warnings.add("NO_ALLOW_RULES");
    if (authority.threshold === 1) warnings.add("SINGLE_SIGNER");
    if (timeMs(bundle.policy.not_after) - nowMs <= DAY_MS) warnings.add("EXPIRY_WITHIN_24H");
    const v: Validated = {
      valid: true, pin: pinFor(bundle), signatures: sigs, required: authority.threshold,
      warnings: [...warnings].sort(),
    };
    return { status: 200, body: v as unknown as Json };
  }

  /* ================= deployment controls ================= */

  /** POST /v1/deployment/pin */
  async pin(rec: AuthRecord, rawBody: Json): Promise<StoredResponse> {
    return this.command("POST /v1/deployment/pin", "/v1/deployment/pin", rec, ["operator"], rawBody,
      (b) => {
        const sp = vSignedPin(b, "$");
        return { request_id: sp.command.request_id, signedPin: sp };
      },
      (parsed, nowMs) => {
        const sp = parsed.signedPin;
        const cmd = sp.command;
        if (cmd.tenant_id !== this.config.tenant_id || cmd.gateway_id !== this.config.gateway_id ||
            cmd.target.charter_id !== this.root.charter_id) {
          throw new CharterError("SCHEMA", "pin identity mismatch");
        }
        const dep = this.deployment();
        // Recordable rejections: thrown as plain CharterError; command() catch
        // appends CommandRejected + tombstone in a fresh tx.
        const { authority, head } = this.currentAuthority();
        checkSignatureSet(sp.signatures, authority, signMessage("pin", cmd));
        if (!(nowMs < timeMs(cmd.expires_at)) || timeMs(cmd.expires_at) - nowMs > PIN_MAX_AHEAD_MS) {
          throw new CharterError("PIN_EXPIRED");
        }
        if (cmd.expected_revision !== dep.revision) throw new CharterError("REVISION_CONFLICT");
        if (cmd.expected_revocation_epoch !== dep.revocation_epoch) throw new CharterError("REVOCATION_CONFLICT");
        if (cmd.authority_policy_hash !== head.policy_hash ||
            cmd.target.version !== head.version || cmd.target.policy_hash !== head.policy_hash ||
            cmd.target.engine !== ENGINE) {
          throw new CharterError("PIN_NOT_HEAD");
        }
        const targetBundle = this.loadBundle(cmd.target.version);
        if (digest("manifest", targetBundle.manifest) !== cmd.target.manifest_hash) throw new CharterError("PIN_NOT_HEAD");
        const elig = this.bundleEligible(targetBundle);
        if (elig.revoked || !elig.signaturesValid) throw new CharterError("POLICY_INACTIVE");
        if (cmd.target.manifest_hash !== dep.installed_manifest_hash) throw new CharterError("MANIFEST_UNAVAILABLE");
        const p = targetBundle.policy;
        if (nowMs < timeMs(p.not_before) || nowMs >= timeMs(p.not_after)) throw new CharterError("POLICY_INACTIVE");
        const artifact: ControlArtifact = { kind: "pin", value: sp };
        const controlHash = digest("control", artifact as unknown as Json);
        const newDep: Deployment = { ...dep, revision: dep.revision + 1, state: "ACTIVE", pin: cmd.target };
        const seq = this.appendAudit(rec.principal_id, cmd.target, {
          type: "PinActivated",
          value: { revision: newDep.revision, revocation_epoch: dep.revocation_epoch, previous_pin: dep.pin, pin: cmd.target, control_hash: controlHash, in_flight: dep.in_flight },
        }, msTime(nowMs));
        this.insertControl(seq, artifact);
        this.saveDeployment(newDep);
        return { status: 200, body: { deployment: { ...newDep, in_flight: dep.in_flight }, audit_seq: seq } as unknown as Json };
      });
  }

  /** POST /v1/deployment/pause — allowed during clock faults. */
  async pause(rec: AuthRecord, rawBody: Json): Promise<StoredResponse> {
    return this.command("POST /v1/deployment/pause", "/v1/deployment/pause", rec, ["operator"], rawBody,
      (b) => vPauseRequest(b, "$"),
      (pr, nowMs) => {
        const dep = this.deployment();
        if (pr.expected_revision !== dep.revision) {
          throw new CharterError("REVISION_CONFLICT");
        }
        const artifact: ControlArtifact = { kind: "pause", value: pr };
        const controlHash = digest("control", artifact as unknown as Json);
        const newDep: Deployment = { ...dep, revision: dep.revision + 1, state: "PAUSED" };
        const seq = this.appendAudit(rec.principal_id, dep.pin, {
          type: "GatewayPaused", value: { revision: newDep.revision, control_hash: controlHash, in_flight: dep.in_flight },
        }, msTime(nowMs));
        this.insertControl(seq, artifact);
        this.saveDeployment(newDep);
        return { status: 200, body: { deployment: { ...newDep, in_flight: dep.in_flight }, audit_seq: seq } as unknown as Json };
      }, { clockExempt: true, operatorBucket: true, restrictiveCap: true });
  }

  /** POST /v1/revocations — permanent, epoch-CAS. */
  async revoke(rec: AuthRecord, rawBody: Json): Promise<StoredResponse> {
    return this.command("POST /v1/revocations", "/v1/revocations", rec, ["operator"], rawBody,
      (b) => vRevokeRequest(b, "$"),
      (rr, nowMs) => {
        const dep = this.deployment();
        if (rr.expected_revocation_epoch !== dep.revocation_epoch) throw new CharterError("REVOCATION_CONFLICT");
        if (!this.targetKnown(rr.target)) throw new CharterError("NOT_FOUND");
        if (this.isRevoked(rr.target)) throw new CharterError("ALREADY_REVOKED");
        const artifact: ControlArtifact = { kind: "revoke", value: rr };
        const controlHash = digest("control", artifact as unknown as Json);
        const epoch = dep.revocation_epoch + 1;
        const seq = this.appendAudit(rec.principal_id, dep.pin, {
          type: "TargetRevoked", value: { epoch, target: rr.target, control_hash: controlHash, in_flight: dep.in_flight },
        }, msTime(nowMs));
        this.insertControl(seq, artifact);
        const targetId = rr.target.kind === "policy" ? rr.target.policy_hash
          : rr.target.kind === "credential" ? rr.target.credential_id : rr.target.key_id;
        const rev: Revocation = { ...rr, epoch, actor_id: rec.principal_id, effective_seq: seq, recorded_at: msTime(nowMs) };
        this.store.run(
          "INSERT INTO revocations(epoch,target_kind,target_id,record_jcs,effective_seq) VALUES(?,?,?,?,?)",
          epoch, rr.target.kind, targetId, canonicalize(rev as unknown as Json), seq);
        const newDep = { ...dep, revocation_epoch: epoch };
        this.saveDeployment(newDep);
        return { status: 201, body: { revocation: rev, deployment: { ...newDep, in_flight: dep.in_flight } } as unknown as Json };
      }, { clockExempt: true, operatorBucket: true, restrictiveCap: true });
  }

  private targetKnown(t: RevokeTarget): boolean {
    if (t.kind === "policy") {
      return this.store.get<{ version: number }>("SELECT version FROM policies WHERE policy_hash=?", t.policy_hash) !== undefined;
    }
    if (t.kind === "credential") {
      return [...this.authByHash.values()].some((r) => r.credential_id === t.credential_id);
    }
    if (this.root.bootstrap.keys.some((k) => k.key_id === t.key_id)) return true;
    const rows = this.store.all<{ bundle_jcs: string }>("SELECT bundle_jcs FROM policies");
    return rows.some((r) =>
      (parseJsonText(r.bundle_jcs) as unknown as Bundle).policy.next_authority.keys.some((k) => k.key_id === t.key_id));
  }

  /* ================= fleet ================= */

  /** POST /v1/fleet/heartbeat */
  async heartbeat(rec: AuthRecord, rawBody: Json): Promise<StoredResponse> {
    return this.command("POST /v1/fleet/heartbeat", "/v1/fleet/heartbeat", rec, ["instance"], rawBody,
      (b) => vHeartbeat(b, "$"),
      (hb, nowMs) => {
        if (rec.instance_id === null || hb.instance_id !== rec.instance_id) {
          throw new CharterError("FORBIDDEN", "heartbeat names a different installation");
        }
        const prev = this.store.get<{ counter: number }>("SELECT counter FROM instances WHERE instance_id=?", hb.instance_id);
        if (hb.counter !== (prev?.counter ?? 0) + 1) {
          throw new CharterError("COUNTER_CONFLICT");
        }
        const expiresMs = nowMs + HEARTBEAT_FRESH_MS;
        const seq = this.appendAudit(rec.principal_id, this.deployment().pin, {
          type: "InstanceObserved", value: { heartbeat: hb, expires_at: msTime(expiresMs) },
        }, msTime(nowMs));
        this.store.run(
          "INSERT INTO instances(instance_id,counter,received_ms,observation_jcs) VALUES(?,?,?,?) " +
          "ON CONFLICT(instance_id) DO UPDATE SET counter=excluded.counter,received_ms=excluded.received_ms,observation_jcs=excluded.observation_jcs",
          hb.instance_id, hb.counter, nowMs,
          canonicalize({ observed_pin: hb.observed_pin, manifest_hash: hb.manifest_hash } as unknown as Json));
        const fl = this.fleetFor(hb.instance_id, nowMs);
        return { status: 200, body: { counter: hb.counter, expires_at: msTime(expiresMs), state: fl.state, audit_seq: seq } as unknown as Json };
      });
  }

  /* ================= gateway ================= */

  /** POST /v1/gateway/check */
  async check(rec: AuthRecord, rawBody: Json): Promise<StoredResponse> {
    return this.admission(rec, rawBody, false);
  }

  /** POST /v1/gateway/call */
  async call(rec: AuthRecord, rawBody: Json): Promise<StoredResponse> {
    return this.admission(rec, rawBody, true);
  }

  private async admission(rec: AuthRecord, rawBody: Json, isCall: boolean): Promise<StoredResponse> {
    const op = isCall ? "POST /v1/gateway/call" : "POST /v1/gateway/check";
    const path = isCall ? "/v1/gateway/call" : "/v1/gateway/check";
    if (isCall) this.waiting++;
    try {
      const out = await this.barrier(async () => {
        this.checkLive();
        const req = vCallRequest(rawBody, "$"); // SCHEMA — never recorded
        const reqHash = this.requestHash("POST", path, rawBody);
        const nowMs = this.clock.sample();
        if (rec.role !== "agent" || rec.instance_id !== this.config.instance_id) {
          throw this.reject(op, reqHash, req.request_id, "FORBIDDEN", rec, nowMs);
        }
        const replay = this.resolveRetry(req.request_id, rec.principal_id, op, reqHash, nowMs, isCall);
        if (replay) return { kind: "replay" as const, resp: replay };
        this.capacityCheck(nowMs, false);
        const dep = this.deployment();
        if (isCall && (dep.in_flight >= Math.min(this.config.max_in_flight, MAX_IN_FLIGHT) || this.waiting > MAX_WAITING)) {
          throw new CharterError("BUSY", "admission queue full");
        }
        this.limiter.mutation(this.config.tenant_id, rec.principal_id, nowMs);
        if (this.clock.isUnsafe()) {
          throw this.reject(op, reqHash, req.request_id, "CLOCK_UNSAFE", rec, nowMs);
        }
        if (dep.state === "UNPINNED") {
          throw this.reject(op, reqHash, req.request_id, "UNPINNED", rec, nowMs);
        }
        if (dep.state === "PAUSED") {
          throw this.reject(op, reqHash, req.request_id, "PAUSED", rec, nowMs);
        }
        const activePin = dep.pin!;
        if (activePin.manifest_hash !== dep.installed_manifest_hash) {
          throw this.reject(op, reqHash, req.request_id, "MANIFEST_UNAVAILABLE", rec, nowMs);
        }
        const fl = this.fleetFor(rec.instance_id!, nowMs);
        if (fl.state === "MISSING") {
          throw this.reject(op, reqHash, req.request_id, "INSTANCE_STALE", rec, nowMs);
        }
        if (fl.state === "MISMATCH") {
          throw this.reject(op, reqHash, req.request_id, "INSTANCE_MISMATCH", rec, nowMs);
        }
        const bundle = this.loadBundle(activePin.version);
        if (digest("policy", bundle.policy) !== activePin.policy_hash ||
            digest("manifest", bundle.manifest) !== activePin.manifest_hash) {
          throw new CharterError("AUDIT_UNAVAILABLE", "stored bundle hash mismatch");
        }
        const elig = this.bundleEligible(bundle);
        const principal = this.principal(rec);
        const inputHash = digest("input", { request: req, principal });
        const now = msTime(nowMs);
        const decision = evaluate({
          policy: bundle.policy, manifest: bundle.manifest, active_pin: activePin,
          request: req, principal, now,
          policy_revoked: elig.revoked, policy_signatures_valid: elig.signaturesValid,
        });
        const dd: DecisionData = {
          request_id: req.request_id, input_hash: inputHash, evaluated_at: now,
          decision, revision: dep.revision, revocation_epoch: dep.revocation_epoch,
          instance_counter: fl.counter,
        };

        if (!isCall) {
          const { resp, seq } = this.store.tx(() => {
            this.maybeInjectFault();
            const s = this.appendAudit(rec.principal_id, activePin, { type: "CheckEvaluated", value: dd }, now);
            const result: CheckResult = { decision, input_hash: inputHash, enforcement: false, audit_seq: s };
            const r: StoredResponse = { status: 200, body: result as unknown as Json };
            this.storeResponse(req.request_id, rec.principal_id, op, reqHash, r, nowMs, s, "check");
            return { resp: r, seq: s };
          });
          return { kind: "done" as const, resp };
        }

        if (decision.verdict === "DENY") {
          const { resp } = this.store.tx(() => {
            this.maybeInjectFault();
            const s = this.appendAudit(rec.principal_id, activePin, { type: "CallDenied", value: dd }, now);
            const result: CallResult = {
              request_id: req.request_id, state: "DENIED", decision, input_hash: inputHash,
              output: null, output_available: false, output_hash: null, audit_seqs: [s],
            };
            const r: StoredResponse = { status: 200, body: result as unknown as Json };
            this.storeResponse(req.request_id, rec.principal_id, op, reqHash, r, nowMs, s, "call");
            this.insertCallRow(req, rec.principal_id, inputHash, "DENIED", decision, timeMs(req.deadline), [s]);
            this.bumpCallMetrics(decision, nowMs);
            return { resp: r };
          });
          return { kind: "done" as const, resp };
        }

        // ALLOW → durable COMMITTED marker (atomic with tombstone + event).
        const commit = this.store.tx(() => {
          this.maybeInjectFault();
          const s = this.appendAudit(rec.principal_id, activePin, { type: "CallCommitted", value: dd }, now);
          const result: CallResult = {
            request_id: req.request_id, state: "COMMITTED", decision, input_hash: inputHash,
            output: null, output_available: false, output_hash: null, audit_seqs: [s],
          };
          const r: StoredResponse = { status: 202, body: result as unknown as Json };
          this.storeResponse(req.request_id, rec.principal_id, op, reqHash, r, nowMs, s, "call");
          this.insertCallRow(req, rec.principal_id, inputHash, "COMMITTED", decision, timeMs(req.deadline), [s]);
          this.bumpCallMetrics(decision, nowMs);
          return { resp: r, seq: s };
        });

        if (this.hooks.crashAfterMarker) {
          this.hooks.crashAfterMarker = false;
          this.crashed = true;
          throw new CrashFault();
        }

        if (this.hooks.advanceClockToMs !== undefined) {
          const to = this.hooks.advanceClockToMs;
          this.hooks.advanceClockToMs = undefined;
          this.clock.inject = () => to;
        }

        // §7.1 step 6: post-commit timed recheck while still holding the barrier.
        const nowMs2 = this.clock.sample();
        const invalid = this.postCommitInvalid(rec, req, nowMs2, activePin);
        if (invalid) {
          const resp = this.store.tx(() => {
            const s2 = this.appendAudit(this.config.system_principal_id, activePin,
              { type: "CallFinished", value: { request_id: req.request_id, state: "NOT_SENT", output_hash: null } }, msTime(nowMs2));
            this.finishCall(req.request_id, "NOT_SENT", null, null, s2);
            const result: CallResult = {
              request_id: req.request_id, state: "NOT_SENT", decision,
              input_hash: inputHash, output: null, output_available: false,
              output_hash: null, audit_seqs: [commit.seq, s2],
            };
            const r: StoredResponse = { status: 200, body: result as unknown as Json };
            this.updateStoredResponse(req.request_id, r, nowMs2);
            this.metrics.not_sent++;
            return r;
          });
          return { kind: "done" as const, resp };
        }

        // §7.1 step 8: initiate exactly one immutable RECORDS.run promise now.
        const tool = installedTool(this.manifest, req.tool)!;
        const ar: AdapterRequest = {
          request_id: req.request_id, principal_id: rec.principal_id, scope: req.scope,
          pin: activePin, input_hash: inputHash, operation: tool.operation,
          resource: req.resource, args: req.args, deadline: req.deadline,
        };
        let adapterPromise: Promise<AdapterResponse>;
        try {
          adapterPromise = Promise.resolve(this.adapter.run(ar));
          adapterPromise.catch(() => undefined); // never unhandled
        } catch {
          adapterPromise = Promise.resolve({ status: "unknown" });
        }
        return {
          kind: "committed" as const, req, decision, inputHash,
          commitSeq: commit.seq, activePin, adapterPromise,
          deadlineMs: timeMs(req.deadline),
        };
      });

      if (out.kind !== "committed") return out.resp;
      return await this.driveCall(rec, out);
    } catch (e) {
      if (e instanceof CharterError && e.code === "AUDIT_UNAVAILABLE") this.metrics.audit_failures++;
      throw e;
    } finally {
      if (isCall) this.waiting--;
    }
  }

  private maybeInjectFault(): void {
    if (this.hooks.failNextCommit) {
      this.hooks.failNextCommit = false;
      throw new CharterError("AUDIT_UNAVAILABLE", "injected commit failure");
    }
  }

  private insertCallRow(req: CallRequest, owner: string, inputHash: Hash, state: CallState,
    decision: Decision, deadlineMs: number, seqs: number[]): void {
    this.store.run(
      "INSERT INTO calls(request_id,owner_id,input_hash,state,decision_jcs,deadline_ms,output_enc,output_hash,audit_seqs_jcs) VALUES(?,?,?,?,?,?,NULL,NULL,?)",
      req.request_id, owner, inputHash, state,
      canonicalize(decision as unknown as Json), deadlineMs, canonicalize(seqs as unknown as Json));
  }

  private bumpCallMetrics(decision: Decision, nowMs: number): void {
    const w = Math.floor(nowMs / 60000) * 60000;
    if (w !== this.metrics.windowStart) {
      this.metrics = { windowStart: w, calls: 0, allows: 0, denies: 0, indeterminate: 0, not_sent: 0, audit_failures: 0 };
    }
    this.metrics.calls++;
    if (decision.verdict === "ALLOW") this.metrics.allows++;
    else this.metrics.denies++;
  }

  /** §7.1 step 6–7 recheck: every timed authority after the durable marker. */
  private postCommitInvalid(rec: AuthRecord, req: CallRequest, nowMs: number, activePin: Pin): boolean {
    if (this.clock.isUnsafe()) return true;
    if (nowMs >= timeMs(req.deadline)) return true;
    if (nowMs >= timeMs(rec.expires_at)) return true;
    if (this.isRevoked({ kind: "credential", credential_id: rec.credential_id })) return true;
    const dep = this.deployment();
    if (dep.state !== "ACTIVE" || !jsonEqual(dep.pin, activePin)) return true;
    const bundle = this.loadBundle(activePin.version);
    const elig = this.bundleEligible(bundle);
    if (elig.revoked || !elig.signaturesValid) return true;
    if (nowMs < timeMs(bundle.policy.not_before) || nowMs >= timeMs(bundle.policy.not_after)) return true;
    const fl = this.fleetFor(rec.instance_id!, nowMs);
    if (fl.state !== "MATCHED") return true;
    return false;
  }

  /** Await adapter outcome outside the barrier; persist the first terminal result. */
  private async driveCall(rec: AuthRecord, c: {
    req: CallRequest; decision: Decision; inputHash: Hash; commitSeq: number;
    activePin: Pin; adapterPromise: Promise<AdapterResponse>; deadlineMs: number;
  }): Promise<StoredResponse> {
    let outcome: AdapterResponse | "timeout";
    const nowMs = this.clock.sample();
    const wait = Math.max(0, c.deadlineMs - nowMs);
    const cap = this.capMs === undefined ? wait : Math.min(wait, this.capMs);
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const timeout = new Promise<"timeout">((res) => { timer = setTimeout(() => res("timeout"), cap); });
      outcome = await Promise.race([c.adapterPromise, timeout]);
    } catch {
      outcome = "timeout";
    } finally {
      if (timer) clearTimeout(timer);
    }
    return this.barrier(() => {
      return this.store.tx(() => {
        const row = this.callRow(c.req.request_id);
        if (!row || row.state !== "COMMITTED") {
          // Late/duplicate outcome can never replace a terminal state.
          const st = (row?.state ?? "INDETERMINATE") as CallState;
          return { status: statusForCall(st), body: this.callResult(c.req.request_id, false) };
        }
        const now2 = this.clock.sample();
        let state: CallState;
        let output: Json = null;
        let outputHash: Hash | null = null;
        if (outcome === "timeout" || outcome.status === "unknown") {
          state = "INDETERMINATE";
        } else {
          const okOut = validAdapterOutput(outcome.output);
          if (!okOut) {
            state = "INDETERMINATE";
          } else {
            state = outcome.status === "ok" ? "SUCCEEDED" : "FAILED";
            output = outcome.output;
            outputHash = sha256Hex(canonicalize(outcome.output));
          }
        }
        const seq = this.appendAudit(rec.principal_id, c.activePin,
          { type: "CallFinished", value: { request_id: c.req.request_id, state: state as "SUCCEEDED" | "FAILED" | "INDETERMINATE", output_hash: outputHash } }, msTime(now2));
        const outText = output === null ? null : canonicalize(output);
        this.finishCall(c.req.request_id, state, outText, outputHash, seq);
        const result: CallResult = {
          request_id: c.req.request_id, state, decision: c.decision, input_hash: c.inputHash,
          output, output_available: output !== null, output_hash: outputHash,
          audit_seqs: [c.commitSeq, seq],
        };
        if (state === "INDETERMINATE") this.metrics.indeterminate++;
        const resp: StoredResponse = { status: statusForCall(state), body: result as unknown as Json };
        this.updateStoredResponse(c.req.request_id, resp, now2);
        return resp;
      });
    });
  }

  private finishCall(requestId: string, state: CallState, outputText: string | null,
    outputHash: Hash | null, seq: number): void {
    const encText = outputText === null ? null : this.enc.encrypt("calls", requestId, "output_enc", outputText);
    const row = this.callRow(requestId);
    const seqs = row ? (JSON.parse(row.audit_seqs_jcs) as number[]) : [];
    if (!seqs.includes(seq)) seqs.push(seq);
    this.store.run(
      "UPDATE calls SET state=?, output_enc=?, output_hash=?, audit_seqs_jcs=? WHERE request_id=?",
      state, encText, outputHash, canonicalize(seqs as unknown as Json), requestId);
  }

  private callRow(requestId: string): {
    state: string; input_hash: string; decision_jcs: string; output_enc: string | null;
    output_hash: string | null; audit_seqs_jcs: string; owner_id: string; deadline_ms: number;
  } | undefined {
    return this.store.get<{
      state: string; input_hash: string; decision_jcs: string; output_enc: string | null;
      output_hash: string | null; audit_seqs_jcs: string; owner_id: string; deadline_ms: number;
    }>("SELECT state,input_hash,decision_jcs,output_enc,output_hash,audit_seqs_jcs,owner_id,deadline_ms FROM calls WHERE request_id=?", requestId);
  }

  private responseLive(requestId: string, nowMs: number): boolean {
    const row = this.store.get<{ response_until_ms: number }>("SELECT response_until_ms FROM requests WHERE request_id=?", requestId);
    return row !== undefined && nowMs < row.response_until_ms;
  }

  /** Rebuild CallResult from durable state; suppress output when expired. */
  callResult(requestId: string, outputLive: boolean): Json {
    const row = this.callRow(requestId);
    if (!row) throw new CharterError("NOT_FOUND");
    const decision = JSON.parse(row.decision_jcs) as Decision;
    let output: Json = null;
    let available = false;
    if (outputLive && row.output_enc !== null) {
      output = parseJsonText(this.enc.decrypt("calls", requestId, "output_enc", row.output_enc));
      available = true;
    }
    return {
      request_id: requestId, state: row.state, decision, input_hash: row.input_hash,
      output, output_available: available, output_hash: row.output_hash,
      audit_seqs: JSON.parse(row.audit_seqs_jcs),
    } as unknown as Json;
  }

  /** GET /v1/gateway/calls/{id} */
  async getCall(rec: AuthRecord, requestId: string): Promise<StoredResponse> {
    this.checkLive();
    const nowMs = this.clock.sample();
    const row = this.callRow(requestId);
    if (!row) throw new CharterError("NOT_FOUND");
    if (rec.role === "agent" && row.owner_id !== rec.principal_id) throw new CharterError("NOT_FOUND");
    if (rec.role !== "agent" && rec.role !== "reader" && rec.role !== "operator") throw new CharterError("FORBIDDEN");
    const live = this.responseLive(requestId, nowMs);
    return { status: statusForCall(row.state as CallState), body: this.callResult(requestId, live) };
  }

  /* ================= disputes ================= */

  /** POST /v1/disputes */
  async dispute(rec: AuthRecord, rawBody: Json): Promise<StoredResponse> {
    return this.command("POST /v1/disputes", "/v1/disputes", rec, ["agent", "reader", "operator"], rawBody,
      (b) => vDisputeRequest(b, "$"),
      (dr, nowMs) => {
        const entry = this.store.get<{ body_jcs: string }>("SELECT body_jcs FROM audit WHERE seq=?", dr.cited_seq);
        let ok = false;
        if (entry) {
          const body = JSON.parse(entry.body_jcs) as AuditBody;
          const t = body.event.type;
          if ((t === "CheckEvaluated" || t === "CallDenied" || t === "CallCommitted") &&
              jsonEqual(body.policy_pin, dr.pin) &&
              (rec.role !== "agent" || body.actor_id === rec.principal_id)) {
            ok = true;
          }
        }
        if (!ok) throw new CharterError("NOT_FOUND", "cited entry unusable for dispute");
        const seq = this.appendAudit(rec.principal_id, dr.pin, {
          type: "DisputeRecorded",
          value: { dispute_id: dr.dispute_id, cited_seq: dr.cited_seq, category: dr.category, statement_hash: sha256Hex(dr.statement) },
        }, msTime(nowMs));
        const dispute: Dispute = {
          ...dr, actor_id: rec.principal_id, recorded_at: msTime(nowMs),
          status: "RECORDED_ADVISORY", receipt_seq: seq,
        };
        const enc = this.enc.encrypt("disputes", dr.dispute_id, "record_enc", canonicalize(dispute as unknown as Json));
        this.store.run("INSERT INTO disputes(dispute_id,owner_id,receipt_seq,record_enc) VALUES(?,?,?,?)",
          dr.dispute_id, rec.principal_id, seq, enc);
        return { status: 201, body: dispute as unknown as Json };
      });
  }

  /* ================= reads ================= */

  /** GET /v1/readyz */
  async readyz(_rec: AuthRecord): Promise<StoredResponse> {
    this.checkLive();
    const nowMs = this.clock.sample();
    if (this.clock.isUnsafe()) throw new CharterError("CLOCK_UNSAFE");
    const dep = this.deployment();
    if (dep.state === "UNPINNED") throw new CharterError("UNPINNED");
    if (dep.state === "PAUSED") throw new CharterError("PAUSED");
    const pin = dep.pin!;
    if (pin.manifest_hash !== dep.installed_manifest_hash) throw new CharterError("MANIFEST_UNAVAILABLE");
    const bundle = this.loadBundle(pin.version);
    const elig = this.bundleEligible(bundle);
    const p = bundle.policy;
    if (elig.revoked || !elig.signaturesValid || nowMs < timeMs(p.not_before) || nowMs >= timeMs(p.not_after)) {
      throw new CharterError("POLICY_INACTIVE");
    }
    const fl = this.fleetFor(this.config.instance_id, nowMs);
    if (fl.state === "MISSING") throw new CharterError("INSTANCE_STALE");
    if (fl.state === "MISMATCH") throw new CharterError("INSTANCE_MISMATCH");
    return { status: 200, body: { ready: true, deployment: dep } as unknown as Json };
  }

  async versions(after: number, limit: number): Promise<StoredResponse> {
    this.checkLive();
    const rows = this.store.all<{ version: number; bundle_jcs: string }>(
      "SELECT version,bundle_jcs FROM policies WHERE version>? ORDER BY version LIMIT ?", after, limit + 1);
    const page = rows.slice(0, limit);
    const versions = page.map((r) => pinFor(parseJsonText(r.bundle_jcs) as unknown as Bundle));
    const next_after = rows.length > limit ? page[page.length - 1]!.version : null;
    return { status: 200, body: { versions, head_version: this.meta().head_version, next_after } as unknown as Json };
  }

  async getBundle(version: number): Promise<StoredResponse> {
    this.checkLive();
    const row = this.store.get<{ bundle_jcs: string }>("SELECT bundle_jcs FROM policies WHERE version=?", version);
    if (!row) throw new CharterError("NOT_FOUND");
    return { status: 200, body: parseJsonText(row.bundle_jcs) };
  }

  async getCitation(version: number, ruleId: string): Promise<StoredResponse> {
    this.checkLive();
    const bundle = this.loadBundle(version);
    return { status: 200, body: cite(bundle, ruleId as import("../types.ts").RuleId) as unknown as Json };
  }

  async getDeployment(): Promise<StoredResponse> {
    this.checkLive();
    return { status: 200, body: this.deployment() as unknown as Json };
  }

  async revocations(afterEpoch: number, limit: number): Promise<StoredResponse> {
    this.checkLive();
    const rows = this.store.all<{ record_jcs: string; epoch: number }>(
      "SELECT record_jcs,epoch FROM revocations WHERE epoch>? ORDER BY epoch LIMIT ?", afterEpoch, limit + 1);
    const page = rows.slice(0, limit);
    const next_after = rows.length > limit ? page[page.length - 1]!.epoch : null;
    return {
      status: 200,
      body: { epoch: this.deployment().revocation_epoch, revocations: page.map((r) => JSON.parse(r.record_jcs)), next_after } as unknown as Json,
    };
  }

  async fleet(): Promise<StoredResponse> {
    this.checkLive();
    const nowMs = this.clock.sample();
    const dep = this.deployment();
    const instances: InstanceView[] = [...this.config.instance_inventory].sort().map((id) => {
      const fl = this.fleetFor(id, nowMs);
      const row = this.store.get<{ received_ms: number | null; observation_jcs: string }>(
        "SELECT received_ms,observation_jcs FROM instances WHERE instance_id=?", id);
      const obs = row ? (JSON.parse(row.observation_jcs) as { observed_pin: Pin | null; manifest_hash: Hash }) : null;
      return {
        instance_id: id, counter: fl.counter,
        received_at: fl.receivedMs === null ? null : msTime(fl.receivedMs),
        expires_at: fl.receivedMs === null ? null : msTime(fl.receivedMs + HEARTBEAT_FRESH_MS),
        observed_pin: obs?.observed_pin ?? null,
        manifest_hash: obs?.manifest_hash ?? null,
        state: fl.state,
      } as InstanceView;
    });
    let status: Fleet["status"];
    if (dep.pin === null) status = "EMPTY";
    else if (instances.some((i) => i.state === "MISMATCH")) status = "SPLIT";
    else if (instances.some((i) => i.state === "MISSING")) status = "MISSING";
    else status = "HEALTHY";
    const fleet: Fleet = { as_of: msTime(nowMs), desired_pin: dep.pin, status, instances };
    return { status: 200, body: fleet as unknown as Json };
  }

  async auditPage(afterSeq: number, throughSeq: number, limit: number): Promise<StoredResponse> {
    this.checkLive();
    const head = this.meta().next_seq - 1;
    if (!isIntSafe(throughSeq) || !isIntSafe(afterSeq) || throughSeq > head || throughSeq < afterSeq) {
      throw new CharterError("SCHEMA", "through_seq out of bounds");
    }
    const rows = this.store.all<{ seq: number; hash: string; body_jcs: string; key_id: string; signature: string }>(
      "SELECT seq,hash,body_jcs,key_id,signature FROM audit WHERE seq>? AND seq<=? ORDER BY seq LIMIT ?",
      afterSeq, throughSeq, limit + 1);
    const page = rows.slice(0, limit);
    const entries: AuditEntry[] = page.map((r) => ({
      body: JSON.parse(r.body_jcs) as AuditBody, hash: r.hash,
      key_id: r.key_id as AuditEntry["key_id"], signature: r.signature,
    }));
    const controls: ControlArtifact[] = [];
    for (const r of page) {
      const body = JSON.parse(r.body_jcs) as AuditBody;
      const ch = controlHashOf(body.event);
      if (ch) {
        const c = this.store.get<{ artifact_jcs: string }>("SELECT artifact_jcs FROM controls WHERE audit_seq=?", r.seq);
        if (!c) throw new CharterError("AUDIT_UNAVAILABLE", "control artifact missing");
        const artifact = JSON.parse(c.artifact_jcs) as ControlArtifact;
        if (digest("control", artifact as unknown as Json) !== ch) {
          throw new CharterError("AUDIT_UNAVAILABLE", "control hash mismatch");
        }
        controls.push(artifact);
      }
    }
    const next_after = rows.length > limit ? page[page.length - 1]!.seq : null;
    return { status: 200, body: { entries, controls, through_seq: throughSeq, next_after } as unknown as Json };
  }

  async checkpoint(throughSeq: number | null): Promise<StoredResponse> {
    this.checkLive();
    const head = this.meta().next_seq - 1;
    const want = throughSeq === null ? head : throughSeq;
    if (want > head || want < 0) throw new CharterError("NOT_FOUND", "through_seq beyond head");
    const existing = this.store.get<{ checkpoint_jcs: string }>(
      "SELECT checkpoint_jcs FROM checkpoints WHERE through_seq=?", want);
    if (existing) return { status: 200, body: parseJsonText(existing.checkpoint_jcs) };
    if (throughSeq !== null && want !== head) throw new CharterError("NOT_FOUND", "historical checkpoint unavailable");
    const cp = this.makeCheckpoint(want);
    return { status: 200, body: cp as unknown as Json };
  }

  private makeCheckpoint(throughSeq: number): Checkpoint {
    const head = this.meta().next_seq - 1;
    if (throughSeq > head) throw new CharterError("SCHEMA", "through_seq beyond head");
    const existing = this.store.get<{ checkpoint_jcs: string }>(
      "SELECT checkpoint_jcs FROM checkpoints WHERE through_seq=?", throughSeq);
    if (existing) return parseJsonText(existing.checkpoint_jcs) as unknown as Checkpoint;
    const nowMs = this.clock.sample();
    const key = this.auditKeyAt(throughSeq);
    if (!key || key.key_id !== this.config.audit_key_id) throw new CharterError("AUDIT_UNAVAILABLE");
    const headHash = throughSeq === 0 ? ZERO_HASH
      : this.store.get<{ hash: string }>("SELECT hash FROM audit WHERE seq=?", throughSeq)!.hash;
    const body: import("../types.ts").CheckpointBody = {
      schema: "charter.checkpoint/1", tenant_id: this.root.tenant_id, log_id: this.root.log_id,
      through_seq: throughSeq, head_hash: headHash, time: msTime(nowMs),
    };
    const signature = Buffer.from(signBytes(signMessage("checkpoint", body), this.auditSeed)).toString("base64url");
    const cp: Checkpoint = { body, key_id: key.key_id as Checkpoint["key_id"], signature };
    this.store.run("INSERT INTO checkpoints(through_seq,checkpoint_jcs) VALUES(?,?)",
      throughSeq, canonicalize(cp as unknown as Json));
    return cp;
  }

  async metricsSnapshot(): Promise<StoredResponse> {
    this.checkLive();
    if (!this.config.metrics_enabled) throw new CharterError("NOT_FOUND");
    const nowMs = this.clock.sample();
    const w = Math.floor(nowMs / 60000) * 60000;
    if (w !== this.metrics.windowStart) {
      this.metrics = { windowStart: w, calls: 0, allows: 0, denies: 0, indeterminate: 0, not_sent: 0, audit_failures: 0 };
    }
    const dep = this.deployment();
    const fleet = (await this.fleet()).body as unknown as Fleet;
    const snap: MetricSnapshot = {
      window_seconds: 60, calls: this.metrics.calls, allows: this.metrics.allows,
      denies: this.metrics.denies, indeterminate: this.metrics.indeterminate,
      not_sent: this.metrics.not_sent, audit_failures: this.metrics.audit_failures,
      pin_revision: dep.revision, revocation_epoch: dep.revocation_epoch,
      instances_matched: fleet.instances.filter((i) => i.state === "MATCHED").length,
      instances_missing: fleet.instances.filter((i) => i.state === "MISSING").length,
      instances_mismatch: fleet.instances.filter((i) => i.state === "MISMATCH").length,
    };
    return { status: 200, body: snap as unknown as Json };
  }

  async disputes(rec: AuthRecord, afterSeq: number, limit: number): Promise<StoredResponse> {
    this.checkLive();
    const rows = rec.role === "agent"
      ? this.store.all<{ record_enc: string; receipt_seq: number; dispute_id: string }>(
          "SELECT record_enc,receipt_seq,dispute_id FROM disputes WHERE owner_id=? AND receipt_seq>? ORDER BY receipt_seq LIMIT ?",
          rec.principal_id, afterSeq, limit + 1)
      : this.store.all<{ record_enc: string; receipt_seq: number; dispute_id: string }>(
          "SELECT record_enc,receipt_seq,dispute_id FROM disputes WHERE receipt_seq>? ORDER BY receipt_seq LIMIT ?",
          afterSeq, limit + 1);
    const page = rows.slice(0, limit);
    const next_after = rows.length > limit ? page[page.length - 1]!.receipt_seq : null;
    const list = page.map((r) => {
      try {
        return JSON.parse(this.enc.decrypt("disputes", r.dispute_id, "record_enc", r.record_enc));
      } catch {
        throw new CharterError("AUDIT_UNAVAILABLE", "dispute record undecryptable");
      }
    });
    return { status: 200, body: { disputes: list, next_after } as unknown as Json };
  }

  /* ================= recovery + export ================= */

  /** Crash/restart recovery: orphan COMMITTED → INDETERMINATE; never resend. */
  recover(): void {
    this.crashed = false;
    const orphans = this.store.all<{ request_id: string; audit_seqs_jcs: string }>(
      "SELECT request_id,audit_seqs_jcs FROM calls WHERE state='COMMITTED'");
    if (orphans.length === 0) return;
    this.store.tx(() => {
      const nowMs = this.clock.sample();
      for (const o of orphans) {
        let pin: Pin | null = this.deployment().pin;
        const firstSeq = (JSON.parse(o.audit_seqs_jcs) as number[])[0];
        if (firstSeq !== undefined) {
          const e = this.store.get<{ body_jcs: string }>("SELECT body_jcs FROM audit WHERE seq=?", firstSeq);
          if (e) pin = (JSON.parse(e.body_jcs) as AuditBody).policy_pin;
        }
        const seq = this.appendAudit(this.config.system_principal_id, pin,
          { type: "CallFinished", value: { request_id: o.request_id as import("../types.ts").RequestId, state: "INDETERMINATE", output_hash: null } }, msTime(nowMs));
        this.finishCall(o.request_id, "INDETERMINATE", null, null, seq);
        this.metrics.indeterminate++;
        const row = this.store.get<{ result_jcs: string }>("SELECT result_jcs FROM requests WHERE request_id=?", o.request_id);
        if (row) {
          const meta = JSON.parse(row.result_jcs) as { status: number };
          meta.status = 202;
          this.store.run("UPDATE requests SET result_jcs=? WHERE request_id=?", canonicalize(meta), o.request_id);
        }
      }
    });
  }

  /** Evidence record for `audit export` (in-memory ≤256 entries form). */
  buildEvidence(throughSeq: number, start: Checkpoint | null,
    inputs: { request: CallRequest; principal: Principal }[]): Evidence {
    const head = this.meta().next_seq - 1;
    if (throughSeq > head || throughSeq < 0) throw new CharterError("SCHEMA", "through_seq out of bounds");
    if (start !== null) {
      const key = this.auditKeyAt(start.body.through_seq);
      if (!key) throw new CharterError("SCHEMA", "start checkpoint key range unknown");
      const msg = signMessage("checkpoint", start.body);
      if (start.key_id !== key.key_id ||
          !verifyBytes(msg, Buffer.from(start.signature, "base64url"), Buffer.from(key.public_key, "hex"))) {
        throw new CharterError("SIGNATURE_INVALID", "start checkpoint");
      }
    }
    const firstWant = (start?.body.through_seq ?? 0) + 1;
    const rows = this.store.all<{ seq: number; hash: string; body_jcs: string; key_id: string; signature: string }>(
      "SELECT seq,hash,body_jcs,key_id,signature FROM audit WHERE seq>=? AND seq<=? ORDER BY seq",
      firstWant, throughSeq);
    const entries: AuditEntry[] = rows.map((r) => ({
      body: JSON.parse(r.body_jcs) as AuditBody, hash: r.hash,
      key_id: r.key_id as AuditEntry["key_id"], signature: r.signature,
    }));
    const controls: ControlArtifact[] = [];
    for (const r of rows) {
      const body = JSON.parse(r.body_jcs) as AuditBody;
      if (controlHashOf(body.event)) {
        const c = this.store.get<{ artifact_jcs: string }>("SELECT artifact_jcs FROM controls WHERE audit_seq=?", r.seq);
        if (!c) throw new CharterError("AUDIT_UNAVAILABLE", "control artifact missing");
        controls.push(JSON.parse(c.artifact_jcs) as ControlArtifact);
      }
    }
    const bundles: Bundle[] = this.store.all<{ bundle_jcs: string }>(
      "SELECT bundle_jcs FROM policies ORDER BY version")
      .map((r) => parseJsonText(r.bundle_jcs) as unknown as Bundle);
    const end = this.makeCheckpoint(throughSeq);
    const sortedInputs = [...inputs].sort((a, b) =>
      Buffer.compare(Buffer.from(a.request.request_id), Buffer.from(b.request.request_id)));
    return { schema: "charter.evidence/1", root: this.root, bundles, start, entries, controls, end, inputs: sortedInputs };
  }
}

/* ---------- helpers ---------- */

function isIntSafe(v: number): boolean {
  return Number.isSafeInteger(v) && v >= 0;
}

function isIdStr(v: unknown, prefix: string): boolean {
  return typeof v === "string" && new RegExp(`^${prefix}_[A-Za-z0-9_-]{21}$`).test(v);
}

function utf8Size(b: Uint8Array): number {
  return b.length;
}

function recordable(code: import("../errors.ts").ErrorCode): boolean {
  // Authenticated, schema-valid, bounded rejections — except validation and
  // rate-limit failures, and faults that cannot be durably logged.
  return !["PARSE", "SCHEMA", "LIMIT", "UNSUPPORTED_VERSION", "UNSUPPORTED_COMPOSITION",
    "BUSY", "AUDIT_UNAVAILABLE", "AUTH_REQUIRED"].includes(code);
}

function statusForCall(state: CallState): number {
  return state === "COMMITTED" || state === "INDETERMINATE" ? 202 : 200;
}

function controlHashOf(event: AuditEvent): Hash | null {
  const v = event.value as { control_hash?: Hash };
  return v !== null && typeof v === "object" && "control_hash" in v ? v.control_hash! : null;
}

function validAdapterOutput(output: Json): boolean {
  try {
    const text = canonicalize(output);
    if (Buffer.byteLength(text, "utf8") > 64 * 1024) return false;
    return jsonDepth(output) <= 16;
  } catch {
    return false;
  }
}

function jsonDepth(v: Json): number {
  if (Array.isArray(v)) return 1 + Math.max(0, ...v.map(jsonDepth));
  if (v !== null && typeof v === "object") {
    return 1 + Math.max(0, ...Object.values(v).map(jsonDepth));
  }
  return 0;
}
