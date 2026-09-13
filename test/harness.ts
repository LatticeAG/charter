/**
 * §11.2 test harness — builds fixture worlds E/P/F over a real HTTP server.
 * All fixture key/credential material is RFC 8032 public test data, never production.
 */
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import type { AuditEvent, Config, AuthFile, AuthRecord, Decision, Detached, EncryptionKeys, Json } from "../src/types.ts";
import type { ErrorCode } from "../src/errors.ts";
import { Store } from "../src/engine/store.ts";
import { TenantEngine } from "../src/engine/tenant.ts";
import { FixtureRecordsAdapter } from "../src/adapter/fixture.ts";
import { serve } from "../src/http/server.ts";
import * as fx from "../fixtures/corpus.ts";

export const FIXTURE_TOKEN = (credId: string): string =>
  createHash("sha256").update("charter-fixture-token/" + credId).digest("base64url");
const tokHash = (credId: string): string =>
  createHash("sha256").update(Buffer.from(FIXTURE_TOKEN(credId), "base64url")).digest("hex");

const CRED = (id: string, role: AuthRecord["role"], principal: string, instance: string | null, scopes: string[], expires: string): AuthRecord => ({
  credential_id: id as AuthRecord["credential_id"], token_hash: tokHash(id),
  tenant_id: fx.T as AuthRecord["tenant_id"], principal_id: principal as AuthRecord["principal_id"],
  role, scopes, instance_id: instance as AuthRecord["instance_id"], expires_at: expires,
});

export const CRED_OPERATOR = fx.ID("ccr", "O");
export const CRED_INSTANCE = fx.ID("ccr", "I");
export const CRED_READER = fx.ID("ccr", "R");
export const CRED_PUBLISHER = fx.ID("ccr", "V");
/** §11.1: all fixture credentials are valid until T0 + 24h. */
export const EXP24 = "2026-09-13T00:00:00.000Z";

export function fixtureAuth(overrides: { agentExpires?: string; extra?: AuthRecord[] } = {}): AuthFile {
  return {
    schema: "charter.auth/1",
    records: [
      CRED(fx.CR, "agent", fx.A, fx.I, ["task-a"], overrides.agentExpires ?? EXP24),
      CRED(CRED_OPERATOR, "operator", fx.O, null, [], EXP24),
      CRED(CRED_INSTANCE, "instance", fx.ID("cpr", "I"), fx.I, [], EXP24),
      CRED(CRED_READER, "reader", fx.ID("cpr", "R"), null, [], EXP24),
      CRED(CRED_PUBLISHER, "publisher", fx.ID("cpr", "V"), null, [], EXP24),
      ...(overrides.extra ?? []),
    ],
  };
}
export const ROLE_TOKEN: Record<string, string> = {
  agent: FIXTURE_TOKEN(fx.CR), operator: FIXTURE_TOKEN(CRED_OPERATOR),
  instance: FIXTURE_TOKEN(CRED_INSTANCE), reader: FIXTURE_TOKEN(CRED_READER),
  publisher: FIXTURE_TOKEN(CRED_PUBLISHER),
};

export const SYS_PRINCIPAL = fx.ID("cpr", "S");

export function fixtureConfig(endpoint = "http://127.0.0.1:8787"): Config {
  return {
    schema: "charter.config/1", environment: "local", endpoint,
    tenant_id: fx.T as Config["tenant_id"], gateway_id: fx.G as Config["gateway_id"],
    instance_id: fx.I as Config["instance_id"], system_principal_id: SYS_PRINCIPAL as Config["system_principal_id"],
    root_file: "./trust.json", manifest_file: "./manifest.json",
    instance_inventory: [fx.I as Config["instance_id"]],
    client_credential_ref: "env:CHARTER_CLIENT_CREDENTIAL",
    auth_records_ref: "env:CHARTER_AUTH_RECORDS", audit_seed_ref: "env:CHARTER_AUDIT_SEED",
    audit_key_id: fx.KC as Config["audit_key_id"], response_keys_ref: "env:CHARTER_RESPONSE_KEYS",
    storage_soft_limit_bytes: 64 * 1024 * 1024, max_in_flight: 32, metrics_enabled: true,
  };
}
export const FIXTURE_KEYS: EncryptionKeys = {
  active_key_id: "k1", keys: [{ key_id: "k1", key_base64url: Buffer.alloc(32, 7).toString("base64url") }],
};

export class World {
  dir: string;
  store: Store;
  adapter = new FixtureRecordsAdapter();
  engine: TenantEngine;
  server: Server | undefined;
  base = "";
  clockMs = Date.parse(fx.T0);
  auth: AuthFile;
  config: Config;

  constructor(auth?: AuthFile, opts: { metrics?: boolean } = {}) {
    this.dir = mkdtempSync(join(tmpdir(), "charter-test-"));
    this.store = new Store(join(this.dir, "tenant.db"));
    this.auth = auth ?? fixtureAuth();
    this.config = fixtureConfig();
    if (opts.metrics === false) this.config.metrics_enabled = false;
    this.engine = TenantEngine.provision(this.engineOpts());
  }

  engineOpts() {
    return {
      store: this.store, config: this.config, root: fx.ROOT as never, manifest: fx.M1 as never,
      auth: this.auth, encryptionKeys: FIXTURE_KEYS,
      auditSeed: Buffer.from(fx.SEEDS[2]!, "hex"), adapter: this.adapter,
      clockInject: () => this.clockMs,
    };
  }

  set(t: string): void { this.clockMs = Date.parse(t); }

  /** E → P → F progression at the harness clock. */
  async toP(): Promise<void> {
    const r = await this.http("operator", "POST", "/v1/charters", fx.PUBLISH1 as unknown as Json);
    if (r.status !== 201) throw new Error("toP publish failed: " + JSON.stringify(r.body));
  }
  async toF(): Promise<void> {
    await this.toP();
    const r1 = await this.http("operator", "POST", "/v1/deployment/pin", fx.U1 as unknown as Json);
    if (r1.status !== 200) throw new Error("toF pin failed: " + JSON.stringify(r1.body));
    const r2 = await this.http("instance", "POST", "/v1/fleet/heartbeat", fx.HB1 as unknown as Json);
    if (r2.status !== 200) throw new Error("toF heartbeat failed: " + JSON.stringify(r2.body));
  }

  async listen(): Promise<void> {
    if (this.server) return;
    this.server = await serve(this.engine, 0, "127.0.0.1");
    const a = this.server.address();
    this.base = `http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`;
  }

  async http(role: string | null, method: string, path: string, body: Json | null = null): Promise<{ status: number; body: Json; headers: Record<string, string> }> {
    if (!this.server) await this.listen();
    const headers: Record<string, string> = {};
    if (role) headers.authorization = "Bearer " + ROLE_TOKEN[role];
    const init: RequestInit = { method, headers };
    if (body !== null) {
      headers["content-type"] = "application/json";
      init.body = fx.J(body);
    }
    const res = await fetch(this.base + path, init);
    const text = await res.text();
    const h: Record<string, string> = {};
    res.headers.forEach((v, k) => (h[k] = v));
    return { status: res.status, body: text ? JSON.parse(text) : null, headers: h };
  }

  events(fromSeq: number): AuditEvent[] {
    const rows = this.store.db.prepare(`SELECT body_jcs FROM audit WHERE seq>? ORDER BY seq`).all(fromSeq) as { body_jcs: string }[];
    return rows.map((r) => (JSON.parse(r.body_jcs) as { event: AuditEvent }).event);
  }
  eventNames(fromSeq: number): string[] { return this.events(fromSeq).map((e) => e.type); }
  auditHead(): number {
    const r = this.store.db.prepare(`SELECT MAX(seq) s FROM audit`).get() as { s: number | null };
    return r.s ?? 0;
  }
  get initiations(): number { return this.adapter.initiated.length; }

  /** Restart the engine on the same store (auth rollout / crash recovery).
   *  Re-serves HTTP so the live route table hits the new engine. */
  async reopen(auth?: AuthFile): Promise<TenantEngine> {
    if (auth) this.auth = auth;
    this.engine = TenantEngine.open(this.engineOpts());
    if (this.server) {
      const old = this.server;
      this.server = undefined;
      old.closeAllConnections();
      await new Promise<void>((res) => old.close(() => res()));
      await this.listen();
    }
    return this.engine;
  }

  close(): void {
    try {
      this.server?.closeAllConnections();
      this.server?.close();
    } catch { /* ignore */ }
    try { this.store.close(); } catch { /* ignore */ }
    try { rmSync(this.dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

export function deny(reason: string, rule_ids: string[] = []): Decision {
  return { verdict: "DENY", reason: reason as Decision["reason"], rule_ids: rule_ids as Decision["rule_ids"] };
}
export function detached(k: string, s: string): Detached {
  return { key_id: k as Detached["key_id"], signature: s };
}
export function errCode(e: unknown): ErrorCode | null {
  return e && typeof e === "object" && "code" in e ? (e as { code: ErrorCode }).code : null;
}
