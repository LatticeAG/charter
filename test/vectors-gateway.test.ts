/** TV-C gateway/trace vectors — real HTTP against a provisioned engine. */
import test from "node:test";
import assert from "node:assert/strict";
import * as fx from "../fixtures/corpus.ts";
import { World, fixtureAuth, CRED_OPERATOR } from "./harness.ts";
import { verifyBundle } from "../src/index.ts";
import type { Json } from "../src/types.ts";

async function worldE(): Promise<World> { return new World(); }
async function worldP(): Promise<World> { const w = new World(); await w.toP(); return w; }
async function worldF(): Promise<World> { const w = new World(); await w.toF(); return w; }

test("TV-C-19 resource traversal encoding", async () => {
  const w = await worldF();
  try {
    const head = w.auditHead();
    const r = await w.http("agent", "POST", "/v1/gateway/call", { ...fx.Q1, resource: "records/%2e%2e/private" } as Json);
    assert.equal(r.status, 400);
    assert.equal((r.body as { error: { code: string } }).error.code, "SCHEMA");
    assert.equal(w.initiations, 0);
    assert.deepEqual(w.eventNames(head), []);
  } finally { w.close(); }
});

test("TV-C-23 typed arguments", async () => {
  const w = await worldF();
  try {
    const head = w.auditHead();
    const r = await w.http("agent", "POST", "/v1/gateway/call", { ...fx.Q1, tool: "record.list", args: { limit: "10" } } as unknown as Json);
    assert.equal(r.status, 400);
    assert.equal((r.body as { error: { code: string } }).error.code, "SCHEMA");
    assert.equal(w.initiations, 0);
    assert.deepEqual(w.eventNames(head), []);
  } finally { w.close(); }
});

test("TV-C-24 missing argument does not bypass predicate", async () => {
  const w = await worldF();
  try {
    const head = w.auditHead();
    const r = await w.http("agent", "POST", "/v1/gateway/call", { ...fx.Q1, tool: "record.put", args: {} } as unknown as Json);
    assert.equal(r.status, 400);
    assert.equal((r.body as { error: { code: string } }).error.code, "SCHEMA");
    assert.equal(w.initiations, 0);
    assert.deepEqual(w.eventNames(head), []);
  } finally { w.close(); }
});

test("TV-C-30 check is never executable authority", async () => {
  const w = await worldF();
  try {
    const head = w.auditHead();
    const r = await w.http("agent", "POST", "/v1/gateway/check", fx.Q1 as Json);
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { decision: fx.ALLOW, input_hash: fx.IH1, enforcement: false, audit_seq: 4 });
    assert.equal(w.initiations, 0);
    assert.deepEqual(w.eventNames(head), ["CheckEvaluated"]);
  } finally { w.close(); }
});

test("TV-C-31 successful durable admission", async () => {
  const w = await worldF();
  try {
    const head = w.auditHead();
    const r = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, fx.SUCCESS1);
    assert.equal(w.initiations, 1);
    assert.deepEqual(w.eventNames(head), ["CallCommitted", "CallFinished"]);
    // first initiation occurs after durable seq 4
    assert.ok(w.auditHead() >= 4);
  } finally { w.close(); }
});

test("TV-C-32 denied call cannot touch adapter", async () => {
  const w = await worldF();
  try {
    const q = { ...fx.Q1, tool: "record.delete" };
    const r = await w.http("agent", "POST", "/v1/gateway/call", q as Json);
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, {
      request_id: q.request_id, state: "DENIED", decision: fx.deny("HARD_DENY", [fx.RD]),
      input_hash: fx.D("input", { request: q, principal: fx.PRINCIPAL }),
      output: null, output_available: false, output_hash: null, audit_seqs: [4],
    });
    assert.equal(w.initiations, 0);
  } finally { w.close(); }
});

test("TV-C-33 exact replay preserves one initiation", async () => {
  const w = await worldF();
  try {
    const r1 = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r1.status, 200);
    const r2 = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r2.status, 200);
    assert.deepEqual(r2.body, fx.SUCCESS1);
    assert.equal(w.initiations, 1);
    assert.equal(w.auditHead(), 5);
  } finally { w.close(); }
});

test("TV-C-34 changed body under same request ID", async () => {
  const w = await worldF();
  try {
    await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    const r2 = await w.http("agent", "POST", "/v1/gateway/call", { ...fx.Q1, resource: "records/b" } as Json);
    assert.equal(r2.status, 409);
    assert.deepEqual(r2.body, { error: { code: "IDEMPOTENCY_CONFLICT", retryable: false, audit_seq: 6 } });
    assert.equal(w.initiations, 1);
  } finally { w.close(); }
});

test("TV-C-35 audit failure before marker", async () => {
  const w = await worldF();
  try {
    w.engine.hooks.failNextCommit = true;
    const r = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r.status, 503);
    assert.deepEqual(r.body, { error: { code: "AUDIT_UNAVAILABLE", retryable: true, audit_seq: null } });
    assert.equal(w.initiations, 0);
    assert.equal(w.auditHead(), 3);
    const tomb = w.store.get("SELECT request_id FROM requests WHERE request_id=?", fx.Q1.request_id);
    assert.equal(tomb, undefined);
  } finally { w.close(); }
});

test("TV-C-36 crash in marker/send gap", async () => {
  const w = await worldF();
  try {
    w.engine.hooks.crashAfterMarker = true;
    const r = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r.status, 503); // crashed transport observes failure
    assert.equal(w.initiations, 0);
    const head = w.auditHead();
    await w.reopen(); // restart → recovery
    assert.deepEqual(w.eventNames(head - 1).slice(0), w.eventNames(3));
    const q = await w.http("agent", "GET", `/v1/gateway/calls/${fx.Q1.request_id}`);
    assert.equal(q.status, 202);
    assert.equal((q.body as { state: string }).state, "INDETERMINATE");
    assert.deepEqual((q.body as { audit_seqs: number[] }).audit_seqs, [4, 5]);
    assert.deepEqual(w.eventNames(3), ["CallCommitted", "CallFinished"]);
    // retry cannot increase initiations
    const r2 = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r2.status, 202);
    assert.equal(w.initiations, 0);
  } finally { w.close(); }
});

test("TV-C-37 validity expires during commit", async () => {
  const w = await worldF();
  try {
    w.engine.hooks.advanceClockToMs = Date.parse(fx.T30);
    const r = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r.status, 200);
    const b = r.body as { state: string; decision: { verdict: string }; audit_seqs: number[] };
    assert.equal(b.state, "NOT_SENT");
    assert.equal(b.decision.verdict, "ALLOW");
    assert.deepEqual(b.audit_seqs, [4, 5]);
    assert.equal(w.initiations, 0);
    assert.deepEqual(w.eventNames(3), ["CallCommitted", "CallFinished"]);
  } finally { w.close(); }
});

test("TV-C-38 revocation wins admission race", async () => {
  const w = await worldF();
  try {
    const rv = await w.http("operator", "POST", "/v1/revocations", fx.REVOKE1 as Json);
    assert.equal(rv.status, 201);
    const r = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r.status, 200);
    const b = r.body as { state: string; decision: { reason: string }; audit_seqs: number[] };
    assert.equal(b.state, "DENIED");
    assert.deepEqual(b.decision, fx.deny("POLICY_REVOKED"));
    assert.deepEqual(b.audit_seqs, [5]);
    assert.equal(w.initiations, 0);
    assert.deepEqual(w.eventNames(3), ["TargetRevoked", "CallDenied"]);
    assert.equal(w.engine.deployment().revocation_epoch, 1);
  } finally { w.close(); }
});

test("TV-C-39 initiation wins revocation race", async () => {
  const w = await worldF();
  try {
    let release!: (v: unknown) => void;
    const gate = new Promise((res) => { release = res; });
    w.adapter.program(() => gate.then(() => ({ status: "ok", output: { value: "ok" } } as never)));
    const callP = w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    // wait until the adapter is initiated
    for (let i = 0; i < 200 && w.initiations === 0; i++) await new Promise((r) => setTimeout(r, 5));
    assert.equal(w.initiations, 1);
    const rv = await w.http("operator", "POST", "/v1/revocations", fx.REVOKE1 as Json);
    assert.equal(rv.status, 201);
    const rbody = rv.body as { revocation: { epoch: number; effective_seq: number }; deployment: { in_flight: number } };
    assert.equal(rbody.revocation.epoch, 1);
    assert.equal(rbody.revocation.effective_seq, 5);
    assert.equal(rbody.deployment.in_flight, 1);
    release(undefined);
    const r = await callP;
    assert.equal(r.status, 200);
    const b = r.body as { state: string; audit_seqs: number[] };
    assert.equal(b.state, "SUCCEEDED");
    assert.deepEqual(b.audit_seqs, [4, 6]);
    assert.equal(w.initiations, 1);
  } finally { w.close(); }
});

test("TV-C-40 revoked credential cannot query retained output", async () => {
  const w = await worldF();
  try {
    await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(w.initiations, 1);
    const rv = await w.http("operator", "POST", "/v1/revocations", {
      request_id: fx.ID("crq", "R"), expected_revocation_epoch: 0,
      target: { kind: "credential", credential_id: fx.CR }, reason: "Key compromise",
    } as Json);
    assert.equal(rv.status, 201);
    const q = await w.http("agent", "GET", `/v1/gateway/calls/${fx.Q1.request_id}`);
    assert.equal(q.status, 401);
    assert.deepEqual(q.body, { error: { code: "AUTH_REQUIRED", retryable: false, audit_seq: null } });
    assert.equal(w.initiations, 1);
  } finally { w.close(); }
});

test("TV-C-41 policy-key revocation depletes threshold", async () => {
  const w = await worldF();
  try {
    const rv = await w.http("operator", "POST", "/v1/revocations", {
      ...fx.REVOKE1, target: { kind: "policy_key", key_id: fx.KA },
    } as Json);
    assert.equal(rv.status, 201);
    const r = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r.status, 200);
    const b = r.body as { state: string; decision: { reason: string }; audit_seqs: number[] };
    assert.equal(b.state, "DENIED");
    assert.deepEqual(b.decision, fx.deny("POLICY_KEY_REVOKED"));
    assert.deepEqual(b.audit_seqs, [5]);
    assert.equal(w.initiations, 0);
    assert.equal(w.engine.deployment().revocation_epoch, 1);
    // historical verifyBundle unaffected by runtime revocation
    assert.deepEqual(verifyBundle(fx.B1 as never, fx.ROOT as never, []), fx.VALID1);
  } finally { w.close(); }
});

test("TV-C-42 revocation epoch CAS", async () => {
  const w = await worldF();
  try {
    const rv1 = await w.http("operator", "POST", "/v1/revocations", fx.REVOKE1 as Json);
    assert.equal(rv1.status, 201);
    const rv2 = await w.http("operator", "POST", "/v1/revocations", {
      ...fx.REVOKE1, request_id: fx.ID("crq", "S"),
      target: { kind: "credential", credential_id: fx.CR },
    } as Json);
    assert.equal(rv2.status, 409);
    assert.deepEqual(rv2.body, { error: { code: "REVOCATION_CONFLICT", retryable: false, audit_seq: 5 } });
    assert.equal(w.engine.deployment().revocation_epoch, 1);
    // CR remains unrevoked — agent calls still authenticate
    const q = await w.http("agent", "POST", "/v1/gateway/check", { ...fx.Q1, request_id: fx.ID("crq", "K") } as Json);
    assert.equal(q.status, 200); // POLICY_REVOKED decision, not AUTH failure
  } finally { w.close(); }
});

test("TV-C-43 no unrevocation route", async () => {
  const w = await worldF();
  try {
    await w.http("operator", "POST", "/v1/revocations", fx.REVOKE1 as Json);
    const r = await w.http("operator", "DELETE", "/v1/revocations");
    assert.equal(r.status, 405);
    assert.equal((r.body as { error: { code: string } }).error.code, "SCHEMA");
    assert.ok(r.headers.allow!.includes("GET"));
    assert.ok(r.headers.allow!.includes("POST"));
    assert.equal(w.engine.deployment().revocation_epoch, 1);
  } finally { w.close(); }
});

test("TV-C-44 pin expiry equality", async () => {
  const w = await worldP();
  try {
    w.set(fx.T300);
    const r = await w.http("operator", "POST", "/v1/deployment/pin", fx.U1 as unknown as Json);
    assert.equal(r.status, 422);
    assert.deepEqual(r.body, { error: { code: "PIN_EXPIRED", retryable: false, audit_seq: 2 } });
    const dep = w.engine.deployment();
    assert.equal(dep.revision, 0);
    assert.equal(dep.state, "UNPINNED");
  } finally { w.close(); }
});

test("TV-C-45 pin cannot ignore intervening revocation", async () => {
  const w = await worldF();
  try {
    await w.http("operator", "POST", "/v1/revocations", {
      request_id: fx.ID("crq", "R"), expected_revocation_epoch: 0,
      target: { kind: "credential", credential_id: fx.CR }, reason: "compromise",
    } as Json);
    const pin = fx.signedPin({ ...fx.pc, request_id: fx.ID("crq", "N"), expected_revision: 1, expected_revocation_epoch: 0 });
    const r = await w.http("operator", "POST", "/v1/deployment/pin", pin as unknown as Json);
    assert.equal(r.status, 409);
    assert.deepEqual(r.body, { error: { code: "REVOCATION_CONFLICT", retryable: false, audit_seq: 5 } });
    const dep = w.engine.deployment();
    assert.equal(dep.revision, 1);
    assert.equal(dep.revocation_epoch, 1);
  } finally { w.close(); }
});

test("TV-C-46 publication does not activate", async () => {
  const w = await worldF();
  try {
    const r = await w.http("operator", "POST", "/v1/charters", { request_id: fx.ID("crq", "W"), bundle: fx.B2 } as unknown as Json);
    assert.equal(r.status, 201);
    assert.deepEqual(r.body, { pin: fx.P2, head_version: 2, audit_seq: 4 });
    assert.deepEqual(w.engine.deployment().pin, fx.P1);
    assert.equal(w.engine.deployment().revision, 1);
    assert.equal(w.initiations, 0);
  } finally { w.close(); }
});

test("TV-C-47 stale head cannot be repinned", async () => {
  const w = await worldF();
  try {
    await w.http("operator", "POST", "/v1/charters", { request_id: fx.ID("crq", "W"), bundle: fx.B2 } as unknown as Json);
    const pin = fx.signedPin({ ...fx.pc, request_id: fx.ID("crq", "N"), expected_revision: 1, authority_policy_hash: fx.H2, target: fx.P1 });
    const r = await w.http("operator", "POST", "/v1/deployment/pin", pin as unknown as Json);
    assert.equal(r.status, 409);
    assert.deepEqual(r.body, { error: { code: "PIN_NOT_HEAD", retryable: false, audit_seq: 5 } });
    assert.deepEqual(w.engine.deployment().pin, fx.P1);
  } finally { w.close(); }
});

test("TV-C-48 concurrent successor fork has one winner", async () => {
  const w = await worldF();
  try {
    const alt = fx.bundle({ ...fx.C2, description: "Alternate candidate." });
    const r1 = await w.http("operator", "POST", "/v1/charters", { request_id: fx.ID("crq", "W"), bundle: fx.B2 } as unknown as Json);
    const r2 = await w.http("operator", "POST", "/v1/charters", { request_id: fx.ID("crq", "X"), bundle: alt } as unknown as Json);
    assert.deepEqual([r1.status, r2.status], [201, 409]);
    assert.equal((r2.body as { error: { code: string } }).error.code, "VERSION_CONFLICT");
    const versions = await w.http("reader", "GET", "/v1/charters?after=0&limit=100");
    const vbody = versions.body as { versions: { policy_hash: string }[]; head_version: number };
    assert.equal(vbody.head_version, 2);
    assert.equal(vbody.versions.length, 2);
    const head = await w.http("reader", "GET", "/v1/charters/2");
    assert.equal((head.body as { policy: { source: { pull_request: number } } }).policy.source.pull_request, 8);
    assert.deepEqual(w.engine.deployment().pin, fx.P1);
  } finally { w.close(); }
});

test("TV-C-49 pause is restrictive and explicit", async () => {
  const w = await worldF();
  try {
    const p = await w.http("operator", "POST", "/v1/deployment/pause", fx.PAUSE1 as Json);
    assert.equal(p.status, 200);
    const r = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r.status, 503);
    assert.deepEqual(r.body, { error: { code: "PAUSED", retryable: false, audit_seq: 5 } });
    const dep = w.engine.deployment();
    assert.equal(dep.revision, 2);
    assert.equal(dep.state, "PAUSED");
    assert.equal(w.initiations, 0);
  } finally { w.close(); }
});

test("TV-C-50 fleet exact freshness cutoff", async () => {
  const w = await worldF();
  try {
    w.set(fx.T180);
    const head = w.auditHead();
    const r = await w.http("reader", "GET", "/v1/fleet");
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, {
      as_of: fx.T180, desired_pin: fx.P1, status: "MISSING",
      instances: [{ instance_id: fx.I, counter: 1, received_at: fx.T0, expires_at: fx.T180, observed_pin: fx.P1, manifest_hash: fx.MH, state: "MISSING" }],
    });
    assert.equal(w.auditHead(), head); // read routes append no event
  } finally { w.close(); }
});

test("TV-C-51 heartbeat replay cannot buy time", async () => {
  const w = await worldF();
  try {
    w.set(fx.T180);
    const r = await w.http("instance", "POST", "/v1/fleet/heartbeat", fx.HB1 as Json);
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { counter: 1, expires_at: fx.T180, state: "MATCHED", audit_seq: 3 });
    const f = await w.http("reader", "GET", "/v1/fleet");
    assert.equal((f.body as { status: string }).status, "MISSING");
    assert.equal(w.auditHead(), 3);
  } finally { w.close(); }
});

test("TV-C-52 fresh divergent installation", async () => {
  const w = await worldF();
  try {
    const hb = await w.http("instance", "POST", "/v1/fleet/heartbeat",
      { ...fx.HB1, request_id: fx.ID("crq", "J"), counter: 2, observed_pin: null } as Json);
    assert.equal(hb.status, 200);
    assert.deepEqual(hb.body, { counter: 2, expires_at: fx.T180, state: "MISMATCH", audit_seq: 4 });
    const r = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r.status, 503);
    assert.deepEqual(r.body, { error: { code: "INSTANCE_MISMATCH", retryable: true, audit_seq: 5 } });
    assert.equal(w.initiations, 0);
  } finally { w.close(); }
});

test("TV-C-53 dispute never becomes law", async () => {
  const w = await worldF();
  try {
    const c1 = await w.http("agent", "POST", "/v1/gateway/check", fx.Q1 as Json);
    assert.equal(c1.status, 200);
    const d = await w.http("agent", "POST", "/v1/disputes", fx.DR1 as Json);
    assert.equal(d.status, 201);
    assert.deepEqual(d.body, fx.DISPUTE1);
    const c2 = await w.http("agent", "POST", "/v1/gateway/check", { ...fx.Q1, request_id: fx.ID("crq", "K") } as Json);
    assert.equal(c2.status, 200);
    const b = c2.body as { decision: { verdict: string }; enforcement: boolean; audit_seq: number };
    assert.equal(b.decision.verdict, "ALLOW");
    assert.equal(b.enforcement, false);
    assert.equal(b.audit_seq, 6);
    assert.deepEqual(w.engine.deployment().pin, fx.P1);
    assert.equal(w.engine.deployment().revision, 1);
    assert.equal(w.engine.deployment().revocation_epoch, 0);
    assert.equal(w.initiations, 0);
  } finally { w.close(); }
});

test("TV-C-59 response expiry preserves consumption", async () => {
  const w = new World();
  try {
    await w.toF();
    const r1 = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r1.status, 200);
    assert.equal(w.initiations, 1);
    // pause at T0+23h
    w.set("2026-09-12T23:00:00.000Z");
    const p = await w.http("operator", "POST", "/v1/deployment/pause",
      { request_id: fx.ID("crq", "Z"), expected_revision: 1, reason: "Controlled auth rollout" } as Json);
    assert.equal(p.status, 200);
    // controlled auth rollout: restart with operator O credential ccr_N
    const credN = {
      credential_id: fx.ID("ccr", "N"), token_hash: undefined as never,
      tenant_id: fx.T, principal_id: fx.O, role: "operator" as const,
      scopes: [], instance_id: null, expires_at: "2026-09-13T23:00:00.000Z",
    };
    const { createHash } = await import("node:crypto");
    const tokN = createHash("sha256").update("charter-fixture-token/" + credN.credential_id).digest("base64url");
    credN.token_hash = createHash("sha256").update(Buffer.from(tokN, "base64url")).digest("hex") as never;
    await w.reopen({
      schema: "charter.auth/1",
      records: [...fixtureAuth().records, credN as never],
    });
    w.set("2026-09-13T00:00:00.000Z");
    // query with the fresh operator credential while still paused
    const headers = { authorization: "Bearer " + tokN };
    const res = await fetch(`${w.base}/v1/gateway/calls/${fx.Q1.request_id}`, { headers });
    const body = await res.json();
    assert.equal(res.status, 200);
    assert.deepEqual(body, { ...fx.SUCCESS1, output: null, output_available: false });
    assert.equal(w.initiations, 1);
  } finally { w.close(); }
});

test("TV-C-60 adapter uncertainty remains terminal", async () => {
  const w = await worldF();
  try {
    w.adapter.program(() => ({ status: "unknown" } as never));
    const r1 = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r1.status, 202);
    const expected = {
      request_id: fx.Q1.request_id, state: "INDETERMINATE", decision: fx.ALLOW,
      input_hash: fx.IH1, output: null, output_available: false, output_hash: null,
      audit_seqs: [4, 5],
    };
    assert.deepEqual(r1.body, expected);
    const r2 = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r2.status, 202);
    assert.deepEqual(r2.body, expected);
    assert.equal(w.initiations, 1);
  } finally { w.close(); }
});

test("TV-C-61 partition cannot use cached ALLOW", async () => {
  const w = await worldF();
  try {
    const c = await w.http("agent", "POST", "/v1/gateway/check", fx.Q1 as Json);
    assert.equal(c.status, 200);
    assert.equal(w.auditHead(), 4);
    w.engine.hooks.partitioned = true;
    const r = await w.http("agent", "POST", "/v1/gateway/call", { ...fx.Q1, request_id: fx.ID("crq", "K") } as Json);
    assert.equal(r.status, 503);
    assert.deepEqual(r.body, { error: { code: "AUDIT_UNAVAILABLE", retryable: true, audit_seq: null } });
    assert.equal(w.initiations, 0);
    assert.equal(w.auditHead(), 4);
  } finally { w.close(); }
});

test("TV-C-65 credential expires during admission persistence", async () => {
  const w = new World(fixtureAuth({ agentExpires: "2026-09-12T00:00:00.010Z" }));
  try {
    await w.toF();
    w.engine.hooks.advanceClockToMs = Date.parse("2026-09-12T00:00:00.010Z");
    const r = await w.http("agent", "POST", "/v1/gateway/call", fx.Q1 as Json);
    assert.equal(r.status, 200);
    const b = r.body as { state: string; decision: { verdict: string }; audit_seqs: number[] };
    assert.equal(b.state, "NOT_SENT");
    assert.equal(b.decision.verdict, "ALLOW");
    assert.deepEqual(b.audit_seqs, [4, 5]);
    assert.equal(w.initiations, 0);
    assert.deepEqual(w.eventNames(3), ["CallCommitted", "CallFinished"]);
  } finally { w.close(); }
});

test("TV-C-66 retryable fleet failure does not poison request identity", async () => {
  const w = await worldF();
  try {
    w.set(fx.T180);
    const q = { ...fx.Q1, deadline: "2026-09-12T00:03:30.000Z" };
    const r1 = await w.http("agent", "POST", "/v1/gateway/call", q as Json);
    assert.equal(r1.status, 503);
    assert.deepEqual(r1.body, { error: { code: "INSTANCE_STALE", retryable: true, audit_seq: 4 } });
    const hb = await w.http("instance", "POST", "/v1/fleet/heartbeat", { ...fx.HB1, request_id: fx.ID("crq", "J"), counter: 2 } as Json);
    assert.equal(hb.status, 200);
    const r2 = await w.http("agent", "POST", "/v1/gateway/call", q as Json);
    assert.equal(r2.status, 200);
    const b = r2.body as { state: string; audit_seqs: number[] };
    assert.equal(b.state, "SUCCEEDED");
    assert.deepEqual(b.audit_seqs, [6, 7]);
    assert.equal(w.initiations, 1);
    assert.deepEqual(w.eventNames(3), ["CommandRejected", "InstanceObserved", "CallCommitted", "CallFinished"]);
  } finally { w.close(); }
});
