/**
 * §11.1 executable fixed corpus — verbatim port of the spec's JavaScript block.
 * This module deliberately re-implements J/D/S inline (not via src/) so that
 * the conformance vectors compare two independent implementations.
 */
import { createHash, createPrivateKey, createPublicKey, sign as rawSign } from "node:crypto";
import assert from "node:assert/strict";

export const J = (x: unknown): string => {
  if (x === null) return "null";
  if (typeof x === "string" || typeof x === "boolean") return JSON.stringify(x);
  if (typeof x === "number") {
    assert(Number.isSafeInteger(x) && x >= 0 && !Object.is(x, -0));
    return JSON.stringify(x);
  }
  if (Array.isArray(x)) return "[" + x.map(J).join(",") + "]";
  assert(typeof x === "object");
  return "{" + Object.keys(x as Record<string, unknown>).sort()
    .map((k) => JSON.stringify(k) + ":" + J((x as Record<string, unknown>)[k])).join(",") + "}";
};
export const sha = (x: string): string => createHash("sha256").update(x).digest("hex");
export const D = (k: string, x: unknown): string => sha("LAGI-CHARTER/" + k + "/1\n" + J(x));
export const S = (k: string, x: unknown): Buffer => Buffer.from("LAGI-CHARTER/sign/" + k + "/1\n" + D(k, x));
export const ID = (p: string, c: string): string => p + "_" + c.repeat(21);

export const SEEDS = [
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
];
export const SK = SEEDS.map((seed) =>
  createPrivateKey({ key: Buffer.from("302e020100300506032b657004220420" + seed, "hex"), format: "der", type: "pkcs8" }));
export const PK = SK.map((key) => createPublicKey(key));
export const PUB = PK.map((key) => key.export({ format: "der", type: "spki" }).subarray(-32).toString("hex"));

export const T = ID("cte", "A"), C = ID("cch", "A"), G = ID("cgw", "A"), I = ID("cin", "A"),
  A = ID("cpr", "A"), O = ID("cpr", "B"), L = ID("clg", "A");
export const KA = ID("cky", "A"), KB = ID("cky", "B"), KC = ID("cky", "C"),
  CR = ID("ccr", "A"), RA = ID("crl", "A"), RD = ID("crl", "D");
export const T0 = "2026-09-12T00:00:00.000Z", T30 = "2026-09-12T00:00:30.000Z",
  T180 = "2026-09-12T00:03:00.000Z", T300 = "2026-09-12T00:05:00.000Z";
export const END = "2026-10-12T00:00:00.000Z";

export const AUTH = { threshold: 2, keys: [{ key_id: KA, public_key: PUB[0] }, { key_id: KB, public_key: PUB[1] }] };
export const ROOT = {
  schema: "charter.root/1", tenant_id: T, charter_id: C, gateway_id: G, log_id: L,
  bootstrap: AUTH, audit_keys: [{ key_id: KC, public_key: PUB[2], from_seq: 1, through_seq: null }],
} as const;
export const M1 = {
  schema: "charter.manifest/1", gateway_id: G, engine: "charter.eval/1",
  resource_grammar: "segments/1", adapter_build_hash: sha("charter-fixture-records/1"),
  tools: [
    { tool: "record.delete", binding: "RECORDS", operation: "delete", args: [] },
    { tool: "record.export", binding: "RECORDS", operation: "export", args: [{ name: "destination", kind: "string", max_bytes: 64 }] },
    { tool: "record.get", binding: "RECORDS", operation: "get", args: [] },
    { tool: "record.list", binding: "RECORDS", operation: "list", args: [{ name: "limit", kind: "integer", min: 1, max: 100 }] },
    { tool: "record.put", binding: "RECORDS", operation: "put", args: [{ name: "value", kind: "string", max_bytes: 4096 }] },
  ],
} as const;
export const MH = D("manifest", M1);
export const rule = (id: string, tools: string[]) => ({
  id, text: "Records within the authenticated task scope.", principals: ["*"],
  tools, scopes: ["task-a"], resources: [{ match: "segment_prefix", value: "records" }], when: [],
});
export const C1 = {
  schema: "charter.policy/1", tenant_id: T, charter_id: C, version: 1, previous_hash: null,
  engine: "charter.eval/1", manifest_hash: MH, issued_at: T0, not_before: T0, not_after: END,
  source: { repository: "latticeagi/charter-policy", pull_request: 7, commit: "a".repeat(40) },
  description: "Citable rules for record operations.", next_authority: AUTH,
  hard_denies: [rule(RD, ["record.delete"])],
  scope_rules: [rule(RA, ["record.get", "record.list", "record.put"])],
} as const;
export const H1 = D("policy", C1);
export const C2 = { ...C1, version: 2, previous_hash: H1, source: { repository: "latticeagi/charter-policy", pull_request: 8, commit: "b".repeat(40) } };
export const H2 = D("policy", C2);
export const P1 = { charter_id: C, version: 1, policy_hash: H1, manifest_hash: MH, engine: "charter.eval/1" } as const;
export const P2 = { ...P1, version: 2, policy_hash: H2 };
export const sig = (n: number, k: string, x: unknown) => ({
  key_id: [KA, KB, KC][n]!, signature: rawSign(null, S(k, x), SK[n]!).toString("base64url"),
});
export const bundle = (c: unknown) => ({ policy: c as never, manifest: M1, signatures: [sig(0, "policy", c), sig(1, "policy", c)] });
export const B1 = bundle(C1), B2 = bundle(C2);
export const pc = {
  schema: "charter.pin/1", tenant_id: T, gateway_id: G, request_id: ID("crq", "P"),
  expected_revision: 0, expected_revocation_epoch: 0, authority_policy_hash: H1,
  target: P1, expires_at: T300,
};
export const signedPin = (command: unknown) => ({ command, signatures: [sig(0, "pin", command), sig(1, "pin", command)] });
export const U1 = signedPin(pc);
export const PUBLISH1 = { request_id: ID("crq", "V"), bundle: B1 };
export const PRINCIPAL = { principal_id: A, credential_id: CR, instance_id: I, scopes: ["task-a"] };
export const Q1 = {
  request_id: ID("crq", "Q"), pin: P1, scope: "task-a", tool: "record.get",
  resource: "records/a", args: {}, deadline: T30,
};
export const ALLOW = { verdict: "ALLOW", reason: "ALLOW_SCOPE", rule_ids: [RA] } as const;
export const deny = (reason: string, rule_ids: string[] = []) => ({ verdict: "DENY", reason, rule_ids });
export const EI1 = {
  policy: C1, manifest: M1, active_pin: P1, request: Q1, principal: PRINCIPAL,
  now: T0, policy_revoked: false, policy_signatures_valid: true,
};
export const evalFor = (policy: Record<string, unknown>, request: Record<string, unknown>) => {
  const pin = { ...P1, version: policy.version, policy_hash: D("policy", policy), manifest_hash: (policy as { manifest_hash: string }).manifest_hash };
  return { ...EI1, policy, active_pin: pin, request: { ...request, pin } };
};
export const IH1 = D("input", { request: Q1, principal: PRINCIPAL });
export const OH1 = sha(J({ value: "ok" }));
export const DEP = { gateway_id: G, revision: 1, revocation_epoch: 0, state: "ACTIVE", pin: P1, installed_manifest_hash: MH, in_flight: 0 };
export const HB1 = { request_id: ID("crq", "H"), instance_id: I, counter: 1, observed_pin: P1, manifest_hash: MH };
export const FLEET1 = {
  as_of: T0, desired_pin: P1, status: "HEALTHY",
  instances: [{ instance_id: I, counter: 1, received_at: T0, expires_at: T180, observed_pin: P1, manifest_hash: MH, state: "MATCHED" }],
};
export const CITE1 = {
  schema: "charter.citation/1", pin: P1, rule_id: RA, pointer: "/scope_rules/0",
  clause_hash: D("clause", C1.scope_rules[0]), rule: C1.scope_rules[0],
};
export const VALID1 = { valid: true, pin: P1, signatures: 2, required: 2, warnings: [] };
export const PAUSE1 = { request_id: ID("crq", "Z"), expected_revision: 1, reason: "Incident containment" };
export const REVOKE1 = { request_id: ID("crq", "R"), expected_revocation_epoch: 0, target: { kind: "policy", policy_hash: H1 }, reason: "Policy withdrawn" };
export const REV1 = { ...REVOKE1, epoch: 1, actor_id: O, effective_seq: 4, recorded_at: T0 };
export const DR1 = {
  request_id: ID("crq", "D"), dispute_id: ID("cds", "A"), pin: P1, cited_seq: 4,
  category: "SCOPE_MATCH", statement: "Please review the records/a task boundary.", evidence_hashes: [],
};
export const DISPUTE1 = { ...DR1, actor_id: A, recorded_at: T0, status: "RECORDED_ADVISORY", receipt_seq: 5 };
export const SUCCESS1 = {
  request_id: Q1.request_id, state: "SUCCEEDED", decision: ALLOW, input_hash: IH1,
  output: { value: "ok" }, output_available: true, output_hash: OH1, audit_seqs: [4, 5],
};
export const AR1 = {
  request_id: Q1.request_id, principal_id: A, scope: "task-a", pin: P1, input_hash: IH1,
  operation: "get", resource: "records/a", args: {}, deadline: T30,
};
export const EB1 = {
  schema: "charter.audit/1", tenant_id: T, log_id: L, seq: 1, prev_hash: "0".repeat(64),
  time: T0, actor_id: O, policy_pin: P1,
  event: { type: "PolicyPublished", value: { pin: P1, source: C1.source } },
};
export const E1 = { body: EB1, hash: D("audit", EB1), ...sig(2, "audit", EB1) };
export const CPB1 = { schema: "charter.checkpoint/1", tenant_id: T, log_id: L, through_seq: 1, head_hash: D("audit", EB1), time: T0 };
export const CP1 = { body: CPB1, ...sig(2, "checkpoint", CPB1) };
export const EV1 = { schema: "charter.evidence/1", root: ROOT, bundles: [B1], start: null, entries: [E1], controls: [], end: CP1, inputs: [] };
export const VERIFY1 = { integrity: "VALID", replay: "MATCH", through_seq: 1, checkpoint_match: true, truth: "NOT_ATTESTED" };
export const METRICS1 = {
  window_seconds: 60, calls: 0, allows: 0, denies: 0, indeterminate: 0, not_sent: 0,
  audit_failures: 0, pin_revision: 1, revocation_epoch: 0,
  instances_matched: 1, instances_missing: 0, instances_mismatch: 0,
};
export const RFC_SIG = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

// §11.1 self-checks — the corpus is invalid if these fail.
assert.equal(PUB[0], "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
assert.equal(rawSign(null, Buffer.alloc(0), SK[0]!).toString("hex"), RFC_SIG);
assert.equal(OH1, "16cfa6ba3d308e6c52a96d7d50018be09d175a518b74d5bcc6e39281ef75fa9b");
assert.equal(MH, "0041f7d1ade12b07d955e859b19492702455d158f404a78aa35ce441c7770feb");
assert.equal(H1, "5371688308b373e3ff2538071ac8f7454a86526e81b0b2a488e01864cb270471");
assert.equal(H2, "c71ef7b091621fa1091f4bc96d54f95d37304abbf0785ffeeb1b4e5831d64ce9");
assert.equal(IH1, "8363ebdf70c9d6ddad9b7ae1f4e0324a5379d4b2c537f038c9ddb80e3c4aff14");
assert.equal(CITE1.clause_hash, "b59728a09d519f991b32b894565db3674fe954f80eeb7393524e763c6214d278");
assert.equal(D("audit", EB1), "d40669c6b86bbd1ef41e353a17c189b8c31d3502a1993a83f3885b3beba60a9c");
