/** TV-C offline vectors — parser, digest, crypto, verify, evaluate, cite. */
import test from "node:test";
import assert from "node:assert/strict";
import { sign as cryptoSign } from "node:crypto";
import * as fx from "../fixtures/corpus.ts";
import { errCode } from "./harness.ts";
import { canonicalize } from "../src/json/jcs.ts";
import { parseJsonText } from "../src/json/strict.ts";
import { parseYamlSubset } from "../src/yaml/subset.ts";
import { parsePolicy, digest, sign, verifyBundle, compile, evaluate, cite, verifyEvidence } from "../src/index.ts";
import { verifyBytes, publicKeyFromSeed } from "../src/crypto/ed25519.ts";
import { signMessage } from "../src/crypto/digest.ts";
import type { EvalInput, Json } from "../src/types.ts";

const EI = (x: unknown): EvalInput => x as EvalInput;

test("TV-C-01 canonical JSON member order", () => {
  assert.equal(canonicalize({ z: 1, a: true } as Json), '{"a":true,"z":1}');
});

test("TV-C-02 UTF-16, not Unicode scalar ordering", () => {
  const s = canonicalize({ "": 1, "\u{10000}": 2 } as Json);
  assert.equal(s, '{"\u{10000}":2,"":1}');
});

test("TV-C-03 published policy and manifest digest", () => {
  assert.equal(digest("policy", fx.C1 as unknown as Json), fx.H1);
  assert.equal(digest("manifest", fx.M1 as unknown as Json), fx.MH);
  assert.match(fx.H1, /^[0-9a-f]{64}$/);
  assert.match(fx.MH, /^[0-9a-f]{64}$/);
});

test("TV-C-04 independent Ed25519 oracle", () => {
  const sigB = sign("policy", fx.C1 as never, fx.KA as never, "fixture:0");
  assert.deepEqual(sigB, fx.B1.signatures[0]);
  // RFC 8032 empty-message oracle
  const empty = new Uint8Array(0);
  const sigHex = Buffer.from(cryptoSign(null, empty, fx.SK[0]!)).toString("hex");
  assert.equal(sigHex, fx.RFC_SIG);
  const pub0 = Buffer.from(fx.PUB[0]!, "hex");
  const pub1 = Buffer.from(fx.PUB[1]!, "hex");
  assert.equal(verifyBytes(empty, Buffer.from(fx.RFC_SIG, "hex"), pub0), true);
  assert.equal(verifyBytes(empty, Buffer.from(fx.RFC_SIG, "hex"), pub1), false);
  assert.equal(Buffer.from(publicKeyFromSeed(new Uint8Array(Buffer.from(fx.SEEDS[0]!, "hex")))).toString("hex"), fx.PUB[0]);
});

test("TV-C-05 duplicate JSON key", () => {
  assert.throws(() => parseJsonText('{"version":1,"version":2}'), (e: unknown) => errCode(e) === "PARSE");
});

function tryCatch(fn: () => unknown): unknown {
  try { return fn(); } catch (e) { return e; }
}

test("TV-C-06 YAML anchor/alias", () => {
  const r = tryCatch(() => parseYamlSubset("a: &x [1]\nb: *x\n"));
  assert.equal(errCode(r), "PARSE");
});

test("TV-C-07 Unicode normalization is not silent", () => {
  const text = fx.J({ ...fx.C1, description: "Café" });
  const r = tryCatch(() => parsePolicy(new TextEncoder().encode(text), "json"));
  assert.equal(errCode(r), "SCHEMA");
});

test("TV-C-08 exponent token rejection", () => {
  const text = fx.J(fx.C1).replace('"version":1', '"version":1e0');
  const r = tryCatch(() => parsePolicy(new TextEncoder().encode(text), "json"));
  assert.equal(errCode(r), "PARSE");
});

test("TV-C-09 unknown override field", () => {
  const text = fx.J({ ...fx.C1, allow_all: true });
  const r = tryCatch(() => parsePolicy(new TextEncoder().encode(text), "json"));
  assert.equal(errCode(r), "SCHEMA");
});

test("TV-C-10 exact bundle verification", () => {
  const v = verifyBundle(fx.B1 as never, fx.ROOT as never, []);
  assert.deepEqual(v, fx.VALID1);
});

test("TV-C-11 duplicate signature ID", () => {
  const b = { ...fx.B1, signatures: [fx.B1.signatures[0], fx.B1.signatures[0]] };
  const r = tryCatch(() => verifyBundle(b as never, fx.ROOT as never, []));
  assert.equal(errCode(r), "SIGNATURE_DUPLICATE");
});

test("TV-C-12 one signer cannot meet two", () => {
  const b = { ...fx.B1, signatures: [fx.B1.signatures[0]] };
  const r = tryCatch(() => verifyBundle(b as never, fx.ROOT as never, []));
  assert.equal(errCode(r), "QUORUM");
});

test("TV-C-13 text edits invalidate signatures", () => {
  const b = { ...fx.B1, policy: { ...fx.C1, description: "Changed text." } };
  const r = tryCatch(() => verifyBundle(b as never, fx.ROOT as never, []));
  assert.equal(errCode(r), "SIGNATURE_INVALID");
});

test("TV-C-14 key aliases cannot create independence", () => {
  const p = {
    ...fx.C1,
    next_authority: { threshold: 2, keys: [{ key_id: fx.KA, public_key: fx.PUB[0] }, { key_id: fx.KB, public_key: fx.PUB[0] }] },
  };
  const r = tryCatch(() => compile(p as never, fx.M1 as never));
  assert.equal(errCode(r), "SCHEMA");
});

test("TV-C-15 baseline scoped allow", () => {
  assert.deepEqual(evaluate(EI(fx.EI1)), fx.ALLOW);
});

test("TV-C-16 hard deny", () => {
  const r = evaluate(EI({ ...fx.EI1, request: { ...fx.Q1, tool: "record.delete" } }));
  assert.deepEqual(r, fx.deny("HARD_DENY", [fx.RD]));
});

test("TV-C-17 deny dominates overlapping allow", () => {
  const policy = { ...fx.C1, scope_rules: [fx.rule(fx.RA, ["record.delete"])] };
  const r = evaluate(EI(fx.evalFor(policy as never, { ...fx.Q1, tool: "record.delete" })));
  assert.deepEqual(r, fx.deny("HARD_DENY", [fx.RD]));
});

test("TV-C-18 segment boundary", () => {
  const r = evaluate(EI({ ...fx.EI1, request: { ...fx.Q1, resource: "records2/a" } }));
  assert.deepEqual(r, fx.deny("NO_SCOPE"));
});

test("TV-C-20 principal scope cannot be selected by caller", () => {
  const r = evaluate(EI({ ...fx.EI1, request: { ...fx.Q1, scope: "task-b" } }));
  assert.deepEqual(r, fx.deny("PRINCIPAL_SCOPE"));
});

test("TV-C-21 unknown tool alias", () => {
  const r = evaluate(EI({ ...fx.EI1, request: { ...fx.Q1, tool: "records.get" } }));
  assert.deepEqual(r, fx.deny("UNKNOWN_TOOL"));
});

test("TV-C-22 known uncovered operation", () => {
  const r = evaluate(EI({ ...fx.EI1, request: { ...fx.Q1, tool: "record.export", args: { destination: "task-b" } } }));
  assert.deepEqual(r, fx.deny("NO_SCOPE"));
});

test("TV-C-25 exact pin, not version label", () => {
  const r = evaluate(EI({ ...fx.EI1, request: { ...fx.Q1, pin: { ...fx.P1, policy_hash: "f".repeat(64) } } }));
  assert.deepEqual(r, fx.deny("PIN_MISMATCH"));
});

test("TV-C-26 installed manifest integrity", () => {
  const r = evaluate(EI({ ...fx.EI1, manifest: { ...fx.M1, adapter_build_hash: "f".repeat(64) } }));
  assert.deepEqual(r, fx.deny("MANIFEST_MISMATCH"));
});

test("TV-C-27 policy expiry equality", () => {
  const r = evaluate(EI({ ...fx.EI1, now: fx.END }));
  assert.deepEqual(r, fx.deny("POLICY_EXPIRED"));
});

test("TV-C-28 future validity", () => {
  const r = evaluate(EI({ ...fx.EI1, now: "2026-09-11T23:59:59.999Z" }));
  assert.deepEqual(r, fx.deny("POLICY_NOT_YET_VALID"));
});

test("TV-C-29 deadline equality", () => {
  const r = evaluate(EI({ ...fx.EI1, now: fx.T30 }));
  assert.deepEqual(r, fx.deny("DEADLINE"));
});

test("TV-C-54 immutable citation resolves exact bytes", () => {
  const c = cite(fx.B1 as never, fx.RA as never);
  assert.deepEqual(c, fx.CITE1);
  assert.equal(digest("clause", c.rule as unknown as Json), fx.CITE1.clause_hash);
  assert.equal(c.pointer, "/scope_rules/0");
});

test("TV-C-55 offline genesis evidence", () => {
  const v = verifyEvidence(fx.EV1 as never, fx.ROOT as never, fx.CP1 as never, true);
  assert.deepEqual(v, fx.VERIFY1);
});

test("TV-C-56 audit body tampering", () => {
  const ev = { ...fx.EV1, entries: [{ ...fx.E1, body: { ...fx.EB1, actor_id: fx.A } }] };
  const v = verifyEvidence(ev as never, fx.ROOT as never, fx.CP1 as never, true);
  assert.deepEqual(v, { integrity: "INVALID", replay: "NOT_REQUESTED", through_seq: 0, checkpoint_match: false, truth: "NOT_ATTESTED" });
});

test("TV-C-57 missing anchored suffix", () => {
  const ev = { ...fx.EV1, entries: [] };
  const v = verifyEvidence(ev as never, fx.ROOT as never, fx.CP1 as never, false);
  assert.deepEqual(v, { integrity: "INCOMPLETE", replay: "NOT_REQUESTED", through_seq: 0, checkpoint_match: false, truth: "NOT_ATTESTED" });
});

test("TV-C-58 replay does not trust embedded roots", () => {
  const badRoot = { ...fx.ROOT, bootstrap: { threshold: 1, keys: [{ key_id: fx.KA, public_key: fx.PUB[1] }] } };
  const v = verifyEvidence(fx.EV1 as never, badRoot as never, fx.CP1 as never, true);
  assert.deepEqual(v, { integrity: "INVALID", replay: "NOT_REQUESTED", through_seq: 0, checkpoint_match: false, truth: "NOT_ATTESTED" });
});

test("TV-C-62 integer bound is numeric, not lexical", () => {
  const c = {
    ...fx.C1,
    scope_rules: [{ ...fx.rule(fx.RA, ["record.list"]), when: [{ arg: "limit", op: "int_lte", value: 10 }] }],
  };
  const got = [9, 11].map((limit) =>
    evaluate(EI(fx.evalFor(c as never, { ...fx.Q1, tool: "record.list", args: { limit } }))));
  assert.deepEqual(got[0], fx.ALLOW);
  assert.deepEqual(got[1], fx.deny("NO_SCOPE"));
});
