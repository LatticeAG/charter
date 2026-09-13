/** §11.3 adversarial campaigns — TS side. Deterministic seeded generator;
 * each case contributes one tagged result line to a rolling SHA-256.
 * Usage: node test/campaign.mjs <canon|parse|eval> <count> [fixtureJson] */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { parseJsonText } from "../src/json/strict.ts";
import { canonicalize } from "../src/json/jcs.ts";
import { evaluate } from "../src/core/evaluate.ts";
import { CharterError } from "../src/errors.ts";

/* ---------- deterministic byte stream (identical in Python) ---------- */
class Rng {
  constructor(seed, index) {
    this.seed = seed; this.index = index; this.block = 0; this.buf = Buffer.alloc(0); this.off = 0;
  }
  byte() {
    if (this.off >= this.buf.length) {
      this.buf = createHash("sha256").update(`charter.campaign/1\n${this.seed}/${this.index}/${this.block++}`).digest();
      this.off = 0;
    }
    return this.buf[this.off++];
  }
  int(n) { let v = 0; for (let i = 0; i < n; i++) v = v * 256 + this.byte(); return v; }
  pick(arr) { return arr[this.byte() % arr.length]; }
}

/* ---------- shared case builders ---------- */
const KEY_POOL = ["a", "b", "z", "aa", "k1", "x_y", "A", "é", "中", "q9", "k-2", "zz"];
const STR_POOL = ["", "a", "hello", "x\"y", "back\\slash", "nl\n", "tab\t", "é", "中文字", "s\u0301".normalize("NFC"), "ctrl", "z", "snowman ☃", "0", "-0", "1e3"];

function genValue(r, depth) {
  const t = r.byte() % 10;
  if (depth >= 4) {
    // leaf only
    const l = r.byte() % 4;
    if (l === 0) return r.pick(STR_POOL);
    if (l === 1) return r.int(4) % 9007199254740991;
    if (l === 2) return r.byte() % 2 === 0;
    return null;
  }
  if (t <= 2) { // object
    const n = r.byte() % 5;
    const o = {};
    const used = new Set();
    for (let i = 0; i < n; i++) {
      const k = r.pick(KEY_POOL) + (r.byte() % 4 === 0 ? String(r.byte() % 8) : "");
      if (used.has(k)) continue;
      used.add(k);
      o[k] = genValue(r, depth + 1);
    }
    return o;
  }
  if (t <= 4) { // array
    const n = r.byte() % 4;
    const a = [];
    for (let i = 0; i < n; i++) a.push(genValue(r, depth + 1));
    return a;
  }
  if (t <= 6) return r.pick(STR_POOL);
  if (t <= 8) return r.int(5) % 9007199254740991;
  return r.byte() % 3 === 0 ? null : (r.byte() % 2 === 0);
}

const MALFORMED = [
  () => '{"a":1,"a":2}',                                   // duplicate member
  () => '[1,2,]',                                         // trailing comma
  () => '{"x":01}',                                       // leading zero
  () => '{"x":1e3}',                                      // exponent
  () => '{"x":-1}',                                       // negative
  () => '{"x":9007199254740992}',                         // unsafe integer
  () => '"lone\\ud800"',                                  // unpaired high surrogate
  () => '"lone\\udc00"',                                  // lone low surrogate
  () => '{"a":"bad\\x"}',                                 // bad escape
  () => '{"a":"rawctrl"}',                           // raw control char
  () => 'tru',                                            // bad literal
  () => '{"a" 1}',                                        // missing colon
  () => '{"a":1} trailing',                               // trailing bytes
  () => '\ufeff{"a":1}',                                   // BOM
  () => '[' + '1,'.repeat(130) + '1]',                    // array >256 elements
  () => '{' + Array.from({ length: 257 }, (_, i) => `"k${i}":0`).join(",") + '}', // >256 members
  () => '['.repeat(17) + ']'.repeat(17),                  // depth >16
  () => '{"s":"é"}'.normalize("NFD"),                // non-NFC string
  () => '{"é":0}'.normalize("NFD"),                  // non-NFC member name
  () => '{"a":}',                                         // missing value
  () => '',                                               // empty input
  () => '   ',                                            // whitespace only
  () => '"unterminated',                                  // unterminated string
  () => '{"a":+1}',                                       // plus sign
  () => '{a:1}',                                          // unquoted key
  () => '"ok" ',                                          // top-level valid string (accepted)
  () => '{"k":[0,{"m":true}]}',                           // valid nested (accepted)
  (r) => canonicalize(genValue(r, 0)).slice(0, -1),       // truncated valid doc
];

function genEvalInput(r, fx) {
  const tools = ["record.get", "record.put", "record.delete", "record.list", "record.export", "unknown.tool"];
  const scopes = ["task-a", "task-b", "other"];
  const resources = ["records/a", "records/b", "records", "other/x", "records/a/b"];
  const deadline = [fx.T30, fx.T0, fx.T180, fx.END][r.byte() % 4];
  const now = [fx.T0, fx.T30, fx.END][r.byte() % 3];
  const tool = r.pick(tools);
  const args = {};
  if (tool === "record.put") args.value = r.pick(STR_POOL).slice(0, 16);
  if (tool === "record.list") args.limit = r.byte() % 3 === 0 ? r.byte() % 120 : r.byte() % 101;
  if (tool === "record.export") args.destination = r.pick(STR_POOL).slice(0, 70);
  if (r.byte() % 5 === 0) args.extra = r.byte(); // excess arg → SCHEMA for known tools
  const req = {
    request_id: `crq_${"Q".repeat(21)}`,
    pin: r.byte() % 4 === 0 ? fx.P2 : fx.P1,
    scope: r.pick(scopes), tool, resource: r.pick(resources), args, deadline,
  };
  const principal = {
    principal_id: r.byte() % 8 === 0 ? fx.O : fx.A,
    credential_id: fx.CR, instance_id: fx.I,
    scopes: r.byte() % 4 === 0 ? ["task-b"] : ["task-a"],
  };
  return {
    policy: fx.C1, manifest: fx.M1, active_pin: fx.P1, request: req,
    principal, now, policy_revoked: r.byte() % 16 === 0,
    policy_signatures_valid: r.byte() % 16 !== 1,
  };
}

/* ---------- campaign modes ---------- */
const [mode, countS, fixturePath] = process.argv.slice(2);
const count = Number(countS);
const roll = createHash("sha256");
const dump = process.env.CHARTER_DUMP === "1";
const emit = (line) => { roll.update(line + "\n"); if (dump) console.log(line); };

if (mode === "canon") {
  for (let i = 0; i < count; i++) {
    const r = new Rng("canon", i);
    try {
      emit(`${i}:ok:${createHash("sha256").update(canonicalize(genValue(r, 0))).digest("hex")}`);
    } catch (e) {
      emit(`${i}:err:${e instanceof CharterError ? e.code : "INTERNAL"}`);
    }
  }
} else if (mode === "parse") {
  for (let i = 0; i < count; i++) {
    const r = new Rng("parse", i);
    const text = MALFORMED[r.byte() % MALFORMED.length](r);
    try {
      emit(`${i}:ok:${createHash("sha256").update(canonicalize(parseJsonText(text))).digest("hex")}`);
    } catch (e) {
      emit(`${i}:err:${e instanceof CharterError ? e.code : "INTERNAL"}`);
    }
  }
} else if (mode === "eval") {
  const fx = JSON.parse(readFileSync(fixturePath ?? "/tmp/charter-fixtures.json", "utf8"));
  for (let i = 0; i < count; i++) {
    const r = new Rng("eval", i);
    try {
      const d = evaluate(genEvalInput(r, fx));
      emit(`${i}:ok:${createHash("sha256").update(canonicalize(d)).digest("hex")}`);
    } catch (e) {
      emit(`${i}:err:${e instanceof CharterError ? e.code : "INTERNAL"}`);
    }
  }
} else {
  console.error("usage: campaign.mjs <canon|parse|eval> <count> [fixtureJson]");
  process.exit(2);
}
console.log(`${mode} ${count} sha256:${roll.digest("hex")}`);
