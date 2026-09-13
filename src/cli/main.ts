/** `charter` CLI — §4 command surface. One canonical JSON object + LF on stdout. */
import { randomBytes } from "node:crypto";
import { openSync, readFileSync, writeSync, closeSync, existsSync, mkdirSync, renameSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { CharterError, exitCodeFor, retryable } from "../errors.ts";
import { canonicalize, jsonEqual } from "../json/jcs.ts";
import { parseJsonText } from "../json/strict.ts";
import { parseYamlSubset } from "../yaml/subset.ts";
import { digest, signMessage, sha256Hex } from "../crypto/digest.ts";
import { signBytes, verifyBytes } from "../crypto/ed25519.ts";
import { isId, msTime, timeMs } from "../scalars.ts";
import {
  vAuditEntry, vBundle, vCallRequest, vCheckpoint, vDisputeRequest, vHeartbeat,
  vManifest, vPauseRequest, vPinCommand, vPolicy, vRevokeRequest, vRootFile,
  vSignedPin,
} from "../schema/validate.ts";
import { compile } from "../core/compile.ts";
import { verifyBundle } from "../core/verify-bundle.ts";
import { verifyEvidence } from "../core/verify-evidence.ts";
import { diff } from "../core/diff.ts";
import { cite, pinFor } from "../core/cite.ts";
import { Store } from "../engine/store.ts";
import { TenantEngine } from "../engine/tenant.ts";
import { FixtureRecordsAdapter } from "../adapter/fixture.ts";
import { serve } from "../http/server.ts";
import { loadTenant, secretRef, type LoadedTenant } from "../config.ts";
import { HttpClient, type Client } from "./client.ts";
import type {
  AuditEntry, Bundle, Checkpoint, ControlArtifact, Detached, Evidence,
  Json, Linted, Manifest, Pin, Policy, SignedPin, Warning,
} from "../types.ts";
import { ENGINE } from "../types.ts";

const VERSION = "0.1.0";
const USAGE = `charter — LatticeAGI Charter zone core (charter/1)

Usage: charter [--config PATH] [--json] [--timeout-ms N] <command> ...

Commands:
  policy lint FILE --manifest FILE --root FILE [--predecessor FILE]...
  policy canonicalize FILE --out FILE
  policy diff OLD NEW --manifest FILE
  policy sign FILE --manifest FILE --key-id cky_* --key-ref env:NAME --out FILE
  policy bundle FILE --manifest FILE --signature FILE... --root FILE --out FILE [--predecessor FILE]...
  policy verify BUNDLE --root FILE [--predecessor FILE]... [--at TIME]
  policy publish BUNDLE --request-id crq_*
  policy versions [--after N] [--limit N]
  policy fetch VERSION --out FILE
  policy cite VERSION RULE_ID
  pin sign FILE --key-id cky_* --key-ref env:NAME --out FILE
  pin assemble FILE --signature FILE... --root FILE --bundle FILE --out FILE [--predecessor FILE]...
  pin activate FILE
  gateway status
  gateway pause FILE
  gateway check FILE
  gateway call FILE
  gateway result crq_*
  revoke FILE --yes
  revocations list [--after-epoch N] [--limit N]
  dispute record FILE
  dispute list [--after-seq N] [--limit N]
  fleet heartbeat FILE
  fleet status [--watch-ms N]
  audit export --through-seq N --out FILE [--start-checkpoint FILE] [--inputs FILE]
  audit verify FILE --root FILE [--end-checkpoint FILE] [--replay]
  metrics
  config validate
  serve --local
  storage verify --backup FILE --end-checkpoint FILE --root FILE
`;

interface Args { flags: Map<string, string | true>; pos: string[]; }

function parseArgs(argv: string[]): Args {
  const flags = new Map<string, string | true>();
  const pos: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--json" || a === "--help" || a === "--version" || a === "--local" || a === "--replay" || a === "--yes") {
      flags.set(a.slice(2), true);
    } else if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq >= 0) flags.set(a.slice(2, eq), a.slice(eq + 1));
      else if (i + 1 < argv.length && !argv[i + 1]!.startsWith("--")) flags.set(a.slice(2), argv[++i]!);
      else flags.set(a.slice(2), true);
    } else pos.push(a);
  }
  return { flags, pos };
}

function str(a: Args, name: string): string | undefined {
  const v = a.flags.get(name);
  return typeof v === "string" ? v : undefined;
}
function strReq(a: Args, name: string): string {
  const v = str(a, name);
  if (v === undefined) throw new CharterError("SCHEMA", `missing --${name}`);
  return v;
}
function intReq(a: Args, name: string): number {
  const v = strReq(a, name);
  if (!/^[0-9]+$/.test(v)) throw new CharterError("SCHEMA", `bad --${name}`);
  const n = Number(v);
  if (!Number.isSafeInteger(n)) throw new CharterError("SCHEMA", `bad --${name}`);
  return n;
}
function posInt(v: string | undefined, name: string): number {
  const s = v ?? missing(name);
  if (!/^[0-9]+$/.test(s)) throw new CharterError("SCHEMA", `bad ${name}`);
  const n = Number(s);
  if (!Number.isSafeInteger(n)) throw new CharterError("SCHEMA", `bad ${name}`);
  return n;
}

function intOpt(a: Args, name: string, d: number): number {
  const v = str(a, name);
  if (v === undefined) return d;
  if (!/^[0-9]+$/.test(v)) throw new CharterError("SCHEMA", `bad --${name}`);
  return Number(v);
}
function strAll(argv: string[], name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === `--${name}` && i + 1 < argv.length) out.push(argv[i + 1]!);
    else if (argv[i]!.startsWith(`--${name}=`)) out.push(argv[i]!.slice(name.length + 3));
  }
  return out;
}

function readJsonFile(path: string): Json {
  return parseJsonText(readFileSync(path === "-" ? "/dev/stdin" : path, "utf8"));
}
function readStructuredFile(path: string): Json {
  const text = readFileSync(path === "-" ? "/dev/stdin" : path, "utf8");
  const t = text.trimStart();
  if (t.startsWith("{") || t.startsWith("[")) return parseJsonText(text);
  return parseYamlSubset(text) as Json;
}

/** Atomic create-exclusive output write; existing path → exit 2. */
function writeOut(path: string, text: string): void {
  if (existsSync(path)) throw new CharterError("SCHEMA", `output exists: ${path}`);
  const dir = dirname(resolve(path));
  mkdirSync(dir, { recursive: true });
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  const fd = openSync(tmp, "wx");
  try { writeSync(fd, text); } finally { closeSync(fd); }
  renameSync(tmp, path);
}

function seedFromRef(keyRef: string): Uint8Array {
  const raw = new TextDecoder().decode(secretRef(keyRef));
  const seed = Buffer.from(raw, "base64url");
  if (seed.length !== 32 || seed.toString("base64url") !== raw) {
    throw new CharterError("SCHEMA", "key seed must be canonical base64url of 32 bytes");
  }
  return seed;
}
function signDetached(keyRef: string, keyId: string, message: Uint8Array): Detached {
  return { key_id: keyId as Detached["key_id"], signature: Buffer.from(signBytes(message, seedFromRef(keyRef))).toString("base64url") };
}

/** Sorted-unique warning set per §4. */
function warnings(policy: Policy, atMs: number): Warning[] {
  const w = new Set<Warning>();
  if (policy.scope_rules.length === 0) w.add("NO_ALLOW_RULES");
  if (policy.next_authority.threshold === 1) w.add("SINGLE_SIGNER");
  if (timeMs(policy.not_after) - atMs <= 86_400_000) w.add("EXPIRY_WITHIN_24H");
  return [...w].sort();
}

/* ---- network plumbing -------------------------------------------------- */

function makeClient(loaded: LoadedTenant, timeoutMs: number): Client {
  const ep = loaded.config.endpoint;
  if (!/^https?:\/\//.test(ep)) throw new CharterError("SCHEMA", "endpoint must be an http(s) origin");
  return new HttpClient(ep.replace(/\/$/, ""), loaded.clientToken, timeoutMs);
}

function ok(resp: { status: number; body: Json }): Json {
  if (resp.status >= 400) {
    const err = (resp.body as { error?: { code?: string; audit_seq?: number | null } }).error;
    throw new CharterError((err?.code ?? "AUDIT_UNAVAILABLE") as import("../errors.ts").ErrorCode, undefined, err?.audit_seq ?? null);
  }
  return resp.body;
}

/* ---- result → exit code ------------------------------------------------ */

interface Out { body: Json; exit: number; }
const out = (body: Json, exit = 0): Out => ({ body, exit });

function callExit(body: Json): number {
  const r = body as unknown as { state?: string; decision?: { verdict: string } };
  switch (r.state) {
    case "SUCCEEDED": return 0;
    case "DENIED": return 3;
    case "FAILED": case "NOT_SENT": return 9;
    case "COMMITTED": case "INDETERMINATE": return 8;
    default: return 0;
  }
}
function checkExit(body: Json): number {
  const d = (body as { decision?: { verdict: string } }).decision;
  return d?.verdict === "DENY" ? 3 : 0;
}
function fleetExit(body: Json): number {
  const s = (body as { status?: string }).status;
  return s === "EMPTY" || s === "MISSING" || s === "SPLIT" ? 3 : 0;
}
function verifyExit(body: Json): number {
  const v = body as { integrity?: string; replay?: string };
  if (v.integrity === "INVALID") return 4;
  if (v.integrity === "INCOMPLETE") return 8;
  if (v.replay === "MISMATCH") return 4;
  if (v.replay === "INPUTS_MISSING" || v.replay === "CONTEXT_MISSING") return 8;
  return 0;
}

/* ---- main -------------------------------------------------------------- */

export async function main(argv: string[]): Promise<number> {
  const a = parseArgs(argv);
  if (a.flags.has("version")) {
    process.stdout.write(canonicalize({ version: VERSION, engine: ENGINE, api: "charter.http/1" } as Json) + "\n");
    return 0;
  }
  if (a.flags.has("help") || a.pos.length === 0) {
    process.stderr.write(USAGE);
    return a.pos.length === 0 && !a.flags.has("help") ? 2 : 0;
  }
  const timeoutMs = intOpt(a, "timeout-ms", 10_000);
  if (timeoutMs < 1 || timeoutMs > 60_000) {
    process.stdout.write(canonicalize({ error: { code: "SCHEMA", retryable: false, audit_seq: null } } as Json) + "\n");
    return 2;
  }
  const configPath = str(a, "config") ?? "./charter.yaml";
  // Command table: group verbs take a second command word (which is then
  // shifted off so dispatch reads operands from pos[1] onward); the rest are
  // single-word commands.
  const GROUPS = new Set(["policy", "pin", "gateway", "revocations", "dispute", "fleet", "audit", "config", "storage"]);
  const w0 = a.pos[0] ?? "";
  let cmd: string;
  if (w0 === "serve") cmd = a.flags.has("local") ? "serve --local" : "serve";
  else if (GROUPS.has(w0) && a.pos.length > 1) { cmd = `${w0} ${a.pos[1]}`; a.pos.shift(); }
  else cmd = w0;
  try {
    const r = await dispatch(cmd, a, argv, { configPath, timeoutMs });
    if (r !== null) process.stdout.write(canonicalize(r.body) + "\n");
    return r === null ? 0 : r.exit;
  } catch (e) {
    const code = e instanceof CharterError ? e.code : "AUDIT_UNAVAILABLE";
    const auditSeq = e instanceof CharterError ? e.auditSeq : null;
    process.stdout.write(canonicalize({ error: { code, retryable: retryable(code), audit_seq: auditSeq } } as Json) + "\n");
    return exitCodeFor(code);
  }
}

async function dispatch(
  cmd: string, a: Args, argv: string[],
  ctx: { configPath: string; timeoutMs: number },
): Promise<Out | null> {
  const needClient = (): { client: Client; loaded: LoadedTenant } => {
    const loaded = loadTenant(ctx.configPath);
    return { client: makeClient(loaded, ctx.timeoutMs), loaded };
  };
  const predecessors = (): Bundle[] =>
    strAll(argv, "predecessor").map((f) => vBundle(readJsonFile(f), "$.predecessor"));

  switch (cmd) {
    /* ---------------- offline policy ops ---------------- */
    case "policy lint": {
      const policy = vPolicy(readStructuredFile(a.pos[1] ?? missing("FILE")), "$.policy");
      const manifest = vManifest(readStructuredFile(strReq(a, "manifest")), "$.manifest");
      const root = vRootFile(readJsonFile(strReq(a, "root")), "$.root");
      lintLineage(policy, manifest, root, predecessors());
      compile(policy, manifest);
      const r: Linted = {
        valid: true, policy_hash: digest("policy", policy),
        manifest_hash: digest("manifest", manifest),
        warnings: warnings(policy, Date.now()),
      };
      return out(r as unknown as Json);
    }
    case "policy canonicalize": {
      const policy = vPolicy(readStructuredFile(a.pos[1] ?? missing("FILE")), "$.policy");
      const text = canonicalize(policy as unknown as Json);
      const o = strReq(a, "out");
      writeOut(o, text); // J(Policy), no LF
      return out({ policy_hash: digest("policy", policy), bytes: Buffer.byteLength(text, "utf8"), out: o } as unknown as Json);
    }
    case "policy diff": {
      const oldP = vPolicy(readStructuredFile(a.pos[1] ?? missing("OLD")), "$.old");
      const newP = vPolicy(readStructuredFile(a.pos[2] ?? missing("NEW")), "$.new");
      const manifest = vManifest(readStructuredFile(strReq(a, "manifest")), "$.manifest");
      compile(oldP, manifest); compile(newP, manifest);
      return out(diff(oldP, newP) as unknown as Json);
    }
    case "policy sign": {
      const policy = vPolicy(readStructuredFile(a.pos[1] ?? missing("FILE")), "$.policy");
      const manifest = vManifest(readStructuredFile(strReq(a, "manifest")), "$.manifest");
      compile(policy, manifest);
      const keyId = strReq(a, "key-id");
      const det = signDetached(strReq(a, "key-ref"), keyId, signMessage("policy", policy));
      const o = strReq(a, "out");
      writeOut(o, canonicalize(det as unknown as Json));
      return out({ policy_hash: digest("policy", policy), key_id: keyId, out: o } as unknown as Json);
    }
    case "policy bundle": {
      const policy = vPolicy(readStructuredFile(a.pos[1] ?? missing("FILE")), "$.policy");
      const manifest = vManifest(readStructuredFile(strReq(a, "manifest")), "$.manifest");
      const root = vRootFile(readJsonFile(strReq(a, "root")), "$.root");
      const sigs = strAll(argv, "signature").map((f) => vDetachedFile(readJsonFile(f)));
      const bundle: Bundle = { policy, manifest, signatures: sigs };
      verifyBundle(bundle, root, predecessors());
      const o = strReq(a, "out");
      writeOut(o, canonicalize(bundle as unknown as Json));
      return out({ pin: pinFor(bundle), signatures: sigs.length, out: o } as unknown as Json);
    }
    case "policy verify": {
      const bundle = vBundle(readJsonFile(a.pos[1] ?? missing("BUNDLE")), "$.bundle");
      const root = vRootFile(readJsonFile(strReq(a, "root")), "$.root");
      const at = str(a, "at");
      return out(verifyBundle(bundle, root, predecessors(), at) as unknown as Json);
    }
    /* ---------------- registry ops ---------------- */
    case "policy publish": {
      const { client } = needClient();
      const bundle = vBundle(readJsonFile(a.pos[1] ?? missing("BUNDLE")), "$.bundle");
      const requestId = strReq(a, "request-id");
      return out(ok(await client.call("POST", "/v1/charters", { request_id: requestId, bundle } as unknown as Json)));
    }
    case "policy versions": {
      const { client } = needClient();
      return out(ok(await client.call("GET", "/v1/charters", null,
        { after: String(intOpt(a, "after", 0)), limit: String(intOpt(a, "limit", 100)) })));
    }
    case "policy fetch": {
      const { client } = needClient();
      const body = ok(await client.call("GET", `/v1/charters/${posInt(a.pos[1], "VERSION")}`, null));
      const bundle = vBundle(body, "$.bundle");
      const loaded = loadTenant(ctx.configPath);
      // Complete local chain verification before the file exists.
      const preds: Bundle[] = [];
      for (let v = 1; v < bundle.policy.version; v++) {
        preds.push(vBundle(ok(await client.call("GET", `/v1/charters/${v}`, null)), "$.predecessor"));
      }
      verifyBundle(bundle, loaded.root, preds);
      const o = strReq(a, "out");
      writeOut(o, canonicalize(bundle as unknown as Json));
      return out({ pin: pinFor(bundle), out: o } as unknown as Json);
    }
    case "policy cite": {
      const { client } = needClient();
      const version = posInt(a.pos[1], "VERSION");
      const ruleId = a.pos[2] ?? missing("RULE_ID");
      const body = ok(await client.call("GET", `/v1/charters/${version}`, null));
      const bundle = vBundle(body, "$.bundle");
      const loaded = loadTenant(ctx.configPath);
      const preds: Bundle[] = [];
      for (let v = 1; v < version; v++) {
        preds.push(vBundle(ok(await client.call("GET", `/v1/charters/${v}`, null)), "$.predecessor"));
      }
      verifyBundle(bundle, loaded.root, preds);
      return out(cite(bundle, ruleId as never) as unknown as Json);
    }
    /* ---------------- pin ops ---------------- */
    case "pin sign": {
      const command = vPinCommand(readJsonFile(a.pos[1] ?? missing("FILE")), "$.command");
      const keyId = strReq(a, "key-id");
      const det = signDetached(strReq(a, "key-ref"), keyId, signMessage("pin", command));
      const o = strReq(a, "out");
      writeOut(o, canonicalize({ command, signature: det } as unknown as Json));
      return out({ pin: command.target, key_id: keyId, out: o } as unknown as Json);
    }
    case "pin assemble": {
      const command = vPinCommand(readJsonFile(a.pos[1] ?? missing("FILE")), "$.command");
      const root = vRootFile(readJsonFile(strReq(a, "root")), "$.root");
      const bundle = vBundle(readJsonFile(strReq(a, "bundle")), "$.bundle");
      verifyBundle(bundle, root, predecessors());
      if (digest("policy", bundle.policy) !== command.authority_policy_hash) {
        throw new CharterError("HASH_MISMATCH", "command authority is not --bundle policy");
      }
      const sigs = strAll(argv, "signature").map((f) => {
        const sf = readJsonFile(f) as { command?: unknown; signature?: Detached };
        if (!jsonEqual(sf.command as Json, command as unknown as Json)) {
          throw new CharterError("SCHEMA", "signature file command differs");
        }
        return vDetachedFile(sf.signature as Json);
      });
      if (sigs.length === 0) throw new CharterError("QUORUM", "no signature files");
      const sp: SignedPin = { command, signatures: sigs };
      // Verify the assembled set under the authority named by --bundle.
      const authority = bundle.policy.next_authority;
      const seen = new Set<string>();
      let count = 0;
      for (const s of sigs) {
        if (seen.has(s.key_id)) throw new CharterError("SIGNATURE_DUPLICATE");
        seen.add(s.key_id);
        const key = authority.keys.find((k) => k.key_id === s.key_id);
        if (!key) throw new CharterError("KEY_UNKNOWN");
        if (!verifyBytes(signMessage("pin", command), Buffer.from(s.signature, "base64url"), Buffer.from(key.public_key, "hex"))) {
          throw new CharterError("SIGNATURE_INVALID");
        }
        count++;
      }
      if (count < authority.threshold) throw new CharterError("QUORUM");
      const o = strReq(a, "out");
      writeOut(o, canonicalize(sp as unknown as Json));
      return out({ pin: command.target, signatures: count, out: o } as unknown as Json);
    }
    case "pin activate": {
      const { client } = needClient();
      const sp = vSignedPin(readJsonFile(a.pos[1] ?? missing("FILE")), "$.pin");
      return out(ok(await client.call("POST", "/v1/deployment/pin", sp as unknown as Json)));
    }
    /* ---------------- gateway ops ---------------- */
    case "gateway status": {
      const { client } = needClient();
      const deployment = await client.call("GET", "/v1/deployment", null);
      const ready = await client.call("GET", "/v1/readyz", null);
      return out({
        deployment: deployment.status < 400 ? deployment.body : null,
        readiness: ready.status < 400 ? ready.body : ready.body,
      } as unknown as Json);
    }
    case "gateway pause": {
      const { client } = needClient();
      const body = vPauseRequest(readJsonFile(a.pos[1] ?? missing("FILE")), "$.pause");
      return out(ok(await client.call("POST", "/v1/deployment/pause", body as unknown as Json)));
    }
    case "gateway check": {
      const { client } = needClient();
      const req = vCallRequest(readJsonFile(a.pos[1] ?? missing("FILE")), "$.request");
      const body = ok(await client.call("POST", "/v1/gateway/check", req as unknown as Json));
      return out(body, checkExit(body));
    }
    case "gateway call": {
      const { client } = needClient();
      const req = vCallRequest(readJsonFile(a.pos[1] ?? missing("FILE")), "$.request");
      try {
        const body = ok(await client.call("POST", "/v1/gateway/call", req as unknown as Json));
        return out(body, callExit(body));
      } catch (e) {
        if (e instanceof CharterError && e.code === "AUDIT_UNAVAILABLE" && e.message === "request timeout") {
          return out({ error: { code: "AUDIT_UNAVAILABLE", retryable: true, audit_seq: null }, request_id: req.request_id } as unknown as Json, 8);
        }
        throw e;
      }
    }
    case "gateway result": {
      const { client } = needClient();
      const id = a.pos[1] ?? missing("ID");
      if (!isId(id, "crq")) throw new CharterError("SCHEMA", "bad request id");
      const body = ok(await client.call("GET", `/v1/gateway/calls/${id}`, null));
      return out(body, callExit(body));
    }
    /* ---------------- revocations ---------------- */
    case "revoke": {
      const { client } = needClient();
      const body = vRevokeRequest(readJsonFile(a.pos[1] ?? missing("FILE")), "$.revoke");
      if (!a.flags.has("yes") && !process.stdin.isTTY) {
        throw new CharterError("SCHEMA", "noninteractive revoke requires --yes");
      }
      return out(ok(await client.call("POST", "/v1/revocations", body as unknown as Json)));
    }
    case "revocations list": {
      const { client } = needClient();
      return out(ok(await client.call("GET", "/v1/revocations", null,
        { after_epoch: String(intOpt(a, "after-epoch", 0)), limit: String(intOpt(a, "limit", 100)) })));
    }
    /* ---------------- disputes ---------------- */
    case "dispute record": {
      const { client } = needClient();
      const req = vDisputeRequest(readJsonFile(a.pos[1] ?? missing("FILE")), "$.request");
      return out(ok(await client.call("POST", "/v1/disputes", req as unknown as Json)));
    }
    case "dispute list": {
      const { client } = needClient();
      return out(ok(await client.call("GET", "/v1/disputes", null,
        { after_seq: String(intOpt(a, "after-seq", 0)), limit: String(intOpt(a, "limit", 100)) })));
    }
    /* ---------------- fleet ---------------- */
    case "fleet heartbeat": {
      const { client } = needClient();
      const req = vHeartbeat(readJsonFile(a.pos[1] ?? missing("FILE")), "$.request");
      return out(ok(await client.call("POST", "/v1/fleet/heartbeat", req as unknown as Json)));
    }
    case "fleet status": {
      const { client } = needClient();
      const watchMs = intOpt(a, "watch-ms", 0);
      if (watchMs !== 0 && (watchMs < 1000 || watchMs > 60_000)) throw new CharterError("SCHEMA", "bad --watch-ms");
      const body = ok(await client.call("GET", "/v1/fleet", null));
      if (watchMs === 0) return out(body, fleetExit(body));
      // --watch-ms: one canonical JSONL snapshot per poll.
      process.stdout.write(canonicalize(body) + "\n");
      await new Promise((r) => setTimeout(r, watchMs));
      for (;;) {
        const b = ok(await client.call("GET", "/v1/fleet", null));
        process.stdout.write(canonicalize(b) + "\n");
        await new Promise((r) => setTimeout(r, watchMs));
      }
    }
    /* ---------------- audit ---------------- */
    case "audit export": {
      const { client, loaded } = needClient();
      const through = intReq(a, "through-seq");
      const o = strReq(a, "out");
      const start = str(a, "start-checkpoint");
      const startCp = start ? vCheckpoint(readJsonFile(start), "$.start") : null;
      const inputs = str(a, "inputs") ? (readJsonFile(str(a, "inputs")!) as unknown as Evidence["inputs"]) : [];
      // Assemble the stream from remote pages; root comes from local trust config.
      const entries: AuditEntry[] = [];
      const controls: ControlArtifact[] = [];
      let after = startCp === null ? 0 : startCp.body.through_seq;
      for (;;) {
        const page = ok(await client.call("GET", "/v1/audit", null,
          { after_seq: String(after), through_seq: String(through), limit: "100" })) as unknown as {
            entries: AuditEntry[]; controls: ControlArtifact[]; next_after: number | null;
          };
        entries.push(...page.entries); controls.push(...page.controls);
        if (page.next_after === null) break;
        after = page.next_after;
      }
      const end = vCheckpoint(ok(await client.call("GET", `/v1/audit/checkpoint?through_seq=${through}`, null)), "$.end");
      // Every published bundle is required for lineage verification.
      const versions = ok(await client.call("GET", "/v1/charters", null, { after: "0", limit: "100" })) as unknown as
        { versions: { version: number }[] };
      const bundles: Bundle[] = [];
      for (const v of versions.versions) {
        bundles.push(vBundle(ok(await client.call("GET", `/v1/charters/${v.version}`, null)), "$.bundle"));
      }
      const lines: string[] = [];
      lines.push(canonicalize({ record: "header", schema: "charter.stream/1", root: loaded.root, start: startCp, end } as unknown as Json));
      for (const b of bundles) lines.push(canonicalize({ record: "bundle", bundle: b } as unknown as Json));
      for (const c of controls) lines.push(canonicalize({ record: "control", control: c } as unknown as Json));
      for (const e of entries) lines.push(canonicalize({ record: "entry", entry: e } as unknown as Json));
      for (const i of inputs) lines.push(canonicalize({ record: "input", input: i } as unknown as Json));
      lines.push(canonicalize({
        record: "trailer", bundles: bundles.length, controls: controls.length,
        entries: entries.length, inputs: inputs.length, through_seq: through,
      } as unknown as Json));
      writeOut(o, lines.join("\n") + "\n");
      return out({ through_seq: through, entries: entries.length, out: o } as unknown as Json);
    }
    case "audit verify": {
      const ev = evidenceFromNdjson(readFileSync(a.pos[1] ?? missing("FILE"), "utf8"));
      const root = vRootFile(readJsonFile(strReq(a, "root")), "$.root");
      const ec = str(a, "end-checkpoint");
      const endCp = ec ? vCheckpoint(readJsonFile(ec), "$.end_checkpoint") : null;
      const v = verifyEvidence(ev, root, endCp, a.flags.has("replay"));
      return out(v as unknown as Json, verifyExit(v as unknown as Json));
    }
    /* ---------------- misc ---------------- */
    case "metrics": {
      const { client } = needClient();
      return out(ok(await client.call("GET", "/v1/metrics", null)));
    }
    case "config validate": {
      const loaded = loadTenant(ctx.configPath);
      return out({
        valid: true, manifest_hash: digest("manifest", loaded.manifest),
        instance_count: loaded.config.instance_inventory.length,
      } as unknown as Json);
    }
    case "serve --local": {
      if (!a.flags.has("local")) throw new CharterError("SCHEMA", "serve requires --local");
      const loaded = loadTenant(ctx.configPath);
      if (loaded.config.environment !== "local") {
        throw new CharterError("SCHEMA", "serve --local rejects production configuration");
      }
      const ep = new URL(loaded.config.endpoint);
      const store = new Store(resolve(dirname(resolve(ctx.configPath)), "tenant.db"));
      const hasMeta = store.get<{ singleton: number }>("SELECT singleton FROM meta WHERE singleton=1");
      const opts = {
        store, config: loaded.config, root: loaded.root, manifest: loaded.manifest,
        auth: loaded.auth, encryptionKeys: loaded.encryptionKeys, auditSeed: loaded.auditSeed,
        adapter: new FixtureRecordsAdapter(),
      };
      const engine = hasMeta ? TenantEngine.open(opts) : TenantEngine.provision(opts);
      process.stdout.write(canonicalize({ mode: "local", api: "charter.http/1" } as Json) + "\n");
      await serve(engine, Number(ep.port) || 8787, ep.hostname);
      return new Promise<never>(() => { /* run forever */ });
    }
    case "storage verify": {
      const backup = strReq(a, "backup");
      const endCp = vCheckpoint(readJsonFile(strReq(a, "end-checkpoint")), "$.end_checkpoint");
      const root = vRootFile(readJsonFile(strReq(a, "root")), "$.root");
      return out(storageVerify(backup, endCp, root));
    }
    default:
      throw new CharterError("SCHEMA", `unknown command: ${cmd}`);
  }
}

function missing(name: string): never {
  throw new CharterError("SCHEMA", `missing ${name}`);
}
function vDetachedFile(v: Json): Detached {
  const o = v as { key_id?: unknown; signature?: unknown };
  if (typeof o.key_id !== "string" || !isId(o.key_id, "cky") || typeof o.signature !== "string") {
    throw new CharterError("SCHEMA", "bad Detached file");
  }
  return { key_id: o.key_id as Detached["key_id"], signature: o.signature };
}
function lintLineage(policy: Policy, _manifest: Manifest, root: import("../types.ts").RootFile, preds: Bundle[]): void {
  if (policy.tenant_id !== root.tenant_id || policy.charter_id !== root.charter_id) {
    throw new CharterError("SCHEMA", "policy identity mismatch vs root");
  }
  if (policy.version === 1) {
    if (policy.previous_hash !== null) throw new CharterError("SCHEMA", "version 1 must have previous_hash null");
    return;
  }
  const prev = preds.find((b) => b.policy.version === policy.version - 1);
  if (!prev) throw new CharterError("VERSION_CONFLICT", "missing predecessor");
  if (policy.previous_hash !== digest("policy", prev.policy)) {
    throw new CharterError("HASH_MISMATCH", "previous_hash does not bind predecessor");
  }
}

/** §9 offline storage verification: integrity_check + full chain + head match. */
function storageVerify(backupPath: string, endCp: Checkpoint, root: import("../types.ts").RootFile): Json {
  const store = new Store(backupPath, { readonly: true });
  try {
    const ic = store.get<{ integrity_check: string }>("PRAGMA integrity_check");
    if (ic?.integrity_check !== "ok") throw new CharterError("AUDIT_UNAVAILABLE", "sqlite integrity_check failed");
    const meta = store.get<{ storage_version: number; head_hash: string; next_seq: number; root_hash: string }>(
      "SELECT storage_version,head_hash,next_seq,root_hash FROM meta WHERE singleton=1");
    if (!meta || meta.storage_version !== 1) throw new CharterError("UNSUPPORTED_VERSION", "storage_version != 1");
    if (meta.root_hash !== sha256Hex(canonicalize(root as unknown as Json))) {
      throw new CharterError("HASH_MISMATCH", "store root does not match --root");
    }
    const rows = store.all<{ seq: number; hash: string; body_jcs: string; key_id: string; signature: string }>(
      "SELECT seq,hash,body_jcs,key_id,signature FROM audit ORDER BY seq");
    let prev = "0".repeat(64);
    let expect = 1;
    for (const r of rows) {
      const body = JSON.parse(r.body_jcs);
      if (r.seq !== expect++ || r.hash !== digest("audit", body) || body.prev_hash !== prev) {
        throw new CharterError("AUDIT_UNAVAILABLE", "audit chain broken");
      }
      const key = root.audit_keys.find((k) => k.from_seq <= r.seq && (k.through_seq === null || r.seq <= k.through_seq));
      if (!key || key.key_id !== r.key_id ||
          !verifyBytes(signMessage("audit", body), Buffer.from(r.signature, "base64url"), Buffer.from(key.public_key, "hex"))) {
        throw new CharterError("SIGNATURE_INVALID", "audit signature");
      }
      prev = r.hash;
    }
    const through = rows.length;
    const key = root.audit_keys.find((k) =>
      k.from_seq <= endCp.body.through_seq && (k.through_seq === null || endCp.body.through_seq <= k.through_seq));
    if (!key || key.key_id !== endCp.key_id ||
        !verifyBytes(signMessage("checkpoint", endCp.body), Buffer.from(endCp.signature, "base64url"), Buffer.from(key.public_key, "hex"))) {
      throw new CharterError("SIGNATURE_INVALID", "end checkpoint");
    }
    if (endCp.body.through_seq !== through || endCp.body.head_hash !== prev) {
      throw new CharterError("HASH_MISMATCH", "checkpoint does not match store head");
    }
    return { valid: true, storage_version: 1, through_seq: through } as unknown as Json;
  } finally {
    store.close();
  }
}

/** Reassemble an Evidence record from the export NDJSON stream. */
export function evidenceFromNdjson(text: string): Evidence {
  if (!text.endsWith("\n")) throw new CharterError("SCHEMA", "stream must end with LF");
  const lines = text.slice(0, -1).split("\n");
  let root: Evidence["root"] | null = null;
  let start: Checkpoint | null = null;
  let end: Checkpoint | null = null;
  const bundles: Bundle[] = [];
  const controls: ControlArtifact[] = [];
  const entries: Evidence["entries"] = [];
  const inputs: Evidence["inputs"] = [];
  let sawTrailer = false;
  for (const line of lines) {
    const rec = parseJsonText(line) as { record?: string };
    switch (rec.record) {
      case "header": {
        const h = rec as unknown as { root: Evidence["root"]; start: Checkpoint | null; end: Checkpoint };
        root = h.root; start = h.start; end = h.end;
        break;
      }
      case "bundle": bundles.push((rec as { bundle: Bundle }).bundle); break;
      case "control": controls.push((rec as { control: ControlArtifact }).control); break;
      case "entry": entries.push(vAuditEntry((rec as { entry: Evidence["entries"][number] }).entry, "$.entry")); break;
      case "input": inputs.push((rec as { input: Evidence["inputs"][number] }).input); break;
      case "trailer": {
        if (sawTrailer) throw new CharterError("SCHEMA", "duplicate trailer");
        sawTrailer = true; break;
      }
      default: throw new CharterError("SCHEMA", "unknown stream record");
    }
  }
  if (root === null || end === null || !sawTrailer) throw new CharterError("SCHEMA", "incomplete stream");
  return { schema: "charter.evidence/1", root, bundles, start, entries, controls, end, inputs };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
