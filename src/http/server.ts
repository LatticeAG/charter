/** §3 HTTP surface — 22 routes, bearer auth, closed-body limits, error mapping. */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { CharterError, retryable, statusFor } from "../errors.ts";
import { parseJsonBytes } from "../json/strict.ts";
import { canonicalize } from "../json/jcs.ts";
import { isId } from "../scalars.ts";
import type { AuthRecord, Json } from "../types.ts";
import type { StoredResponse, TenantEngine } from "../engine/tenant.ts";

const BODY_CAP = 64 * 1024;
const PUBLISH_CAP = 256 * 1024;
const QUERY_CAP = 1024;

/** Method mismatch on a known route — 405 with SCHEMA error body. */
class MethodNotAllowed extends CharterError {
  constructor() {
    super("SCHEMA", "method not allowed");
    this.name = "MethodNotAllowed";
  }
}

type Role = AuthRecord["role"];

interface Ctx {
  engine: TenantEngine;
  rec: AuthRecord;
  params: Record<string, string>;
  query: URLSearchParams;
  body: Json;
}

type Handler = (c: Ctx) => Promise<StoredResponse>;

interface Route {
  method: string;
  pattern: RegExp;
  keys: string[];
  roles: Role[];
  bodyCap: number;
  handler: Handler;
}

function pat(spec: string): { pattern: RegExp; keys: string[] } {
  const keys: string[] = [];
  const re = spec.replace(/\{([a-z_]+)\}/g, (_m, k: string) => {
    keys.push(k);
    return "([^/]+)";
  });
  return { pattern: new RegExp(`^${re}$`), keys };
}

function routes(engine: TenantEngine): Route[] {
  const r = (
    method: string, spec: string, roles: Role[], handler: Handler, bodyCap = BODY_CAP,
  ): Route => ({ method, ...pat(spec), roles, handler, bodyCap });

  return [
    r("POST", "/v1/charters", ["publisher", "operator"], (c) => engine.publish(c.rec, c.body), PUBLISH_CAP),
    r("POST", "/v1/charters/validate", ["publisher", "operator"], (c) => engine.validateBundleRoute(c.rec, c.body)),
    r("GET", "/v1/charters", ["reader", "publisher", "operator", "agent"], (c) =>
      engine.versions(qInt(c, "after", 0), qInt(c, "limit", 100))),
    r("GET", "/v1/charters/{version}", ["reader", "publisher", "operator", "agent"], (c) =>
      engine.getBundle(paramInt(c.params.version!, "version"))),
    r("GET", "/v1/charters/{version}/rules/{rule_id}", ["reader", "publisher", "operator", "agent"], (c) => {
      if (!isId(c.params.rule_id!, "crl")) throw new CharterError("SCHEMA", "bad rule id");
      return engine.getCitation(paramInt(c.params.version!, "version"), c.params.rule_id!);
    }),
    r("GET", "/v1/deployment", ["reader", "operator", "instance", "agent"], (c) => engine.getDeployment()),
    r("POST", "/v1/deployment/pin", ["operator"], (c) => engine.pin(c.rec, c.body)),
    r("POST", "/v1/deployment/pause", ["operator"], (c) => engine.pause(c.rec, c.body)),
    r("POST", "/v1/revocations", ["operator"], (c) => engine.revoke(c.rec, c.body)),
    r("GET", "/v1/revocations", ["reader", "operator"], (c) =>
      engine.revocations(qInt(c, "after_epoch", 0), qInt(c, "limit", 100))),
    r("POST", "/v1/gateway/check", ["agent"], (c) => engine.check(c.rec, c.body)),
    r("POST", "/v1/gateway/call", ["agent"], (c) => engine.call(c.rec, c.body)),
    r("GET", "/v1/gateway/calls/{request_id}", ["agent", "reader", "operator"], (c) => {
      if (!isId(c.params.request_id!, "crq")) throw new CharterError("SCHEMA", "bad request id");
      return engine.getCall(c.rec, c.params.request_id!);
    }),
    r("POST", "/v1/disputes", ["agent", "reader", "operator"], (c) => engine.dispute(c.rec, c.body)),
    r("GET", "/v1/disputes", ["agent", "reader", "operator"], (c) =>
      engine.disputes(c.rec, qInt(c, "after_seq", 0), qInt(c, "limit", 100))),
    r("POST", "/v1/fleet/heartbeat", ["instance"], (c) => engine.heartbeat(c.rec, c.body)),
    r("GET", "/v1/fleet", ["reader", "operator", "instance"], (c) => engine.fleet()),
    r("GET", "/v1/audit", ["reader", "operator"], (c) =>
      engine.auditPage(qInt(c, "after_seq", 0), qIntReq(c, "through_seq"), qInt(c, "limit", 100))),
    r("GET", "/v1/audit/checkpoint", ["reader", "operator"], (c) =>
      engine.checkpoint(qIntOpt(c, "through_seq"))),
    r("GET", "/v1/metrics", ["operator"], (c) => engine.metricsSnapshot()),
    r("GET", "/v1/readyz", ["operator"], (c) => engine.readyz(c.rec)),
  ];
}

function qInt(c: Ctx, name: string, dflt: number): number {
  const v = c.query.get(name);
  if (v === null) return dflt;
  if (!/^[0-9]+$/.test(v)) throw new CharterError("SCHEMA", `bad ${name}`);
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n > 2 ** 53 - 1) throw new CharterError("SCHEMA", `bad ${name}`);
  return n;
}

function qIntReq(c: Ctx, name: string): number {
  const v = c.query.get(name);
  if (v === null) throw new CharterError("SCHEMA", `missing ${name}`);
  return qInt(c, name, 0);
}

function qIntOpt(c: Ctx, name: string): number | null {
  return c.query.get(name) === null ? null : qInt(c, name, 0);
}

function paramInt(v: string, name: string): number {
  if (!/^[0-9]+$/.test(v)) throw new CharterError("SCHEMA", `bad ${name}`);
  const n = Number(v);
  if (!Number.isSafeInteger(n)) throw new CharterError("SCHEMA", `bad ${name}`);
  return n;
}

async function readBody(req: IncomingMessage, cap: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const ch of req) {
    const b = ch as Buffer;
    total += b.length;
    if (total > cap) throw new CharterError("LIMIT", "body exceeds cap");
    chunks.push(b);
  }
  return Buffer.concat(chunks);
}

function send(res: ServerResponse, status: number, body: Json, busy = false): void {
  const text = canonicalize(body) + "\n";
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(text),
    ...(busy ? { "retry-after": "1" } : {}),
  });
  res.end(text);
}

export function serve(engine: TenantEngine, port: number, host: string): Promise<Server> {
  const table = routes(engine);
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://local");
      if (url.search.length > QUERY_CAP) throw new CharterError("LIMIT", "query too long");
      const path = url.pathname;
      if (req.method === "GET" && path === "/healthz") {
        return send(res, 200, { status: "up", api: "charter.http/1" } as Json);
      }
      // Path-pattern match precedes method check: wrong method on a known
      // route → 405 SCHEMA with an Allow header listing valid methods.
      const candidates = table.filter((rt) => rt.pattern.test(path));
      const match = candidates.find((rt) => rt.method === req.method);
      if (candidates.length === 0) throw new CharterError("SCHEMA", "no such route");
      if (!match) {
        const allow = [...new Set(candidates.map((rt) => rt.method))].sort();
        res.setHeader("allow", allow.join(", "));
        throw new MethodNotAllowed();
      }

      const authz = req.headers.authorization;
      if (typeof authz !== "string" || !authz.startsWith("Bearer ")) {
        throw new CharterError("AUTH_REQUIRED");
      }
      const rec = engine.authenticate(authz.slice(7));
      if (!match.roles.includes(rec.role)) throw new CharterError("FORBIDDEN");

      let body: Json = null;
      if (req.method === "POST") {
        const raw = await readBody(req, match.bodyCap);
        body = parseJsonBytes(new Uint8Array(raw)) as Json;
      }
      const m = match.pattern.exec(path)!;
      const params: Record<string, string> = {};
      match.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]!); });
      const out = await match.handler({ engine, rec, params, query: url.searchParams, body });
      send(res, out.status, out.body);
    } catch (e) {
      const code = e instanceof CharterError ? e.code : "AUDIT_UNAVAILABLE";
      const status = e instanceof MethodNotAllowed ? 405 : statusFor(code);
      send(res, status, {
        error: { code, retryable: retryable(code), audit_seq: e instanceof CharterError ? e.auditSeq : null },
      } as Json, code === "BUSY");
    }
  });
  return new Promise((resolve) => {
    server.listen(port, host, () => resolve(server));
  });
}
