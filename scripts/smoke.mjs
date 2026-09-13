/** Live CLI smoke: boots a fixture world (state F) over real HTTP and runs
 * the `charter` binary with --json. Fixture material only — never production.
 * Usage: node scripts/smoke.mjs */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFileSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { World, fixtureAuth, fixtureConfig, ROLE_TOKEN, FIXTURE_KEYS } from "../test/harness.ts";
import * as fx from "../fixtures/corpus.ts";

const run_ = promisify(execFile);
const BIN = resolve("bin/charter");
const w = new World();
await w.toF();
await w.listen();

const dir = mkdtempSync(join(tmpdir(), "charter-smoke-"));
const cfg = fixtureConfig(w.base);
const yaml = Object.entries(cfg).map(([k, v]) => {
  if (Array.isArray(v)) return `${k}: [${v.map((x) => JSON.stringify(x)).join(", ")}]`;
  if (typeof v === "string") return `${k}: ${JSON.stringify(v)}`;
  return `${k}: ${v}`;
}).join("\n") + "\n";
const cfgPath = join(dir, "charter.yaml");
writeFileSync(cfgPath, yaml);
writeFileSync(join(dir, "trust.json"), fx.J(fx.ROOT));
writeFileSync(join(dir, "manifest.json"), fx.J(fx.M1));
writeFileSync(join(dir, "request.json"), fx.J(fx.Q1));
// `gateway check` consumes request_id crq_Q...; the call needs a distinct id.
const callReq = { ...fx.Q1, request_id: "crq_" + "S".repeat(21) };
writeFileSync(join(dir, "request-call.json"), fx.J(callReq));
writeFileSync(join(dir, "policy.json"), fx.J(fx.C1));
writeFileSync(join(dir, "policy2.json"), fx.J(fx.C2));
writeFileSync(join(dir, "bundle.json"), fx.J(fx.B1));

const env = {
  ...process.env,
  CHARTER_CLIENT_CREDENTIAL: ROLE_TOKEN.agent,
  CHARTER_AUTH_RECORDS: fx.J(fixtureAuth()),
  CHARTER_AUDIT_SEED: Buffer.from(fx.SEEDS[2], "hex").toString("base64url"),
  CHARTER_RESPONSE_KEYS: fx.J(FIXTURE_KEYS),
};

const base = [BIN, "--config", cfgPath, "--json"];
async function run(args, role = "agent") {
  let code = 0, stdout = "", stderr = "";
  const roleEnv = { ...env, CHARTER_CLIENT_CREDENTIAL: ROLE_TOKEN[role] };
  try {
    const r = await run_(process.execPath, [...base, ...args], { env: roleEnv });
    stdout = r.stdout; stderr = r.stderr;
  } catch (e) {
    code = e.code ?? 1; stdout = e.stdout ?? ""; stderr = e.stderr ?? "";
  }
  console.log(`\n$ charter ${args.join(" ")}   [exit ${code}, role=${role}]`);
  process.stdout.write(stdout);
  if (stderr) console.log(`stderr: ${stderr}`);
}

const head = w.auditHead();
await run(["config", "validate"]);
await run(["policy", "canonicalize", join(dir, "policy.json"), "--out", join(dir, "canon.json")]);
await run(["policy", "lint", join(dir, "policy.json"), "--manifest", join(dir, "manifest.json"), "--root", join(dir, "trust.json")]);
await run(["policy", "verify", join(dir, "bundle.json"), "--root", join(dir, "trust.json")]);
await run(["policy", "diff", join(dir, "policy.json"), join(dir, "policy2.json"), "--manifest", join(dir, "manifest.json")]);
await run(["policy", "versions"]);
await run(["policy", "fetch", "1", "--out", join(dir, "fetched.json")]);
await run(["policy", "cite", "1", fx.RA]);
await run(["gateway", "status"]);
await run(["gateway", "check", join(dir, "request.json")]);
await run(["gateway", "call", join(dir, "request-call.json")]);
await run(["gateway", "result", callReq.request_id]);
await run(["fleet", "status"], "operator");
await run(["revocations", "list"], "reader");
await run(["metrics"], "operator");
await run(["audit", "export", "--through-seq", String(w.auditHead()), "--out", join(dir, "evidence.ndjson")], "operator");
await run(["audit", "verify", join(dir, "evidence.ndjson"), "--root", join(dir, "trust.json")]);

console.log(`\n--- evidence.ndjson head ---`);
console.log(readFileSync(join(dir, "evidence.ndjson"), "utf-8").split("\n").slice(0, 3).join("\n"));
w.close();
