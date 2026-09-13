/** TV-C-63/64 — real `charter` binary subprocess tests over live HTTP. */
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import * as fx from "../fixtures/corpus.ts";
import { World, fixtureAuth, fixtureConfig, ROLE_TOKEN, FIXTURE_KEYS } from "./harness.ts";
import type { Json } from "../src/types.ts";

const run = promisify(execFile);
const BIN = resolve("bin/charter");

function envFor(config: { environment: string }): Record<string, string> {
  return {
    ...process.env as Record<string, string>,
    CHARTER_CLIENT_CREDENTIAL: ROLE_TOKEN.agent ?? "",
    CHARTER_AUTH_RECORDS: fx.J(fixtureAuth()),
    CHARTER_AUDIT_SEED: Buffer.from(fx.SEEDS[2] ?? "", "hex").toString("base64url"),
    CHARTER_RESPONSE_KEYS: fx.J(FIXTURE_KEYS),
  };
}

function writeFixtureDir(dir: string, cfg: Json): string {
  writeFileSync(join(dir, "charter.yaml"), toYaml(cfg));
  writeFileSync(join(dir, "trust.json"), fx.J(fx.ROOT));
  writeFileSync(join(dir, "manifest.json"), fx.J(fx.M1));
  return join(dir, "charter.yaml");
}

/** Minimal YAML emitter for the flat §5.2 config shape. */
function toYaml(c: Json): string {
  const o = c as Record<string, Json>;
  return Object.entries(o).map(([k, v]) => {
    if (Array.isArray(v)) return `${k}: [${v.map((x) => JSON.stringify(x)).join(", ")}]`;
    if (typeof v === "string") return `${k}: ${JSON.stringify(v)}`;
    return `${k}: ${String(v)}`;
  }).join("\n") + "\n";
}

test("TV-C-63 CLI machine contract", async () => {
  const w = await worldForCli();
  const dir = mkdtempSync(join(tmpdir(), "charter-cli-"));
  try {
    const cfg = fixtureConfig(w.base) as unknown as Json;
    const cfgPath = writeFixtureDir(dir, cfg);
    writeFileSync(join(dir, "request.json"), fx.J(fx.Q1));
    const { stdout, stderr } = await run(process.execPath, [BIN, "--config", cfgPath, "--json", "gateway", "check", join(dir, "request.json")], { env: envFor(cfg as { environment: string }) });
    assert.equal(stdout, fx.J({ decision: fx.ALLOW, input_hash: fx.IH1, enforcement: false, audit_seq: 4 }) + "\n");
    assert.equal(stderr, "");
  } finally { w.close(); rmSync(dir, { recursive: true, force: true }); }
});

async function worldForCli(): Promise<World> {
  const w = new World();
  await w.toF();
  await w.listen();
  return w;
}

test("TV-C-64 public fixture keys cannot run production", async () => {
  const dir = mkdtempSync(join(tmpdir(), "charter-cli-"));
  try {
    const cfg = { ...fixtureConfig(), environment: "production", endpoint: "https://charter.example.test" } as unknown as Json;
    const cfgPath = writeFixtureDir(dir, cfg);
    try {
      await run(process.execPath, [BIN, "--config", cfgPath, "--json", "config", "validate"], { env: envFor(cfg as { environment: string }) });
      assert.fail("expected exit 2");
    } catch (e) {
      const err = e as { code: number; stdout: string; stderr: string };
      assert.equal(err.code, 2);
      const out = JSON.parse(err.stdout) as { error: { code: string } };
      assert.equal(out.error.code, "SCHEMA");
      // rejection must not print private key material
      assert.ok(!err.stdout.includes(fx.SEEDS[2]!));
      assert.ok(!err.stderr.includes(fx.SEEDS[2]!));
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
