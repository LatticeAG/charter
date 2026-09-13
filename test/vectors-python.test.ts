/** Cross-language conformance: run the §11.1 corpus through the Python SDK
 * and compare every function result against the fixture oracles. */
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as fx from "../fixtures/corpus.ts";

test("Python SDK reproduces the §11.1 corpus", () => {
  const dir = mkdtempSync(join(tmpdir(), "charter-py-"));
  try {
    const fixturePath = join(dir, "fixtures.json");
    execFileSync(process.execPath, ["test/dump-fixtures.mjs", fixturePath]);
    const raw = execFileSync("python3", ["test/differential.py", fixturePath],
      { cwd: process.cwd(), encoding: "utf-8", maxBuffer: 64 * 1024 * 1024 });
    const out = JSON.parse(raw) as Record<string, unknown>;

    assert.deepEqual(out["parse_policy"], JSON.parse(fx.J(fx.C1)));
    assert.equal(out["canonicalize_C1"], fx.J(fx.C1));
    assert.equal(out["digest_policy_C1"], fx.H1);
    assert.equal(out["digest_manifest_M1"], fx.MH);
    assert.deepEqual(out["verify_bundle_B1"], JSON.parse(fx.J(fx.VALID1)));
    assert.deepEqual(out["compile"], { policy_hash: fx.H1, manifest_hash: fx.MH, engine: "charter.eval/1" });
    assert.deepEqual(out["evaluate_EI1"], JSON.parse(fx.J(fx.ALLOW)));
    assert.deepEqual(out["cite"], JSON.parse(fx.J(fx.CITE1)));
    assert.deepEqual(out["diff_same"], { old_hash: fx.H1, new_hash: fx.H1, changes: [] });
    assert.deepEqual(out["sign_policy_fixture0"], JSON.parse(fx.J(fx.B1.signatures[0])));
    assert.deepEqual(out["verify_evidence_EV1"], JSON.parse(fx.J(fx.VERIFY1)));
    assert.equal(out["pub0"], "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    assert.equal(out["sig_empty"], fx.RFC_SIG);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
