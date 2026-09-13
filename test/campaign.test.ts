/** §11.3 supplementary adversarial campaigns — cross-language differential.
 * Runs the deterministic seeded generators in TS and Python at the spec's
 * mandatory counts and asserts the rolling digests are identical. */
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TIMEOUT = 300_000;

function run(file: string, mode: string, count: number, fixture: string): string {
  const cmd = file.endsWith(".py") ? "python3" : process.execPath;
  return execFileSync(cmd, [file, mode, String(count), fixture],
    { cwd: process.cwd(), encoding: "utf-8", timeout: TIMEOUT }).trim();
}

test("§11.3 campaigns: TS/Python produce identical result streams", { timeout: TIMEOUT }, () => {
  const dir = mkdtempSync(join(tmpdir(), "charter-campaign-"));
  try {
    const fixture = join(dir, "fixtures.json");
    execFileSync(process.execPath, ["test/dump-fixtures.mjs", fixture]);
    for (const [mode, count] of [["canon", 100_000], ["parse", 100_000], ["eval", 10_000]] as const) {
      const ts = run("test/campaign.mjs", mode, count, fixture);
      const py = run("test/campaign.py", mode, count, fixture);
      assert.equal(ts, py, `${mode} diverged: TS=${ts} PY=${py}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
