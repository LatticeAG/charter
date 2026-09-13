/** §3.7 diff: RFC 6901 pointers, byte-ordered changes, whole-array granularity. */
import { digest } from "../crypto/digest.ts";
import { jsonEqual } from "../json/jcs.ts";
import type { Diff, Json, Policy } from "../types.ts";

function escapePointer(seg: string): string {
  return seg.replace(/~/g, "~0").replace(/\//g, "~1");
}

function walk(base: string, a: Json, b: Json, out: { pointer: string; before: Json; after: Json }[]): void {
  if (jsonEqual(a, b)) return;
  const aObj = a !== null && typeof a === "object" && !Array.isArray(a);
  const bObj = b !== null && typeof b === "object" && !Array.isArray(b);
  if (aObj && bObj) {
    const ao = a as Record<string, Json>;
    const bo = b as Record<string, Json>;
    const keys = new Set([...Object.keys(ao), ...Object.keys(bo)]);
    for (const k of [...keys].sort()) {
      const p = base + "/" + escapePointer(k);
      const av = k in ao ? ao[k]! : null;
      const bv = k in bo ? bo[k]! : null;
      if (!(k in ao) || !(k in bo)) {
        out.push({ pointer: p, before: av, after: bv });
      } else {
        walk(p, av, bv, out);
      }
    }
    return;
  }
  // Arrays compare whole; scalars compare directly.
  out.push({ pointer: base === "" ? "" : base, before: a, after: b });
}

export function diff(old_policy: Policy, new_policy: Policy): Diff {
  const changes: { pointer: string; before: Json; after: Json }[] = [];
  walk("", old_policy as unknown as Json, new_policy as unknown as Json, changes);
  const byteCmp = (x: string, y: string) => Buffer.compare(Buffer.from(x, "utf8"), Buffer.from(y, "utf8"));
  changes.sort((x, y) => byteCmp(x.pointer, y.pointer));
  return {
    old_hash: digest("policy", old_policy),
    new_hash: digest("policy", new_policy),
    changes,
  };
}
