/** RFC 8785 canonical JSON serialization over the charter/1 validated subset. */
import { CharterError } from "../errors.ts";
import { isInt, isNfc } from "../scalars.ts";
import type { Json } from "../types.ts";

function fail(what: string): never {
  throw new CharterError("SCHEMA", `canonicalize: ${what}`);
}

function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (i + 1 >= s.length || n < 0xdc00 || n > 0xdfff) return true;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/** J(x): canonical UTF-8 text. Keys sorted by UTF-16 code-unit order (JS default). */
export function canonicalize(x: Json): string {
  if (x === null) return "null";
  const t = typeof x;
  if (t === "boolean") return x === true ? "true" : "false";
  if (t === "number") {
    const n = x as number;
    if (!isInt(n)) fail("number outside Int grammar");
    return String(n);
  }
  if (t === "string") {
    const s = x as string;
    if (!isNfc(s)) fail("non-NFC string");
    if (hasLoneSurrogate(s)) fail("lone surrogate");
    return JSON.stringify(s);
  }
  if (Array.isArray(x)) {
    return "[" + x.map(canonicalize).join(",") + "]";
  }
  if (t === "object") {
    const o = x as Record<string, Json>;
    const keys = Object.keys(o).sort(); // UTF-16 code-unit order
    const parts: string[] = [];
    for (const k of keys) {
      const v = o[k];
      if (v === undefined) fail(`undefined member ${k}`);
      if (!isNfc(k) || hasLoneSurrogate(k)) fail(`invalid member name ${JSON.stringify(k)}`);
      parts.push(JSON.stringify(k) + ":" + canonicalize(v));
    }
    return "{" + parts.join(",") + "}";
  }
  fail(`unsupported value type ${t}`);
}

/** J(x) as bytes. */
export function canonicalBytes(x: Json): Uint8Array {
  return new TextEncoder().encode(canonicalize(x));
}

/** Structural deep-equality on canonical values. */
export function jsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null) return false;
  if (Array.isArray(a)) {
    if (!Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => jsonEqual(v, b[i]));
  }
  if (typeof a === "object") {
    const ao = a as Record<string, unknown>;
    const bo = b as Record<string, unknown>;
    const ak = Object.keys(ao);
    const bk = Object.keys(bo);
    if (ak.length !== bk.length) return false;
    return ak.every((k) => k in bo && jsonEqual(ao[k], bo[k]));
  }
  return false;
}
