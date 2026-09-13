/** §1.1 scalar grammar: Int, Hash, Public, Signature, Time, Label, ToolName, Resource, ID<P>. */
import { CharterError } from "./errors.ts";

const RE_LABEL = /^[a-z][a-z0-9_-]{0,63}$/;
const RE_TOOL = /^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$/;
const RE_HASH = /^[0-9a-f]{64}$/;
const RE_PUBLIC = /^[0-9a-f]{64}$/;
const RE_ID_CHARS = /^[A-Za-z0-9_-]{21}$/;
const RE_SEGMENT = /^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$/;
const RE_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$/;
const RE_REPO = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;

export const ID_PREFIXES = ["cte", "cch", "cgw", "cin", "cpr", "cky", "ccr", "crq", "crl", "cds", "clg"] as const;
export type IdPrefix = (typeof ID_PREFIXES)[number];

export const MAX_SAFE = 9007199254740991;

export function isInt(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0);
}

export function isHash(v: unknown): v is string {
  return typeof v === "string" && RE_HASH.test(v);
}

export function isPublic(v: unknown): v is string {
  return typeof v === "string" && RE_PUBLIC.test(v);
}

export function isLabel(v: unknown): v is string {
  return typeof v === "string" && RE_LABEL.test(v);
}

export function isToolName(v: unknown): v is string {
  return typeof v === "string" && RE_TOOL.test(v);
}

/** Canonical unpadded base64url of exactly 64 bytes; decode/re-encode identical. */
export function isSignature(v: unknown): v is string {
  if (typeof v !== "string") return false;
  const raw = Buffer.from(v, "base64url");
  return raw.length === 64 && raw.toString("base64url") === v;
}

export function isResource(v: unknown): v is string {
  if (typeof v !== "string") return false;
  const bytes = Buffer.byteLength(v, "utf8");
  if (bytes < 1 || bytes > 512) return false;
  // ASCII only — excludes percent/backslash/colon/query/unicode by construction.
  if (!/^[\x21-\x7e]+$/.test(v)) return false;
  const segs = v.split("/");
  for (const s of segs) {
    if (!RE_SEGMENT.test(s)) return false;
    if (s === "." || s === "..") return false;
    if (s.includes("..")) {
      // Dot sequences inside a segment: only a leading-dot segment is forbidden by
      // RE_SEGMENT (first char class excludes '.'), and "." / ".." handled above.
    }
  }
  return true;
}

export function isId(v: unknown, prefix: IdPrefix): v is string {
  if (typeof v !== "string") return false;
  const head = prefix + "_";
  if (!v.startsWith(head)) return false;
  return RE_ID_CHARS.test(v.slice(head.length));
}

export function isTime(v: unknown): v is string {
  if (typeof v !== "string") return false;
  const m = RE_TIME.exec(v);
  if (!m) return false;
  const [, ys, mos, ds, hs, mis, ss, mss] = m;
  const y = +ys!, mo = +mos!, d = +ds!, h = +hs!, mi = +mis!, s = +ss!;
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59) return false;
  const ms = Date.UTC(y, mo - 1, d, h, mi, s, +mss!);
  if (Number.isNaN(ms)) return false;
  const dt = new Date(ms);
  return (
    dt.getUTCFullYear() === y && dt.getUTCMonth() === mo - 1 &&
    dt.getUTCDate() === d && dt.getUTCHours() === h &&
    dt.getUTCMinutes() === mi && dt.getUTCSeconds() === s
  );
}

export function timeMs(t: string): number {
  const m = RE_TIME.exec(t);
  if (!m) throw new CharterError("SCHEMA", "invalid Time");
  const [, ys, mos, ds, hs, mis, ss, mss] = m;
  return Date.UTC(+ys!, +mos! - 1, +ds!, +hs!, +mis!, +ss!, +mss!);
}

export function msTime(ms: number): string {
  if (!Number.isSafeInteger(ms) || ms < 0) throw new CharterError("SCHEMA", "ms out of range");
  const d = new Date(ms);
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${p(d.getUTCFullYear(), 4)}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}` +
    `T${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}.${p(d.getUTCMilliseconds(), 3)}Z`;
}

export function isRepository(v: unknown): v is string {
  return typeof v === "string" && RE_REPO.test(v);
}

export function isScalar(v: unknown): v is string | number | boolean {
  return typeof v === "string" || isInt(v) || typeof v === "boolean";
}

/** NFC check on a decoded string (§1.1: reject, never normalize). */
export function isNfc(s: string): boolean {
  return s === s.normalize("NFC");
}

export function utf8Bytes(s: string): number {
  return Buffer.byteLength(s, "utf8");
}

export function require(cond: unknown, detail: string): asserts cond {
  if (!cond) throw new CharterError("SCHEMA", detail);
}

export function requireInt(v: unknown, what: string): asserts v is number {
  if (!isInt(v)) throw new CharterError("SCHEMA", `${what}: not a safe nonnegative integer`);
}

export function requireHash(v: unknown, what: string): asserts v is string {
  if (!isHash(v)) throw new CharterError("SCHEMA", `${what}: not a 64-hex hash`);
}

export function requireStr(v: unknown, what: string): asserts v is string {
  if (typeof v !== "string" || !isNfc(v)) throw new CharterError("SCHEMA", `${what}: invalid string`);
}

export function makeId(prefix: IdPrefix, chars: string): string {
  const id = `${prefix}_${chars}`;
  if (!isId(id, prefix)) throw new CharterError("SCHEMA", `invalid ${prefix} id`);
  return id;
}
