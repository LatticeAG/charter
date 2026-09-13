/**
 * Strict JSON parser for the charter/1 wire grammar (§1.1).
 * Rejects: invalid UTF-8, BOM, trailing bytes, duplicate members, fractions,
 * exponents, -0, negative/out-of-range integers, lone surrogates, depth > 16,
 * >256 members per object, >256 array elements. Post-pass rejects non-NFC
 * strings as SCHEMA (lexical failures are PARSE).
 */
import { CharterError } from "../errors.ts";
import { isNfc, MAX_SAFE } from "../scalars.ts";
import type { Json } from "../types.ts";

const MAX_DEPTH = 16;
const MAX_MEMBERS = 256;
const MAX_ELEMENTS = 256;

class P {
  s: string;
  i = 0;
  constructor(s: string) {
    this.s = s;
  }
  err(what: string): never {
    throw new CharterError("PARSE", `json: ${what} at offset ${this.i}`);
  }
  ws(): void {
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }
  peek(): number {
    return this.i < this.s.length ? this.s.charCodeAt(this.i) : -1;
  }
  value(depth: number): Json {
    if (depth > MAX_DEPTH) this.err("depth > 16");
    this.ws();
    const c = this.peek();
    if (c === 0x7b) return this.object(depth);
    if (c === 0x5b) return this.array(depth);
    if (c === 0x22) return this.string();
    if (c === 0x74) return this.lit("true", true);
    if (c === 0x66) return this.lit("false", false);
    if (c === 0x6e) return this.lit("null", null);
    if (c >= 0x30 && c <= 0x39) return this.number();
    this.err("unexpected token");
  }
  lit(word: string, v: Json): Json {
    if (this.s.slice(this.i, this.i + word.length) !== word) this.err("bad literal");
    this.i += word.length;
    return v;
  }
  number(): number {
    const start = this.i;
    if (this.s.charCodeAt(this.i) === 0x30) {
      this.i++;
      // leading zero: next char must not be a digit
      if (this.peek() >= 0x30 && this.peek() <= 0x39) this.err("leading zero");
    } else {
      while (this.peek() >= 0x30 && this.peek() <= 0x39) this.i++;
    }
    const c = this.peek();
    if (c === 0x2e || c === 0x65 || c === 0x45 || c === 0x2b || c === 0x2d) {
      this.err("non-integer numeric token");
    }
    const text = this.s.slice(start, this.i);
    const n = Number(text);
    if (!Number.isSafeInteger(n) || n < 0 || n > MAX_SAFE) this.err("integer out of range");
    return n;
  }
  string(): string {
    this.i++; // consume "
    let out = "";
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x22) {
        this.i++;
        return out;
      }
      if (c === 0x5c) {
        this.i++;
        const e = this.peek();
        switch (e) {
          case 0x22: out += '"'; this.i++; break;
          case 0x5c: out += "\\"; this.i++; break;
          case 0x2f: out += "/"; this.i++; break;
          case 0x62: out += "\b"; this.i++; break;
          case 0x66: out += "\f"; this.i++; break;
          case 0x6e: out += "\n"; this.i++; break;
          case 0x72: out += "\r"; this.i++; break;
          case 0x74: out += "\t"; this.i++; break;
          case 0x75: {
            this.i++;
            const h1 = this.hex4();
            if (h1 >= 0xd800 && h1 <= 0xdbff) {
              // high surrogate must be followed by \uDC00-\uDFFF
              if (this.s.charCodeAt(this.i) === 0x5c && this.s.charCodeAt(this.i + 1) === 0x75) {
                this.i += 2;
                const h2 = this.hex4();
                if (h2 >= 0xdc00 && h2 <= 0xdfff) {
                  out += String.fromCharCode(h1, h2);
                } else {
                  this.err("unpaired high surrogate");
                }
              } else {
                this.err("unpaired high surrogate");
              }
            } else if (h1 >= 0xdc00 && h1 <= 0xdfff) {
              this.err("lone low surrogate");
            } else {
              out += String.fromCharCode(h1);
            }
            break;
          }
          default:
            this.err("bad escape");
        }
      } else {
        if (c < 0x20) this.err("raw control character");
        out += this.s[this.i];
        this.i++;
      }
    }
    this.err("unterminated string");
  }
  hex4(): number {
    const t = this.s.slice(this.i, this.i + 4);
    if (t.length !== 4 || !/^[0-9a-fA-F]{4}$/.test(t)) this.err("bad \\u escape");
    this.i += 4;
    return parseInt(t, 16);
  }
  object(depth: number): Json {
    this.i++; // {
    const obj: Record<string, Json> = {};
    this.ws();
    if (this.peek() === 0x7d) {
      this.i++;
      return obj;
    }
    for (;;) {
      this.ws();
      if (this.peek() !== 0x22) this.err("object key must be string");
      const k = this.string();
      if (Object.prototype.hasOwnProperty.call(obj, k)) this.err("duplicate member");
      this.ws();
      if (this.peek() !== 0x3a) this.err("expected :");
      this.i++;
      obj[k] = this.value(depth + 1);
      const count = Object.keys(obj).length;
      if (count > MAX_MEMBERS) this.err("object members > 256");
      this.ws();
      const c = this.peek();
      if (c === 0x2c) {
        this.i++;
        continue;
      }
      if (c === 0x7d) {
        this.i++;
        return obj;
      }
      this.err("expected , or }");
    }
  }
  array(depth: number): Json {
    this.i++; // [
    const arr: Json[] = [];
    this.ws();
    if (this.peek() === 0x5d) {
      this.i++;
      return arr;
    }
    for (;;) {
      arr.push(this.value(depth + 1));
      if (arr.length > MAX_ELEMENTS) this.err("array elements > 256");
      this.ws();
      const c = this.peek();
      if (c === 0x2c) {
        this.i++;
        continue;
      }
      if (c === 0x5d) {
        this.i++;
        return arr;
      }
      this.err("expected , or ]");
    }
  }
}

function checkNfc(v: Json): void {
  if (typeof v === "string") {
    if (!isNfc(v)) throw new CharterError("SCHEMA", "json: non-NFC string");
    return;
  }
  if (Array.isArray(v)) {
    for (const x of v) checkNfc(x);
    return;
  }
  if (v !== null && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) {
      if (!isNfc(k)) throw new CharterError("SCHEMA", "json: non-NFC member name");
      checkNfc(x);
    }
  }
}

/** Parse strict JSON bytes → Json. Throws CharterError(PARSE|SCHEMA). */
export function parseJsonBytes(bytes: Uint8Array): Json {
  let s: string;
  try {
    s = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new CharterError("PARSE", "json: invalid UTF-8");
  }
  return parseJsonText(s);
}

/** Parse a strict JSON string (or UTF-8 bytes, e.g. a SQLite BLOB) → Json. */
export function parseJsonText(s: string | Uint8Array): Json {
  if (typeof s !== "string") {
    try {
      s = new TextDecoder("utf-8", { fatal: true }).decode(s);
    } catch {
      throw new CharterError("PARSE", "json: invalid UTF-8");
    }
  }
  if (s.length > 0 && s.charCodeAt(0) === 0xfeff) {
    throw new CharterError("PARSE", "json: BOM");
  }
  const p = new P(s);
  const v = p.value(1);
  p.ws();
  if (p.i !== s.length) throw new CharterError("PARSE", "json: trailing bytes");
  checkNfc(v);
  return v;
}
