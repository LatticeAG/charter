/**
 * Strict YAML 1.2 parser restricted to the charter/1 JSON scalar subset (§5.1):
 * one document, no aliases/anchors/merges/tags/directives/includes/interpolation,
 * no duplicate or non-string keys, no implicit timestamps or non-JSON
 * numeric/boolean forms. Comments and formatting are unsigned presentation.
 */
import { CharterError } from "../errors.ts";
import { isNfc, MAX_SAFE } from "../scalars.ts";
import type { Json } from "../types.ts";

const MAX_DEPTH = 16;
const MAX_MEMBERS = 256;
const MAX_ELEMENTS = 256;

function err(what: string, line?: number): never {
  throw new CharterError("PARSE", `yaml: ${what}${line !== undefined ? ` at line ${line}` : ""}`);
}

type Line = { indent: number; text: string; no: number };

/** True when text at pos starts a scalar-terminating colon (`:` + space/EOL/flow-delimiter). */
function isKeyColon(text: string, pos: number, flow: boolean): boolean {
  if (text.charCodeAt(pos) !== 0x3a) return false;
  const next = pos + 1 >= text.length ? -1 : text.charCodeAt(pos + 1);
  if (next === -1) return true;
  if (next === 0x20 || next === 0x09) return true;
  if (flow && (next === 0x2c || next === 0x7d || next === 0x5d)) return true;
  return false;
}

function hex4(text: string, pos: number, line: number): number {
  const t = text.slice(pos, pos + 4);
  if (t.length !== 4 || !/^[0-9a-fA-F]{4}$/.test(t)) err("bad \\u escape", line);
  return parseInt(t, 16);
}

/** Parse a double-quoted JSON string starting at pos (text.charCodeAt(pos) === '"'). */
function quoted(text: string, pos: number, line: number): [string, number] {
  let out = "";
  let i = pos + 1;
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (c === 0x22) return [out, i + 1];
    if (c === 0x5c) {
      const e = i + 1 < text.length ? text.charCodeAt(i + 1) : -1;
      switch (e) {
        case 0x22: out += '"'; i += 2; break;
        case 0x5c: out += "\\"; i += 2; break;
        case 0x2f: out += "/"; i += 2; break;
        case 0x62: out += "\b"; i += 2; break;
        case 0x66: out += "\f"; i += 2; break;
        case 0x6e: out += "\n"; i += 2; break;
        case 0x72: out += "\r"; i += 2; break;
        case 0x74: out += "\t"; i += 2; break;
        case 0x75: {
          const h1 = hex4(text, i + 2, line);
          i += 6;
          if (h1 >= 0xd800 && h1 <= 0xdbff) {
            if (text.charCodeAt(i) === 0x5c && text.charCodeAt(i + 1) === 0x75) {
              const h2 = hex4(text, i + 2, line);
              if (h2 >= 0xdc00 && h2 <= 0xdfff) {
                out += String.fromCharCode(h1, h2);
                i += 6;
              } else err("unpaired high surrogate", line);
            } else err("unpaired high surrogate", line);
          } else if (h1 >= 0xdc00 && h1 <= 0xdfff) {
            err("lone low surrogate", line);
          } else {
            out += String.fromCharCode(h1);
          }
          break;
        }
        default: err("bad escape", line);
      }
    } else {
      if (c < 0x20) err("raw control character", line);
      out += text[i];
      i++;
    }
  }
  err("unterminated string", line);
}

const RE_INT = /^(0|[1-9][0-9]*)$/;
const RE_NUMLIKE = /^[-+]?\d|^\.inf$|^\.nan$|^\.INF$|^\.NaN$|^0[xob]/i;
const RE_BOOLISH = /^(yes|no|on|off|true|false|null|~)$/i;
const RE_TIMESTAMP = /^\d{4}-\d{2}-\d{2}([Tt ]|\b)/;
const RE_PLAIN_BAD_START = /^[\[\]{},#&*!|>'"%@`?]/;

/** Classify a plain scalar text → Json. Non-JSON forms are PARSE failures. */
function scalarValue(text: string, line: number): Json {
  if (text === "null") return null;
  if (text === "true") return true;
  if (text === "false") return false;
  if (RE_INT.test(text)) {
    const n = Number(text);
    if (!Number.isSafeInteger(n) || n > MAX_SAFE) err("integer out of range", line);
    return n;
  }
  if (RE_NUMLIKE.test(text)) err("non-JSON numeric form", line);
  if (RE_BOOLISH.test(text)) err("non-JSON boolean/null form", line);
  if (RE_TIMESTAMP.test(text)) err("implicit timestamp", line);
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) < 0x20) err("control character in scalar", line);
  }
  return text;
}

export class YamlSubsetParser {
  private lines: Line[] = [];
  private pos = 0;

  parse(source: string): Json {
    if (source.length > 0 && source.charCodeAt(0) === 0xfeff) err("BOM");
    const rawLines = source.split(/\r\n|\r|\n/);
    for (let i = 0; i < rawLines.length; i++) {
      const raw = rawLines[i]!;
      const t = raw.trimStart();
      if (t.startsWith("%")) err("directive", i + 1);
      if (/^-{3}(\s|$)/.test(t) || /^\.{3}(\s|$)/.test(t)) err("document marker", i + 1);
      let indent = 0;
      while (indent < raw.length && raw.charCodeAt(indent) === 0x20) indent++;
      if (indent < raw.length && raw.charCodeAt(indent) === 0x09) err("tab indentation", i + 1);
      const content = raw.slice(indent);
      if (content === "" || content.startsWith("#")) continue; // blank / comment
      this.lines.push({ indent, text: content, no: i + 1 });
    }
    if (this.lines.length === 0) err("empty document");
    const v = this.block(this.lines[0]!.indent, 1);
    if (this.pos < this.lines.length) {
      err("unexpected trailing content", this.lines[this.pos]!.no);
    }
    checkNfc(v);
    return v;
  }

  /** Parse a block node whose lines sit at the given indent. */
  private block(indent: number, depth: number): Json {
    if (depth > MAX_DEPTH) err("depth > 16", this.lines[this.pos]?.no);
    const line = this.lines[this.pos];
    if (!line || line.indent !== indent) err("bad indentation", line?.no);
    if (line.text === "-" || line.text.startsWith("- ")) return this.sequence(indent, depth);
    return this.mapping(indent, depth, undefined);
  }

  /** Find the key/value split colon of a mapping entry, or -1. */
  private keyColon(text: string, line: number): number {
    let i = 0;
    if (text.charCodeAt(0) === 0x22) {
      const [, end] = quoted(text, 0, line);
      i = end;
      while (i < text.length && text.charCodeAt(i) === 0x20) i++;
      return i < text.length && text.charCodeAt(i) === 0x3a &&
        (i + 1 >= text.length || text.charCodeAt(i + 1) === 0x20) ? i : -1;
    }
    if (text.charCodeAt(0) === 0x3f && (text.length === 1 || text.charCodeAt(1) === 0x20)) {
      err("complex key", line);
    }
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 0x20 && i + 1 < text.length && text.charCodeAt(i + 1) === 0x23) return -1; // " #" comment
      if (isKeyColon(text, i, false)) return i;
      if (c === 0x3a) return -1; // colon not followed by space — not a key split
      i++;
    }
    return -1;
  }

  private mapping(indent: number, depth: number, firstText: string | undefined): Json {
    const obj: Record<string, Json> = {};
    let first = firstText;
    for (;;) {
      let text: string;
      let no: number;
      if (first !== undefined) {
        text = first;
        no = this.lines[this.pos - 1]?.no ?? 0;
        first = undefined;
      } else {
        const line = this.lines[this.pos];
        if (!line || line.indent !== indent || line.text === "-" || line.text.startsWith("- ")) break;
        text = line.text;
        no = line.no;
        this.pos++;
      }
      const split = this.keyColon(text, no);
      if (split < 0) err("expected key: entry", no);
      const keyText = text.slice(0, split).trimEnd();
      let key: string;
      if (keyText.charCodeAt(0) === 0x22) {
        const [k] = quoted(keyText, 0, no);
        key = k;
      } else {
        const kv = scalarValue(keyText, no);
        if (typeof kv !== "string") err("non-string key", no);
        key = kv;
      }
      if (Object.prototype.hasOwnProperty.call(obj, key)) err("duplicate key", no);
      const rest = text.slice(split + 1);
      const value = this.valueAfterKey(rest, indent, depth, no);
      obj[key] = value;
      if (Object.keys(obj).length > MAX_MEMBERS) err("object members > 256", no);
    }
    return obj;
  }

  private sequence(indent: number, depth: number): Json {
    const arr: Json[] = [];
    for (;;) {
      const line = this.lines[this.pos];
      if (!line || line.indent !== indent) break;
      if (!(line.text === "-" || line.text.startsWith("- "))) break;
      this.pos++;
      const rest = line.text === "-" ? "" : line.text.slice(2);
      if (rest === "" || rest.trimStart().startsWith("#")) {
        // Nested block: deeper indent, or a seq at the same effective column.
        const next = this.lines[this.pos];
        if (next && next.indent > indent) {
          arr.push(this.block(next.indent, depth + 1));
        } else if (next && next.indent === indent &&
                   (next.text === "-" || next.text.startsWith("- "))) {
          // `-` then sibling `-` items: empty item → null
          arr.push(null);
        } else {
          arr.push(null);
        }
      } else {
        const trimmed = rest.trimStart();
        const innerIndent = indent + 2 + (rest.length - trimmed.length);
        const innerColon = trimmed.startsWith("[") || trimmed.startsWith("{") || trimmed.startsWith('"')
          ? -1 : this.keyColon(trimmed, line.no);
        if (innerColon >= 0) {
          // `- key: value` — inline mapping whose siblings align at innerIndent
          const m = this.mapping(innerIndent, depth + 1, trimmed);
          arr.push(m);
        } else if (trimmed === "-" || trimmed.startsWith("- ")) {
          // `- - nested` block sequences are outside the strict subset.
          err("nested block sequence on same line", line.no);
        } else {
          arr.push(this.inline(trimmed, line.no, depth + 1, false));
        }
      }
      if (arr.length > MAX_ELEMENTS) err("array elements > 256", line.no);
    }
    return arr;
  }

  /** Value after `key:` — either inline on the same line or a nested block. */
  private valueAfterKey(rest: string, indent: number, depth: number, no: number): Json {
    const trimmed = rest.trimStart();
    if (trimmed === "" || trimmed.startsWith("#")) {
      const next = this.lines[this.pos];
      if (next && next.indent > indent) return this.block(next.indent, depth + 1);
      if (next && next.indent === indent && (next.text === "-" || next.text.startsWith("- "))) {
        return this.sequence(indent, depth + 1);
      }
      return null;
    }
    return this.inlineValue(trimmed, no, depth + 1);
  }

  /** Parse a complete inline value that must consume the whole text (block context). */
  private inlineValue(text: string, no: number, depth: number): Json {
    const [v, pos] = this.flow(text, 0, no, depth, false);
    // remainder may only be whitespace then optional comment
    const rest = text.slice(pos);
    if (!/^(\s*#.*)?\s*$/.test(rest) && rest.trim() !== "" && !rest.trimStart().startsWith("#")) {
      err("trailing content after value", no);
    }
    return v;
  }

  private inline(text: string, no: number, depth: number, flow: boolean): Json {
    const [v] = this.flow(text, 0, no, depth, flow);
    return v;
  }

  /** Flow/block scalar or collection at pos → [value, nextPos]. */
  private flow(text: string, pos: number, line: number, depth: number, inFlow: boolean): [Json, number] {
    if (depth > MAX_DEPTH) err("depth > 16", line);
    while (pos < text.length && (text.charCodeAt(pos) === 0x20 || text.charCodeAt(pos) === 0x09)) pos++;
    if (pos >= text.length) err("missing value", line);
    const c = text.charCodeAt(pos);
    if (c === 0x5b) return this.flowSeq(text, pos + 1, line, depth);
    if (c === 0x7b) return this.flowMap(text, pos + 1, line, depth);
    if (c === 0x22) return quoted(text, pos, line);
    if (c === 0x27) err("single-quoted string", line);
    if (c === 0x26) err("anchor", line);
    if (c === 0x2a) err("alias", line);
    if (c === 0x21) err("tag", line);
    if (c === 0x7c || c === 0x3e) err("block scalar", line);
    if (c === 0x23) err("missing value", line);
    // plain scalar
    let end = pos;
    for (;;) {
      if (end >= text.length) break;
      const ch = text.charCodeAt(end);
      if (ch === 0x20 && end + 1 < text.length && text.charCodeAt(end + 1) === 0x23) break; // " #"
      if (inFlow && (ch === 0x2c || ch === 0x7d || ch === 0x5d)) break;
      if (isKeyColon(text, end, inFlow)) break;
      if (ch === 0x3a && !isKeyColon(text, end, inFlow)) {
        // colon inside plain scalar (e.g. env:NAME) — allowed
      }
      end++;
      if (!inFlow && end < text.length && text.charCodeAt(end) === 0x23 &&
          text.charCodeAt(end - 1) !== 0x20) {
        // '#' inside a plain scalar without preceding space is literal; continue
      }
    }
    const raw = text.slice(pos, end).replace(/\s+$/, "");
    if (raw === "") err("missing value", line);
    if (RE_PLAIN_BAD_START.test(raw)) err("bad scalar start", line);
    return [scalarValue(raw, line), end];
  }

  private flowSeq(text: string, pos: number, line: number, depth: number): [Json, number] {
    const arr: Json[] = [];
    let p = pos;
    for (;;) {
      p = this.skipWsComment(text, p, line);
      if (p >= text.length) err("unterminated [", line);
      if (text.charCodeAt(p) === 0x5d) return [arr, p + 1];
      const [v, np] = this.flow(text, p, line, depth + 1, true);
      arr.push(v);
      if (arr.length > MAX_ELEMENTS) err("array elements > 256", line);
      p = this.skipWsComment(text, np, line);
      if (p >= text.length) err("unterminated [", line);
      const c = text.charCodeAt(p);
      if (c === 0x2c) { p++; continue; }
      if (c === 0x5d) return [arr, p + 1];
      err("expected , or ]", line);
    }
  }

  private flowMap(text: string, pos: number, line: number, depth: number): [Json, number] {
    const obj: Record<string, Json> = {};
    let p = pos;
    for (;;) {
      p = this.skipWsComment(text, p, line);
      if (p >= text.length) err("unterminated {", line);
      if (text.charCodeAt(p) === 0x7d) return [obj, p + 1];
      // key
      let key: string;
      if (text.charCodeAt(p) === 0x22) {
        const [k, np] = quoted(text, p, line);
        key = k;
        p = np;
      } else {
        let end = p;
        while (end < text.length && !isKeyColon(text, end, true)) end++;
        const raw = text.slice(p, end).trim();
        const kv = scalarValue(raw, line);
        if (typeof kv !== "string") err("non-string key", line);
        key = kv;
        p = end;
      }
      p = this.skipWsComment(text, p, line);
      if (p >= text.length || text.charCodeAt(p) !== 0x3a) err("expected :", line);
      p++;
      const [v, np] = this.flow(text, p, line, depth + 1, true);
      if (Object.prototype.hasOwnProperty.call(obj, key)) err("duplicate key", line);
      obj[key] = v;
      if (Object.keys(obj).length > MAX_MEMBERS) err("object members > 256", line);
      p = this.skipWsComment(text, np, line);
      if (p >= text.length) err("unterminated {", line);
      const c = text.charCodeAt(p);
      if (c === 0x2c) { p++; continue; }
      if (c === 0x7d) return [obj, p + 1];
      err("expected , or }", line);
    }
  }

  private skipWsComment(text: string, pos: number, line: number): number {
    let p = pos;
    for (;;) {
      while (p < text.length && (text.charCodeAt(p) === 0x20 || text.charCodeAt(p) === 0x09)) p++;
      if (p < text.length && text.charCodeAt(p) === 0x23) err("comment inside flow collection", line);
      return p;
    }
  }
}

function checkNfc(v: Json): void {
  if (typeof v === "string") {
    if (!isNfc(v)) throw new CharterError("SCHEMA", "yaml: non-NFC string");
    return;
  }
  if (Array.isArray(v)) {
    for (const x of v) checkNfc(x);
    return;
  }
  if (v !== null && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) {
      if (!isNfc(k)) throw new CharterError("SCHEMA", "yaml: non-NFC member name");
      checkNfc(x);
    }
  }
}

/** Parse one strict YAML-subset document → Json. */
export function parseYamlSubset(source: string): Json {
  return new YamlSubsetParser().parse(source);
}
