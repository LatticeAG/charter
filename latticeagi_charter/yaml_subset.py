"""Strict YAML 1.2 parser restricted to the charter/1 JSON scalar subset (§5.1):
one document, no aliases/anchors/merges/tags/directives/includes/interpolation,
no duplicate or non-string keys, no implicit timestamps or non-JSON
numeric/boolean forms. Comments and formatting are unsigned presentation.
"""
import re

from .errors import CharterError
from .scalars import is_nfc, MAX_SAFE

MAX_DEPTH = 16
MAX_MEMBERS = 256
MAX_ELEMENTS = 256

RE_INT = re.compile(r"^(0|[1-9][0-9]*)$")
RE_NUMLIKE = re.compile(r"^[-+]?\d|^\.inf$|^\.nan$|^\.INF$|^\.NaN$|^0[xob]", re.I)
RE_BOOLISH = re.compile(r"^(yes|no|on|off|true|false|null|~)$", re.I)
RE_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}([Tt ]|\b)")
RE_PLAIN_BAD_START = re.compile(r"^[\[\]{},#&*!|>'\"%@`?]")


def _err(what, line=None):
    raise CharterError("PARSE", f"yaml: {what}" + (f" at line {line}" if line is not None else ""))


def _is_key_colon(text, pos, flow):
    if pos >= len(text) or ord(text[pos]) != 0x3A:
        return False
    nxt = ord(text[pos + 1]) if pos + 1 < len(text) else -1
    if nxt == -1 or nxt in (0x20, 0x09):
        return True
    if flow and nxt in (0x2C, 0x7D, 0x5D):
        return True
    return False


def _hex4(text, pos, line):
    t = text[pos:pos + 4]
    if len(t) != 4 or not re.match(r"^[0-9a-fA-F]{4}$", t):
        _err("bad \\u escape", line)
    return int(t, 16)


def _quoted(text, pos, line):
    """Parse a double-quoted JSON string starting at pos → (str, nextPos)."""
    out = []
    i = pos + 1
    while i < len(text):
        c = ord(text[i])
        if c == 0x22:
            return "".join(out), i + 1
        if c == 0x5C:
            e = ord(text[i + 1]) if i + 1 < len(text) else -1
            if e == 0x22:
                out.append('"'); i += 2
            elif e == 0x5C:
                out.append("\\"); i += 2
            elif e == 0x2F:
                out.append("/"); i += 2
            elif e == 0x62:
                out.append("\b"); i += 2
            elif e == 0x66:
                out.append("\f"); i += 2
            elif e == 0x6E:
                out.append("\n"); i += 2
            elif e == 0x72:
                out.append("\r"); i += 2
            elif e == 0x74:
                out.append("\t"); i += 2
            elif e == 0x75:
                h1 = _hex4(text, i + 2, line)
                i += 6
                if 0xD800 <= h1 <= 0xDBFF:
                    if i + 1 < len(text) and text[i] == "\\" and text[i + 1] == "u":
                        h2 = _hex4(text, i + 2, line)
                        if 0xDC00 <= h2 <= 0xDFFF:
                            out.append(chr(0x10000 + ((h1 - 0xD800) << 10) + h2 - 0xDC00))
                            i += 6
                        else:
                            _err("unpaired high surrogate", line)
                    else:
                        _err("unpaired high surrogate", line)
                elif 0xDC00 <= h1 <= 0xDFFF:
                    _err("lone low surrogate", line)
                else:
                    out.append(chr(h1))
            else:
                _err("bad escape", line)
        else:
            if c < 0x20:
                _err("raw control character", line)
            out.append(text[i])
            i += 1
    _err("unterminated string", line)


def _scalar_value(text, line):
    if text == "null":
        return None
    if text == "true":
        return True
    if text == "false":
        return False
    if RE_INT.match(text):
        n = int(text)
        if n > MAX_SAFE:
            _err("integer out of range", line)
        return n
    if RE_NUMLIKE.match(text):
        _err("non-JSON numeric form", line)
    if RE_BOOLISH.match(text):
        _err("non-JSON boolean/null form", line)
    if RE_TIMESTAMP.match(text):
        _err("implicit timestamp", line)
    for ch in text:
        if ord(ch) < 0x20:
            _err("control character in scalar", line)
    return text


class _Parser:
    def __init__(self):
        self.lines = []  # (indent, text, lineno)
        self.pos = 0

    def parse(self, source):
        if source and ord(source[0]) == 0xFEFF:
            _err("BOM")
        for i, raw in enumerate(re.split(r"\r\n|\r|\n", source)):
            t = raw.lstrip()
            if t.startswith("%"):
                _err("directive", i + 1)
            if re.match(r"^-{3}(\s|$)", t) or re.match(r"^\.{3}(\s|$)", t):
                _err("document marker", i + 1)
            indent = 0
            while indent < len(raw) and raw[indent] == " ":
                indent += 1
            if indent < len(raw) and raw[indent] == "\t":
                _err("tab indentation", i + 1)
            content = raw[indent:]
            if content == "" or content.startswith("#"):
                continue
            self.lines.append((indent, content, i + 1))
        if not self.lines:
            _err("empty document")
        v = self._block(self.lines[0][0], 1)
        if self.pos < len(self.lines):
            _err("unexpected trailing content", self.lines[self.pos][2])
        _check_nfc(v)
        return v

    def _block(self, indent, depth):
        if depth > MAX_DEPTH:
            _err("depth > 16", self.lines[self.pos][2] if self.pos < len(self.lines) else None)
        if self.pos >= len(self.lines) or self.lines[self.pos][0] != indent:
            _err("bad indentation", self.lines[self.pos][2] if self.pos < len(self.lines) else None)
        text = self.lines[self.pos][1]
        if text == "-" or text.startswith("- "):
            return self._sequence(indent, depth)
        return self._mapping(indent, depth, None)

    def _key_colon(self, text, line):
        i = 0
        if ord(text[0]) == 0x22:
            _, end = _quoted(text, 0, line)
            i = end
            while i < len(text) and ord(text[i]) == 0x20:
                i += 1
            ok = (i < len(text) and ord(text[i]) == 0x3A
                  and (i + 1 >= len(text) or ord(text[i + 1]) == 0x20))
            return i if ok else -1
        if ord(text[0]) == 0x3F and (len(text) == 1 or ord(text[1]) == 0x20):
            _err("complex key", line)
        while i < len(text):
            c = ord(text[i])
            if c == 0x20 and i + 1 < len(text) and ord(text[i + 1]) == 0x23:
                return -1
            if _is_key_colon(text, i, False):
                return i
            if c == 0x3A:
                return -1
            i += 1
        return -1

    def _mapping(self, indent, depth, first_text):
        obj = {}
        first = first_text
        while True:
            if first is not None:
                text, no = first, (self.lines[self.pos - 1][2] if self.pos > 0 else 0)
                first = None
            else:
                if self.pos >= len(self.lines):
                    break
                ind, text, no = self.lines[self.pos]
                if ind != indent or text == "-" or text.startswith("- "):
                    break
                self.pos += 1
            split = self._key_colon(text, no)
            if split < 0:
                _err("expected key: entry", no)
            key_text = text[:split].rstrip()
            if key_text and ord(key_text[0]) == 0x22:
                key, _ = _quoted(key_text, 0, no)
            else:
                kv = _scalar_value(key_text, no)
                if not isinstance(kv, str):
                    _err("non-string key", no)
                key = kv
            if key in obj:
                _err("duplicate key", no)
            obj[key] = self._value_after_key(text[split + 1:], indent, depth, no)
            if len(obj) > MAX_MEMBERS:
                _err("object members > 256", no)
        return obj

    def _sequence(self, indent, depth):
        arr = []
        while True:
            if self.pos >= len(self.lines):
                break
            ind, text, no = self.lines[self.pos]
            if ind != indent or not (text == "-" or text.startswith("- ")):
                break
            self.pos += 1
            rest = "" if text == "-" else text[2:]
            if rest == "" or rest.lstrip().startswith("#"):
                if self.pos < len(self.lines) and self.lines[self.pos][0] > indent:
                    arr.append(self._block(self.lines[self.pos][0], depth + 1))
                else:
                    arr.append(None)
            else:
                trimmed = rest.lstrip()
                inner_indent = indent + 2 + (len(rest) - len(trimmed))
                inner_colon = (-1 if trimmed.startswith(("[", "{", '"'))
                               else self._key_colon(trimmed, no))
                if inner_colon >= 0:
                    arr.append(self._mapping(inner_indent, depth + 1, trimmed))
                elif trimmed == "-" or trimmed.startswith("- "):
                    _err("nested block sequence on same line", no)
                else:
                    arr.append(self._inline(trimmed, no, depth + 1, False))
            if len(arr) > MAX_ELEMENTS:
                _err("array elements > 256", no)
        return arr

    def _value_after_key(self, rest, indent, depth, no):
        trimmed = rest.lstrip()
        if trimmed == "" or trimmed.startswith("#"):
            if self.pos < len(self.lines) and self.lines[self.pos][0] > indent:
                return self._block(self.lines[self.pos][0], depth + 1)
            if (self.pos < len(self.lines) and self.lines[self.pos][0] == indent
                    and (self.lines[self.pos][1] == "-" or self.lines[self.pos][1].startswith("- "))):
                return self._sequence(indent, depth + 1)
            return None
        return self._inline_value(trimmed, no, depth + 1)

    def _inline_value(self, text, no, depth):
        v, pos = self._flow(text, 0, no, depth, False)
        rest = text[pos:]
        stripped = rest.strip()
        if stripped != "" and not stripped.startswith("#"):
            _err("trailing content after value", no)
        return v

    def _inline(self, text, no, depth, flow):
        v, _ = self._flow(text, 0, no, depth, flow)
        return v

    def _flow(self, text, pos, line, depth, in_flow):
        if depth > MAX_DEPTH:
            _err("depth > 16", line)
        while pos < len(text) and ord(text[pos]) in (0x20, 0x09):
            pos += 1
        if pos >= len(text):
            _err("missing value", line)
        c = ord(text[pos])
        if c == 0x5B:
            return self._flow_seq(text, pos + 1, line, depth)
        if c == 0x7B:
            return self._flow_map(text, pos + 1, line, depth)
        if c == 0x22:
            return _quoted(text, pos, line)
        if c == 0x27:
            _err("single-quoted string", line)
        if c == 0x26:
            _err("anchor", line)
        if c == 0x2A:
            _err("alias", line)
        if c == 0x21:
            _err("tag", line)
        if c in (0x7C, 0x3E):
            _err("block scalar", line)
        if c == 0x23:
            _err("missing value", line)
        end = pos
        while True:
            if end >= len(text):
                break
            ch = ord(text[end])
            if ch == 0x20 and end + 1 < len(text) and ord(text[end + 1]) == 0x23:
                break
            if in_flow and ch in (0x2C, 0x7D, 0x5D):
                break
            if _is_key_colon(text, end, in_flow):
                break
            end += 1
        raw = re.sub(r"\s+$", "", text[pos:end])
        if raw == "":
            _err("missing value", line)
        if RE_PLAIN_BAD_START.match(raw):
            _err("bad scalar start", line)
        return _scalar_value(raw, line), end

    def _flow_seq(self, text, pos, line, depth):
        arr = []
        p = pos
        while True:
            p = self._skip_ws(text, p, line)
            if p >= len(text):
                _err("unterminated [", line)
            if ord(text[p]) == 0x5D:
                return arr, p + 1
            v, np = self._flow(text, p, line, depth + 1, True)
            arr.append(v)
            if len(arr) > MAX_ELEMENTS:
                _err("array elements > 256", line)
            p = self._skip_ws(text, np, line)
            if p >= len(text):
                _err("unterminated [", line)
            c = ord(text[p])
            if c == 0x2C:
                p += 1
                continue
            if c == 0x5D:
                return arr, p + 1
            _err("expected , or ]", line)

    def _flow_map(self, text, pos, line, depth):
        obj = {}
        p = pos
        while True:
            p = self._skip_ws(text, p, line)
            if p >= len(text):
                _err("unterminated {", line)
            if ord(text[p]) == 0x7D:
                return obj, p + 1
            if ord(text[p]) == 0x22:
                key, p = _quoted(text, p, line)
            else:
                end = p
                while end < len(text) and not _is_key_colon(text, end, True):
                    end += 1
                raw = text[p:end].strip()
                kv = _scalar_value(raw, line)
                if not isinstance(kv, str):
                    _err("non-string key", line)
                key = kv
                p = end
            p = self._skip_ws(text, p, line)
            if p >= len(text) or ord(text[p]) != 0x3A:
                _err("expected :", line)
            p += 1
            v, np = self._flow(text, p, line, depth + 1, True)
            if key in obj:
                _err("duplicate key", line)
            obj[key] = v
            if len(obj) > MAX_MEMBERS:
                _err("object members > 256", line)
            p = self._skip_ws(text, np, line)
            if p >= len(text):
                _err("unterminated {", line)
            c = ord(text[p])
            if c == 0x2C:
                p += 1
                continue
            if c == 0x7D:
                return obj, p + 1
            _err("expected , or }", line)

    def _skip_ws(self, text, pos, line):
        p = pos
        while p < len(text) and ord(text[p]) in (0x20, 0x09):
            p += 1
        if p < len(text) and ord(text[p]) == 0x23:
            _err("comment inside flow collection", line)
        return p


def _check_nfc(v):
    if isinstance(v, str):
        if not is_nfc(v):
            raise CharterError("SCHEMA", "yaml: non-NFC string")
        return
    if isinstance(v, list):
        for x in v:
            _check_nfc(x)
        return
    if isinstance(v, dict):
        for k, x in v.items():
            if not is_nfc(k):
                raise CharterError("SCHEMA", "yaml: non-NFC member name")
            _check_nfc(x)


def parse_yaml_subset(source):
    if isinstance(source, (bytes, bytearray)):
        try:
            source = bytes(source).decode("utf-8")
        except UnicodeDecodeError:
            raise CharterError("PARSE", "yaml: invalid UTF-8")
    return _Parser().parse(source)
