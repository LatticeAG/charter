"""Strict JSON parser for the charter/1 wire grammar (§1.1).
Rejects: invalid UTF-8, BOM, trailing bytes, duplicate members, fractions,
exponents, -0, negative/out-of-range integers, lone surrogates, depth > 16,
>256 members per object, >256 array elements. Post-pass rejects non-NFC
strings as SCHEMA (lexical failures are PARSE).
"""
from .errors import CharterError
from .scalars import is_nfc, MAX_SAFE

MAX_DEPTH = 16
MAX_MEMBERS = 256
MAX_ELEMENTS = 256


class _P:
    def __init__(self, s):
        self.s = s
        self.i = 0

    def err(self, what):
        raise CharterError("PARSE", f"json: {what} at offset {self.i}")

    def ws(self):
        while self.i < len(self.s) and self.s[self.i] in " \t\n\r":
            self.i += 1

    def peek(self):
        return ord(self.s[self.i]) if self.i < len(self.s) else -1

    def value(self, depth):
        if depth > MAX_DEPTH:
            self.err("depth > 16")
        self.ws()
        c = self.peek()
        if c == 0x7B:
            return self.object(depth)
        if c == 0x5B:
            return self.array(depth)
        if c == 0x22:
            return self.string()
        if c == 0x74:
            return self.lit("true", True)
        if c == 0x66:
            return self.lit("false", False)
        if c == 0x6E:
            return self.lit("null", None)
        if 0x30 <= c <= 0x39:
            return self.number()
        self.err("unexpected token")

    def lit(self, word, v):
        if self.s[self.i:self.i + len(word)] != word:
            self.err("bad literal")
        self.i += len(word)
        return v

    def number(self):
        start = self.i
        if self.peek() == 0x30:
            self.i += 1
            if 0x30 <= self.peek() <= 0x39:
                self.err("leading zero")
        else:
            while 0x30 <= self.peek() <= 0x39:
                self.i += 1
        c = self.peek()
        if c in (0x2E, 0x65, 0x45, 0x2B, 0x2D):
            self.err("non-integer numeric token")
        text = self.s[start:self.i]
        n = int(text)
        if n < 0 or n > MAX_SAFE:
            self.err("integer out of range")
        return n

    def string(self):
        self.i += 1  # consume "
        out = []
        while self.i < len(self.s):
            c = ord(self.s[self.i])
            if c == 0x22:
                self.i += 1
                return "".join(out)
            if c == 0x5C:
                self.i += 1
                e = self.peek()
                if e == 0x22:
                    out.append('"'); self.i += 1
                elif e == 0x5C:
                    out.append("\\"); self.i += 1
                elif e == 0x2F:
                    out.append("/"); self.i += 1
                elif e == 0x62:
                    out.append("\b"); self.i += 1
                elif e == 0x66:
                    out.append("\f"); self.i += 1
                elif e == 0x6E:
                    out.append("\n"); self.i += 1
                elif e == 0x72:
                    out.append("\r"); self.i += 1
                elif e == 0x74:
                    out.append("\t"); self.i += 1
                elif e == 0x75:
                    self.i += 1
                    h1 = self.hex4()
                    if 0xD800 <= h1 <= 0xDBFF:
                        if (self.i + 1 < len(self.s) and self.s[self.i] == "\\"
                                and self.s[self.i + 1] == "u"):
                            self.i += 2
                            h2 = self.hex4()
                            if 0xDC00 <= h2 <= 0xDFFF:
                                out.append(chr(0x10000 + ((h1 - 0xD800) << 10) + h2 - 0xDC00))
                            else:
                                self.err("unpaired high surrogate")
                        else:
                            self.err("unpaired high surrogate")
                    elif 0xDC00 <= h1 <= 0xDFFF:
                        self.err("lone low surrogate")
                    else:
                        out.append(chr(h1))
                else:
                    self.err("bad escape")
            else:
                if c < 0x20:
                    self.err("raw control character")
                if 0xD800 <= c <= 0xDFFF:
                    self.err("lone surrogate")
                out.append(self.s[self.i])
                self.i += 1
        self.err("unterminated string")

    def hex4(self):
        t = self.s[self.i:self.i + 4]
        if len(t) != 4 or not all(ch in "0123456789abcdefABCDEF" for ch in t):
            self.err("bad \\u escape")
        self.i += 4
        return int(t, 16)

    def object(self, depth):
        self.i += 1  # {
        obj = {}
        self.ws()
        if self.peek() == 0x7D:
            self.i += 1
            return obj
        while True:
            self.ws()
            if self.peek() != 0x22:
                self.err("object key must be string")
            k = self.string()
            if k in obj:
                self.err("duplicate member")
            self.ws()
            if self.peek() != 0x3A:
                self.err("expected :")
            self.i += 1
            obj[k] = self.value(depth + 1)
            if len(obj) > MAX_MEMBERS:
                self.err("object members > 256")
            self.ws()
            c = self.peek()
            if c == 0x2C:
                self.i += 1
                continue
            if c == 0x7D:
                self.i += 1
                return obj
            self.err("expected , or }")

    def array(self, depth):
        self.i += 1  # [
        arr = []
        self.ws()
        if self.peek() == 0x5D:
            self.i += 1
            return arr
        while True:
            arr.append(self.value(depth + 1))
            if len(arr) > MAX_ELEMENTS:
                self.err("array elements > 256")
            self.ws()
            c = self.peek()
            if c == 0x2C:
                self.i += 1
                continue
            if c == 0x5D:
                self.i += 1
                return arr
            self.err("expected , or ]")


def _check_nfc(v):
    if isinstance(v, str):
        if not is_nfc(v):
            raise CharterError("SCHEMA", "json: non-NFC string")
        return
    if isinstance(v, list):
        for x in v:
            _check_nfc(x)
        return
    if isinstance(v, dict):
        for k, x in v.items():
            if not is_nfc(k):
                raise CharterError("SCHEMA", "json: non-NFC member name")
            _check_nfc(x)


def parse_json_bytes(data):
    try:
        s = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        raise CharterError("PARSE", "json: invalid UTF-8")
    return parse_json_text(s)


def parse_json_text(s):
    if isinstance(s, (bytes, bytearray)):
        return parse_json_bytes(s)
    if s and ord(s[0]) == 0xFEFF:
        raise CharterError("PARSE", "json: BOM")
    p = _P(s)
    v = p.value(1)
    p.ws()
    if p.i != len(s):
        raise CharterError("PARSE", "json: trailing bytes")
    _check_nfc(v)
    return v
