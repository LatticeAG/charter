"""RFC 8785 canonical JSON serialization over the charter/1 validated subset."""
from .errors import CharterError
from .scalars import is_int, is_nfc

_ESCAPES = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
            0x22: '\\"', 0x5C: "\\\\"}


def _quote(s):
    """JSON.stringify string escaping: C0 controls as \\uXXXX (lowercase),
    named escapes for the usual six, everything else raw UTF-8."""
    out = ['"']
    for ch in s:
        c = ord(ch)
        if c in _ESCAPES:
            out.append(_ESCAPES[c])
        elif c < 0x20:
            out.append("\\u%04x" % c)
        elif 0xD800 <= c <= 0xDFFF:
            # Unreachable — callers reject lone surrogates first; emit the
            # JS-compatible escaped form defensively.
            out.append("\\u%04x" % c)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _has_lone_surrogate(s):
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in s)


def _utf16_key(k):
    return k.encode("utf-16-be", "surrogatepass")


def canonicalize(x):
    if x is None:
        return "null"
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, int):
        if not is_int(x):
            raise CharterError("SCHEMA", "canonicalize: number outside Int grammar")
        return str(x)
    if isinstance(x, str):
        if not is_nfc(x):
            raise CharterError("SCHEMA", "canonicalize: non-NFC string")
        if _has_lone_surrogate(x):
            raise CharterError("SCHEMA", "canonicalize: lone surrogate")
        return _quote(x)
    if isinstance(x, list):
        return "[" + ",".join(canonicalize(v) for v in x) + "]"
    if isinstance(x, dict):
        parts = []
        for k in sorted(x.keys(), key=_utf16_key):
            v = x[k]
            if v is None and k not in x:
                raise CharterError("SCHEMA", f"canonicalize: undefined member {k}")
            if not is_nfc(k) or _has_lone_surrogate(k):
                raise CharterError("SCHEMA", "canonicalize: invalid member name")
            parts.append(_quote(k) + ":" + canonicalize(v))
        return "{" + ",".join(parts) + "}"
    raise CharterError("SCHEMA", f"canonicalize: unsupported value type {type(x).__name__}")


def canonical_bytes(x):
    return canonicalize(x).encode("utf-8")


def json_equal(a, b):
    if a is b:
        return True
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, int) and isinstance(b, int):
        return a == b
    if type(a) is not type(b) or a is None or b is None:
        return False
    if isinstance(a, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict):
        if len(a) != len(b):
            return False
        return all(k in b and json_equal(v, b[k]) for k, v in a.items())
    return a == b
