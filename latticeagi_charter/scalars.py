"""§1.1 scalar grammar: Int, Hash, Public, Signature, Time, Label, ToolName, Resource, ID<P>."""
import base64
import re
import unicodedata
from datetime import datetime, timezone

from .errors import CharterError

RE_LABEL = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
RE_TOOL = re.compile(r"^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$")
RE_HEX64 = re.compile(r"^[0-9a-f]{64}$")
RE_ID_CHARS = re.compile(r"^[A-Za-z0-9_-]{21}$")
RE_SEGMENT = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9_.\-]{0,127}$")
RE_TIME = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$")
RE_REPO = re.compile(r"^[A-Za-z0-9_.\-]{1,100}/[A-Za-z0-9_.\-]{1,100}$")

ID_PREFIXES = ("cte", "cch", "cgw", "cin", "cpr", "cky", "ccr", "crq", "crl", "cds", "clg")
MAX_SAFE = 9007199254740991


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_SAFE


def is_hash(v):
    return isinstance(v, str) and bool(RE_HEX64.match(v))


is_public = is_hash


def is_label(v):
    return isinstance(v, str) and bool(RE_LABEL.match(v))


def is_tool_name(v):
    return isinstance(v, str) and bool(RE_TOOL.match(v))


def is_signature(v):
    """Canonical unpadded base64url of exactly 64 bytes."""
    if not isinstance(v, str):
        return False
    try:
        raw = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
    except Exception:
        return False
    return len(raw) == 64 and base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == v


def is_resource(v):
    if not isinstance(v, str):
        return False
    n = len(v.encode("utf-8"))
    if n < 1 or n > 512:
        return False
    if not re.match(r"^[\x21-\x7e]+$", v):
        return False
    for s in v.split("/"):
        if not RE_SEGMENT.match(s):
            return False
        if s in (".", ".."):
            return False
    return True


def is_id(v, prefix):
    if not isinstance(v, str):
        return False
    head = prefix + "_"
    if not v.startswith(head):
        return False
    return bool(RE_ID_CHARS.match(v[len(head):]))


def _utc_ms(y, mo, d, h, mi, s, ms):
    """Date.UTC semantics: years 0-99 map to 1900+y."""
    if 0 <= y <= 99:
        y += 1900
    try:
        dt = datetime(y, mo, d, h, mi, s, ms * 1000, tzinfo=timezone.utc)
    except ValueError:
        return None
    return int(dt.timestamp() * 1000)


def is_time(v):
    if not isinstance(v, str):
        return False
    m = RE_TIME.match(v)
    if not m:
        return False
    y, mo, d, h, mi, s, ms = (int(x) for x in m.groups())
    if mo < 1 or mo > 12 or d < 1 or d > 31 or h > 23 or mi > 59 or s > 59:
        return False
    got = _utc_ms(y, mo, d, h, mi, s, ms)
    if got is None:
        return False
    # Round-trip: the 0-99 → 1900+y mapping must not have shifted the year,
    # and invalid dates (Feb 30) must not normalize to another day.
    if 0 <= y <= 99:
        return False
    try:
        dt = datetime(y, mo, d, h, mi, s, ms * 1000, tzinfo=timezone.utc)
    except ValueError:
        return False
    return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second) == (y, mo, d, h, mi, s)


def time_ms(t):
    m = RE_TIME.match(t)
    if not m:
        raise CharterError("SCHEMA", "invalid Time")
    y, mo, d, h, mi, s, ms = (int(x) for x in m.groups())
    return _utc_ms(y, mo, d, h, mi, s, ms)


def ms_time(ms):
    if not isinstance(ms, int) or isinstance(ms, bool) or ms < 0 or ms > MAX_SAFE:
        raise CharterError("SCHEMA", "ms out of range")
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return (f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}"
            f"T{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}.{dt.microsecond // 1000:03d}Z")


def is_repository(v):
    return isinstance(v, str) and bool(RE_REPO.match(v))


def is_scalar(v):
    return isinstance(v, str) or is_int(v) or isinstance(v, bool)


def is_nfc(s):
    return s == unicodedata.normalize("NFC", s)


def utf8_bytes(s):
    return len(s.encode("utf-8"))


def require(cond, detail):
    if not cond:
        raise CharterError("SCHEMA", detail)


def make_id(prefix, chars):
    i = f"{prefix}_{chars}"
    if not is_id(i, prefix):
        raise CharterError("SCHEMA", f"invalid {prefix} id")
    return i
