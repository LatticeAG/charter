"""§1.2 domain-separated digests and signature envelopes."""
import hashlib

from .jcs import canonicalize

DIGEST_KINDS = ("manifest", "policy", "pin", "input", "request",
                "clause", "audit", "checkpoint", "control")
SIGN_KINDS = ("policy", "pin", "audit", "checkpoint")


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def digest(kind, value):
    """D(k,x) = hex(SHA256(UTF8("LAGI-CHARTER/" + k + "/1\n") || J(x)))."""
    return sha256_hex(f"LAGI-CHARTER/{kind}/1\n" + canonicalize(value))


def sign_message(kind, value):
    """S(k,x): ASCII bytes an Ed25519 signature covers."""
    return f"LAGI-CHARTER/sign/{kind}/1\n{digest(kind, value)}".encode("utf-8")
