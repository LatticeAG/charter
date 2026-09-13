"""LatticeAGI Charter — offline zone core (charter/1), pure-Python SDK.

CharterCore pure-function surface (§3.7), snake_case aliases with identical
records and error codes. No runtime dependencies.
"""
import base64
import os
import re

from .errors import CharterError, ERROR_CODES, exit_code_for, retryable, status_for
from .jcs import canonicalize as _canon, canonical_bytes, json_equal
from .strict_json import parse_json_bytes, parse_json_text
from .yaml_subset import parse_yaml_subset
from .scalars import is_nfc, time_ms, ms_time
from .digest import digest as _digest, sign_message, sha256_hex
from .ed25519 import sign_bytes, verify_bytes, public_key_from_seed, public_key_hex_from_seed
from .schema import (
    ENGINE, v_bundle, v_checkpoint, v_pin_command, v_policy, v_root_file,
)
from .core import (
    compile as _compile, evaluate as _evaluate, cite as _cite, diff as _diff,
    pin_for, verify_bundle as _verify_bundle, verify_evidence as _verify_evidence,
)

__version__ = "0.1.0"
__all__ = [
    "CharterError", "parse_policy", "canonicalize", "digest", "verify_bundle",
    "compile", "evaluate", "cite", "diff", "sign", "verify_evidence",
    "parse_json", "ENGINE",
]


def parse_policy(data, format):
    """Strict parse of a policy source; raises CharterError with exact code."""
    text = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
    v = parse_json_text(text) if format == "json" else parse_yaml_subset(text)
    return v_policy(v, "$")


def canonicalize(policy):
    """Canonical JCS bytes of a validated policy."""
    return _canon(policy).encode("utf-8")


def digest(kind, value):
    return _digest(kind, value)


def verify_bundle(bundle, root, predecessors, at=None):
    return _verify_bundle(
        v_bundle(bundle, "$.bundle"), v_root_file(root, "$.root"),
        [v_bundle(b, f"$.predecessors[{i}]") for i, b in enumerate(predecessors)], at)


def compile(policy, manifest):  # noqa: A001 — spec name
    return _compile(policy, manifest)


def evaluate(input_):
    return _evaluate(input_)


def cite(bundle, rule_id):
    return _cite(bundle, rule_id)


def diff(old_policy, new_policy):
    return _diff(old_policy, new_policy)


_FIXTURE_SEEDS = (
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
)


def _resolve_handle(handle):
    if re.match(r"^fixture:[0-2]$", handle):
        # Test-only handle: public fixture seeds, rejected by production config.
        return bytes.fromhex(_FIXTURE_SEEDS[int(handle[8:])])
    if not handle.startswith("env:"):
        raise CharterError("SCHEMA", "key handle must be env:NAME")
    raw = os.environ.get(handle[4:])
    if raw is None:
        raise CharterError("SCHEMA", f"secret ref {handle[4:]} unset")
    seed = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    if len(seed) != 32 or base64.urlsafe_b64encode(seed).rstrip(b"=").decode() != raw:
        raise CharterError("SCHEMA", "key handle does not resolve to 32-byte base64url seed")
    return seed


def sign(kind, value, key_id, key_handle):
    """Detached signature over a Policy or PinCommand. `key_handle` is a §5
    secret reference (`env:NAME`); `fixture:N` resolves to the public RFC 8032
    seed list — production handles cannot name fixtures."""
    seed = _resolve_handle(key_handle)
    checked = v_policy(value, "$") if kind == "policy" else v_pin_command(value, "$")
    sig = sign_bytes(sign_message(kind, checked), seed)
    return {"key_id": key_id,
            "signature": base64.urlsafe_b64encode(sig).rstrip(b"=").decode()}


def verify_evidence(evidence, trusted_root, end_checkpoint, replay):
    root = v_root_file(trusted_root, "$.trusted_root")
    end = None if end_checkpoint is None else v_checkpoint(end_checkpoint, "$.end_checkpoint")
    return _verify_evidence(evidence, root, end, replay)


def parse_json(data):
    return parse_json_bytes(data)
