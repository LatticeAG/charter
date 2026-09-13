"""Ed25519 over the charter/1 signing profile (§1.2), pure Python / RFC 8032.

Strictness: rejects noncanonical encodings (y >= p), small-order public keys
and R points, S >= L. Verification uses the strict non-cofactored equation
[S]B = R + [H]A, matching the TypeScript implementation's OpenSSL semantics.
"""
import hashlib

from .errors import CharterError

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _xrecover(y):
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        return None
    if x % 2 != 0:
        x = _P - x
    return x


_BY = (4 * pow(5, _P - 2, _P)) % _P
_B = (_xrecover(_BY), _BY)
_IDENTITY = (0, 1)

_SMALL_ORDER = {
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
}


def _edwards_add(p, q):
    (x1, y1), (x2, y2) = p, q
    xnum = (x1 * y2 + x2 * y1) % _P
    xden = pow(1 + _D * x1 * x2 * y1 * y2, _P - 2, _P)
    ynum = (y1 * y2 + x1 * x2) % _P
    yden = pow(1 - _D * x1 * x2 * y1 * y2, _P - 2, _P)
    return (xnum * xden % _P, ynum * yden % _P)


def _edwards_mul(p, n):
    """Double-and-add over the Edwards curve; n>=0."""
    r = _IDENTITY
    q = p
    while n > 0:
        if n & 1:
            r = _edwards_add(r, q)
        q = _edwards_add(q, q)
        n >>= 1
    return r


def _point_compress(p):
    x, y = p
    return int(y | ((x & 1) << 255)).to_bytes(32, "little")


def _point_decompress(s):
    """Decode a compressed point, or None if not on the curve."""
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    if y >= _P:
        return None
    x = _xrecover(y)
    if x is None:
        return None
    if (x & 1) != (s[31] >> 7):
        x = _P - x
    return (x, y)


def _hint(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _check_point(data, what):
    if len(data) != 32:
        raise CharterError("SCHEMA", f"{what}: bad length")
    hx = bytes(data).hex()
    if hx in _SMALL_ORDER:
        raise CharterError("SIGNATURE_INVALID", f"{what}: small-order point")
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    if y >= _P:
        raise CharterError("SIGNATURE_INVALID", f"{what}: noncanonical encoding")


def public_key_from_seed(seed):
    if len(seed) != 32:
        raise CharterError("SCHEMA", "seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _point_compress(_edwards_mul(_B, a))


def public_key_hex_from_seed(seed):
    return public_key_from_seed(seed).hex()


def sign_bytes(message, seed):
    if len(seed) != 32:
        raise CharterError("SCHEMA", "seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    pub = _point_compress(_edwards_mul(_B, a))
    r = _hint(prefix + message) % _L
    r_pt = _point_compress(_edwards_mul(_B, r))
    s = (r + _hint(r_pt + pub + message) * a) % _L
    return r_pt + s.to_bytes(32, "little")


def verify_bytes(message, signature, public_key):
    """Strict verification; returns False for bad signatures after the
    structural checks. Malformed encodings raise SIGNATURE_INVALID/SCHEMA."""
    if len(public_key) != 32:
        raise CharterError("SCHEMA", "public key length")
    if len(signature) != 64:
        return False
    r_enc, s_enc = signature[:32], signature[32:]
    _check_point(r_enc, "R")
    _check_point(public_key, "public key")
    s = int.from_bytes(s_enc, "little")
    if s >= _L:
        return False
    a = _point_decompress(public_key)
    r = _point_decompress(r_enc)
    if a is None or r is None:
        return False
    h = _hint(r_enc + bytes(public_key) + message) % _L
    lhs = _edwards_mul(_B, s)
    rhs = _edwards_add(r, _edwards_mul(a, h))
    return lhs == rhs
