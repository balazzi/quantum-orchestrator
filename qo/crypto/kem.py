"""QKEM-256: Ring-LWE key-encapsulation mechanism (stdlib only).

Research-grade reference implementation. Structure follows the Kyber
blueprint: IND-CPA public-key encryption over R_q = Z_q[x]/(x^n - 1) with
n=256, q=12289, centered-binomial noise eta=3, lifted to IND-CCA2 with a
Fujisaki-Okamoto transform and implicit rejection on decapsulation failure.

This is NOT ML-KEM and has NOT been audited. For production, replace this
module with ML-KEM-768 (e.g. via liboqs) behind the same interface:
    pk, sk = keygen() | ct, ss = encaps(pk) | ss = decaps(sk, ct)
"""
from __future__ import annotations

import hashlib
import hmac

from .prng import prf, quantum_seed, xof

N = 256
Q = 12289
ETA = 3
POLY_BYTES = N * 2          # 512
PK_BYTES = 32 + POLY_BYTES  # seed_a || t  = 544
CT_BYTES = 2 * POLY_BYTES   # u || v      = 1024
SK_BYTES = POLY_BYTES + PK_BYTES + 32 + 32  # s || pk || H(pk) || z


# ---------------------------------------------------------------- polynomials
def _add(a: list[int], b: list[int]) -> list[int]:
    return [(x + y) % Q for x, y in zip(a, b)]


def _sub(a: list[int], b: list[int]) -> list[int]:
    return [(x - y) % Q for x, y in zip(a, b)]


def _mul(a: list[int], b: list[int]) -> list[int]:
    c = [0] * N
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if bj:
                    k = (i + j) % N
                    c[k] = (c[k] + ai * bj) % Q
    return c


# ------------------------------------------------------------------ sampling
class _Bits:
    def __init__(self, data: bytes):
        self.d = data
        self.p = 0

    def take(self, n: int) -> int:
        v = 0
        for i in range(n):
            v |= ((self.d[self.p >> 3] >> (self.p & 7)) & 1) << i
            self.p += 1
        return v


def _cbd(buf: bytes) -> list[int]:
    """Centered binomial distribution, eta=3. Consumes exactly 192 bytes."""
    br = _Bits(buf)
    out = []
    for _ in range(N):
        a = sum(br.take(1) for _ in range(ETA))
        b = sum(br.take(1) for _ in range(ETA))
        out.append(a - b)
    return out


def _uniform(buf: bytes) -> list[int]:
    """Uniform polynomial mod Q via rejection sampling of 14-bit words."""
    br = _Bits(buf)
    out: list[int] = []
    while len(out) < N:
        v = br.take(14)
        if v < Q:
            out.append(v)
    return out


# ------------------------------------------------------------- encode/decode
def _enc_poly(p: list[int]) -> bytes:
    return b"".join((c % Q).to_bytes(2, "little") for c in p)


def _dec_poly(b: bytes) -> list[int]:
    return [int.from_bytes(b[i:i + 2], "little") for i in range(0, len(b), 2)]


def _msg_poly(m: bytes) -> list[int]:
    return [((m[i >> 3] >> (i & 7)) & 1) * (Q // 2) for i in range(N)]


def _decode(p: list[int]) -> bytes:
    m = bytearray(32)
    for i, c in enumerate(p):
        d = c if c <= Q // 2 else Q - c
        if d >= Q // 4:
            m[i >> 3] |= 1 << (i & 7)
    return bytes(m)


# ------------------------------------------------------------------ IND-CPA
def _cpa_keygen(seed: bytes):
    a = _uniform(prf(seed, b"kem-a", 768))
    s = _cbd(prf(seed, b"kem-s", 192))
    e = _cbd(prf(seed, b"kem-e", 192))
    t = _add(_mul(a, s), e)
    return (seed, t), s


def _cpa_encrypt(pk, m32: bytes, coins: bytes) -> bytes:
    seed_a, t = pk
    a = _uniform(prf(seed_a, b"kem-a", 768))
    r = _cbd(coins[0:192])
    e1 = _cbd(coins[192:384])
    e2 = _cbd(coins[384:576])
    u = _add(_mul(a, r), e1)
    v = _add(_add(_mul(t, r), e2), _msg_poly(m32))
    return _enc_poly(u) + _enc_poly(v)


def _cpa_decrypt(s: list[int], ct: bytes) -> bytes:
    u = _dec_poly(ct[:POLY_BYTES])
    v = _dec_poly(ct[POLY_BYTES:CT_BYTES])
    return _decode(_sub(v, _mul(s, u)))


def _parse_pk(pk: bytes):
    return pk[:32], _dec_poly(pk[32:PK_BYTES])


# ------------------------------------------------------------------ IND-CCA
def keygen(seed: bytes | None = None) -> tuple[bytes, bytes]:
    seed = seed or quantum_seed(32)
    (seed_a, t), s = _cpa_keygen(seed)
    pk = seed_a + _enc_poly(t)
    hpk = hashlib.sha256(pk).digest()
    z = quantum_seed(32)  # implicit-rejection secret
    sk = _enc_poly(s) + pk + hpk + z
    assert len(sk) == SK_BYTES
    return pk, sk


def encaps(pk: bytes) -> tuple[bytes, bytes]:
    m = quantum_seed(32)
    hpk = hashlib.sha256(pk).digest()
    kr = xof(b"QO-KEM-G\x00" + m + hpk, 32 + 576)
    kbar, coins = kr[:32], kr[32:]
    ct = _cpa_encrypt(_parse_pk(pk), m, coins)
    ss = xof(b"QO-KEM-H\x00" + kbar + hashlib.sha256(ct).digest(), 32)
    return ct, ss


def decaps(sk: bytes, ct: bytes) -> bytes:
    s = _dec_poly(sk[:POLY_BYTES])
    pk = sk[POLY_BYTES:POLY_BYTES + PK_BYTES]
    hpk = sk[POLY_BYTES + PK_BYTES:POLY_BYTES + PK_BYTES + 32]
    z = sk[POLY_BYTES + PK_BYTES + 32:SK_BYTES]
    m2 = _cpa_decrypt(s, ct)
    kr = xof(b"QO-KEM-G\x00" + m2 + hpk, 32 + 576)
    kbar, coins = kr[:32], kr[32:]
    ct2 = _cpa_encrypt(_parse_pk(pk), m2, coins)
    ok = hmac.compare_digest(ct, ct2)
    pre = kbar if ok else z  # implicit rejection: never leak failure
    return xof(b"QO-KEM-H\x00" + pre + hashlib.sha256(ct).digest(), 32)
