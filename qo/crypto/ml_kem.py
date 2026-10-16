"""ML-KEM (FIPS 203) — Module-Lattice Key-Encapsulation Mechanism.

Pure-Python, stdlib-only implementation of the NIST standard ML-KEM
(FIPS 203, August 2024). All three parameter sets are supported;
ML-KEM-768 is the default and the recommended general-purpose choice.

    ek, dk = ml_kem.keygen()            # seedable: keygen(seed64)
    ct, ss = ml_kem.encaps(ek)          # deterministic: encaps(ek, m32)
    ss     = ml_kem.decaps(dk, ct)

Verified against Wycheproof ML-KEM KAT vectors (see scripts/verify_kat.py;
one vector is pinned in tests/test_mlkem.py). Security review status:
reference construction, not independently audited — as with any crypto
code, prefer a vetted library (liboqs, BoringSSL) for high-assurance
deployments.
"""
from __future__ import annotations

import hashlib
import hmac
import os

Q = 3329
N = 256


# ------------------------------------------------------------------ NTT
def _bitrev7(x: int) -> int:
    return int(f"{x:07b}"[::-1], 2)


_ZETAS = [pow(17, _bitrev7(i), Q) for i in range(128)]
_GAMMAS = [pow(17, 2 * _bitrev7(i) + 1, Q) for i in range(128)]


def _ntt(f: list[int]) -> list[int]:
    """FIPS 203 Algorithm 9."""
    f = list(f)
    i, length = 1, 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = _ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = (zeta * f[j + length]) % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f


def _intt(f: list[int]) -> list[int]:
    """FIPS 203 Algorithm 10."""
    f = list(f)
    i, length = 127, 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = _ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = (zeta * (f[j + length] - t)) % Q
        length *= 2
    return [(x * 3303) % Q for x in f]  # 3303 = 128^-1 mod q


def _basemul(a: list[int], b: list[int]) -> list[int]:
    """FIPS 203 Algorithm 12 (MultiplyNTTs)."""
    h = [0] * N
    for i in range(128):
        a0, a1 = a[2 * i], a[2 * i + 1]
        b0, b1 = b[2 * i], b[2 * i + 1]
        g = _GAMMAS[i]
        h[2 * i] = (a0 * b0 + a1 * b1 * g) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


# ------------------------------------------------------------- arithmetic
def _add(a: list[int], b: list[int]) -> list[int]:
    return [(x + y) % Q for x, y in zip(a, b)]


def _sub(a: list[int], b: list[int]) -> list[int]:
    return [(x - y) % Q for x, y in zip(a, b)]


# --------------------------------------------------------------- sampling
def _prf(seed: bytes, eta: int, n: int) -> bytes:
    """FIPS 203 PRF_eta(s, b): SHAKE256(s || b), 64*eta bytes."""
    return hashlib.shake_256(seed + bytes([n])).digest(64 * eta)


def _cbd(buf: bytes, eta: int) -> list[int]:
    """FIPS 203 SamplePolyCBD_eta."""
    out, pos = [], 0
    for _ in range(N):
        x = y = 0
        for _ in range(eta):
            x += (buf[pos >> 3] >> (pos & 7)) & 1
            pos += 1
        for _ in range(eta):
            y += (buf[pos >> 3] >> (pos & 7)) & 1
            pos += 1
        out.append((x - y) % Q)
    return out


def _sample_ntt(rho: bytes, i: int, j: int) -> list[int]:
    """FIPS 203 SampleNTT: rejection-sample 12-bit coeffs from SHAKE128."""
    stream = hashlib.shake_128(rho + bytes([i, j])).digest(840)
    out: list[int] = []
    for t in range(0, len(stream), 3):
        d1 = stream[t] + 256 * (stream[t + 1] & 15)
        d2 = (stream[t + 1] >> 4) + 16 * stream[t + 2]
        if d1 < Q:
            out.append(d1)
            if len(out) == N:
                return out
        if d2 < Q:
            out.append(d2)
            if len(out) == N:
                return out
    raise RuntimeError("SampleNTT: XOF stream exhausted (impossible)")


# -------------------------------------------------------- encode / compress
def _encode(poly: list[int], d: int) -> bytes:
    out, acc, bits = bytearray(), 0, 0
    mask = (1 << d) - 1
    for c in poly:
        acc |= (c & mask) << bits
        bits += d
        while bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            bits -= 8
    if bits:
        out.append(acc & 0xFF)
    return bytes(out)


def _decode(buf: bytes, d: int) -> list[int]:
    out, acc, bits, pos = [], 0, 0, 0
    mask = (1 << d) - 1
    for _ in range(N):
        while bits < d:
            acc |= buf[pos] << bits
            pos += 1
            bits += 8
        out.append(acc & mask)
        acc >>= d
        bits -= d
    return out


def _compress(poly: list[int], d: int) -> list[int]:
    mask = (1 << d) - 1
    return [(((c << (d + 1)) + Q) // (2 * Q)) & mask for c in poly]


def _decompress(vals: list[int], d: int) -> list[int]:
    return [((v * Q) + (1 << (d - 1))) >> d for v in vals]


# ------------------------------------------------------------------ K-PKE
class _P:
    def __init__(self, k, eta1, eta2, du, dv):
        self.k, self.eta1, self.eta2, self.du, self.dv = k, eta1, eta2, du, dv


P512 = _P(2, 3, 2, 10, 4)
P768 = _P(3, 2, 2, 10, 4)
P1024 = _P(4, 2, 2, 11, 5)


def _kpke_keygen(d32: bytes, p: _P):
    seed = hashlib.sha3_512(d32).digest()
    rho, sigma = seed[:32], seed[32:]
    a_hat = [[_sample_ntt(rho, i, j) for j in range(p.k)]   # already NTT-domain
             for i in range(p.k)]
    s = [_cbd(_prf(sigma, p.eta1, n), p.eta1) for n in range(p.k)]
    e = [_cbd(_prf(sigma, p.eta1, p.k + n), p.eta1) for n in range(p.k)]
    s_hat = [_ntt(x) for x in s]
    t = []
    for i in range(p.k):
        acc = [0] * N
        for j in range(p.k):
            acc = _add(acc, _basemul(a_hat[i][j], s_hat[j]))
        t.append(_add(_intt(acc), e[i]))
    ek = b"".join(_encode(x, 12) for x in t) + rho
    dk = b"".join(_encode(x, 12) for x in s)
    return ek, dk


def _kpke_encrypt(ek: bytes, m32: bytes, r32: bytes, p: _P) -> bytes:
    t_hat = [_ntt(_decode(ek[i * 384:(i + 1) * 384], 12)) for i in range(p.k)]
    rho = ek[384 * p.k:]
    # A_hat_T[i][j] = NTT(SampleNTT(rho, j, i))
    r = [_cbd(_prf(r32, p.eta1, n), p.eta1) for n in range(p.k)]
    e1 = [_cbd(_prf(r32, p.eta2, p.k + n), p.eta2) for n in range(p.k)]
    e2 = _cbd(_prf(r32, p.eta2, 2 * p.k), p.eta2)
    r_hat = [_ntt(x) for x in r]
    u = []
    for i in range(p.k):
        acc = [0] * N
        for j in range(p.k):
            acc = _add(acc, _basemul(_sample_ntt(rho, j, i), r_hat[j]))  # NTT-domain
        u.append(_add(_intt(acc), e1[i]))
    acc = [0] * N
    for i in range(p.k):
        acc = _add(acc, _basemul(t_hat[i], r_hat[i]))
    v = _add(_add(_intt(acc), e2), _decompress(_decode(m32, 1), 1))
    c1 = b"".join(_encode(_compress(x, p.du), p.du) for x in u)
    c2 = _encode(_compress(v, p.dv), p.dv)
    return c1 + c2


def _kpke_decrypt(dk: bytes, ct: bytes, p: _P) -> bytes:
    s = [_decode(dk[i * 384:(i + 1) * 384], 12) for i in range(p.k)]
    l1 = 32 * p.du * p.k
    c1b, c2b = ct[:l1], ct[l1:]
    u = [_decompress(_decode(c1b[i * 32 * p.du:(i + 1) * 32 * p.du],
                             p.du), p.du) for i in range(p.k)]
    v = _decompress(_decode(c2b, p.dv), p.dv)
    s_hat = [_ntt(x) for x in s]
    u_hat = [_ntt(x) for x in u]
    acc = [0] * N
    for i in range(p.k):
        acc = _add(acc, _basemul(s_hat[i], u_hat[i]))
    w = _sub(v, _intt(acc))
    return _encode(_compress(w, 1), 1)


# ----------------------------------------------------------------- ML-KEM
class MLKEM:
    """FIPS 203 ML-KEM for one parameter set."""

    def __init__(self, p: _P, name: str):
        self.p, self.name = p, name
        self.ek_bytes = 384 * p.k + 32
        self.dk_bytes = 384 * p.k + self.ek_bytes + 64
        self.ct_bytes = 32 * (p.du * p.k + p.dv)

    def keygen(self, seed64: bytes | None = None):
        if seed64 is None:
            d = os.urandom(32)
            z = os.urandom(32)
        else:
            d, z = seed64[:32], seed64[32:64]
        ek, dk_pke = _kpke_keygen(d, self.p)
        dk = dk_pke + ek + hashlib.sha3_256(ek).digest() + z
        assert len(ek) == self.ek_bytes and len(dk) == self.dk_bytes
        return ek, dk

    def encaps(self, ek: bytes, m32: bytes | None = None):
        m32 = m32 or os.urandom(32)
        h = hashlib.sha3_256(ek).digest()
        kr = hashlib.sha3_512(m32 + h).digest()
        k, r = kr[:32], kr[32:]
        c = _kpke_encrypt(ek, m32, r, self.p)
        ss = hashlib.shake_256(k + hashlib.sha3_256(c).digest()).digest(32)
        assert len(c) == self.ct_bytes
        return c, ss

    def decaps(self, dk: bytes, c: bytes):
        p = self.p
        dk_pke = dk[:384 * p.k]
        ek = dk[384 * p.k:384 * p.k + self.ek_bytes]
        h = dk[384 * p.k + self.ek_bytes:384 * p.k + self.ek_bytes + 32]
        z = dk[384 * p.k + self.ek_bytes + 32:]
        m = _kpke_decrypt(dk_pke, c, p)
        kr = hashlib.sha3_512(m + h).digest()
        kp, rp = kr[:32], kr[32:]
        c2 = _kpke_encrypt(ek, m, rp, p)
        ok = hmac.compare_digest(c, c2)
        pre = kp if ok else z  # implicit rejection
        return hashlib.shake_256(pre + hashlib.sha3_256(c).digest()).digest(32)


ml_kem_512 = MLKEM(P512, "ML-KEM-512")
ml_kem_768 = MLKEM(P768, "ML-KEM-768")
ml_kem_1024 = MLKEM(P1024, "ML-KEM-1024")

# Default: the NIST-recommended general-purpose parameter set.
keygen = ml_kem_768.keygen
encaps = ml_kem_768.encaps
decaps = ml_kem_768.decaps
