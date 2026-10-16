"""ML-DSA (FIPS 204) — Module-Lattice Digital Signature Algorithm.

Pure-Python, stdlib-only implementation following the FIPS 204 / Dilithium
construction. All three parameter sets; ML-DSA-65 is the default.

    pk, sk = mldsa.keygen()             # or keygen(seed32)
    sig = mldsa.sign(sk, msg)           # deterministic; sign(sk, msg, rnd32) hedged
    ok  = mldsa.verify(pk, msg, sig)

Validated offline (scripts/selftest_dsa.py): iterative NTT against the
direct DFT definition, NTT pointwise multiplication against naive
negacyclic convolution, exact FIPS 204 byte sizes for all parameter sets
(pk/sk/sig = 1952/4032/3309 for ML-DSA-65), determinism, sign/verify
round-trips, and tamper rejection. Byte-level KAT compliance against the
official vectors is pending network access (see scripts/verify_kat.py).

Implementation notes / deliberate choices where the standard text is
ambiguous from memory:
  * ExpandA uses XOF(ρ, j, i) (Dilithium nonce order).
  * The per-signature mask seed is ρ' = SHAKE256(K ∥ μ, 64).
  * Hint encoding is count-prefixed (k count bytes + indices, zero-padded
    to exactly ω+k bytes) — unambiguous and size-correct; FIPS 204's
    exact hint packing should be confirmed against KAT vectors.
Not independently audited — prefer a vetted library for high assurance.
"""
from __future__ import annotations

import hashlib
import os

Q = 8380417
N = 256
D = 13


# ------------------------------------------------------------------ NTT
def _bitrev8(x: int) -> int:
    return int(f"{x:08b}"[::-1], 2)


_ZETAS = [pow(1753, _bitrev8(i), Q) for i in range(256)]
_INV256 = pow(256, -1, Q)


def _ntt(f: list[int]) -> list[int]:
    f = list(f)
    k, length = 0, 128
    while length > 0:
        for start in range(0, N, 2 * length):
            k += 1
            zeta = _ZETAS[k]
            for j in range(start, start + length):
                t = (zeta * f[j + length]) % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f


def _intt(f: list[int]) -> list[int]:
    # Gentleman-Sande inverse; twiddles are the *negated* forward table
    # (matches the FIPS 204 / Dilithium reference structure).
    f = list(f)
    k, length = 256, 1
    while length <= 128:
        for start in range(0, N, 2 * length):
            k -= 1
            zeta = (-_ZETAS[k]) % Q
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = (zeta * (t - f[j + length])) % Q
        length *= 2
    return [(x * _INV256) % Q for x in f]


def _pointwise(a: list[int], b: list[int]) -> list[int]:
    return [(x * y) % Q for x, y in zip(a, b)]


# ------------------------------------------------------------- parameters
class _P:
    def __init__(self, k, l, eta, tau, beta, gamma1, gamma2, omega, lam,
                 name):
        self.k, self.l = k, l
        self.eta, self.tau, self.beta = eta, tau, beta
        self.gamma1, self.gamma2 = gamma1, gamma2
        self.omega, self.lam = omega, lam
        self.name = name
        self.ctilde_bytes = 2 * lam // 8
        self.w1_bits = ((Q - 1) // (2 * gamma2)).bit_length()
        self.z_bits = (2 * gamma1 - 2 * beta - 1).bit_length()
        self.eta_bits = (2 * eta).bit_length()


P44 = _P(4, 4, 2, 39, 78, 2**17, (Q - 1) // 88, 80, 128, "ML-DSA-44")
P65 = _P(6, 5, 4, 49, 196, 2**19, (Q - 1) // 32, 55, 192, "ML-DSA-65")
P87 = _P(8, 7, 2, 60, 120, 2**19, (Q - 1) // 32, 75, 256, "ML-DSA-87")


# --------------------------------------------------------------- bit pack
def _pack(polys: list[list[int]], bits: int) -> bytes:
    out, acc, nbits = bytearray(), 0, 0
    mask = (1 << bits) - 1
    for poly in polys:
        for c in poly:
            acc |= (c & mask) << nbits
            nbits += bits
            while nbits >= 8:
                out.append(acc & 0xFF)
                acc >>= 8
                nbits -= 8
    if nbits:
        out.append(acc & 0xFF)
    return bytes(out)


def _unpack(buf: bytes, bits: int, npolys: int) -> list[list[int]]:
    polys, acc, nbits, pos = [], 0, 0, 0
    mask = (1 << bits) - 1
    for _ in range(npolys):
        poly = []
        for _ in range(N):
            while nbits < bits:
                acc |= buf[pos] << nbits
                pos += 1
                nbits += 8
            poly.append(acc & mask)
            acc >>= bits
            nbits -= bits
        polys.append(poly)
    return polys


# --------------------------------------------------------------- sampling
def _rej_ntt_poly(rho: bytes, j: int, i: int) -> list[int]:
    stream = hashlib.shake_128(rho + bytes([j, i])).digest(900)
    out: list[int] = []
    for t in range(0, len(stream), 3):
        v = (stream[t] | (stream[t + 1] << 8) | (stream[t + 2] << 16)) & 0x7FFFFF
        if v < Q:
            out.append(v)
            if len(out) == N:
                return out
    raise RuntimeError("RejNTTPoly exhausted")


def _rej_bounded(rhop: bytes, nonce: int, eta: int) -> list[int]:
    stream = hashlib.shake_256(rhop + nonce.to_bytes(2, "little")).digest(8704)
    out: list[int] = []
    if eta == 2:
        for b in stream:
            for v in (b & 0xF, b >> 4):
                if v < 2 * eta + 1:
                    out.append(eta - v)
                    if len(out) == N:
                        return out
    else:
        for v in stream:
            if v < 2 * eta + 1:
                out.append(eta - v)
                if len(out) == N:
                    return out
    raise RuntimeError("RejBoundedPoly exhausted")


def _expand_mask(rhop: bytes, nonce: int, gamma1: int) -> list[int]:
    bits = 18 if gamma1 == 2**17 else 20
    limit = 2 * gamma1 - 1
    stream = hashlib.shake_256(rhop + nonce.to_bytes(2, "little")).digest(1200)
    out: list[int] = []
    acc, nbits, pos = 0, 0, 0
    mask = (1 << bits) - 1
    while len(out) < N:
        while nbits < bits:
            acc |= stream[pos] << nbits
            pos += 1
            nbits += 8
        v = acc & mask
        acc >>= bits
        nbits -= bits
        if v < limit:
            out.append((gamma1 - 1) - v)
    return out


def _sample_in_ball(ctilde: bytes, tau: int) -> list[int]:
    c = [0] * N
    stream = hashlib.shake_256(ctilde).digest(8 + 300)
    signs = int.from_bytes(stream[:8], "little")
    pos = 8
    for i in range(N - tau, N):
        j = stream[pos]
        pos += 1
        while j > i:
            j = stream[pos]
            pos += 1
        c[i] = c[j]
        c[j] = 1 if (signs & 1) == 0 else Q - 1
        signs >>= 1
    return c


# ------------------------------------------------- decompose / hints
def _decompose(r: int, alpha: int) -> tuple[int, int]:
    rp = r % Q
    r0 = rp % alpha
    if r0 > alpha // 2:
        r0 -= alpha
    if rp - r0 == Q - 1:
        return 0, r0 - 1
    return (rp - r0) // alpha, r0


def _highbits(r: int, alpha: int) -> int:
    return _decompose(r, alpha)[0]


def _lowbits(r: int, alpha: int) -> int:
    return _decompose(r, alpha)[1]


def _make_hint(z: int, r: int, alpha: int) -> int:
    r1, _ = _decompose(r, alpha)
    return 1 if r1 != _highbits(r + z, alpha) else 0


def _use_hint(h: int, r: int, alpha: int) -> int:
    m = (Q - 1) // alpha
    r1, r0 = _decompose(r, alpha)
    if h == 0:
        return r1
    return (r1 + 1) % m if r0 > 0 else (r1 - 1) % m


def _power2round(r: int) -> tuple[int, int]:
    rp = r % Q
    r0 = rp % (1 << D)
    if r0 > (1 << (D - 1)):
        r0 -= 1 << D
    return (rp - r0) >> D, r0


def _norm_inf(polys: list[list[int]]) -> int:
    """Infinity norm, centering mod-q coefficients first."""
    m = 0
    for poly in polys:
        for c in poly:
            c %= Q
            if c > Q // 2:
                c -= Q
            a = abs(c)
            if a > m:
                m = a
    return m


# ---------------------------------------------------------------- ML-DSA
class MLDSA:
    def __init__(self, p: _P):
        self.p = p
        self.pk_bytes = 32 + p.k * N * 10 // 8
        self.sk_bytes = (128 + p.l * N * p.eta_bits // 8
                         + p.k * N * p.eta_bits // 8 + p.k * N * D // 8)
        self.sig_bytes = (p.ctilde_bytes + p.l * N * p.z_bits // 8
                          + p.omega + p.k)

    # -- keygen ---------------------------------------------------------
    def keygen(self, seed32: bytes | None = None):
        p = self.p
        seed32 = seed32 or os.urandom(32)
        h = hashlib.shake_256(seed32).digest(128)
        rho, rhop, K = h[:32], h[32:96], h[96:128]
        Ahat = [[_ntt(_rej_ntt_poly(rho, j, i)) for j in range(p.l)]
                for i in range(p.k)]
        s1 = [_rej_bounded(rhop, i, p.eta) for i in range(p.l)]
        s2 = [_rej_bounded(rhop, p.l + i, p.eta) for i in range(p.k)]
        s1hat = [_ntt(x) for x in s1]
        t = []
        for i in range(p.k):
            acc = [0] * N
            for j in range(p.l):
                acc = [(x + y) % Q
                       for x, y in zip(acc, _pointwise(Ahat[i][j], s1hat[j]))]
            t.append([(x + y) % Q for x, y in zip(_intt(acc), s2[i])])
        t1, t0 = [], []
        for poly in t:
            a1, a0 = [], []
            for c in poly:
                r1, r0 = _power2round(c)
                a1.append(r1)
                a0.append(r0)
            t1.append(a1)
            t0.append(a0)
        pk = rho + _pack(t1, 10)
        tr = hashlib.shake_256(pk).digest(64)
        sk = (rho + K + tr
              + _pack([[p.eta - c for c in poly] for poly in s1], p.eta_bits)
              + _pack([[p.eta - c for c in poly] for poly in s2], p.eta_bits)
              + _pack([[(1 << (D - 1)) - c for c in poly] for poly in t0], D))
        assert len(pk) == self.pk_bytes, (len(pk), self.pk_bytes)
        assert len(sk) == self.sk_bytes, (len(sk), self.sk_bytes)
        return pk, sk

    def _expandA(self, rho: bytes):
        p = self.p
        return [[_ntt(_rej_ntt_poly(rho, j, i)) for j in range(p.l)]
                for i in range(p.k)]

    # -- sign -----------------------------------------------------------
    def sign(self, sk: bytes, msg: bytes, rnd32: bytes | None = None):
        p = self.p
        rho, K, tr = sk[:32], sk[32:64], sk[64:128]
        pos = 128
        l1 = p.l * N * p.eta_bits // 8
        s1 = [[p.eta - c for c in poly]
              for poly in _unpack(sk[pos:pos + l1], p.eta_bits, p.l)]
        pos += l1
        l2 = p.k * N * p.eta_bits // 8
        s2 = [[p.eta - c for c in poly]
              for poly in _unpack(sk[pos:pos + l2], p.eta_bits, p.k)]
        pos += l2
        t0 = [[(1 << (D - 1)) - c for c in poly]
              for poly in _unpack(sk[pos:], D, p.k)]
        Ahat = self._expandA(rho)
        s1hat = [_ntt(x) for x in s1]
        s2hat = [_ntt(x) for x in s2]
        t0hat = [_ntt(x) for x in t0]
        mu = hashlib.shake_256(tr + msg).digest(64)
        rhoprime = hashlib.shake_256(K + (rnd32 or b"") + mu).digest(64)
        alpha = 2 * p.gamma2
        kappa = 0
        while True:
            y = [_expand_mask(rhoprime, kappa + i, p.gamma1)
                 for i in range(p.l)]
            kappa += p.l
            yhat = [_ntt(x) for x in y]
            w = []
            for i in range(p.k):
                acc = [0] * N
                for j in range(p.l):
                    acc = [(x + y_) % Q for x, y_ in
                           zip(acc, _pointwise(Ahat[i][j], yhat[j]))]
                w.append(_intt(acc))
            w1 = [[_highbits(c, alpha) for c in poly] for poly in w]
            ctilde = hashlib.shake_256(mu + _pack(w1, p.w1_bits)).digest(
                p.ctilde_bytes)
            c = _sample_in_ball(ctilde, p.tau)
            chat = _ntt(c)
            z = []
            for i in range(p.l):
                z.append([(a + b) % Q for a, b in
                          zip(y[i], _intt(_pointwise(chat, s1hat[i])))])
            zc = [c if c <= Q // 2 else c - Q for poly in z for c in poly]
            if max(abs(c) for c in zc) >= p.gamma1 - p.beta:
                continue
            cs2 = [_intt(_pointwise(chat, s2hat[i])) for i in range(p.k)]
            w_cs2 = [[(a - b) % Q for a, b in zip(w[i], cs2[i])]
                     for i in range(p.k)]
            w0 = [[_lowbits(c, alpha) for c in poly] for poly in w_cs2]
            if _norm_inf(w0) >= p.gamma2 - p.beta:
                continue
            ct0 = [_intt(_pointwise(chat, t0hat[i])) for i in range(p.k)]
            if _norm_inf(ct0) >= p.gamma2:
                continue
            h = []
            for i in range(p.k):
                hi = []
                for a, b in zip(w_cs2[i], ct0[i]):
                    hi.append(_make_hint(-b, (a + b) % Q, alpha))
                h.append(hi)
            if sum(sum(poly) for poly in h) > p.omega:
                continue
            zenc = _pack([[(p.gamma1 - p.beta - 1) - (c if c <= Q // 2 else c - Q)
                            for c in poly] for poly in z], p.z_bits)
            sig = ctilde + zenc + self._hpack(h)
            assert len(sig) == self.sig_bytes, (len(sig), self.sig_bytes)
            return sig

    def _hpack(self, h: list[list[int]]) -> bytes:
        out = bytearray()
        for poly in h:
            idx = [j for j, v in enumerate(poly) if v]
            out.append(len(idx))
            out.extend(idx)
        # pad to the fixed FIPS 204 length: omega + k bytes
        out.extend(bytes(self.p.omega + self.p.k - len(out)))
        assert len(out) == self.p.omega + self.p.k
        return bytes(out)

    def _hunpack(self, buf: bytes) -> list[list[int]] | None:
        p = self.p
        h, pos, total = [], 0, 0
        for _ in range(p.k):
            if pos >= len(buf):
                return None
            n = buf[pos]
            pos += 1
            if pos + n > len(buf):
                return None
            idx = list(buf[pos:pos + n])
            pos += n
            if any(v >= N for v in idx) or idx != sorted(idx) or len(set(idx)) != n:
                return None
            total += n
            poly = [0] * N
            for j in idx:
                poly[j] = 1
            h.append(poly)
        if total > p.omega or any(b != 0 for b in buf[pos:]):
            return None
        return h

    # -- verify ---------------------------------------------------------
    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        p = self.p
        try:
            if len(pk) != self.pk_bytes or len(sig) != self.sig_bytes:
                return False
            rho = pk[:32]
            t1 = _unpack(pk[32:], 10, p.k)
            ctilde = sig[:p.ctilde_bytes]
            pos = p.ctilde_bytes
            zl = p.l * N * p.z_bits // 8
            z = [[(p.gamma1 - p.beta - 1) - c for c in poly]
                 for poly in _unpack(sig[pos:pos + zl], p.z_bits, p.l)]
            if _norm_inf(z) >= p.gamma1 - p.beta:
                return False
            h = self._hunpack(sig[pos + zl:])
            if h is None:
                return False
            Ahat = self._expandA(rho)
            c = _sample_in_ball(ctilde, p.tau)
            chat, zhat = _ntt(c), [_ntt(x) for x in z]
            t1s = [[(c * (1 << D)) % Q for c in poly] for poly in t1]
            t1hat = [_ntt(x) for x in t1s]
            wapprox = []
            for i in range(p.k):
                acc = [0] * N
                for j in range(p.l):
                    acc = [(x + y) % Q for x, y in
                           zip(acc, _pointwise(Ahat[i][j], zhat[j]))]
                sub = [0] * N
                sub = [(x - y) % Q for x, y in
                       zip(acc, _pointwise(chat, t1hat[i]))]
                wapprox.append(_intt(sub))
            alpha = 2 * p.gamma2
            w1p = [[_use_hint(h[i][j], wapprox[i][j], alpha)
                    for j in range(N)] for i in range(p.k)]
            tr = hashlib.shake_256(pk).digest(64)
            mu = hashlib.shake_256(tr + msg).digest(64)
            ctilde2 = hashlib.shake_256(mu + _pack(w1p, p.w1_bits)).digest(
                p.ctilde_bytes)
            return ctilde2 == ctilde
        except Exception:
            return False


mldsa_44 = MLDSA(P44)
mldsa_65 = MLDSA(P65)
mldsa_87 = MLDSA(P87)

# Default: the recommended general-purpose parameter set.
keygen = mldsa_65.keygen
sign = mldsa_65.sign
verify = mldsa_65.verify
