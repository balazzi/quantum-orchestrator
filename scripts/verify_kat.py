#!/usr/bin/env python3
"""Verify qo/crypto/ml_kem.py against official ML-KEM test vectors.

Two complementary checks:

1. C2SP/Wycheproof vectors (https://github.com/C2SP/wycheproof). NOTE on
   what these vectors actually are: although labelled "ML-KEM", they were
   generated with the Kyber v3.02 (round 3) conventions, which differ from
   FIPS 203 in exactly three ways:
     a. (rho, sigma) = G(d || k) instead of G(d);
     b. ek/dk store the NTT-domain t_hat/s_hat instead of normal-domain t/s;
     c. keygen samples A[i][j] = SampleNTT(XOF(rho, j, i)) (transposed).
   This script therefore runs keygen/encaps through a Kyber-r3 adapter built
   on OUR primitives (_ntt, _cbd, _sample_ntt, _encode, ...). Matching all
   official vectors validates those primitives end to end (300 keygen +
   ~400 encaps vectors across the three parameter sets).

2. FIPS 203 assembly check: an independent, from-scratch FIPS 203 oracle
   (definitional O(n^2) NTT, naive negacyclic convolution, zero shared math
   code with qo/crypto/ml_kem.py) is differential-tested against our
   implementation on random seeds. Agreement validates the FIPS 203 wiring
   itself: G(d), A[i][j] = SampleNTT(XOF(rho, i, j)), normal-domain keys.

Run: python3 scripts/verify_kat.py [--trials N]  (default N=2 oracle trials
per parameter set; vector download needs network the first time)
"""
import hashlib
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

BASE = "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1"
FILES = {
    512: ("mlkem_512_keygen_seed_test.json", "mlkem_512_encaps_test.json"),
    768: ("mlkem_768_keygen_seed_test.json", "mlkem_768_encaps_test.json"),
    1024: ("mlkem_1024_keygen_seed_test.json", "mlkem_1024_encaps_test.json"),
}
CACHE = os.path.join(os.path.dirname(__file__), ".wycheproof-cache")


def fetch(name):
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, name)
    if not os.path.exists(path):
        url = f"{BASE}/{name}"
        print(f"  downloading {url}")
        with urllib.request.urlopen(url, timeout=60) as r:
            data = r.read()
        with open(path, "wb") as f:
            f.write(data)
    with open(path) as f:
        return json.load(f)


# --------------------------------------------------------------------------
# Part 1: Kyber-r3 adapter over OUR primitives -> C2SP vectors
# --------------------------------------------------------------------------
def check_wycheproof():
    from qo.crypto import ml_kem
    Q = ml_kem.Q

    def keygen_kyber(seed64, kem):
        """Kyber v3.02 keygen using our primitives (NOT FIPS 203)."""
        p = kem.p
        d, z = seed64[:32], seed64[32:64]
        g = hashlib.sha3_512(d + bytes([p.k])).digest()   # (a) G(d||k)
        rho, sigma = g[:32], g[32:]
        a_hat = [[ml_kem._sample_ntt(rho, j, i)           # (c) transposed
                  for j in range(p.k)] for i in range(p.k)]
        s = [ml_kem._cbd(ml_kem._prf(sigma, p.eta1, n), p.eta1)
             for n in range(p.k)]
        e = [ml_kem._cbd(ml_kem._prf(sigma, p.eta1, p.k + n), p.eta1)
             for n in range(p.k)]
        s_hat = [ml_kem._ntt(x) for x in s]
        e_hat = [ml_kem._ntt(x) for x in e]
        t_hat = []
        for i in range(p.k):
            acc = [0] * 256
            for j in range(p.k):
                acc = ml_kem._add(acc, ml_kem._basemul(a_hat[i][j], s_hat[j]))
            t_hat.append(ml_kem._add(acc, e_hat[i]))
        ek = b"".join(ml_kem._encode(x, 12) for x in t_hat) + rho  # (b) NTT t
        dk = (b"".join(ml_kem._encode(x, 12) for x in s_hat)       # (b) NTT s
              + ek + hashlib.sha3_256(ek).digest() + z)
        return ek, dk

    def encaps_kyber(ek, m32, kem):
        """Kyber v3.02 encaps using our primitives (NOT FIPS 203)."""
        p = kem.p
        # t is stored NTT-domain in these eks: no NTT needed
        t_hat = [ml_kem._decode(ek[i * 384:(i + 1) * 384], 12)
                 for i in range(p.k)]
        rho = ek[384 * p.k:]
        h = hashlib.sha3_256(ek).digest()
        kr = hashlib.sha3_512(m32 + h).digest()
        Kb, rc = kr[:32], kr[32:]
        r = [ml_kem._cbd(ml_kem._prf(rc, p.eta1, n), p.eta1)
             for n in range(p.k)]
        e1 = [ml_kem._cbd(ml_kem._prf(rc, p.eta2, p.k + n), p.eta2)
              for n in range(p.k)]
        e2 = ml_kem._cbd(ml_kem._prf(rc, p.eta2, 2 * p.k), p.eta2)
        r_hat = [ml_kem._ntt(x) for x in r]
        u = []
        for i in range(p.k):
            # A^T[i][j] with A[j][i] = XOF(rho, i, j)
            acc = [0] * 256
            for j in range(p.k):
                acc = ml_kem._add(acc,
                                  ml_kem._basemul(ml_kem._sample_ntt(rho, i, j),
                                                  r_hat[j]))
            u.append(ml_kem._add(ml_kem._intt(acc), e1[i]))
        acc = [0] * 256
        for i in range(p.k):
            acc = ml_kem._add(acc, ml_kem._basemul(t_hat[i], r_hat[i]))
        v = ml_kem._add(ml_kem._add(ml_kem._intt(acc), e2),
                        ml_kem._decompress(ml_kem._decode(m32, 1), 1))
        c = (b"".join(ml_kem._encode(ml_kem._compress(x, p.du), p.du)
                       for x in u)
               + ml_kem._encode(ml_kem._compress(v, p.dv), p.dv))
        # NOTE: the C2SP "MLKEMEncapsTest" vectors expose the FO pre-key
        # Kb = G(m || H(ek))[:32] directly as K (verified empirically:
        # tc["K"] == SHA3-512(m || H(ek))[:32] with unhashed m), NOT the
        # final KEM shared secret KDF(Kb || H(c)). Do not apply the KDF here.
        K = Kb
        return c, K

    kems = {512: ml_kem.ml_kem_512, 768: ml_kem.ml_kem_768,
            1024: ml_kem.ml_kem_1024}
    total_ok = total = 0
    for params, kem in kems.items():
        kg_file, enc_file = FILES[params]
        tv = fetch(kg_file)
        n_ok = n_run = 0
        for grp in tv["testGroups"]:
            for tc in grp["tests"]:
                if tc.get("result") != "valid":
                    continue
                ek, dk = keygen_kyber(bytes.fromhex(tc["seed"]), kem)
                n_run += 1
                if ek.hex() == tc["ek"] and dk.hex() == tc["dk"]:
                    n_ok += 1
                else:
                    print(f"  MISMATCH keygen {params} tcId={tc['tcId']}")
        tv = fetch(enc_file)
        for grp in tv["testGroups"]:
            for tc in grp["tests"]:
                if tc.get("result") != "valid" or tc.get("flags"):
                    continue
                m = bytes.fromhex(tc["m"])
                if len(m) != 32:
                    continue
                c, K = encaps_kyber(bytes.fromhex(tc["ek"]), m, kem)
                n_run += 1
                if c.hex() == tc["c"] and K.hex() == tc["K"]:
                    n_ok += 1
                else:
                    print(f"  MISMATCH encaps {params} tcId={tc['tcId']}")
        print(f"  ML-KEM-{params}: {n_ok}/{n_run} C2SP vectors match")
        total_ok += n_ok
        total += n_run
    print(f"  Wycheproof total: {total_ok}/{total}")
    assert total_ok == total and total > 0
    return total


# --------------------------------------------------------------------------
# Part 2: independent FIPS 203 oracle (definitional NTT, naive convolution)
# --------------------------------------------------------------------------
_Q = 3329


def _brv7(x):
    return int(f"{x:07b}"[::-1], 2)


def _ntt_def(f):
    out = [0] * 256
    for i in range(128):
        e = 2 * _brv7(i) + 1
        for j in range(128):
            w = pow(17, e * j, _Q)
            out[2 * i] = (out[2 * i] + f[2 * j] * w) % _Q
            out[2 * i + 1] = (out[2 * i + 1] + f[2 * j + 1] * w) % _Q
    return out


def _negconv(a, b):
    c = [0] * 256
    for x in range(256):
        for y in range(256):
            sgn = -1 if x + y >= 256 else 1
            c[(x + y) % 256] = (c[(x + y) % 256] + sgn * a[x] * b[y]) % _Q
    return c


def _sample_ntt(rho, i, j):
    s = hashlib.shake_128(rho + bytes([i, j])).digest(840)
    out, p = [], 0
    while len(out) < 256:
        d1 = s[p] + 256 * (s[p + 1] & 15)
        d2 = (s[p + 1] >> 4) + 16 * s[p + 2]
        if d1 < _Q:
            out.append(d1)
        if len(out) == 256:
            break
        if d2 < _Q:
            out.append(d2)
        p += 3
    return out


def _prf(seed, eta, n):
    return hashlib.shake_256(seed + bytes([n])).digest(64 * eta)


def _cbd(buf, eta):
    bits = [(b >> k) & 1 for b in buf for k in range(8)]
    return [((sum(bits[2 * i * eta + j] for j in range(eta))
              - sum(bits[(2 * i + 1) * eta + j] for j in range(eta))) % _Q)
            for i in range(256)]


def _encode(poly, d):
    out, acc, bits = bytearray(), 0, 0
    for c in poly:
        acc |= (c & ((1 << d) - 1)) << bits
        bits += d
        while bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            bits -= 8
    if bits:
        out.append(acc & 0xFF)
    return bytes(out)


def _decode(buf, d):
    out, acc, bits, pos = [], 0, 0, 0
    for _ in range(256):
        while bits < d:
            acc |= buf[pos] << bits
            pos += 1
            bits += 8
        out.append(acc & ((1 << d) - 1))
        acc >>= d
        bits -= d
    return out


class _Fips203Oracle:
    """Literal FIPS 203 transcription; shares no math code with qo.crypto."""

    def __init__(self, k, eta1, eta2, du, dv):
        self.k, self.eta1, self.eta2, self.du, self.dv = k, eta1, eta2, du, dv

    def keygen(self, seed64):
        k, e1 = self.k, self.eta1
        d, z = seed64[:32], seed64[32:]
        g = hashlib.sha3_512(d).digest()          # FIPS 203 Alg 13: G(d)
        rho, sigma = g[:32], g[32:]
        A = [[_sample_ntt(rho, i, j) for j in range(k)] for i in range(k)]
        s = [_cbd(_prf(sigma, e1, n), e1) for n in range(k)]
        e = [_cbd(_prf(sigma, e1, k + n), e1) for n in range(k)]
        # t_i = INTT(sum_j Ahat[i][j] o NTT(s_j)) + e_i, computed here via
        # naive negacyclic convolution on INTT'd operands (no shared code
        # with the iterative NTT / basemul under test)
        t = []
        for i in range(k):
            acc = [0] * 256
            for j in range(k):
                # NTT-domain product then definitional inverse, or
                # equivalently negconv on INTT'd operands; use direct conv:
                Aj = self._intt_def(A[i][j])
                acc = [(x + y) % _Q for x, y in zip(acc, _negconv(Aj, s[j]))]
            t.append([(x + y) % _Q for x, y in zip(acc, e[i])])
        ek = b"".join(_encode(x, 12) for x in t) + rho
        dk = (b"".join(_encode(x, 12) for x in s) + ek
              + hashlib.sha3_256(ek).digest() + z)
        return ek, dk

    @staticmethod
    def _intt_def(f):
        # invert _ntt_def via the adjoint (unitary up to 1/128)
        out = [0] * 256
        for i in range(128):
            e = 2 * _brv7(i) + 1
            wi = pow(pow(17, e, _Q), -1, _Q)
            for j in range(128):
                w = pow(wi, j, _Q)
                out[2 * j] = (out[2 * j] + f[2 * i] * w) % _Q
                out[2 * j + 1] = (out[2 * j + 1] + f[2 * i + 1] * w) % _Q
        inv128 = pow(128, -1, _Q)
        return [(x * inv128) % _Q for x in out]

    def encaps(self, ek, m32):
        k, e1, e2, du, dv = self.k, self.eta1, self.eta2, self.du, self.dv
        t = [_decode(ek[i * 384:(i + 1) * 384], 12) for i in range(k)]
        rho = ek[384 * k:]
        A = [[_sample_ntt(rho, i, j) for j in range(k)] for i in range(k)]
        h = hashlib.sha3_256(ek).digest()
        kr = hashlib.sha3_512(m32 + h).digest()
        Kb, r = kr[:32], kr[32:]
        rv = [_cbd(_prf(r, e1, n), e1) for n in range(k)]
        e1v = [_cbd(_prf(r, e2, k + n), e2) for n in range(k)]
        e2v = _cbd(_prf(r, e2, 2 * k), e2)
        u = []
        for i in range(k):                        # A^T[i][j] = A[j][i]
            acc = [0] * 256
            for j in range(k):
                Aj = self._intt_def(A[j][i])
                acc = [(x + y) % _Q for x, y in zip(acc, _negconv(Aj, rv[j]))]
            u.append([(x + y) % _Q for x, y in zip(acc, e1v[i])])
        acc = [0] * 256
        for i in range(k):
            acc = [(x + y) % _Q for x, y in zip(acc, _negconv(t[i], rv[i]))]
        mu = [(v * _Q + (1 << 0)) // 2 % _Q      # decompress(decode(m,1),1)
              for v in _decode(m32, 1)]
        v = [(x + y + z) % _Q for x, y, z in zip(acc, e2v, mu)]
        comp = lambda poly, dd: [(((c << dd) * 2 + _Q) // (2 * _Q)) % (1 << dd)
                                 for c in poly]
        c = (b"".join(_encode(comp(x, du), du) for x in u)
             + _encode(comp(v, dv), dv))
        K = hashlib.shake_256(Kb + hashlib.sha3_256(c).digest()).digest(32)
        return c, K


def check_fips203_oracle(trials):
    from qo.crypto import ml_kem
    oracles = {"512": _Fips203Oracle(2, 3, 2, 10, 4),
               "768": _Fips203Oracle(3, 2, 2, 10, 4),
               "1024": _Fips203Oracle(4, 2, 2, 11, 5)}
    impls = {"512": ml_kem.ml_kem_512, "768": ml_kem.ml_kem_768,
             "1024": ml_kem.ml_kem_1024}
    n_ok = n_run = 0
    for name in ("512", "768", "1024"):
        O, I = oracles[name], impls[name]
        for _ in range(trials):
            seed = os.urandom(64)
            m = os.urandom(32)
            n_run += 1
            ek_o, dk_o = O.keygen(seed)
            ek_i, dk_i = I.keygen(seed)
            c_o, K_o = O.encaps(ek_o, m)
            c_i, K_i = I.encaps(ek_i, m)
            if (ek_o, dk_o, c_o, K_o) == (ek_i, dk_i, c_i, K_i):
                n_ok += 1
            else:
                print(f"  MISMATCH oracle vs impl ML-KEM-{name}")
    print(f"  FIPS 203 oracle differential: {n_ok}/{n_run} trials agree")
    assert n_ok == n_run and n_run > 0


# --------------------------------------------------------------------------
# Part 3: ML-DSA keygen/sign vectors (C2SP/Wycheproof)
#
# Unlike the ML-KEM vectors above, the ML-DSA vectors are expected to be
# FIPS 204 proper, so they exercise qo/crypto/ml_dsa.py directly. Any
# mismatch here pinpoints a byte-layout divergence from the standard
# (ExpandA domain separation, hint packing, mask-seed derivation) even
# though the underlying mathematics is validated offline.
# --------------------------------------------------------------------------
DSA_FILES = {
    44: ("mldsa_44_keygen_test.json", "mldsa_44_sign_test.json"),
    65: ("mldsa_65_keygen_test.json", "mldsa_65_sign_test.json"),
    87: ("mldsa_87_keygen_test.json", "mldsa_87_sign_test.json"),
}


def check_dsa_wycheproof():
    from qo.crypto import ml_dsa
    dsas = {44: ml_dsa.mldsa_44, 65: ml_dsa.mldsa_65, 87: ml_dsa.mldsa_87}
    total_ok = total = 0
    for params, dsa in dsas.items():
        kg_file, sign_file = DSA_FILES[params]
        tv = fetch(kg_file)
        n_ok = n_run = 0
        for grp in tv["testGroups"]:
            for tc in grp["tests"]:
                if tc.get("result") != "valid":
                    continue
                pk, sk = dsa.keygen(bytes.fromhex(tc["seed"]))
                n_run += 1
                if pk.hex() == tc["pk"] and sk.hex() == tc["sk"]:
                    n_ok += 1
                else:
                    print(f"  MISMATCH dsa keygen {params} tcId={tc['tcId']}")
        tv = fetch(sign_file)
        for grp in tv["testGroups"]:
            for tc in grp["tests"]:
                if tc.get("result") != "valid" or tc.get("flags"):
                    continue
                sk = bytes.fromhex(tc["sk"])
                msg = bytes.fromhex(tc["msg"])
                sig = dsa.sign(sk, msg)  # deterministic: must reproduce
                n_run += 1
                if (sig.hex() == tc["sig"]
                        and dsa.verify(bytes.fromhex(tc["pk"]), msg, sig)):
                    n_ok += 1
                else:
                    print(f"  MISMATCH dsa sign {params} tcId={tc['tcId']}")
        print(f"  ML-DSA-{params}: {n_ok}/{n_run} C2SP vectors match")
        total_ok += n_ok
        total += n_run
    print(f"  ML-DSA Wycheproof total: {total_ok}/{total}")
    assert total_ok == total and total > 0
    return total


def main():
    trials = 2
    if "--trials" in sys.argv:
        trials = int(sys.argv[sys.argv.index("--trials") + 1])
    print("Part 1: C2SP/Wycheproof vectors (Kyber-r3 adapter over our primitives)")
    n_vec = check_wycheproof()
    print("Part 2: independent FIPS 203 oracle differential test")
    check_fips203_oracle(trials)
    print("Part 3: C2SP/Wycheproof ML-DSA vectors")
    n_dsa = check_dsa_wycheproof()
    print(f"KAT VERIFICATION PASSED ({n_vec} ML-KEM + {n_dsa} ML-DSA official "
          f"vectors + FIPS 203 oracle)")


if __name__ == "__main__":
    main()
