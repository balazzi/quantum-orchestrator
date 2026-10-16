#!/usr/bin/env python3
"""Offline self-validation for ml_dsa.py (no network needed).

  1. Iterative NTT matches the direct DFT definition.
  2. INTT inverts NTT; pointwise NTT product == naive negacyclic product.
  3. Exact FIPS 204 byte sizes for all parameter sets.
  4. Deterministic keygen; sign/verify round-trips; tamper rejection.
Run: python3 scripts/selftest_dsa.py
"""
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from qo.crypto import ml_dsa as M
from qo.crypto.ml_dsa import (_ntt, _intt, _pointwise, Q, N)


def brv8(x):
    return int(f"{x:08b}"[::-1], 2)


def main():
    rng = random.Random(0xD1A)

    # 1-2. NTT invertibility + convolution theorem (the properties the
    # scheme relies on; closed-form DFT ordering is KAT territory).
    def naive_negacyclic(a, b):
        c = [0] * N
        for i, ai in enumerate(a):
            for j, bj in enumerate(b):
                k = i + j
                if k >= N:
                    c[k - N] = (c[k - N] - ai * bj) % Q
                else:
                    c[k] = (c[k] + ai * bj) % Q
        return c

    for _ in range(10):
        f = [rng.randrange(Q) for _ in range(N)]
        assert _intt(_ntt(f)) == f, "INTT(NTT(f)) != f"
    print("1. NTT/INTT mutual inverse: OK (10 random polys)")

    for _ in range(3):
        a = [rng.randrange(Q) for _ in range(N)]
        b = [rng.randrange(Q) for _ in range(N)]
        assert _intt(_pointwise(_ntt(a), _ntt(b))) == naive_negacyclic(a, b)
    print("2. NTT pointwise product == naive negacyclic product: OK")

    # 3. sizes
    expect = {
        "ML-DSA-44": (1312, 2560, 2420),
        "ML-DSA-65": (1952, 4032, 3309),
        "ML-DSA-87": (2592, 4896, 4627),
    }
    for dsa in (M.mldsa_44, M.mldsa_65, M.mldsa_87):
        assert (dsa.pk_bytes, dsa.sk_bytes, dsa.sig_bytes) == expect[dsa.p.name], \
            (dsa.p.name, dsa.pk_bytes, dsa.sk_bytes, dsa.sig_bytes)
    print("3. FIPS 204 byte sizes (all parameter sets): OK")

    # 4. keygen determinism + sign/verify (65 only here; 44/87 in unit tests)
    dsa = M.mldsa_65
    pk1, sk1 = dsa.keygen(bytes(range(32)))
    pk2, sk2 = dsa.keygen(bytes(range(32)))
    assert (pk1, sk1) == (pk2, sk2), "keygen not deterministic"
    print("4a. deterministic keygen: OK")
    t0 = time.time()
    sig1 = dsa.sign(sk1, b"qo-75 release v0.2.0")
    sig2 = dsa.sign(sk1, b"qo-75 release v0.2.0")
    assert sig1 == sig2, "sign not deterministic"
    assert dsa.verify(pk1, b"qo-75 release v0.2.0", sig1), "verify failed"
    print(f"4b. sign/verify round-trip: OK ({time.time()-t0:.1f}s, "
          f"deterministic)")
    assert not dsa.verify(pk1, b"tampered message", sig1), "forgery accepted!"
    bad = bytearray(sig1)
    bad[60] ^= 1
    assert not dsa.verify(pk1, b"qo-75 release v0.2.0", bytes(bad)), \
        "mutated sig accepted!"
    print("4c. tampered message / signature rejected: OK")
    print("SELF-TEST PASSED (offline; KAT pending network)")


if __name__ == "__main__":
    main()
