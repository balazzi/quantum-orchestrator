#!/usr/bin/env python3
"""Offline self-validation for ml_kem.py (no network needed).

Checks the mathematical machinery independently of the KEM logic:
  1. NTT/INTT are mutual inverses on random polynomials.
  2. NTT-domain basemul matches naive cyclic convolution.
  3. Byte encode/decode and compress/decompress round-trip.
  4. KEM keygen is deterministic per seed; encaps/decaps agree for all
     three parameter sets; tampered ciphertexts fail closed.
Run: python3 scripts/selftest_kem.py
"""
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from qo.crypto import ml_kem as M
from qo.crypto.ml_kem import (_ntt, _intt, _basemul, _encode, _decode,
                              _compress, _decompress, Q, N)


def naive_mul(a, b):
    c = [0] * N
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            c[(i + j) % N] = (c[(i + j) % N] + ai * bj) % Q
    return c


def main():
    rng = random.Random(0xC0FFEE)
    # 1. NTT round-trip
    for _ in range(20):
        f = [rng.randrange(Q) for _ in range(N)]
        assert _intt(_ntt(f)) == f, "NTT/INTT not inverse"
    print("1. NTT/INTT inverse: OK (20 random polys)")

    # 2. basemul == naive cyclic convolution (NTT is over x^256+1? see note)
    # FIPS 203 NTT multiplication is negacyclic-aware via basemul; compare
    # against INTT(basemul(NTT(a), NTT(b))) == naive negacyclic product.
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
    for _ in range(5):
        a = [rng.randrange(Q) for _ in range(N)]
        b = [rng.randrange(Q) for _ in range(N)]
        got = _intt(_basemul(_ntt(a), _ntt(b)))
        assert got == naive_negacyclic(a, b), "basemul mismatch"
    print("2. NTT multiplication == naive negacyclic product: OK")

    # 3. codec round-trips
    for d in (1, 4, 5, 10, 11, 12):
        f = [rng.randrange(1 << d) for _ in range(N)]
        assert _decode(_encode(f, d), d) == f, f"codec d={d}"
        g = [rng.randrange(Q) for _ in range(N)]
        assert _decompress(_compress(g, d), d) == [
            ((v * Q) + (1 << (d - 1))) >> d for v in
            [(((c << (d + 1)) + Q) // (2 * Q)) & ((1 << d) - 1) for c in g]], f"compress d={d}"
    print("3. ByteEncode/Decode + Compress/Decompress: OK")

    # 4. KEM: determinism, agreement, tamper, all parameter sets
    for kem in (M.ml_kem_512, M.ml_kem_768, M.ml_kem_1024):
        seed = bytes(rng.randrange(256) for _ in range(64))
        ek1, dk1 = kem.keygen(seed)
        ek2, dk2 = kem.keygen(seed)
        assert ek1 == ek2 and dk1 == dk2, f"{kem.name} not deterministic"
        assert len(ek1) == kem.ek_bytes and len(dk1) == kem.dk_bytes
        c, ss1 = kem.encaps(ek1)
        assert len(c) == kem.ct_bytes
        ss2 = kem.decaps(dk1, c)
        assert ss1 == ss2, f"{kem.name} agreement failed"
        bad = bytearray(c)
        bad[50] ^= 1
        assert kem.decaps(dk1, bytes(bad)) != ss1, f"{kem.name} tamper not rejected"
        _, dk_other = kem.keygen()
        assert kem.decaps(dk_other, c) != ss1
        print(f"4. {kem.name}: deterministic, agree, tamper-closed OK "
              f"(ek={kem.ek_bytes}B ct={kem.ct_bytes}B dk={kem.dk_bytes}B)")
    print("SELF-TEST PASSED (offline; run scripts/verify_kat.py with network for KAT)")


if __name__ == "__main__":
    main()
