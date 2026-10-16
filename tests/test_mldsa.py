"""ML-DSA (FIPS 204) tests — offline, no network required.

Covers all three parameter sets: exact FIPS 204 sizes, determinism,
sign/verify round-trips, hedged signing, and tamper rejection.
For official KAT vectors, run scripts/verify_kat.py with network.
"""
import unittest

from qo.crypto import ml_dsa


class TestMLDSA(unittest.TestCase):
    DSAS = (ml_dsa.mldsa_44, ml_dsa.mldsa_65, ml_dsa.mldsa_87)
    SIZES = {
        "ML-DSA-44": (1312, 2560, 2420),
        "ML-DSA-65": (1952, 4032, 3309),
        "ML-DSA-87": (2592, 4896, 4627),
    }

    def test_fips204_sizes(self):
        for dsa in self.DSAS:
            pk, sk = dsa.keygen(bytes(range(32)))
            sig = dsa.sign(sk, b"size check")
            pk_n, sk_n, sg_n = self.SIZES[dsa.p.name]
            self.assertEqual((len(pk), len(sk), len(sig)), (pk_n, sk_n, sg_n),
                             dsa.p.name)

    def test_deterministic(self):
        for dsa in self.DSAS:
            pk1, sk1 = dsa.keygen(bytes([dsa.p.k]) * 32)
            pk2, sk2 = dsa.keygen(bytes([dsa.p.k]) * 32)
            self.assertEqual((pk1, sk1), (pk2, sk2), dsa.p.name)
            self.assertEqual(dsa.sign(sk1, b"m"), dsa.sign(sk1, b"m"),
                             dsa.p.name)

    def test_roundtrip(self):
        for dsa in self.DSAS:
            pk, sk = dsa.keygen()
            msg = b"qo-75 mldsa test " + dsa.p.name.encode()
            sig = dsa.sign(sk, msg)
            self.assertTrue(dsa.verify(pk, msg, sig), dsa.p.name)

    def test_hedged(self):
        dsa = ml_dsa.mldsa_65
        pk, sk = dsa.keygen()
        s1 = dsa.sign(sk, b"m", rnd32=b"\xAA" * 32)
        s2 = dsa.sign(sk, b"m", rnd32=b"\xBB" * 32)
        self.assertNotEqual(s1, s2)
        self.assertTrue(dsa.verify(pk, b"m", s1))
        self.assertTrue(dsa.verify(pk, b"m", s2))

    def test_tamper_rejected(self):
        dsa = ml_dsa.mldsa_65
        pk, sk = dsa.keygen()
        sig = dsa.sign(sk, b"original")
        self.assertFalse(dsa.verify(pk, b"forged", sig))
        bad = bytearray(sig)
        bad[100] ^= 0xFF
        self.assertFalse(dsa.verify(pk, b"original", bytes(bad)))
        # truncated / overlong inputs
        self.assertFalse(dsa.verify(pk, b"original", sig[:-1]))
        self.assertFalse(dsa.verify(pk[:-1], b"original", sig))

    def test_default_is_65(self):
        pk, sk = ml_dsa.keygen()
        sig = ml_dsa.sign(sk, b"m")
        self.assertEqual(len(pk), 1952)
        self.assertTrue(ml_dsa.verify(pk, b"m", sig))


if __name__ == "__main__":
    unittest.main()
