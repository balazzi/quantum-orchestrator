"""ML-KEM (FIPS 203) tests — offline, no network required.

Covers all three parameter sets: exact FIPS 203 sizes, determinism,
encap/decap agreement, tamper closure, and wrong-key rejection.
For Wycheproof KAT vectors, run scripts/verify_kat.py with network.
"""
import unittest

from qo.crypto import ml_kem


class TestMLKEM(unittest.TestCase):
    KEMS = (ml_kem.ml_kem_512, ml_kem.ml_kem_768, ml_kem.ml_kem_1024)
    SIZES = {
        "ML-KEM-512": (800, 1632, 768),
        "ML-KEM-768": (1184, 2400, 1088),
        "ML-KEM-1024": (1568, 3168, 1568),
    }

    def test_fips203_sizes(self):
        for kem in self.KEMS:
            ek, dk = kem.keygen(bytes(range(64)))
            c, _ = kem.encaps(ek, bytes([1]) * 32)
            ek_n, dk_n, ct_n = self.SIZES[kem.name]
            self.assertEqual((len(ek), len(dk), len(c)), (ek_n, dk_n, ct_n),
                             kem.name)

    def test_deterministic_keygen(self):
        for kem in self.KEMS:
            seed = bytes([kem.p.k]) * 64
            self.assertEqual(kem.keygen(seed), kem.keygen(seed), kem.name)

    def test_roundtrip(self):
        for kem in self.KEMS:
            ek, dk = kem.keygen()
            c, ss1 = kem.encaps(ek)
            self.assertEqual(ss1, kem.decaps(dk, c), kem.name)
            self.assertEqual(len(ss1), 32)

    def test_tamper_closed(self):
        kem = ml_kem.ml_kem_768
        ek, dk = kem.keygen()
        c, ss1 = kem.encaps(ek)
        bad = bytearray(c)
        bad[512] ^= 0xFF
        self.assertNotEqual(ss1, kem.decaps(dk, bytes(bad)))

    def test_wrong_key(self):
        kem = ml_kem.ml_kem_768
        ek, _ = kem.keygen()
        _, dk2 = kem.keygen()
        c, ss1 = kem.encaps(ek)
        self.assertNotEqual(ss1, kem.decaps(dk2, c))

    def test_default_is_768(self):
        ek, dk = ml_kem.keygen()
        c, ss1 = ml_kem.encaps(ek)
        self.assertEqual(len(ek), 1184)
        self.assertEqual(ss1, ml_kem.decaps(dk, c))


if __name__ == "__main__":
    unittest.main()
