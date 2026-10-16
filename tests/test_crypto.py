"""Crypto round-trip + tamper tests (stdlib unittest)."""
import unittest

from qo.crypto import kem_keygen, encaps, decaps, HashSig


class TestKEM(unittest.TestCase):
    def test_roundtrip(self):
        pk, sk = kem_keygen()
        ct, ss1 = encaps(pk)
        ss2 = decaps(sk, ct)
        self.assertEqual(ss1, ss2)
        self.assertEqual(len(ss1), 32)

    def test_tamper_changes_secret(self):
        pk, sk = kem_keygen()
        ct, ss1 = encaps(pk)
        bad = bytearray(ct)
        bad[100] ^= 0xFF
        ss2 = decaps(sk, bytes(bad))
        self.assertNotEqual(ss1, ss2)  # FO implicit rejection

    def test_wrong_key_fails(self):
        pk, _ = kem_keygen()
        _, sk2 = kem_keygen()
        ct, ss1 = encaps(pk)
        self.assertNotEqual(ss1, decaps(sk2, ct))


class TestHashSig(unittest.TestCase):
    def test_roundtrip(self):
        s = HashSig(height=3)
        pub = s.public_key()
        for i in range(4):
            msg = f"message {i}".encode()
            b = s.sign(msg)
            self.assertTrue(HashSig.verify(pub, msg, b))

    def test_forgery_rejected(self):
        s = HashSig(height=3)
        pub = s.public_key()
        b = s.sign(b"original")
        self.assertFalse(HashSig.verify(pub, b"tampered", b))
        b2 = dict(b)
        sig = bytearray(bytes.fromhex(b2["sig"]))
        sig[0] ^= 1
        b2["sig"] = sig.hex()
        self.assertFalse(HashSig.verify(pub, b"original", b2))

    def test_stateful_counter(self):
        s = HashSig(height=2)
        s.sign(b"a")
        s.sign(b"b")
        self.assertEqual(s.next_idx, 2)


if __name__ == "__main__":
    unittest.main()
