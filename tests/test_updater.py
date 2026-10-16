"""AutoUpdater tests: ML-DSA (FIPS 204) signed update path.

Uses file:// URLs for artifact "downloads" so the real urllib code path is
exercised without network. bus=None to keep apply() synchronous.
"""
import json
import os
import tempfile
import unittest

from qo.crypto import dsa_keygen, dsa_sign
from qo.selfheal.supervisor import AutoUpdater


def _make_manifest(blob: bytes, sig_hex: str) -> dict:
    """Write blob to a temp file and return a manifest dict for it."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, "release.pkg")
    with open(path, "wb") as f:
        f.write(blob)
    return {"version": "0.2.0",
            "artifact_url": "file://" + path,
            "signature": sig_hex}


class TestMLDSAUpdater(unittest.TestCase):
    def setUp(self):
        self.pk, self.sk = dsa_keygen()
        self.state_dir = tempfile.mkdtemp()
        self.updater = AutoUpdater("0.1.0", self.pk, state_dir=self.state_dir)

    def test_valid_signature_applies(self):
        blob = b"quantum orchestrator release v0.2.0"
        sig = dsa_sign(self.sk, blob).hex()
        ok = self.updater.apply(_make_manifest(blob, sig))
        self.assertTrue(ok)
        self.assertEqual(self.updater.current_version, "0.2.0")
        dest = os.path.join(self.state_dir, "qo-0.2.0.pkg")
        self.assertTrue(os.path.exists(dest))
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), blob)

    def test_tampered_signature_rejected(self):
        blob = b"quantum orchestrator release v0.2.0"
        sig = bytearray(dsa_sign(self.sk, blob))
        sig[100] ^= 1
        ok = self.updater.apply(_make_manifest(blob, bytes(sig).hex()))
        self.assertFalse(ok)
        self.assertEqual(self.updater.current_version, "0.1.0")

    def test_wrong_message_rejected(self):
        blob = b"quantum orchestrator release v0.2.0"
        sig = dsa_sign(self.sk, b"something else").hex()
        ok = self.updater.apply(_make_manifest(blob, sig))
        self.assertFalse(ok)
        self.assertEqual(self.updater.current_version, "0.1.0")

    def test_legacy_hashsig_bundle_rejected(self):
        blob = b"quantum orchestrator release v0.2.0"
        manifest = _make_manifest(blob, "")
        manifest["signature"] = {"height": 6, "idx": 0,  # not hex: malformed
                                 "sig": "00", "auth": "00"}
        ok = self.updater.apply(manifest)
        self.assertFalse(ok)
        self.assertEqual(self.updater.current_version, "0.1.0")


if __name__ == "__main__":
    unittest.main()
