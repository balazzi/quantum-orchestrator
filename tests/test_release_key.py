"""Release-key tooling tests: ML-DSA-65 release signing lifecycle.

Uses temp dirs only — never touches the real ~/.qo-75/release-signing.key —
except test_trust_anchor_matches_private_key, which proves the bundled
public key corresponds to the actual stored private key.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.join(os.path.dirname(__file__), "..")
TOOL = os.path.join(REPO, "scripts", "release_key.py")
REAL_SK = os.path.expanduser("~/.qo-75/release-signing.key")


def run_tool(*argv):
    return subprocess.run([sys.executable, TOOL, *argv],
                          capture_output=True, text=True)


class TestReleaseKeyTool(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.sk = os.path.join(self.d, "rel.key")
        self.pub = os.path.join(self.d, "rel.pub.hex")
        self.art = os.path.join(self.d, "qo-9.9.9.pkg")
        with open(self.art, "wb") as f:
            f.write(b"release bytes for tests")

    def test_gen_sign_check_roundtrip(self):
        r = run_tool("gen", "--out", self.sk, "--pub", self.pub)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(os.stat(self.sk).st_mode & 0o777, 0o600)
        man = os.path.join(self.d, "m.json")
        r = run_tool("sign", "--key", self.sk, "--artifact", self.art,
                     "--version", "9.9.9", "--url", "file://" + self.art,
                     "--out", man)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(man) as f:
            m = json.load(f)
        self.assertEqual(m["version"], "9.9.9")
        self.assertEqual(len(bytes.fromhex(m["signature"])), 3309)
        r = run_tool("check", "--manifest", man, "--pub", self.pub)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("VALID", r.stdout)

    def test_check_rejects_tampered_artifact(self):
        run_tool("gen", "--out", self.sk, "--pub", self.pub)
        man = os.path.join(self.d, "m.json")
        run_tool("sign", "--key", self.sk, "--artifact", self.art,
                 "--version", "9.9.9", "--url", "file://" + self.art,
                 "--out", man)
        with open(self.art, "wb") as f:
            f.write(b"tampered bytes")
        r = run_tool("check", "--manifest", man, "--pub", self.pub)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("INVALID", r.stdout)

    def test_check_rejects_wrong_key(self):
        run_tool("gen", "--out", self.sk, "--pub", self.pub)
        other = os.path.join(self.d, "other.key")
        other_pub = os.path.join(self.d, "other.pub.hex")
        run_tool("gen", "--out", other, "--pub", other_pub)
        man = os.path.join(self.d, "m.json")
        run_tool("sign", "--key", other, "--artifact", self.art,
                 "--version", "9.9.9", "--url", "file://" + self.art,
                 "--out", man)
        r = run_tool("check", "--manifest", man, "--pub", self.pub)
        self.assertNotEqual(r.returncode, 0)

    def test_gen_refuses_to_overwrite(self):
        run_tool("gen", "--out", self.sk, "--pub", self.pub)
        r = run_tool("gen", "--out", self.sk, "--pub", self.pub)
        self.assertEqual(r.returncode, 2)
        r = run_tool("gen", "--out", self.sk, "--pub", self.pub, "--force")
        self.assertEqual(r.returncode, 0)

    def test_trust_anchor_matches_private_key(self):
        """The bundled public key must match the stored release private key."""
        if not os.path.exists(REAL_SK):
            self.skipTest("no release key generated yet")
        sys.path.insert(0, REPO)
        from qo.crypto import dsa_sign, dsa_verify
        from qo.selfheal.supervisor import trusted_release_pubkey
        pk = trusted_release_pubkey()
        self.assertEqual(len(pk), 1952)
        with open(REAL_SK) as f:
            sk = bytes.fromhex(f.read().strip())
        sig = dsa_sign(sk, b"trust anchor binding check")
        self.assertTrue(dsa_verify(pk, b"trust anchor binding check", sig))

    def test_updater_accepts_tool_signed_manifest(self):
        """End to end: tool-signed manifest -> AutoUpdater.with_trusted_key."""
        if not os.path.exists(REAL_SK):
            self.skipTest("no release key generated yet")
        sys.path.insert(0, REPO)
        from qo.selfheal.supervisor import AutoUpdater
        man = os.path.join(self.d, "m.json")
        r = run_tool("sign", "--key", REAL_SK, "--artifact", self.art,
                     "--version", "9.9.9", "--url", "file://" + self.art,
                     "--out", man)
        self.assertEqual(r.returncode, 0, r.stderr)
        u = AutoUpdater.with_trusted_key("9.9.8", state_dir=self.d)
        with open(man) as f:
            self.assertTrue(u.apply(json.load(f)))
        self.assertEqual(u.current_version, "9.9.9")


if __name__ == "__main__":
    unittest.main()
