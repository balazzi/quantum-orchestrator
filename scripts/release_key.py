#!/usr/bin/env python3
"""QO-75 release key management (ML-DSA-65, FIPS 204).

The auto-updater (qo/selfheal/supervisor.py) applies an update only if its
manifest carries a valid ML-DSA-65 signature from the release key. This tool
owns the whole release-signing lifecycle:

    python3 scripts/release_key.py gen
        Generate a fresh ML-DSA-65 release keypair. The private key lands at
        ~/.qo-75/release-signing.key (mode 0600); the public key is written to
        qo/selfheal/trusted_release_key.hex (the trust anchor the updater
        loads via trusted_release_pubkey()). Prints the key fingerprint and a
        ready-to-paste wiring snippet.

    python3 scripts/release_key.py sign --artifact FILE --version VER --url URL
        Sign an artifact with the private key and emit a manifest JSON
        (version / artifact_url / signature-hex) the updater accepts.

    python3 scripts/release_key.py check --manifest manifest.json
        Download the artifact and verify its signature against the trusted
        public key. Works offline for file:// URLs.

    python3 scripts/release_key.py rotate
        Same as gen, plus prints the rotation checklist.

Security notes: keep the private key offline or in a vault; only the public
key ships with the project. Signing uses hedged mode (fresh OS randomness
mixed into each signature). Rotation = gen a new pair, replace the bundled
public key, cut a new signed manifest. Compromise = rotate immediately and
note that previously deployed updaters still trust the OLD key until they
apply the next update — there is no in-band revocation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from qo.crypto import dsa_keygen, dsa_sign, dsa_verify
from qo.selfheal.supervisor import (trusted_release_pubkey,
                                    TRUSTED_KEY_PATH)

DEFAULT_SK = os.path.expanduser("~/.qo-75/release-signing.key")
DEFAULT_PUB = TRUSTED_KEY_PATH


def _fingerprint(pk: bytes) -> str:
    return hashlib.sha256(pk).hexdigest()[:16]


def _write_private(path: str, sk: bytes) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(sk.hex())
    except Exception:
        os.close(fd)
        raise
    os.chmod(path, 0o600)  # in case the file already existed


def _read_private(path: str) -> bytes:
    with open(path) as f:
        return bytes.fromhex(f.read().strip())


def cmd_gen(args) -> int:
    if os.path.exists(args.out) and not args.force:
        print(f"refusing to overwrite existing private key: {args.out}\n"
              f"pass --force to rotate (this invalidates the old key)",
              file=sys.stderr)
        return 2
    pk, sk = dsa_keygen()
    _write_private(args.out, sk)
    with open(args.pub, "w") as f:
        f.write(pk.hex() + "\n")
    print(f"release keypair generated (ML-DSA-65)")
    print(f"  private key : {args.out}  (mode 0600 — back this up, keep it offline)")
    print(f"  public key  : {os.path.normpath(args.pub)}  (trust anchor, safe to ship)")
    print(f"  fingerprint : sha256(pk)[:16] = {_fingerprint(pk)}")
    print()
    print("wiring:")
    print("  from qo.selfheal.supervisor import AutoUpdater")
    print("  updater = AutoUpdater.with_trusted_key(current_version=\"0.2.0\")")
    return 0


def cmd_sign(args) -> int:
    sk = _read_private(args.key)
    with open(args.artifact, "rb") as f:
        blob = f.read()
    sig = dsa_sign(sk, blob, rnd32=os.urandom(32))  # hedged mode
    manifest = {"version": args.version,
                "artifact_url": args.url,
                "signature": sig.hex()}
    if args.out:
        with open(args.out, "w") as f:
            json.dump(manifest, f, indent=2)
        print(f"manifest written: {args.out}")
    else:
        print(json.dumps(manifest, indent=2))
    print(f"signed {len(blob)} bytes with ML-DSA-65 ({len(sig)}B signature)")
    return 0


def cmd_check(args) -> int:
    if args.pub:
        with open(args.pub) as f:
            pk = bytes.fromhex(f.read().strip())
    else:
        pk = trusted_release_pubkey()
    with open(args.manifest) as f:
        m = json.load(f)
    req = urllib.request.Request(m["artifact_url"],
                                 headers={"User-Agent": "QO-75-updater"})
    with urllib.request.urlopen(req, timeout=60) as r:
        blob = r.read()
    bundle = m["signature"]
    sig = bytes.fromhex(bundle) if isinstance(bundle, str) else bytes(bundle)
    ok = dsa_verify(pk, blob, sig)
    print(f"manifest v{m.get('version')}: "
          f"signature {'VALID' if ok else 'INVALID'} "
          f"({len(blob)}B artifact, key fp {_fingerprint(pk)})")
    return 0 if ok else 1


def cmd_rotate(args) -> int:
    print("== release key rotation ==\n")
    args.force = True
    rc = cmd_gen(args)
    if rc:
        return rc
    print()
    print("checklist:")
    print("  1. back up the new private key offline; remove it from this machine")
    print("     if release signing happens elsewhere")
    print("  2. commit the new qo/selfheal/trusted_release_key.hex")
    print("  3. cut the next manifest with: release_key.py sign --artifact ...")
    print("  4. note: already-deployed updaters trust the OLD key until they")
    print("     apply this update — ship the rotation promptly")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="release_key.py",
                                 description="QO-75 release key management "
                                             "(ML-DSA-65)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="generate a fresh release keypair")
    g.add_argument("--out", default=DEFAULT_SK, help="private key path")
    g.add_argument("--pub", default=DEFAULT_PUB, help="public key path")
    g.add_argument("--force", action="store_true",
                   help="overwrite an existing private key")

    s = sub.add_parser("sign", help="sign an artifact, emit a manifest")
    s.add_argument("--key", default=DEFAULT_SK, help="private key path")
    s.add_argument("--artifact", required=True, help="artifact file to sign")
    s.add_argument("--version", required=True, help="release version string")
    s.add_argument("--url", required=True,
                   help="artifact URL for the manifest")
    s.add_argument("--out", default=None,
                   help="write manifest JSON here (else stdout)")

    c = sub.add_parser("check", help="verify a manifest against the trusted key")
    c.add_argument("--manifest", required=True, help="manifest JSON path")
    c.add_argument("--pub", default=None,
                   help="public key override (default: bundled trust anchor)")

    r = sub.add_parser("rotate", help="generate a new pair + rotation checklist")
    r.add_argument("--out", default=DEFAULT_SK, help="private key path")
    r.add_argument("--pub", default=DEFAULT_PUB, help="public key path")

    args = ap.parse_args()
    return {"gen": cmd_gen, "sign": cmd_sign,
            "check": cmd_check, "rotate": cmd_rotate}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
