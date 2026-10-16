"""Self-healing supervisor + signature-verified auto-updater.

The supervisor runs watched coroutines with restart-on-crash, backoff, and
health probes. The updater fetches a version manifest, verifies it with
ML-DSA (FIPS 204), and applies it atomically — the self-defending update
path.

Trust-anchor note: the release public key is an ML-DSA-65 public key
(1952 bytes). Manifests signed with the legacy WOTS+/Merkle HashSig scheme
are NOT accepted after this migration; rotate the release key accordingly.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
import urllib.request


# ---------------------------------------------------------------------------
# Release trust anchor: the bundled ML-DSA-65 public key that the updater
# trusts. Managed by scripts/release_key.py (gen/rotate); the private key
# never ships with the project.
# ---------------------------------------------------------------------------
TRUSTED_KEY_PATH = os.path.join(os.path.dirname(__file__),
                                "trusted_release_key.hex")


def trusted_release_pubkey() -> bytes:
    """Load the bundled ML-DSA-65 release public key (1952 bytes)."""
    with open(TRUSTED_KEY_PATH) as f:
        return bytes.fromhex(f.read().strip())


class SelfHealingSupervisor:
    def __init__(self, bus=None):
        self.bus = bus
        self._watched: dict[str, dict] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._running = False

    async def supervise(self, name: str, coro_fn, *, max_restarts: int = 5,
                        backoff: float = 2.0, health_check=None):
        """Watch coro_fn(); restart on exception with exponential backoff."""
        self._watched[name] = {"fn": coro_fn, "max_restarts": max_restarts,
                               "backoff": backoff, "health_check": health_check,
                               "restarts": 0, "state": "running",
                               "last_error": None}
        self._tasks[name] = asyncio.create_task(self._watch(name))

    async def _watch(self, name: str):
        cfg = self._watched[name]
        try:
            while True:
                try:
                    await cfg["fn"]()
                    cfg["state"] = "completed"
                    return
                except asyncio.CancelledError:
                    cfg["state"] = "stopped"
                    return
                except Exception as exc:  # noqa: BLE001
                    cfg["restarts"] += 1
                    cfg["last_error"] = repr(exc)
                    if cfg["restarts"] > cfg["max_restarts"]:
                        cfg["state"] = "failed"
                        if self.bus:
                            await self.bus.publish("supervisor.failed",
                                                   {"name": name,
                                                    "error": repr(exc)})
                        return
                    cfg["state"] = f"restarting ({cfg['restarts']})"
                    if self.bus:
                        await self.bus.publish("supervisor.restart",
                                               {"name": name,
                                                "attempt": cfg["restarts"]})
                    await asyncio.sleep(cfg["backoff"] * (2 ** (cfg["restarts"] - 1)))
        except asyncio.CancelledError:
            cfg["state"] = "stopped"

    async def stop(self):
        for t in self._tasks.values():
            t.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)

    def status(self) -> dict:
        return {n: {k: v for k, v in c.items() if k != "fn"}
                for n, c in self._watched.items()}


class AutoUpdater:
    """Poll a manifest URL; apply updates only if ML-DSA-signed by the release key.

    Args:
        current_version: currently running version string.
        release_pubkey: ML-DSA-65 public key (1952 bytes) of the release signer.
    """

    def __init__(self, current_version: str, release_pubkey: bytes,
                 bus=None, state_dir: str | None = None):
        self.current_version = current_version
        self.release_pubkey = release_pubkey
        self.bus = bus
        self.state_dir = state_dir or os.path.expanduser("~/.qo-75")
        os.makedirs(self.state_dir, exist_ok=True)

    @classmethod
    def with_trusted_key(cls, current_version: str, bus=None,
                         state_dir: str | None = None) -> "AutoUpdater":
        """Construct an updater wired to the bundled release trust anchor."""
        return cls(current_version, trusted_release_pubkey(),
                   bus=bus, state_dir=state_dir)

    def _get_json(self, url: str, timeout: float = 10.0) -> dict:
        req = urllib.request.Request(url, headers={"User-Agent": "QO-75-updater"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())

    def check(self, manifest_url: str) -> dict | None:
        """Return manifest if a newer version is available, else None."""
        try:
            m = self._get_json(manifest_url)
        except Exception:
            return None
        if m.get("version", "") > self.current_version:
            return m
        return None

    def apply(self, manifest: dict) -> bool:
        """Download artifact, verify ML-DSA signature, swap atomically.

        The manifest's ``signature`` field is the ML-DSA-65 signature of the
        artifact bytes, hex-encoded so the manifest stays JSON-friendly
        (raw bytes are accepted too).
        """
        from ..crypto import dsa_verify
        url, bundle = manifest["artifact_url"], manifest["signature"]
        if isinstance(bundle, str):
            try:
                bundle = bytes.fromhex(bundle)
            except ValueError:
                return False  # malformed signature: refuse the update
        elif not isinstance(bundle, (bytes, bytearray)):
            return False  # legacy/foreign bundle format: refuse the update
        req = urllib.request.Request(url, headers={"UserAgent": "QO-75-updater"})
        with urllib.request.urlopen(req, timeout=60) as r:
            blob = r.read()
        if not dsa_verify(self.release_pubkey, blob, bundle):
            if self.bus:
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None
                if loop is not None:
                    loop.create_task(
                        self.bus.publish("updater.rejected",
                                         {"version": manifest.get("version")}))
            return False  # signature invalid: refuse the update
        fd, tmp = tempfile.mkstemp(dir=self.state_dir)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
            dest = os.path.join(self.state_dir, f"qo-{manifest['version']}.pkg")
            os.replace(tmp, dest)  # atomic
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        self.current_version = manifest["version"]
        return True
