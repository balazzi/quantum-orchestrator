"""Hash-based signatures: WOTS+ one-time signatures under a Merkle tree.

Post-quantum by construction (security reduces to SHAKE-256 preimage
resistance). Stateful: each leaf index MUST be used at most once — the
class tracks and persists the counter.

Parameters: n=32, w=16, len=67 chains, tree height h (default 10 -> 1024 sigs).
Not XMSS/SPHINCS+ and not audited; for production use ML-DSA via liboqs
behind the same sign/verify interface.
"""
from __future__ import annotations

import json
import os

from .prng import prf, quantum_seed, xof

N = 32
W = 16
LEN1, LEN2, LEN = 64, 3, 67


def _h(*parts: bytes) -> bytes:
    return xof(b"QO-WOTS-v1\x00" + b"".join(parts), N)


def _chain(x: bytes, idx: int, start: int, steps: int, adrs: bytes) -> bytes:
    for s in range(start, start + steps):
        x = _h(adrs, bytes([idx]), bytes([s]), x)
    return x


def _msg_nibbles(msg: bytes, leaf: int) -> list[int]:
    dgst = xof(b"QO-WOTS-msg\x00" + leaf.to_bytes(4, "big") + msg, LEN1 // 2)
    nibs: list[int] = []
    for byte in dgst:
        nibs += [byte >> 4, byte & 15]
    csum = sum(W - 1 - n for n in nibs)
    nibs += [(csum >> 8) & 15, (csum >> 4) & 15, csum & 15]
    return nibs[:LEN]


def _wots_pk(seed: bytes, leaf: int) -> bytes:
    adrs = b"leaf" + leaf.to_bytes(4, "big")
    elems = []
    for i in range(LEN):
        sk = prf(seed, b"wots-sk" + leaf.to_bytes(4, "big") + bytes([i]), N)
        elems.append(_chain(sk, i, 0, W - 1, adrs))
    return _h(b"".join(elems))


def _wots_sign(seed: bytes, leaf: int, msg: bytes) -> bytes:
    adrs = b"leaf" + leaf.to_bytes(4, "big")
    sig = b""
    for i, n in enumerate(_msg_nibbles(msg, leaf)):
        sk = prf(seed, b"wots-sk" + leaf.to_bytes(4, "big") + bytes([i]), N)
        sig += _chain(sk, i, 0, n, adrs)
    return sig


def _wots_pk_from_sig(sig: bytes, leaf: int, msg: bytes) -> bytes:
    adrs = b"leaf" + leaf.to_bytes(4, "big")
    elems = []
    for i, n in enumerate(_msg_nibbles(msg, leaf)):
        elems.append(_chain(sig[i * N:(i + 1) * N], i, n, W - 1 - n, adrs))
    return _h(b"".join(elems))


class HashSig:
    """Stateful Merkle-tree hash-based signature scheme."""

    def __init__(self, seed: bytes | None = None, height: int = 10):
        self.seed = seed or quantum_seed(32)
        self.height = height
        self.n_leaves = 1 << height
        self.next_idx = 0
        self._leaf_cache: dict[int, bytes] = {}
        self._root: bytes | None = None

    # -- tree internals -----------------------------------------------------
    def _leaf(self, i: int) -> bytes:
        if i not in self._leaf_cache:
            self._leaf_cache[i] = _wots_pk(self.seed, i)
        return self._leaf_cache[i]

    def _node(self, level: int, i: int) -> bytes:
        if level == 0:
            return self._leaf(i)
        l = self._node(level - 1, 2 * i)
        r = self._node(level - 1, 2 * i + 1)
        return _h(b"node" + bytes([level]), l, r)

    def public_key(self) -> bytes:
        if self._root is None:
            self._root = self._node(self.height, 0)
        return self._root

    def _auth_path(self, idx: int) -> bytes:
        path = b""
        node = idx
        for level in range(self.height):
            sib = self._node(level, node ^ 1)
            path += sib
            node >>= 1
        return path

    # -- signing ------------------------------------------------------------
    def sign(self, msg: bytes) -> dict:
        if self.next_idx >= self.n_leaves:
            raise RuntimeError("HashSig: all one-time keys exhausted")
        idx = self.next_idx
        self.next_idx += 1
        return {
            "height": self.height,
            "idx": idx,
            "sig": _wots_sign(self.seed, idx, msg).hex(),
            "auth": self._auth_path(idx).hex(),
        }

    @staticmethod
    def verify(pk: bytes, msg: bytes, bundle: dict) -> bool:
        try:
            height, idx = bundle["height"], bundle["idx"]
            sig = bytes.fromhex(bundle["sig"])
            auth = bytes.fromhex(bundle["auth"])
            if len(sig) != LEN * N or len(auth) != height * N:
                return False
            node = _wots_pk_from_sig(sig, idx, msg)
            for level in range(height):
                sib = auth[level * N:(level + 1) * N]
                l, r = (node, sib) if idx & 1 == 0 else (sib, node)
                node = _h(b"node" + bytes([level + 1]), l, r)
                idx >>= 1
            return node == pk
        except Exception:
            return False

    # -- state --------------------------------------------------------------
    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump({"seed": self.seed.hex(), "height": self.height,
                       "next_idx": self.next_idx}, f)

    @classmethod
    def load(cls, path: str) -> "HashSig":
        with open(path) as f:
            d = json.load(f)
        o = cls(bytes.fromhex(d["seed"]), d["height"])
        o.next_idx = d["next_idx"]
        return o

    @staticmethod
    def state_path(name: str = "default") -> str:
        d = os.path.expanduser("~/.qo-75")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, f"hashsig-{name}.json")
