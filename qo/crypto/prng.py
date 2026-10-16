"""SHAKE-256 based PRF/XOF utilities (stdlib only).

All domain separation is prefixed with b"QO-*-v1\\x00" so outputs from one
context can never collide with another.
"""
from __future__ import annotations

import hashlib
import os


def xof(data: bytes, outlen: int) -> bytes:
    """Raw SHAKE-256 XOF."""
    h = hashlib.shake_256()
    h.update(data)
    return h.digest(outlen)


def prf(key: bytes, ctx: bytes, outlen: int) -> bytes:
    """Keyed PRF: SHAKE-256(domain || ctx || key)."""
    return xof(b"QO-PRF-v1\x00" + ctx + b"\x00" + key, outlen)


def quantum_seed(n: int = 32) -> bytes:
    """System-entropy seed, stretched through SHAKE-256.

    On modern kernels os.urandom() draws from a hardware-backed CSPRNG
    (RDRAND/RDSEED where available) — the closest thing to a QRNG in stdlib.
    """
    return xof(b"QO-QRNG-v1\x00" + os.urandom(64), n)
