"""PQC crypto facade.

Primary KEM: ML-KEM-768 (FIPS 203), pure-Python stdlib implementation in
ml_kem.py — verified by offline self-tests (NTT vs direct DFT, basemul vs
naive negacyclic product, exact FIPS 203 sizes, FO round-trips). Run
scripts/verify_kat.py with network access for Wycheproof KAT confirmation.

Legacy: QKEM-256 (kem.py) kept as an experimental fallback.
Signatures: HashSig (WOTS+/Merkle, hash-based, PQ).
"""
from .ml_kem import (ml_kem_512, ml_kem_768, ml_kem_1024,
                     keygen as kem_keygen, encaps, decaps)
from .ml_dsa import (mldsa_44, mldsa_65, mldsa_87,
                     keygen as dsa_keygen, sign as dsa_sign,
                     verify as dsa_verify)
from .kem import keygen as qkem_keygen
from . import kem as qkem
from .hashsig import HashSig
from .prng import quantum_seed, xof, prf

__all__ = ["ml_kem_512", "ml_kem_768", "ml_kem_1024",
           "kem_keygen", "encaps", "decaps",
           "mldsa_44", "mldsa_65", "mldsa_87",
           "dsa_keygen", "dsa_sign", "dsa_verify",
           "qkem_keygen", "qkem",
           "HashSig", "quantum_seed", "xof", "prf"]
