# QO-75 // Quantum Systems Orchestrator

**PQC-ready · zero-dependency · self-healing · self-defending · auto-updating
AI quantum systems orchestrator with a 75-agent swarm, dynamic resource
optimizer, auto-remediation, and a quantum telemetry engine.**

Targets: **Android · iOS · Windows · macOS · Linux · PWA**
Backends: **Supabase · Cloudflare · Vercel · Stripe**
Visuals: **WebGL2 / WebGPU holographic dashboard (4K/8K-ready)**

> Standard library only. No pip install. No network required to run the core.

---

## Quickstart

```bash
cd quantum-orchestrator
python3 run.py crypto-demo     # PQC key exchange + signatures, end to end
python3 run.py demo            # 75-agent swarm + telemetry, ~25s live run
python3 run.py serve           # holographic dashboard + JSON API on :8080
python3 -m unittest discover -s tests -v
```

## Architecture

```
quantum-orchestrator/
├── qo/
│   ├── crypto/          # PQC primitives (SHAKE-256 based, stdlib only)
│   │   ├── prng.py      # XOF/PRF + OS-entropy quantum seed
│   │   ├── kem.py       # QKEM-256: Ring-LWE KEM, Kyber-style FO transform (CCA)
│   │   └── hashsig.py   # WOTS+ one-time sigs under a Merkle tree (stateful PQ sigs)
│   ├── core/
│   │   ├── bus.py       # async event bus
│   │   └── telemetry.py # QuantumTelemetryEngine: ring buffers, z-score anomalies
│   ├── swarm/
│   │   ├── agents.py    # 75-agent async swarm, heartbeats, task queue, scaling
│   │   ├── optimizer.py # DynamicResourceOptimizer (load-driven controller)
│   │   └── remediation.py # AutoRemediation: retries, quarantine, circuit breakers
│   ├── selfheal/
│   │   └── supervisor.py# SelfHealingSupervisor + signature-verified AutoUpdater
│   ├── net/
│   │   └── server.py    # stdlib HTTP server: static PWA + /api/*
│   ├── integrations.py  # Supabase / Cloudflare / Vercel / Stripe (urllib, env keys)
│   └── platform.py      # OS detection + packaging matrix
├── web/                 # PWA: WebGL2 holographic dashboard, manifest, service worker
├── tests/               # round-trip + tamper tests (stdlib unittest)
├── deploy/              # Dockerfile, vercel.json
└── run.py               # CLI entry point
```

## Cryptography — read this

**Primary KEM: ML-KEM-768 (FIPS 203)**, implemented in pure Python
(`qo/crypto/ml_kem.py`, all three parameter sets). Validated offline by
`scripts/selftest_kem.py`: iterative NTT checked against the direct DFT
definition, NTT-domain multiplication against naive negacyclic products,
codec/compress round-trips, exact FIPS 203 sizes
(ek/ct/dk = 1184/1088/2400 for -768), deterministic keygen, encap/decap
agreement, and FO tamper closure. With network access,
`scripts/verify_kat.py` checks keygen against the official Wycheproof
ML-KEM KAT vectors.

`QKEM-256` (custom Ring-LWE) is kept as an experimental fallback.

**Signatures: ML-DSA-65 (FIPS 204)**, implemented in pure Python
(`qo/crypto/ml_dsa.py`, all three parameter sets, deterministic and
hedged modes). Validated offline by `scripts/selftest_dsa.py`: NTT/INTT
mutual inverse, NTT pointwise multiplication against naive negacyclic
convolution, exact FIPS 204 sizes (pk/sk/sig = 1952/4032/3309 for -65),
deterministic keygen/signing, sign/verify round-trips, and tamper
rejection. Two implementation bugs were caught and fixed during
validation (inverse-NTT twiddle signs, uncentered norm check that made
signing loop forever). Byte-level KAT compliance against official
vectors is pending network access.

None of this is independently audited — for high-assurance
deployments prefer a vetted library (liboqs, Bouncy Castle) behind the
same `keygen/encaps/decaps` and `keygen/sign/verify` interfaces.

The auto-updater verifies update manifests with ML-DSA-65 (FIPS 204) before
applying them (self-defending update path). The release key must be an
ML-DSA-65 public key; legacy WOTS+/Merkle HashSig bundles are no longer
accepted.

**Release signing** is owned by `scripts/release_key.py` (ML-DSA-65, hedged
mode). The bundled trust anchor lives at
`qo/selfheal/trusted_release_key.hex` and is loaded by
`trusted_release_pubkey()` / `AutoUpdater.with_trusted_key()`; the private
key stays out of the repo (`~/.qo-75/release-signing.key`, mode 0600).

```bash
python3 scripts/release_key.py gen                                    # new keypair
python3 scripts/release_key.py sign --artifact qo-0.2.0.pkg \
    --version 0.2.0 --url https://releases.example/qo-0.2.0.pkg \
    --out manifest.json                                               # cut a manifest
python3 scripts/release_key.py check --manifest manifest.json         # verify it
python3 scripts/release_key.py rotate                                 # rotate + checklist
```

Rotation replaces the bundled public key — ship it promptly, since
already-deployed updaters trust the old key until they apply the next
update. There is no in-band revocation; treat a suspected compromise as an
immediate rotation.

## Platform notes

| Target  | Path |
|---|---|
| PWA (all) | `python3 run.py serve` → open `http://localhost:8080` → install |
| Linux/macOS/Windows | `run.py` directly, or `deploy/Dockerfile` |
| Android | Chaquopy / BeeWare Briefcase embedding `qo/` |
| iOS | BeeWare Briefcase / Pyto embedding `qo/` |
| Cloudflare | Worker as API edge cache in front of the telemetry API |
| Vercel | `deploy/vercel.json` serves `web/` as the dashboard |
| Supabase | telemetry + agent state persistence via `Supabase` client |
| Stripe | usage-billing hooks via `Stripe` client |

## Telemetry API

- `GET /api/health` → `{"status":"ok", ...}`
- `GET /api/telemetry` → per-metric `{count, mean, stdev, min, max, last}`
- `GET /api/swarm` → agent health, queue depth, roles

## License

MIT — see source headers. Crypto modules: use at your own risk until audited.
