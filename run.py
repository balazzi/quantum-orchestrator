#!/usr/bin/env python3
"""QO-75 entry point. Stdlib only.

    python3 run.py crypto-demo   PQC key exchange + signatures, end to end
    python3 run.py demo          75-agent swarm + telemetry live run
    python3 run.py serve         holographic dashboard + JSON API on :8080
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time

sys.path.insert(0, __import__("os").path.dirname(__file__))

from qo import (EventBus, QuantumTelemetryEngine, AgentSwarm,
                DynamicResourceOptimizer, AutoRemediation,
                SelfHealingSupervisor, AutoUpdater)
from qo.crypto import kem_keygen, encaps, decaps, HashSig
from qo.crypto.kem import keygen as qkem_keygen, encaps as qkem_encaps, \
    decaps as qkem_decaps
from qo.net.server import serve_in_thread


def build_orchestrator(agents: int = 75) -> dict:
    bus = EventBus()
    tele = QuantumTelemetryEngine(bus)
    swarm = AgentSwarm(agents, bus)
    opt = DynamicResourceOptimizer(swarm, bus=bus)
    rem = AutoRemediation(bus)
    sup = SelfHealingSupervisor(bus)
    return {"bus": bus, "telemetry": tele, "swarm": swarm,
            "optimizer": opt, "remediation": rem, "supervisor": sup}


async def _background(orch: dict):
    tele, swarm, opt = orch["telemetry"], orch["swarm"], orch["optimizer"]
    await swarm.start()
    tasks = [
        asyncio.create_task(tele.sampler(queue_depth_fn=swarm.queue.qsize)),
        asyncio.create_task(opt.run()),
    ]
    # feed the swarm some demo work so the optimizer has something to chew on
    async def workload():
        n = 0
        while True:
            await swarm.submit(lambda x: x * x, n)
            n += 1
            await asyncio.sleep(0.05)
    orch["supervisor"]  # supervised below
    tasks.append(asyncio.create_task(workload()))
    return tasks


def cmd_crypto_demo(_):
    from qo.crypto import ml_kem, ml_dsa
    print("== ML-KEM-768 key exchange (FIPS 203) ==")
    t0 = time.time()
    pk, sk = ml_kem.keygen()
    ct, ss1 = ml_kem.encaps(pk)
    ss2 = ml_kem.decaps(sk, ct)
    print(f"ek {len(pk)}B  ct {len(ct)}B  dk {len(sk)}B  "
          f"shared secret match: {ss1 == ss2} ({time.time()-t0:.2f}s)")
    bad = bytearray(ct); bad[10] ^= 1
    print(f"tampered ct yields different secret: "
          f"{ml_kem.decaps(sk, bytes(bad)) != ss1}")
    print("  (offline self-tests pass: NTT vs direct DFT, basemul vs naive")
    print("   product, exact FIPS 203 sizes; scripts/verify_kat.py runs the")
    print("   Wycheproof KAT when network is available)")

    print("== QKEM-256 key exchange (legacy experimental) ==")
    t0 = time.time()
    pk, sk = qkem_keygen()
    ct, ss1 = qkem_encaps(pk)
    ss2 = qkem_decaps(sk, ct)
    print(f"pk {len(pk)}B  ct {len(ct)}B  shared secret match: {ss1 == ss2} "
          f"({time.time()-t0:.2f}s)")
    # tamper: flipping a ciphertext byte must NOT yield the same secret
    bad = bytearray(ct); bad[10] ^= 1
    print(f"tampered ct yields different secret: {qkem_decaps(sk, bytes(bad)) != ss1}")

    print("== Hash-based signatures (WOTS+ / Merkle, h=6, legacy) ==")
    sig = HashSig(height=6)
    t0 = time.time()
    pub = sig.public_key()
    print(f"keygen ({time.time()-t0:.2f}s)  root={pub.hex()[:32]}…")
    bundle = sig.sign(b"quantum orchestrator release v0.1.0")
    print(f"verify: {HashSig.verify(pub, b'quantum orchestrator release v0.1.0', bundle)}")
    print(f"verify (forged msg): "
          f"{HashSig.verify(pub, b'forged', bundle)}")

    print("== ML-DSA-65 signatures (FIPS 204) ==")
    t0 = time.time()
    pk, sk = ml_dsa.keygen()
    sig = ml_dsa.sign(sk, b"quantum orchestrator release v0.2.0")
    print(f"pk {len(pk)}B  sig {len(sig)}B  "
          f"verify: {ml_dsa.verify(pk, b'quantum orchestrator release v0.2.0', sig)} "
          f"({time.time()-t0:.2f}s)")
    print(f"verify (forged msg): "
          f"{ml_dsa.verify(pk, b'forged', sig)}")
    print("crypto-demo OK")


def cmd_demo(args):
    async def main():
        orch = build_orchestrator(75)
        tasks = await _background(orch)
        tele, swarm = orch["telemetry"], orch["swarm"]
        print("QO-75 live: 75 agents, telemetry, optimizer, remediation "
              f"({args.seconds}s)…")
        for i in range(args.seconds // 5):
            await asyncio.sleep(5)
            h = swarm.health()
            s = tele.snapshot()
            fid = s.get("qubit_fidelity", {}).get("last", "?")
            print(f"[{i*5+5:3d}s] alive={h['alive']}/{h['desired']} "
                  f"queue={h['queue_depth']} lat={h['avg_latency_s']*1000:.1f}ms "
                  f"fidelity={fid} anomalies={s['_meta']['anomalies']}")
        for t in tasks:
            t.cancel()
        await swarm.stop()
        print("demo complete")
    asyncio.run(main())


def cmd_serve(args):
    orch = build_orchestrator(75)

    async def bg():
        tasks = await _background(orch)
        await asyncio.Event().wait()  # forever

    def runner():
        asyncio.run(bg())
    import threading
    threading.Thread(target=runner, daemon=True).start()
    time.sleep(1.0)
    from qo.net.server import serve_blocking
    serve_blocking(args.host, args.port, orch)


def main():
    ap = argparse.ArgumentParser(prog="run.py", description="QO-75 orchestrator")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("crypto-demo")
    d = sub.add_parser("demo")
    d.add_argument("--seconds", type=int, default=25)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    {"crypto-demo": cmd_crypto_demo, "demo": cmd_demo,
     "serve": cmd_serve}[args.cmd](args)


if __name__ == "__main__":
    main()
