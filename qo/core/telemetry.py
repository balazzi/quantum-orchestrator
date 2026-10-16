"""Quantum Telemetry Engine.

Ingests metric samples into ring buffers, computes rolling statistics,
flags z-score anomalies onto the event bus, and exposes a snapshot for the
HTTP API / dashboard. Entropy comes from the OS CSPRNG via SHAKE-256.
"""
from __future__ import annotations

import asyncio
import statistics
import time
from collections import deque

from ..crypto.prng import quantum_seed


class QuantumTelemetryEngine:
    def __init__(self, bus=None, window: int = 512, anomaly_z: float = 4.0):
        self.bus = bus
        self.window = window
        self.anomaly_z = anomaly_z
        self._series: dict[str, deque] = {}
        self.anomalies: list[dict] = []
        self.started_at = time.time()

    # -- ingest -------------------------------------------------------------
    def ingest(self, name: str, value: float, labels: dict | None = None):
        s = self._series.setdefault(name, deque(maxlen=self.window))
        s.append((time.time(), float(value)))
        self._maybe_anomaly(name, float(value))

    def _maybe_anomaly(self, name: str, value: float):
        s = self._series[name]
        if len(s) < 30:
            return
        vals = [v for _, v in s]
        mean = statistics.fmean(vals)
        stdev = statistics.pstdev(vals)
        if stdev <= 0:
            return
        z = (value - mean) / stdev
        if abs(z) >= self.anomaly_z:
            rec = {"metric": name, "value": value, "z": round(z, 2),
                   "ts": time.time()}
            self.anomalies.append(rec)
            if self.bus:
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    return
                loop.create_task(self.bus.publish("telemetry.anomaly", rec))

    # -- read ---------------------------------------------------------------
    def snapshot(self) -> dict:
        out = {}
        for name, s in self._series.items():
            vals = [v for _, v in s]
            if not vals:
                continue
            sv = sorted(vals)
            out[name] = {
                "count": len(vals),
                "mean": round(statistics.fmean(vals), 4),
                "stdev": round(statistics.pstdev(vals), 4),
                "min": round(sv[0], 4),
                "max": round(sv[-1], 4),
                "p95": round(sv[int(0.95 * (len(sv) - 1))], 4),
                "last": round(vals[-1], 4),
            }
        out["_meta"] = {"uptime_s": round(time.time() - self.started_at, 1),
                        "anomalies": len(self.anomalies)}
        return out

    def quantum_entropy(self, n: int = 32) -> str:
        """Fresh entropy, hex-encoded."""
        return quantum_seed(n).hex()

    # -- synthetic quantum sampler ------------------------------------------
    async def sampler(self, interval: float = 1.0, queue_depth_fn=None):
        """Background task emitting qubit-like telemetry."""
        import random
        rng = random.Random(int.from_bytes(quantum_seed(8), "big"))
        t = 0
        while True:
            t += 1
            # qubit fidelity drifts with occasional decoherence events
            fid = 0.999 - 0.0004 * rng.random()
            if rng.random() < 0.02:
                fid -= 0.01 * rng.random()  # decoherence spike
            self.ingest("qubit_fidelity", fid)
            self.ingest("decoherence_us", 80 + 20 * rng.random())
            self.ingest("entanglement_pairs_s", 1200 + 300 * rng.random())
            self.ingest("pqc_handshakes_s", 40 + 10 * rng.random())
            if queue_depth_fn:
                self.ingest("swarm_queue_depth", queue_depth_fn())
            await asyncio.sleep(interval)
