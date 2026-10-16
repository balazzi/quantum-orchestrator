"""Swarm / optimizer / remediation / telemetry tests."""
import asyncio
import unittest

from qo import (EventBus, QuantumTelemetryEngine, AgentSwarm,
                DynamicResourceOptimizer, AutoRemediation)


class TestSwarm(unittest.IsolatedAsyncioTestCase):
    async def test_submit_and_results(self):
        bus = EventBus()
        swarm = AgentSwarm(8, bus)
        await swarm.start()
        try:
            results = await asyncio.gather(
                *[swarm.submit(lambda x: x * 2, i) for i in range(20)])
            self.assertEqual(results, [i * 2 for i in range(20)])
            h = swarm.health()
            self.assertEqual(h["alive"], 8)
            self.assertEqual(h["tasks_done"], 20)
        finally:
            await swarm.stop()

    async def test_failing_task_reports_but_survives(self):
        bus = EventBus()
        seen = []
        bus.subscribe("agent.failure", lambda t, p: seen.append(p))
        swarm = AgentSwarm(4, bus)
        await swarm.start()
        try:
            def boom():
                raise ValueError("kaboom")
            with self.assertRaises(ValueError):
                await swarm.submit(boom)
            await asyncio.sleep(0.2)
            self.assertTrue(seen)
            # swarm still works
            self.assertEqual(await swarm.submit(lambda: 42), 42)
        finally:
            await swarm.stop()

    async def test_scale(self):
        swarm = AgentSwarm(4)
        await swarm.start()
        try:
            await swarm.scale(6)
            self.assertEqual(swarm.desired, 6)
        finally:
            await swarm.stop()


class TestOptimizer(unittest.TestCase):
    def test_decide(self):
        opt = DynamicResourceOptimizer(swarm=None, min_agents=8, max_agents=75)
        self.assertGreater(opt.decide(300, 0.5, 20), 20)   # pressure -> up
        self.assertEqual(opt.decide(0, 0.01, 20), 16)       # idle -> down
        self.assertEqual(opt.decide(10, 0.01, 20), 20)      # calm -> hold
        self.assertLessEqual(opt.decide(10**6, 5, 70), 75)  # capped


class TestRemediation(unittest.TestCase):
    def test_retry_then_quarantine(self):
        r = AutoRemediation(max_retries=3, quarantine_after=5)
        actions = [r.record_failure("agent-001", "compute") for _ in range(5)]
        self.assertEqual(actions[:3], ["retry"] * 3)
        self.assertEqual(actions[3], "restart")
        self.assertEqual(actions[4], "quarantine")
        self.assertIn("agent-001", r.quarantined())
        r.record_success("agent-001")
        self.assertNotIn("agent-001", r.quarantined())

    def test_circuit_breaker(self):
        r = AutoRemediation(breaker_threshold=3, breaker_cooldown=60)
        self.assertEqual(r.circuit("crypto"), "closed")
        for _ in range(3):
            r.record_failure("a", "crypto")
        self.assertEqual(r.circuit("crypto"), "open")


class TestTelemetry(unittest.TestCase):
    def test_snapshot_stats(self):
        t = QuantumTelemetryEngine()
        for i in range(50):
            t.ingest("m", float(i))
        s = t.snapshot()["m"]
        self.assertEqual(s["count"], 50)
        self.assertAlmostEqual(s["mean"], 24.5)
        self.assertEqual(s["min"], 0.0)
        self.assertEqual(s["max"], 49.0)

    def test_anomaly_flagged(self):
        t = QuantumTelemetryEngine(anomaly_z=3.0)
        for _ in range(40):
            t.ingest("m", 1.0)
        t.ingest("m", 100.0)
        self.assertEqual(len(t.anomalies), 1)
        self.assertEqual(t.anomalies[0]["metric"], "m")


if __name__ == "__main__":
    unittest.main()
