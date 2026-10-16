"""Dynamic Resource Optimizer.

Closed-loop controller: samples swarm queue depth and task latency, then
scales the swarm within [min_agents, max_agents]. Pure `decide()` is
testable without a running swarm.
"""
from __future__ import annotations

import asyncio


class DynamicResourceOptimizer:
    def __init__(self, swarm, min_agents: int = 8, max_agents: int = 75,
                 bus=None, interval: float = 2.0):
        self.swarm = swarm
        self.min_agents = min_agents
        self.max_agents = max_agents
        self.bus = bus
        self.interval = interval
        self.history: list[dict] = []

    def decide(self, qsize: int, avg_latency: float, current: int) -> int:
        if qsize > current * 3 and avg_latency > 0.05:
            target = current + max(4, qsize // 8)
        elif qsize > current * 3:
            target = current + max(2, qsize // 16)
        elif qsize == 0 and avg_latency < 0.05 and current > self.min_agents:
            target = current - 4
        elif qsize < current // 4 and avg_latency < 0.02 and current > self.min_agents:
            target = current - 2
        else:
            target = current
        return max(self.min_agents, min(self.max_agents, target))

    async def run(self):
        try:
            while True:
                await asyncio.sleep(self.interval)
                q = self.swarm.queue.qsize()
                lat = self.swarm.avg_latency()
                cur = self.swarm.desired
                target = self.decide(q, lat, cur)
                rec = {"qsize": q, "latency": round(lat, 4),
                       "from": cur, "to": target}
                self.history.append(rec)
                if target != cur:
                    await self.swarm.scale(target)
                    if self.bus:
                        await self.bus.publish("optimizer.scale", rec)
        except asyncio.CancelledError:
            pass
