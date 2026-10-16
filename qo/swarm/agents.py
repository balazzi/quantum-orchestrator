"""75-agent autonomous swarm.

Async workers pull tasks from a shared queue, heartbeat continuously, and
are supervised by a monitor loop that restarts anything that dies. Roles
partition work by kind; the swarm scales up/down on optimizer demand.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

ROLES = ["compute", "crypto", "network", "healer", "renderer", "scout", "sentinel"]


@dataclass
class Agent:
    idx: int
    role: str
    id: str = field(init=False)
    heartbeat: float = field(default_factory=time.time)
    tasks_done: int = 0
    failures: int = 0
    state: str = "starting"  # starting|idle|busy|dead|quarantined

    def __post_init__(self):
        self.id = f"agent-{self.idx:03d}"


class AgentSwarm:
    def __init__(self, size: int = 75, bus=None):
        self.bus = bus
        self.desired = size
        self.queue: asyncio.Queue = asyncio.Queue()
        self.agents: list[Agent] = [
            Agent(i, ROLES[i % len(ROLES)]) for i in range(size)]
        self._workers: dict[str, asyncio.Task] = {}
        self._running = False
        self._monitor_task: asyncio.Task | None = None
        self._latencies: list[float] = []

    # -- lifecycle ----------------------------------------------------------
    async def start(self):
        self._running = True
        for agent in self.agents:
            self._spawn(agent)
        self._monitor_task = asyncio.create_task(self.monitor_loop())
        if self.bus:
            await self.bus.publish("swarm.started", {"size": self.desired})

    async def stop(self):
        self._running = False
        for t in list(self._workers.values()):
            t.cancel()
        if self._monitor_task:
            self._monitor_task.cancel()
        await asyncio.gather(*self._workers.values(),
                             self._monitor_task, return_exceptions=True)
        self._workers.clear()

    def _spawn(self, agent: Agent):
        agent.state = "idle"
        agent.heartbeat = time.time()
        self._workers[agent.id] = asyncio.create_task(
            self._worker(agent), name=agent.id)

    async def scale(self, n: int):
        n = max(1, n)
        if n == self.desired:
            return
        old = self.desired
        self.desired = n
        if n > len(self.agents):
            for i in range(len(self.agents), n):
                a = Agent(i, ROLES[i % len(ROLES)])
                self.agents.append(a)
                if self._running:
                    self._spawn(a)
        if self.bus:
            await self.bus.publish("swarm.scaled", {"from": old, "to": n})

    # -- work ---------------------------------------------------------------
    async def submit(self, fn, *args, _timeout: float | None = None, **kw):
        """Submit a callable (sync or async). Returns its result."""
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        await self.queue.put((fn, args, kw, fut, time.time()))
        return await asyncio.wait_for(asyncio.shield(fut), _timeout)

    async def _worker(self, agent: Agent):
        try:
            while self._running:
                agent.heartbeat = time.time()
                try:
                    item = await asyncio.wait_for(self.queue.get(), 1.0)
                except asyncio.TimeoutError:
                    agent.state = "idle"
                    continue
                fn, args, kw, fut, enqueued = item
                agent.state = "busy"
                try:
                    res = fn(*args, **kw)
                    if asyncio.iscoroutine(res):
                        res = await res
                    self._latencies.append(time.time() - enqueued)
                    if len(self._latencies) > 256:
                        self._latencies.pop(0)
                    agent.tasks_done += 1
                    if not fut.done():
                        fut.set_result(res)
                except Exception as exc:  # noqa: BLE001
                    agent.failures += 1
                    if not fut.done():
                        fut.set_exception(exc)
                    if self.bus:
                        await self.bus.publish("agent.failure", {
                            "agent": agent.id, "role": agent.role,
                            "error": repr(exc)})
                finally:
                    agent.state = "idle"
                    self.queue.task_done()
        except asyncio.CancelledError:
            pass
        finally:
            agent.state = "dead"

    # -- supervision --------------------------------------------------------
    async def monitor_loop(self, interval: float = 1.0):
        try:
            while self._running:
                await asyncio.sleep(interval)
                now = time.time()
                for agent in list(self.agents[:self.desired]):
                    t = self._workers.get(agent.id)
                    if t is None or t.done():
                        if agent.state != "quarantined":
                            if self.bus:
                                await self.bus.publish("agent.restart", {
                                    "agent": agent.id, "role": agent.role})
                            self._spawn(agent)
                    elif now - agent.heartbeat > 10 and agent.state == "busy":
                        # stuck worker: cancel and respawn
                        t.cancel()
                        if self.bus:
                            await self.bus.publish("agent.stuck", {
                                "agent": agent.id})
        except asyncio.CancelledError:
            pass

    # -- introspection ------------------------------------------------------
    def avg_latency(self) -> float:
        return sum(self._latencies) / len(self._latencies) if self._latencies else 0.0

    def health(self) -> dict:
        alive = sum(1 for a in self.agents[:self.desired]
                    if self._workers.get(a.id) and not self._workers[a.id].done())
        by_role: dict[str, int] = {}
        for a in self.agents[:self.desired]:
            by_role[a.role] = by_role.get(a.role, 0) + 1
        return {
            "desired": self.desired,
            "alive": alive,
            "queue_depth": self.queue.qsize(),
            "avg_latency_s": round(self.avg_latency(), 4),
            "tasks_done": sum(a.tasks_done for a in self.agents),
            "failures": sum(a.failures for a in self.agents),
            "roles": by_role,
            "agents": [{"id": a.id, "role": a.role, "state": a.state,
                        "tasks": a.tasks_done, "failures": a.failures}
                       for a in self.agents[:self.desired]],
        }
