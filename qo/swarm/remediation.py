"""Auto-Remediation: retries, quarantine, and per-role circuit breakers.

Subscribes to agent.failure events. Transient errors get retried with
backoff; agents that fail repeatedly are quarantined (excluded from the
respawn pool); a role whose failure rate spikes trips a circuit breaker
that pauses new work for that role until it cools down.
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque


class AutoRemediation:
    def __init__(self, bus=None, max_retries: int = 3,
                 quarantine_after: int = 5, breaker_threshold: int = 10,
                 breaker_cooldown: float = 30.0):
        self.bus = bus
        self.max_retries = max_retries
        self.quarantine_after = quarantine_after
        self.breaker_threshold = breaker_threshold
        self.breaker_cooldown = breaker_cooldown
        self._failures: dict[str, int] = defaultdict(int)
        self._quarantined: set[str] = set()
        self._role_events: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=breaker_threshold * 2))
        self._breaker_open_until: dict[str, float] = {}
        if bus:
            bus.subscribe("agent.failure", self._on_failure)

    # -- event handling -----------------------------------------------------
    async def _on_failure(self, topic, payload):
        self.record_failure(payload["agent"], payload["role"],
                            payload.get("error", ""))

    def record_failure(self, agent_id: str, role: str, error: str = "") -> str:
        """Returns the action taken: retry|restart|quarantine."""
        now = time.time()
        self._failures[agent_id] += 1
        self._role_events[role].append(now)
        n = self._failures[agent_id]
        if n >= self.quarantine_after:
            self._quarantined.add(agent_id)
            action = "quarantine"
        elif n > self.max_retries:
            action = "restart"
        else:
            action = "retry"
        return action

    def record_success(self, agent_id: str):
        self._failures[agent_id] = 0
        self._quarantined.discard(agent_id)

    # -- circuit breaker ----------------------------------------------------
    def circuit(self, role: str) -> str:
        """'open' if the role's breaker is tripped, else 'closed'."""
        now = time.time()
        if now < self._breaker_open_until.get(role, 0):
            return "open"
        events = self._role_events[role]
        recent = [t for t in events if now - t < self.breaker_cooldown]
        if len(recent) >= self.breaker_threshold:
            self._breaker_open_until[role] = now + self.breaker_cooldown
            return "open"
        return "closed"

    def quarantined(self) -> set[str]:
        return set(self._quarantined)

    def report(self) -> dict:
        return {
            "failures": dict(self._failures),
            "quarantined": sorted(self._quarantined),
            "breakers": {r: self.circuit(r)
                         for r in self._role_events},
        }
