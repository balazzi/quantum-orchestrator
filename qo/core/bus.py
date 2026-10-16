"""Async publish/subscribe event bus."""
from __future__ import annotations

import asyncio


class EventBus:
    def __init__(self):
        self._subs: dict[str, list] = {}

    def subscribe(self, topic: str, cb):
        self._subs.setdefault(topic, []).append(cb)
        return cb

    def unsubscribe(self, topic: str, cb):
        try:
            self._subs[topic].remove(cb)
        except (KeyError, ValueError):
            pass

    async def publish(self, topic: str, payload=None):
        for cb in list(self._subs.get(topic, [])):
            try:
                r = cb(topic, payload)
                if asyncio.iscoroutine(r):
                    await r
            except Exception:
                pass  # the bus never dies because a subscriber did
