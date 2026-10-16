"""Backend integrations (stdlib urllib, env-based credentials).

Set: SUPABASE_URL, SUPABASE_KEY, CF_TOKEN, CF_ZONE_ID, VERCEL_TOKEN,
     STRIPE_KEY. Nothing is imported unless you call these.
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error


class APIError(RuntimeError):
    pass


class _Client:
    def __init__(self, base: str, headers: dict):
        self.base = base.rstrip("/")
        self.headers = {"Content-Type": "application/json",
                        "User-Agent": "QO-75", **headers}

    def _req(self, method: str, path: str, body: dict | None = None,
             timeout: float = 15.0):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=self.headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read().decode()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raise APIError(f"{method} {path}: HTTP {e.code} {e.read()[:200]}")
        except Exception as e:  # noqa: BLE001
            raise APIError(f"{method} {path}: {e}")


class Supabase(_Client):
    """Persist telemetry snapshots / agent state to Supabase Postgres."""

    def __init__(self, url=None, key=None):
        url = url or os.environ["SUPABASE_URL"]
        key = key or os.environ["SUPABASE_KEY"]
        super().__init__(url + "/rest/v1",
                         {"apikey": key, "Authorization": f"Bearer {key}"})

    def insert(self, table: str, rows: list[dict]):
        return self._req("POST", f"/{table}", rows)

    def select(self, table: str, query: str = "select=*"):
        return self._req("GET", f"/{table}?{query}")


class Cloudflare(_Client):
    """Purge edge cache / manage zones in front of the telemetry API."""

    def __init__(self, token=None, zone=None):
        token = token or os.environ["CF_TOKEN"]
        zone = zone or os.environ.get("CF_ZONE_ID", "")
        super().__init__("https://api.cloudflare.com/client/v4",
                         {"Authorization": f"Bearer {token}"})
        self.zone = zone

    def purge_cache(self, urls: list[str]):
        return self._req("POST", f"/zones/{self.zone}/purge_cache",
                         {"files": urls})

    def list_dns(self):
        return self._req("GET", f"/zones/{self.zone}/dns_records")


class Vercel(_Client):
    """Trigger dashboard redeploys via Deploy Hooks."""

    def __init__(self, token=None):
        token = token or os.environ["VERCEL_TOKEN"]
        super().__init__("https://api.vercel.com",
                         {"Authorization": f"Bearer {token}"})

    def redeploy_hook(self, hook_url: str):
        # deploy hooks are unauthenticated URLs; plain POST is enough
        req = urllib.request.Request(hook_url, data=b"{}",
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())

    def list_projects(self):
        return self._req("GET", "/v9/projects")


class Stripe(_Client):
    """Usage-billing hooks (payment intents)."""

    def __init__(self, key=None):
        key = key or os.environ["STRIPE_KEY"]
        import base64
        basic = base64.b64encode(f"{key}:".encode()).decode()
        self._form_headers = {"Authorization": f"Basic {basic}",
                              "User-Agent": "QO-75"}
        self.base = "https://api.stripe.com/v1"

    def create_payment_intent(self, amount_cents: int, currency: str = "usd"):
        import urllib.parse
        body = urllib.parse.urlencode(
            {"amount": amount_cents, "currency": currency,
             "automatic_payment_methods[enabled]": "true"}).encode()
        req = urllib.request.Request(
            self.base + "/payment_intents", data=body,
            headers={**self._form_headers,
                     "Content-Type": "application/x-www-form-urlencoded"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            raise APIError(f"stripe: HTTP {e.code} {e.read()[:200]}")
