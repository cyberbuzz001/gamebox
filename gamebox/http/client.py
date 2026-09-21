"""Safety-aware HTTP client.

Every request is authorized by the SafetyController before it is sent, rate
limited, and returned wrapped with redacted evidence. Blocked requests raise
BlockedRequest and never touch the network.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

import requests

from ..core.logger import get_logger, redact, redact_headers
from ..core.models import Evidence, RequestClass
from ..safety.controller import Decision, SafetyController

log = get_logger("http")


class BlockedRequest(RuntimeError):
    def __init__(self, decision: Decision):
        super().__init__(f"Request blocked: {decision.reason}")
        self.decision = decision


@dataclass
class Response:
    status_code: int
    headers: dict[str, str]
    text: str
    url: str
    request_class: RequestClass
    elapsed_ms: float

    def json(self) -> Any:
        import json
        try:
            return json.loads(self.text)
        except Exception:
            return None


class _RateLimiter:
    def __init__(self, rps: float):
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            delta = time.monotonic() - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.monotonic()


class SafeHTTPClient:
    def __init__(self, controller: SafetyController, rps: float = 3.0,
                 timeout: float = 15.0, secret_values: Optional[list[str]] = None):
        self.controller = controller
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "gamebox-security-auditor/0.1 (authorized-test)"})
        self.limiter = _RateLimiter(rps)
        self.timeout = timeout
        self.secret_values = secret_values or []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        json_body: Any = None,
        data: Any = None,
        declared: RequestClass | None = None,
        capture: bool = True,
    ) -> tuple[Response, Optional[Evidence]]:
        body_repr = ""
        if json_body is not None:
            import json as _json
            body_repr = _json.dumps(json_body)
        elif data is not None:
            body_repr = str(data)

        decision = self.controller.authorize(method, url, body_repr, params, declared=declared)
        if not decision.allowed:
            raise BlockedRequest(decision)

        self.limiter.wait()
        start = time.monotonic()
        resp = self.session.request(
            method.upper(), url, headers=headers, params=params,
            json=json_body, data=data, timeout=self.timeout, allow_redirects=False,
        )
        elapsed = (time.monotonic() - start) * 1000.0

        wrapped = Response(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            text=resp.text,
            url=url,
            request_class=decision.request_class,
            elapsed_ms=elapsed,
        )

        evidence = None
        if capture:
            evidence = Evidence(
                endpoint=url,
                method=method.upper(),
                request_headers=redact_headers(headers or {}),
                request_body=redact(body_repr, self.secret_values),
                status_code=resp.status_code,
                response_headers=redact_headers(dict(resp.headers)),
                response_excerpt=redact(resp.text[:800], self.secret_values),
            )
        log.info("%s %s -> %s (%s)", method.upper(), url, resp.status_code,
                 decision.request_class.value)
        return wrapped, evidence

    def get(self, url: str, **kw):
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw):
        return self.request("POST", url, **kw)
