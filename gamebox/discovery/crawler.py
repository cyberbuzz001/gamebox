"""Read-only discovery engine.

Crawls in-scope pages, extracts links/forms, and mines JavaScript for API path
strings. Everything here is READ_ONLY: it only issues GET requests via the safe
client and records discovered endpoints. It never submits forms or mutates state.
"""
from __future__ import annotations

import re
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from ..core.logger import get_logger
from ..core.models import Endpoint
from ..http.client import BlockedRequest, SafeHTTPClient
from ..safety.scope import ScopeManager
from .classify import categorize

log = get_logger("discovery")

# API-path shapes inside HTML/JS: "/api/...", '/v1/...', `/wallet/balance`
_API_RE = re.compile(r"""["'`](/(?:api|v\d|rest|graphql|ws|game|wallet|auth|admin|payment)[a-zA-Z0-9_\-/{}.:]*)["'`]""")
_JS_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)


class _LinkFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[tuple[str, str, list[str]]] = []  # (method, action, fields)
        self._cur_form: tuple[str, str] | None = None
        self._cur_fields: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._cur_form = (a.get("method", "GET").upper(), a.get("action", ""))
            self._cur_fields = []
        elif tag in ("input", "select", "textarea") and self._cur_form is not None:
            if a.get("name"):
                self._cur_fields.append(a["name"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._cur_form is not None:
            self.forms.append((self._cur_form[0], self._cur_form[1], self._cur_fields))
            self._cur_form = None


class Crawler:
    def __init__(self, client: SafeHTTPClient, scope: ScopeManager, max_pages: int = 60):
        self.client = client
        self.scope = scope
        self.max_pages = max_pages

    def crawl(self, base_urls: list[str]) -> list[Endpoint]:
        seen_pages: set[str] = set()
        endpoints: dict[str, Endpoint] = {}
        queue: deque[str] = deque(u for u in base_urls if self.scope.in_scope(u))

        while queue and len(seen_pages) < self.max_pages:
            page = queue.popleft()
            if page in seen_pages or not self.scope.in_scope(page):
                continue
            seen_pages.add(page)
            try:
                resp, _ = self.client.get(page, capture=False)
            except BlockedRequest:
                continue
            except Exception as exc:  # network hiccup: skip, keep crawling
                log.debug("fetch failed %s: %s", page, exc)
                continue

            self._record(endpoints, "GET", page, resp.headers.get("Content-Type", ""),
                         auth=resp.status_code in (401, 403))

            ctype = resp.headers.get("Content-Type", "")
            if "html" in ctype.lower() or "<html" in resp.text.lower():
                self._parse_html(page, resp.text, endpoints, queue)
            self._mine_api_paths(page, resp.text, endpoints)

            # Fetch referenced JS files (in scope) and mine them too.
            for src in _JS_SRC_RE.findall(resp.text):
                js_url = urljoin(page, src)
                if self.scope.in_scope(js_url) and js_url not in seen_pages:
                    seen_pages.add(js_url)
                    try:
                        js_resp, _ = self.client.get(js_url, capture=False)
                        self._mine_api_paths(js_url, js_resp.text, endpoints)
                    except Exception:
                        pass

        result = list(endpoints.values())
        log.info("discovery complete: %d pages, %d endpoints", len(seen_pages), len(result))
        return result

    def _parse_html(self, page: str, html: str, endpoints: dict, queue: deque) -> None:
        parser = _LinkFormParser()
        try:
            parser.feed(html)
        except Exception:
            return
        for href in parser.links:
            full = urljoin(page, href)
            if self.scope.in_scope(full):
                queue.append(full.split("#")[0])
        for method, action, fields in parser.forms:
            full = urljoin(page, action or page)
            if self.scope.in_scope(full):
                ep = self._record(endpoints, method, full, "", params=fields)
                ep.state_changing = method != "GET"

    def _mine_api_paths(self, page: str, text: str, endpoints: dict) -> None:
        for path in set(_API_RE.findall(text)):
            full = urljoin(page, path)
            if self.scope.in_scope(full):
                self._record(endpoints, "GET", full, "", notes="mined from source")

    def _record(self, endpoints: dict, method: str, url: str, ctype: str,
                *, params: list[str] | None = None, auth: bool | None = None,
                notes: str = "") -> Endpoint:
        url = url.split("#")[0]
        key = f"{method.upper()} {url}"
        if key in endpoints:
            ep = endpoints[key]
            if params:
                ep.parameters = sorted(set(ep.parameters) | set(params))
            return ep
        ep = Endpoint(
            method=method.upper(), url=url, parameters=sorted(set(params or [])),
            content_type=ctype, authentication_required=auth,
            category=categorize(url), notes=notes,
        )
        endpoints[key] = ep
        return ep
