"""Passive discovery engine: crawling, robots.txt, sitemap.xml, JS reference
extraction, and endpoint/parameter inventory building.

Everything here is read-only: GET requests to pages that are already
publicly linked or referenced. No forms are submitted with attack payloads,
no authentication is bypassed, and no brute forcing happens outside of the
explicitly rate-limited, user-provided wordlist in pathdiscovery.py.
"""
from __future__ import annotations

import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

from .urlutil import URLStore, get_path, get_query_params, normalize_url

DEFAULT_HEADERS = {
    "User-Agent": "MR-RAYEN-Recon/0.1 (+authorized-assessment)",
}

JS_PATH_PATTERN = re.compile(
    r"""["'](/(?:api/[a-zA-Z0-9_\-./{}]*|[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-{}]+)*))["']"""
)
JS_PARAM_HINTS = {
    "id", "user", "query", "search", "url", "redirect", "file", "path",
    "q", "token", "callback", "next", "return", "page",
}


@dataclass
class ParameterRecord:
    endpoint: str
    method: str
    name: str
    example_value: str
    source: str
    confidence: str  # HIGH, MEDIUM, LOW


@dataclass
class DiscoveryResult:
    url_store: URLStore
    endpoints: set[tuple[str, str]] = field(default_factory=set)  # (method, path)
    parameters: list[ParameterRecord] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    js_referenced_paths: set[str] = field(default_factory=set)
    js_referenced_params: set[str] = field(default_factory=set)
    requests_made: int = 0
    fetch_errors: list[tuple[str, str]] = field(default_factory=list)
    titles: dict[str, str] = field(default_factory=dict)
    status_codes: dict[str, int] = field(default_factory=dict)
    content_types: dict[str, str] = field(default_factory=dict)
    response_times: dict[str, float] = field(default_factory=dict)


class Crawler:
    def __init__(
        self,
        target: str,
        max_pages: int = 150,
        max_requests: int = 300,
        delay: float = 0.1,
        timeout: float = 10.0,
        session: requests.Session | None = None,
    ):
        self.target = target.rstrip("/")
        parts = urlsplit(self.target)
        self.scope_host = parts.netloc.split("@")[-1].split(":")[0]
        self.max_pages = max_pages
        self.max_requests = max_requests
        self.delay = delay
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.result = DiscoveryResult(url_store=URLStore(scope_host=self.scope_host))

    # ------------------------------------------------------------------ #
    def _get(self, url: str) -> requests.Response | None:
        if self.result.requests_made >= self.max_requests:
            return None
        try:
            start = time.monotonic()
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            elapsed = time.monotonic() - start
            self.result.requests_made += 1
            self.result.response_times[url] = elapsed
            self.result.status_codes[url] = resp.status_code
            self.result.content_types[url] = resp.headers.get("Content-Type", "")
            time.sleep(self.delay)
            return resp
        except requests.RequestException as exc:
            self.result.fetch_errors.append((url, str(exc)))
            self.result.requests_made += 1
            return None

    # ------------------------------------------------------------------ #
    def discover_robots(self) -> list[str]:
        urls = []
        robots_url = urljoin(self.target + "/", "robots.txt")
        resp = self._get(robots_url)
        if resp is not None and resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    _, _, path = line.partition(":")
                    path = path.strip()
                    if path and path != "/":
                        urls.append(urljoin(self.target + "/", path.lstrip("/")))
                elif line.lower().startswith("sitemap:"):
                    _, _, sm = line.partition(":")
                    urls.extend(self.discover_sitemap(sm.strip()))
        return urls

    def discover_sitemap(self, sitemap_url: str | None = None) -> list[str]:
        if sitemap_url is None:
            sitemap_url = urljoin(self.target + "/", "sitemap.xml")
        urls: list[str] = []
        resp = self._get(sitemap_url)
        if resp is None or resp.status_code != 200:
            return urls
        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError:
            return urls
        for elem in root.iter():
            tag = elem.tag.rsplit("}", 1)[-1]
            if tag == "loc" and elem.text:
                urls.append(elem.text.strip())
        return urls

    # ------------------------------------------------------------------ #
    def extract_from_html(self, base_url: str, html: str) -> tuple[list[str], list[ParameterRecord]]:
        found_urls: list[str] = []
        params: list[ParameterRecord] = []
        soup = BeautifulSoup(html, "html.parser")

        title_tag = soup.find("title")
        if title_tag and title_tag.text:
            self.result.titles[base_url] = title_tag.text.strip()[:200]

        for tag, attr in (("a", "href"), ("link", "href"), ("script", "src"),
                          ("img", "src"), ("iframe", "src")):
            for el in soup.find_all(tag):
                val = el.get(attr)
                if not val:
                    continue
                if val.startswith(("javascript:", "mailto:", "tel:", "#")):
                    continue
                found_urls.append(urljoin(base_url, val))

        for form in soup.find_all("form"):
            action = form.get("action") or base_url
            action_url = urljoin(base_url, action)
            method = (form.get("method") or "GET").upper()
            endpoint = get_path(action_url)

            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                example_value = inp.get("value", "")
                params.append(
                    ParameterRecord(
                        endpoint=endpoint,
                        method=method,
                        name=name,
                        example_value=example_value or "test",
                        source="HTML form",
                        confidence="HIGH",
                    )
                )
            found_urls.append(action_url)

        # Query params already present on links
        for u in found_urls:
            qp = get_query_params(u)
            if qp:
                endpoint = get_path(u)
                for name in qp:
                    params.append(
                        ParameterRecord(
                            endpoint=endpoint,
                            method="GET",
                            name=name,
                            example_value="test",
                            source="URL query string",
                            confidence="HIGH",
                        )
                    )

        return found_urls, params

    def extract_from_js(self, js_url: str, js_text: str) -> list[str]:
        """Returns newly-discovered referenced paths (as full URLs) found in this JS file."""
        self.result.js_files.append(js_url)
        new_full_urls: list[str] = []
        for match in JS_PATH_PATTERN.finditer(js_text):
            path = match.group(1)
            if len(path) < 2 or len(path) > 120:
                continue
            if path not in self.result.js_referenced_paths:
                self.result.js_referenced_paths.add(path)
                new_full_urls.append(urljoin(self.target + "/", path.lstrip("/")))

        # crude param-name hinting: look for quoted hint words near assignment-like patterns
        lowered = js_text.lower()
        for hint in JS_PARAM_HINTS:
            if re.search ( r"""["']""" + re.escape(hint) + r"""["']\s*[:=]""", lowered):
                self.result.js_referenced_params.add(hint)

        return new_full_urls

    # ------------------------------------------------------------------ #
    def crawl(self) -> DiscoveryResult:
        queue: list[str] = [self.target + "/"]
        queue.extend(self.discover_robots())
        queue.extend(self.discover_sitemap())

        visited_pages = 0
        seen_queue: set[str] = set()

        while queue and visited_pages < self.max_pages and self.result.requests_made < self.max_requests:
            url = queue.pop(0)
            norm = self.result.url_store.add(url)
            if norm is None:
                continue
            if norm in seen_queue:
                continue
            seen_queue.add(norm)

            content_type_hint = get_path(url).lower()
            resp = self._get(url)
            visited_pages += 1
            if resp is None:
                continue

            method = "GET"
            self.result.endpoints.add((method, get_path(url)))

            ctype = resp.headers.get("Content-Type", "")
            if "html" in ctype or content_type_hint.endswith((".html", ".htm", "/")) or content_type_hint == "":
                try:
                    new_urls, params = self.extract_from_html(url, resp.text)
                except Exception:
                    new_urls, params = [], []
                self.result.parameters.extend(params)
                for nu in new_urls:
                    nnorm = self.result.url_store.add(nu)
                    if nnorm and nnorm not in seen_queue:
                        if get_path(nu).lower().endswith(".js"):
                            queue.append(nu)
                        elif len(queue) + visited_pages < self.max_pages:
                            queue.append(nu)
            elif "javascript" in ctype or content_type_hint.endswith(".js"):
                new_js_urls = self.extract_from_js(url, resp.text)
                for full in new_js_urls:
                    nnorm = self.result.url_store.add(full)
                    if nnorm and nnorm not in seen_queue and visited_pages < self.max_pages:
                        queue.append(full)

        return self.result
