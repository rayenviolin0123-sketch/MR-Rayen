"""Controlled, rate-limited path/file existence discovery.

This module only ever performs simple GET requests to check whether a path
responds, and records status/length/title. It never attempts to authenticate,
submit credentials, or access anything beyond what an ordinary unauthenticated
visitor could request. Request volume is capped by max_requests and a
concurrency/delay setting so this cannot be turned into unbounded brute force.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from .discovery import DEFAULT_HEADERS

COMMON_PATHS = [
    "", "login", "admin", "admin/", "api", "api/v1", "uploads", "static",
    "assets", "images", "docs", "documentation", "health", "status",
]

COMMON_FILES = [
    "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
    "humans.txt", "favicon.ico", "manifest.json", "openapi.json",
    "swagger.json", "swagger", "api-docs",
]


@dataclass
class PathResult:
    url: str
    status: int | None
    content_length: int | None
    content_type: str | None
    redirect_to: str | None
    title: str | None
    error: str | None = None


@dataclass
class PathDiscoveryReport:
    results: list[PathResult] = field(default_factory=list)
    requests_made: int = 0
    capped: bool = False


def discover_paths(
    target: str,
    wordlist: list[str] | None = None,
    max_requests: int = 300,
    delay: float = 0.15,
    timeout: float = 10.0,
    session: requests.Session | None = None,
) -> PathDiscoveryReport:
    target = target.rstrip("/")
    session = session or requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    candidates = list(dict.fromkeys(COMMON_PATHS + COMMON_FILES + (wordlist or [])))
    report = PathDiscoveryReport()

    for path in candidates:
        if report.requests_made >= max_requests:
            report.capped = True
            break
        url = urljoin(target + "/", path.lstrip("/"))
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=False)
            report.requests_made += 1
            title = None
            ctype = resp.headers.get("Content-Type", "")
            if "html" in ctype:
                try:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    t = soup.find("title")
                    if t:
                        title = t.text.strip()[:150]
                except Exception:
                    pass
            redirect_to = resp.headers.get("Location") if resp.is_redirect else None
            report.results.append(
                PathResult(
                    url=url,
                    status=resp.status_code,
                    content_length=len(resp.content),
                    content_type=ctype,
                    redirect_to=redirect_to,
                    title=title,
                )
            )
        except requests.RequestException as exc:
            report.requests_made += 1
            report.results.append(
                PathResult(url=url, status=None, content_length=None,
                            content_type=None, redirect_to=None, title=None,
                            error=str(exc))
            )
        time.sleep(delay)

    return report
