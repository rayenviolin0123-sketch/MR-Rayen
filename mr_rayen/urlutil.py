"""URL normalization, deduplication, and scope-checking helpers."""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


def normalize_url(url: str) -> str:
    """Produce a normalized form of a URL for deduplication purposes:
    - lowercase scheme/host
    - strip default ports
    - strip fragment
    - sort query parameters
    - strip trailing slash on path (except root)
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[: -len(":80")]
    if netloc.endswith(":443") and scheme == "https":
        netloc = netloc[: -len(":443")]

    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
        if path == "":
            path = "/"

    query_pairs = sorted(parse_qsl(parts.query, keep_blank_values=True))
    query = urlencode(query_pairs)

    return urlunsplit((scheme, netloc, path, query, ""))


def in_scope(url: str, scope_host: str) -> bool:
    """True if url's host matches the scope host (exact, or subdomain)."""
    host = urlsplit(url).netloc.split("@")[-1].split(":")[0].lower()
    scope_host = scope_host.lower()
    return host == scope_host or host.endswith("." + scope_host)


def is_supported_scheme(url: str) -> bool:
    return urlsplit(url).scheme in ("http", "https")


BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp4", ".mp3", ".avi", ".mov", ".wav", ".ogg", ".webm",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".exe", ".dll", ".so", ".dmg", ".bin",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}


def is_binary_resource(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(path.endswith(ext) for ext in BINARY_EXTENSIONS)


def get_query_params(url: str) -> list[str]:
    parts = urlsplit(url)
    return [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]


def get_path(url: str) -> str:
    return urlsplit(url).path or "/"


@dataclass
class SkippedURL:
    url: str
    reason: str


@dataclass
class URLStore:
    """Tracks discovered URLs, normalized/deduped forms, and skip reasons."""
    scope_host: str
    all_urls: dict[str, str] = field(default_factory=dict)       # normalized -> original (first seen)
    skipped: list[SkippedURL] = field(default_factory=list)
    excluded_patterns: list[str] = field(default_factory=list)

    def add(self, url: str, method: str = "GET") -> str | None:
        """Returns the normalized URL if accepted, else None (and records skip reason)."""
        if not is_supported_scheme(url):
            self.skipped.append(SkippedURL(url, "unsupported protocol"))
            return None
        if not in_scope(url, self.scope_host):
            self.skipped.append(SkippedURL(url, "outside scope"))
            return None
        for pat in self.excluded_patterns:
            if pat in url:
                self.skipped.append(SkippedURL(url, f"explicitly excluded ({pat})"))
                return None
        if is_binary_resource(url):
            self.skipped.append(SkippedURL(url, "binary resource"))
            return None

        norm = normalize_url(url)
        if norm in self.all_urls:
            self.skipped.append(SkippedURL(url, "duplicate"))
            return norm
        self.all_urls[norm] = url
        return norm

    @property
    def unique_urls(self) -> list[str]:
        return list(self.all_urls.keys())

    @property
    def parameterized_urls(self) -> list[str]:
        return [u for u in self.unique_urls if get_query_params(u)]

    @property
    def static_urls(self) -> list[str]:
        return [u for u in self.unique_urls if not get_query_params(u)]
