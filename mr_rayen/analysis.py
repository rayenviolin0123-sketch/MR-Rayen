"""Passive security-hygiene analysis: technology fingerprinting, security
header checks, cookie flag checks, CORS configuration checks, and detection
of verbose error/debug pages that a target returns on its own for ordinary
requests.

Nothing here sends a crafted/attack payload. All findings come from
inspecting responses to requests already made during normal discovery.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "Mitigates XSS/data-injection by restricting allowed sources.",
    "Strict-Transport-Security": "Forces browsers to use HTTPS for this host.",
    "X-Frame-Options": "Prevents clickjacking via iframe embedding.",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks.",
    "Referrer-Policy": "Controls how much referrer info is leaked to other sites.",
    "Permissions-Policy": "Restricts access to powerful browser features.",
}

TECH_SIGNATURES = [
    # (regex on header value or html, header name or None for body, label)
    (re.compile(r"nginx", re.I), "Server", "nginx"),
    (re.compile(r"apache", re.I), "Server", "Apache"),
    (re.compile(r"cloudflare", re.I), "Server", "Cloudflare"),
    (re.compile(r"Microsoft-IIS", re.I), "Server", "Microsoft IIS"),
    (re.compile(r"express", re.I), "X-Powered-By", "Express (Node.js)"),
    (re.compile(r"php", re.I), "X-Powered-By", "PHP"),
    (re.compile(r"asp\.net", re.I), "X-Powered-By", "ASP.NET"),
    (re.compile(r"django", re.I), None, "Django"),
    (re.compile(r"laravel", re.I), None, "Laravel"),
    (re.compile(r"wordpress", re.I), None, "WordPress"),
    (re.compile(r"next\.js|__NEXT_DATA__", re.I), None, "Next.js"),
    (re.compile(r"react", re.I), None, "React"),
    (re.compile(r"vue", re.I), None, "Vue.js"),
    (re.compile(r"generator[\"'][^>]*content=[\"']([^\"']+)", re.I), None, "meta-generator"),
]

ERROR_PAGE_INDICATORS = [
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"Warning: .*on line \d+", re.I),
    re.compile(r"Fatal error:", re.I),
    re.compile(r"Exception in thread", re.I),
    re.compile(r"Whitelabel Error Page"),
    re.compile(r"DEBUG = True"),
    re.compile(r"at [\w.$]+\(.*\.java:\d+\)"),
    re.compile(r"System\.Exception", re.I),
    re.compile(r"ORA-\d{5}"),
    re.compile(r"org\.postgresql\.util\.PSQLException"),
    re.compile(r"MySQL server version for the right syntax"),
    re.compile(r"Microsoft OLE DB Provider for SQL Server"),
    re.compile(r"\b(?:/usr/|/var/www/|/home/\w+/|C:\\\\)[\w./\\\\-]+", re.I),
]

SENSITIVE_PATTERNS = {
    "AWS Access Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Generic Bearer Token": re.compile(r"\bBearer\s+[A-Za-z0-9\-_.]{10,}\b"),
    "Password-like assignment": re.compile(r"\bpassword\s*=\s*[^\s&\"']{3,}", re.I),
    "Private Key Header": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
}


@dataclass
class Finding:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    url: str
    evidence: str
    recommendation: str = ""
    cwe: str | None = None


@dataclass
class AnalysisResult:
    technologies: set[str] = field(default_factory=set)
    findings: list[Finding] = field(default_factory=list)


def mask_secret(match: str) -> str:
    if len(match) <= 8:
        return match[:2] + "*" * (len(match) - 2)
    return match[:6] + "*" * 8


def detect_technology(url: str, resp: requests.Response, result: AnalysisResult) -> None:
    for pattern, header_name, label in TECH_SIGNATURES:
        haystack = ""
        if header_name:
            haystack = resp.headers.get(header_name, "")
        else:
            haystack = resp.text[:20000] if resp.text else ""
        if pattern.search(haystack):
            if label == "meta-generator":
                m = pattern.search(haystack)
                if m:
                    result.technologies.add(f"Generator: {m.group(1)}")
            else:
                result.technologies.add(label)

    server = resp.headers.get("Server")
    if server:
        result.technologies.add(f"Server header: {server}")
    powered = resp.headers.get("X-Powered-By")
    if powered:
        result.technologies.add(f"X-Powered-By: {powered}")


def check_security_headers(url: str, resp: requests.Response, result: AnalysisResult) -> None:
    missing = []
    for header, desc in SECURITY_HEADERS.items():
        if header not in resp.headers:
            missing.append(header)

    if missing:
        result.findings.append(
            Finding(
                severity="LOW" if len(missing) < 4 else "MEDIUM",
                category="Security Headers",
                title=f"Missing security headers: {', '.join(missing)}",
                url=url,
                evidence=f"Response did not include: {', '.join(missing)}",
                recommendation="Add the missing headers at the web server or application layer.",
                cwe="CWE-693",
            )
        )


def check_cookies(url: str, resp: requests.Response, result: AnalysisResult) -> None:
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        httponly = cookie.has_nonstandard_attr("HttpOnly") or cookie.get_nonstandard_attr("HttpOnly") is not None
        # http.cookiejar doesn't expose HttpOnly directly; check raw header instead
        raw_set_cookie = resp.headers.get("Set-Cookie", "")
        if cookie.name in raw_set_cookie and "httponly" not in raw_set_cookie.lower():
            issues.append("missing HttpOnly flag")
        if "samesite" not in raw_set_cookie.lower():
            issues.append("missing SameSite attribute")

        if issues:
            result.findings.append(
                Finding(
                    severity="LOW",
                    category="Cookie Issues",
                    title=f"Cookie '{cookie.name}' missing protective flags",
                    url=url,
                    evidence=", ".join(issues),
                    recommendation="Set Secure, HttpOnly, and SameSite on session/sensitive cookies.",
                    cwe="CWE-614",
                )
            )


def check_cors(url: str, resp: requests.Response, result: AnalysisResult) -> None:
    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials")
    if acao == "*" and acac and acac.lower() == "true":
        result.findings.append(
            Finding(
                severity="HIGH",
                category="CORS",
                title="Overly permissive CORS with credentials allowed",
                url=url,
                evidence="Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true",
                recommendation="Never combine a wildcard origin with credentialed CORS responses.",
                cwe="CWE-942",
            )
        )
    elif acao == "*":
        result.findings.append(
            Finding(
                severity="INFO",
                category="CORS",
                title="Wildcard CORS origin",
                url=url,
                evidence="Access-Control-Allow-Origin: *",
                recommendation="Restrict to known origins if this endpoint returns sensitive data.",
                cwe="CWE-942",
            )
        )


def check_error_disclosure(url: str, resp: requests.Response, result: AnalysisResult) -> None:
    body = resp.text[:50000] if resp.text else ""
    for pattern in ERROR_PAGE_INDICATORS:
        m = pattern.search(body)
        if m:
            result.findings.append(
                Finding(
                    severity="LOW",
                    category="Information Disclosure",
                    title="Verbose error/debug disclosure",
                    url=url,
                    evidence=f"Response contains indicator matching: {m.group(0)[:120]!r}",
                    recommendation="Disable verbose/debug error output in production.",
                    cwe="CWE-209",
                )
            )
            break


def check_sensitive_patterns(url: str, resp: requests.Response, result: AnalysisResult) -> None:
    body = resp.text[:50000] if resp.text else ""
    for label, pattern in SENSITIVE_PATTERNS.items():
        m = pattern.search(body)
        if m:
            result.findings.append(
                Finding(
                    severity="MEDIUM",
                    category="Information Disclosure",
                    title=f"Possible exposed {label}",
                    url=url,
                    evidence=f"Matched pattern (masked): {mask_secret(m.group(0))}",
                    recommendation="Remove secrets from client-visible responses; rotate if exposed.",
                    cwe="CWE-200",
                )
            )


def analyze_response(url: str, resp: requests.Response, result: AnalysisResult) -> None:
    detect_technology(url, resp, result)
    check_security_headers(url, resp, result)
    check_cookies(url, resp, result)
    check_cors(url, resp, result)
    check_error_disclosure(url, resp, result)
    check_sensitive_patterns(url, resp, result)
