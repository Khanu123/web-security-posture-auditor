from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


REQUIRED_HEADERS = {
    "strict-transport-security": "Add HSTS to enforce HTTPS for repeat visitors.",
    "content-security-policy": "Add a Content Security Policy to reduce XSS impact.",
    "x-frame-options": "Add X-Frame-Options or frame-ancestors to reduce clickjacking risk.",
    "x-content-type-options": "Add X-Content-Type-Options: nosniff.",
    "referrer-policy": "Add a Referrer-Policy to limit sensitive URL leakage.",
}


@dataclass(frozen=True)
class Finding:
    severity: str
    title: str
    evidence: str
    recommendation: str


def fetch_headers(url: str, timeout: int = 8) -> dict[str, str]:
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "WebSecurityPostureAuditor/1.0"})
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        headers = {key.lower(): value for key, value in response.headers.items()}
        cookies = response.headers.get_all("Set-Cookie", [])
        if cookies:
            headers["set-cookie"] = "\n".join(cookies)
        return headers


def load_headers(path: str | Path) -> dict[str, str]:
    return {key.lower(): value for key, value in json.loads(Path(path).read_text(encoding="utf-8")).items()}


def inspect_tls(url: str, timeout: int = 8) -> dict[str, object]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("TLS inspection requires an https:// URL with a hostname.")
    context = ssl.create_default_context()
    with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=parsed.hostname) as tls_socket:
            certificate = tls_socket.getpeercert()
            return {
                "version": tls_socket.version() or "unknown",
                "cipher": (tls_socket.cipher() or ("unknown",))[0],
                "not_after": certificate.get("notAfter", ""),
            }


def audit(url: str, headers: dict[str, str], tls: dict[str, object] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append(
            Finding("high", "Site is not using HTTPS", parsed.scheme or "missing scheme", "Serve the application over HTTPS.")
        )

    for header, recommendation in REQUIRED_HEADERS.items():
        if header == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", ""):
            continue
        if header not in headers:
            findings.append(
                Finding("medium", f"Missing {header}", "Header not present", recommendation)
            )

    csp = headers.get("content-security-policy", "")
    if csp and ("'unsafe-inline'" in csp or "*" in csp):
        findings.append(
            Finding("medium", "Weak Content Security Policy", csp, "Remove wildcards and unsafe inline script allowances where possible.")
        )

    if csp and "object-src" not in csp:
        findings.append(Finding("low", "CSP does not define object-src", csp, "Set object-src 'none' unless plugins are explicitly required."))
    if csp and "base-uri" not in csp:
        findings.append(Finding("low", "CSP does not define base-uri", csp, "Set base-uri 'self' or 'none' to restrict base URL injection."))

    hsts = headers.get("strict-transport-security", "")
    max_age = re_search_max_age(hsts)
    if hsts and (max_age is None or max_age < 15_552_000):
        findings.append(Finding("medium", "HSTS max-age is too short", hsts, "Use an HSTS max-age of at least 180 days after deployment validation."))

    for cookie in _cookies(headers.get("set-cookie", "")):
        lower = cookie.lower()
        name = cookie.split("=", 1)[0].strip() or "unnamed"
        if "secure" not in lower:
            findings.append(Finding("high", f"Cookie {name} lacks Secure", cookie, "Add the Secure attribute to session and sensitive cookies."))
        if "httponly" not in lower:
            findings.append(Finding("medium", f"Cookie {name} lacks HttpOnly", cookie, "Add HttpOnly unless client-side script access is required."))
        if "samesite=" not in lower:
            findings.append(Finding("medium", f"Cookie {name} lacks SameSite", cookie, "Set SameSite=Lax or Strict unless cross-site use is required."))

    allow_origin = headers.get("access-control-allow-origin", "")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
    if allow_origin == "*" and allow_credentials:
        findings.append(Finding("high", "Credentialed CORS uses wildcard origin", "Access-Control-Allow-Origin=* and credentials=true", "Use an explicit allow-list and never combine credentials with a wildcard origin."))
    elif allow_origin == "*":
        findings.append(Finding("medium", "CORS allows every origin", "Access-Control-Allow-Origin=*", "Restrict cross-origin access to required trusted origins."))

    server = headers.get("server", "")
    if server and any(char.isdigit() for char in server):
        findings.append(
            Finding("low", "Server version disclosure", server, "Avoid exposing exact server versions in HTTP headers.")
        )

    if tls:
        version = str(tls.get("version", "unknown"))
        if version in {"TLSv1", "TLSv1.1", "TLS 1.0", "TLS 1.1"}:
            findings.append(Finding("high", "Legacy TLS protocol negotiated", version, "Disable TLS 1.0 and 1.1; require TLS 1.2 or later."))
        not_after = str(tls.get("not_after", ""))
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (expiry - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(Finding("high", "TLS certificate is expired", not_after, "Renew and deploy a valid certificate immediately."))
            elif days < 30:
                findings.append(Finding("medium", "TLS certificate expires within 30 days", not_after, "Renew the certificate before expiry."))

    return findings


def re_search_max_age(value: str) -> int | None:
    match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _cookies(value: str) -> list[str]:
    return [cookie.strip() for cookie in value.splitlines() if cookie.strip()]


def grade(findings: list[Finding]) -> str:
    score = 100
    penalties = {"high": 30, "medium": 12, "low": 5}
    for finding in findings:
        score -= penalties.get(finding.severity, 0)
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def write_report(url: str, findings: list[Finding], path: str | Path) -> None:
    rows = "\n".join(
        f"| {finding.severity.upper()} | {finding.title} | {finding.evidence} | {finding.recommendation} |"
        for finding in findings
    )
    report = f"""# Web Security Posture Report

Target: `{url}`

Grade: **{grade(findings)}**

| Severity | Finding | Evidence | Recommendation |
| --- | --- | --- | --- |
{rows or '| - | No findings | - | - |'}
"""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(report, encoding="utf-8")
