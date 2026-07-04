from __future__ import annotations

import json
import ssl
import urllib.request
from dataclasses import dataclass
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
        return {key.lower(): value for key, value in response.headers.items()}


def load_headers(path: str | Path) -> dict[str, str]:
    return {key.lower(): value for key, value in json.loads(Path(path).read_text(encoding="utf-8")).items()}


def audit(url: str, headers: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append(
            Finding("high", "Site is not using HTTPS", parsed.scheme or "missing scheme", "Serve the application over HTTPS.")
        )

    for header, recommendation in REQUIRED_HEADERS.items():
        if header not in headers:
            findings.append(
                Finding("medium", f"Missing {header}", "Header not present", recommendation)
            )

    csp = headers.get("content-security-policy", "")
    if csp and ("'unsafe-inline'" in csp or "*" in csp):
        findings.append(
            Finding("medium", "Weak Content Security Policy", csp, "Remove wildcards and unsafe inline script allowances where possible.")
        )

    server = headers.get("server", "")
    if server and any(char.isdigit() for char in server):
        findings.append(
            Finding("low", "Server version disclosure", server, "Avoid exposing exact server versions in HTTP headers.")
        )

    return findings


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
    Path(path).write_text(report, encoding="utf-8")
