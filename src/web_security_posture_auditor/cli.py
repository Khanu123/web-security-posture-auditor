from __future__ import annotations

import argparse

from .core import audit, fetch_headers, grade, load_headers, write_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Passively audit web security headers.")
    parser.add_argument("--url", default="https://example.com")
    parser.add_argument("--headers-json", help="Use saved headers instead of making a network request.")
    parser.add_argument("--out", default="web_security_report.md")
    args = parser.parse_args()

    headers = load_headers(args.headers_json) if args.headers_json else fetch_headers(args.url)
    findings = audit(args.url, headers)
    write_report(args.url, findings, args.out)
    print(f"Findings: {len(findings)}")
    print(f"Grade: {grade(findings)}")
    print(f"Report: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
