import unittest
import tempfile
from pathlib import Path

from web_security_posture_auditor.core import audit, grade, inspect_tls, re_search_max_age, write_report


class WebAuditorTests(unittest.TestCase):
    def test_missing_headers_lower_grade(self):
        findings = audit("http://example.com", {"server": "nginx/1.18.0"})

        self.assertTrue(any("HTTPS" in finding.title for finding in findings))
        self.assertIn(grade(findings), {"D", "F"})

    def test_strong_headers_can_get_a(self):
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
        }

        self.assertEqual(grade(audit("https://example.com", headers)), "A")

    def test_csp_frame_ancestors_can_replace_x_frame_options(self):
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
        }
        self.assertFalse(any("x-frame-options" in finding.title for finding in audit("https://example.com", headers)))

    def test_insecure_session_cookie_is_flagged(self):
        findings = audit("https://example.com", {"set-cookie": "session=abc; Path=/"})
        titles = {finding.title for finding in findings}
        self.assertIn("Cookie session lacks Secure", titles)
        self.assertIn("Cookie session lacks HttpOnly", titles)
        self.assertIn("Cookie session lacks SameSite", titles)

    def test_credentialed_wildcard_cors_is_high_risk(self):
        findings = audit("https://example.com", {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"})
        finding = next(item for item in findings if "Credentialed CORS" in item.title)
        self.assertEqual(finding.severity, "high")

    def test_short_hsts_is_flagged(self):
        findings = audit("https://example.com", {"strict-transport-security": "max-age=60"})
        self.assertTrue(any("too short" in item.title for item in findings))
        self.assertEqual(re_search_max_age("max-age=60"), 60)

    def test_legacy_tls_is_flagged_from_supplied_evidence(self):
        findings = audit("https://example.com", {}, {"version": "TLSv1.1"})
        self.assertTrue(any("Legacy TLS" in item.title for item in findings))

    def test_tls_inspection_rejects_non_https_target(self):
        with self.assertRaisesRegex(ValueError, "https"):
            inspect_tls("http://example.com")

    def test_report_contains_grade_and_recommendations(self):
        findings = audit("https://example.com", {"server": "nginx/1.18.0"})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.md"
            write_report("https://example.com", findings, path)
            report = path.read_text(encoding="utf-8")
        self.assertIn("Grade:", report)
        self.assertIn("Recommendation", report)


if __name__ == "__main__":
    unittest.main()
