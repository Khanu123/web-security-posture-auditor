import unittest

from web_security_posture_auditor.core import audit, grade


class WebAuditorTests(unittest.TestCase):
    def test_missing_headers_lower_grade(self):
        findings = audit("http://example.com", {"server": "nginx/1.18.0"})

        self.assertTrue(any("HTTPS" in finding.title for finding in findings))
        self.assertIn(grade(findings), {"D", "F"})

    def test_strong_headers_can_get_a(self):
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
        }

        self.assertEqual(grade(audit("https://example.com", headers)), "A")


if __name__ == "__main__":
    unittest.main()
