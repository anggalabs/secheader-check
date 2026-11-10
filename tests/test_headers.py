"""Unit test untuk analisis header (tanpa jaringan).

Jalankan: python3 -m unittest discover -s tests -v
"""

import unittest

from secheader_check.headers import (
    FAIL, PASS, WARN, analyze_headers, check_csp, check_frame_options, check_hsts,
    check_info_leak, check_referrer_policy, compute_score, grade, normalize_headers,
)

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
    "Server": "nginx",
}


class TestNormalize(unittest.TestCase):
    def test_lowercase_and_merge_duplicates(self):
        raw = [("X-Test", "a"), ("x-test", "b")]

        class Fake:
            def items(self):
                return raw

        self.assertEqual(normalize_headers(Fake()), {"x-test": "a, b"})


class TestChecks(unittest.TestCase):
    def test_hsts_missing(self):
        self.assertEqual(check_hsts({}, True).status, FAIL)

    def test_hsts_http_site(self):
        self.assertEqual(check_hsts({}, False).status, FAIL)

    def test_hsts_short_max_age(self):
        self.assertEqual(check_hsts({"strict-transport-security": "max-age=300"}, True).status, WARN)

    def test_hsts_good(self):
        self.assertEqual(check_hsts({"strict-transport-security": "max-age=31536000"}, True).status, PASS)

    def test_csp_unsafe_inline(self):
        f = check_csp({"content-security-policy": "script-src 'self' 'unsafe-inline'"})
        self.assertEqual(f.status, WARN)
        self.assertIn("unsafe-inline", f.message)

    def test_csp_wildcard(self):
        self.assertEqual(check_csp({"content-security-policy": "default-src *"}).status, WARN)

    def test_csp_unsafe_inline_in_style_only_is_ok(self):
        # Kasus nyata GitHub: unsafe-inline hanya di style-src, script-src ketat.
        csp = "default-src 'none'; script-src github.githubassets.com; style-src 'unsafe-inline'"
        self.assertEqual(check_csp({"content-security-policy": csp}).status, PASS)

    def test_csp_unsafe_inline_ignored_with_nonce(self):
        csp = "script-src 'self' 'nonce-abc123' 'unsafe-inline'"
        self.assertEqual(check_csp({"content-security-policy": csp}).status, PASS)

    def test_csp_without_script_restriction(self):
        csp = "frame-ancestors 'self'"
        self.assertEqual(check_csp({"content-security-policy": csp}).status, WARN)

    def test_csp_falls_back_to_default_src(self):
        csp = "default-src 'self' 'unsafe-eval'"
        self.assertEqual(check_csp({"content-security-policy": csp}).status, WARN)

    def test_csp_report_only(self):
        self.assertEqual(check_csp({"content-security-policy-report-only": "default-src 'self'"}).status, WARN)

    def test_frame_ancestors_counts_as_protection(self):
        f = check_frame_options({"content-security-policy": "frame-ancestors 'self'"})
        self.assertEqual(f.status, PASS)

    def test_xfo_sameorigin(self):
        self.assertEqual(check_frame_options({"x-frame-options": "sameorigin"}).status, PASS)

    def test_referrer_last_value_wins(self):
        f = check_referrer_policy({"referrer-policy": "no-referrer, unsafe-url"})
        self.assertEqual(f.status, WARN)

    def test_info_leak(self):
        f = check_info_leak({"server": "Apache/2.4.41", "x-powered-by": "PHP/7.4"})
        self.assertEqual(f.status, WARN)
        self.assertEqual(check_info_leak({"server": "nginx"}).status, PASS)


class TestScore(unittest.TestCase):
    def test_good_headers_score_100(self):
        findings = analyze_headers(GOOD_HEADERS, is_https=True)
        self.assertTrue(all(f.status == PASS for f in findings), findings)
        self.assertEqual(compute_score(findings), 100)

    def test_no_headers_scores_low(self):
        score = compute_score(analyze_headers({}, is_https=True))
        self.assertLess(score, 60)
        self.assertEqual(grade(score), "F")

    def test_grade_boundaries(self):
        self.assertEqual(grade(90), "A")
        self.assertEqual(grade(89), "B")
        self.assertEqual(grade(0), "F")


if __name__ == "__main__":
    unittest.main()
