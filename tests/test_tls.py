"""Unit test untuk penilaian TLS (tanpa jaringan)."""

import unittest

from secheader_check.headers import FAIL, PASS, WARN, compute_score
from secheader_check.tls import TLSInfo, tls_findings


class TestTLSFindings(unittest.TestCase):
    def test_network_error_does_not_reduce_score(self):
        findings = tls_findings(TLSInfo(ok=False, error_kind="network", error="DNS gagal"))
        self.assertEqual(findings[0].status, WARN)
        self.assertEqual(compute_score(findings), 100)

    def test_certificate_error_is_fail(self):
        findings = tls_findings(TLSInfo(ok=False, error_kind="certificate", error="expired"))
        self.assertEqual(findings[0].status, FAIL)

    def test_expiring_soon(self):
        findings = tls_findings(TLSInfo(ok=True, protocol="TLSv1.3", days_left=10))
        self.assertEqual(findings[0].status, WARN)

    def test_expires_within_a_week(self):
        findings = tls_findings(TLSInfo(ok=True, protocol="TLSv1.3", days_left=3))
        self.assertEqual(findings[0].status, FAIL)

    def test_old_protocol(self):
        findings = tls_findings(TLSInfo(ok=True, protocol="TLSv1.1", days_left=90))
        self.assertEqual(findings[1].status, FAIL)

    def test_healthy(self):
        findings = tls_findings(TLSInfo(ok=True, protocol="TLSv1.3", days_left=90))
        self.assertTrue(all(f.status == PASS for f in findings))


if __name__ == "__main__":
    unittest.main()
