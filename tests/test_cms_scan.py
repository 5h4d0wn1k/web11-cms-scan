#!/usr/bin/env python3
"""Tests for WEB11 — CMS Scanner CLI live path + firmware engine."""

import os
import sys
import threading
import unittest
from http.server import HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(1, os.path.join(ROOT, "firmware"))

import cms_scan  # noqa: E402
from cms_scan import _CMSSimulatorHandler, run_target, CLEAN_BODY, CLEAN_HEADERS  # noqa: E402
from firmware.cms_scan import fingerprint_cms  # noqa: E402


class SimulatorServerTest(unittest.TestCase):
    def setUp(self):
        self.server = HTTPServer(("127.0.0.1", 0), _CMSSimulatorHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]
        self.addCleanup(self._close)

    def _close(self):
        self.server.shutdown()
        self.server.server_close()

    def url(self, path):
        return "http://127.0.0.1:{}{}".format(self.port, path)


class LiveScanTest(SimulatorServerTest):
    def test_wordpress_detected_live(self):
        scanner, _ = run_target(self.url("/wp/"), 5, False)
        self.assertTrue(any(
            r.get("cms") == "wordpress" and r.get("detected")
            for r in scanner.findings
        ))
        self.assertGreater(
            sum(len(r.get("checks", [])) for r in scanner.findings), 0
        )

    def test_joomla_detected_live(self):
        scanner, _ = run_target(self.url("/joomla/"), 5, False)
        self.assertTrue(any(
            r.get("cms") == "joomla" and r.get("detected")
            for r in scanner.findings
        ))

    def test_drupal_detected_live(self):
        scanner, _ = run_target(self.url("/drupal/"), 5, False)
        self.assertTrue(any(
            r.get("cms") == "drupal" and r.get("detected")
            for r in scanner.findings
        ))

    def test_clean_control_no_false_positive(self):
        scanner, _ = run_target(self.url("/clean/"), 5, False)
        self.assertFalse(any(r.get("detected") for r in scanner.findings))

    def test_missing_security_headers_found_on_wordpress(self):
        scanner, _ = run_target(self.url("/wp/"), 5, False)
        all_checks = [c for r in scanner.findings for c in r.get("checks", [])]
        self.assertTrue(any(
            c.get("type") == "missing_header" or "Missing security header" in c.get("desc", "")
            for c in all_checks
        ))


class FingerprintUnitTest(unittest.TestCase):
    def test_clean_no_fingerprint(self):
        self.assertEqual(fingerprint_cms(CLEAN_BODY, dict(CLEAN_HEADERS)), {})

    def test_sample_indicator_count(self):
        fp = fingerprint_cms(
            "WORD_MARKER_ONE word marker", {"X-Powered-By": "PHP/7.4"}
        )
        # Bare markers without two real signature hits shouldn't match
        self.assertEqual(fp, {})


class DemoTest(SimulatorServerTest):
    def test_demo_vulnerable_returns_0(self):
        self.assertEqual(cms_scan.run_demo(clean=False), 0)

    def test_demo_clean_returns_0(self):
        self.assertEqual(cms_scan.run_demo(clean=True), 0)


if __name__ == "__main__":
    unittest.main()