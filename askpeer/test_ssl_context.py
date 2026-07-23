#!/usr/bin/env python3
"""KO-L3 unit tests — CA-pinned SSL context for ask_peer's HTTPS legs (2026-07-23).

ask_peer_server._build_ssl_context must return:
  * a VERIFYING context (CERT_REQUIRED + hostname check) when a CA bundle is configured
    (KOINE_CA_FILE, or gateway.py's OIDC_CA_FILE / LAB_CA_FILE aliases);
  * a verifying context (system trust store) when the configured path doesn't exist —
    a bad CA path must fail toward verification, never silently downgrade;
  * the legacy permissive context ONLY when no CA file is configured (so unconfigured
    deployments keep today's behavior).

Run directly: python3 askpeer/test_ssl_context.py
"""
import importlib.util
import os
import ssl
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "ask_peer_server", os.path.join(HERE, "ask_peer_server.py"))
aps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aps)

SYSTEM_CA = "/etc/ssl/certs/ca-certificates.crt"


class SslContextBuilder(unittest.TestCase):
    def test_no_ca_configured_is_permissive_legacy(self):
        ctx = aps._build_ssl_context("")
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx.check_hostname)

    def test_ca_path_gives_verifying_context(self):
        ca = SYSTEM_CA if os.path.exists(SYSTEM_CA) else "/nonexistent/ca.pem"
        ctx = aps._build_ssl_context(ca)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    @unittest.skipUnless(os.path.exists(SYSTEM_CA), "no system CA bundle on this box")
    def test_real_bundle_loads_certs(self):
        ctx = aps._build_ssl_context(SYSTEM_CA)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreater(ctx.cert_store_stats()["x509_ca"], 0)

    def test_missing_ca_path_still_verifies(self):
        # configured-but-missing must NOT downgrade to CERT_NONE
        ctx = aps._build_ssl_context("/nonexistent/lab-ca.pem")
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_module_default_without_env_is_legacy(self):
        # in this test process none of the CA env vars are set
        for var in ("KOINE_CA_FILE", "OIDC_CA_FILE", "LAB_CA_FILE"):
            self.assertNotIn(var, os.environ)
        self.assertEqual(aps.KOINE_CA_FILE, "")
        self.assertEqual(aps._SSL.verify_mode, ssl.CERT_NONE)


if __name__ == "__main__":
    unittest.main(verbosity=1)
