#!/usr/bin/env python3
"""Unit tests for KO-M3: the /audit read credential is split from the submission bearer.
A holder of AUDIT_TOKEN can read /audit but cannot submit; the submission bearer no
longer unlocks /audit once AUDIT_TOKEN is set. No pip deps, no network.
Run: python3 gateway/test_audit_token.py
"""
import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_tmp = tempfile.mkdtemp(prefix="gwaudit-")
_agents = os.path.join(_tmp, "agents.json")
with open(_agents, "w") as f:
    json.dump({"agents": [{"name": "local", "endpoint": "http://127.0.0.1:1/ask"}]}, f)
os.environ["STATE_DIR"] = _tmp
os.environ["AGENTS_JSON"] = _agents
os.environ.setdefault("ENDPOINT_TOKEN", "test")
os.environ["GW_BEARER_TOKEN"] = "SUBMIT-bearer"
os.environ["AUDIT_TOKEN"] = "AUDIT-readonly"

spec = importlib.util.spec_from_file_location("gateway", os.path.join(HERE, "gateway.py"))
gw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gw)


class _FakeHandler:
    """Minimal stand-in exposing just what _authed_readonly touches (self.headers)."""
    _authed_readonly = gw.Handler._authed_readonly

    def __init__(self, bearer):
        self.headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}


class AuditTokenSplit(unittest.TestCase):
    def test_audit_token_reads(self):
        self.assertTrue(_FakeHandler("AUDIT-readonly")._authed_readonly())

    def test_submission_bearer_cannot_read_audit_when_audit_token_set(self):
        # the whole point of KO-M3: submit-as-anyone bearer != audit reader
        self.assertFalse(_FakeHandler("SUBMIT-bearer")._authed_readonly())

    def test_audit_token_is_not_a_submission_identity(self):
        who, _ = gw._identify({"Authorization": "Bearer AUDIT-readonly"})
        self.assertIsNone(who)

    def test_wrong_and_missing_rejected(self):
        self.assertFalse(_FakeHandler("nonsense")._authed_readonly())
        self.assertFalse(_FakeHandler(None)._authed_readonly())

    def test_legacy_fallback_when_no_audit_token(self):
        gw.AUDIT_TOKEN = ""
        try:
            self.assertTrue(_FakeHandler("SUBMIT-bearer")._authed_readonly())
            self.assertFalse(_FakeHandler("AUDIT-readonly")._authed_readonly())
        finally:
            gw.AUDIT_TOKEN = "AUDIT-readonly"


if __name__ == "__main__":
    unittest.main()
