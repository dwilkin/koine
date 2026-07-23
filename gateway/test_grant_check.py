#!/usr/bin/env python3
"""Unit tests for gateway._grant_check — the SPEC §5 hard fields (types, max_per_day,
thread_depth, expires) enforced on granted (cross-domain) edges. No pip deps, no network:
imports gateway.py with a throwaway STATE_DIR + agents.json and stubs the counters.
Run: python3 gateway/test_grant_check.py
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_tmp = tempfile.mkdtemp(prefix="gwtest-")
_agents = os.path.join(_tmp, "agents.json")
with open(_agents, "w") as f:
    json.dump({"agents": [
        {"name": "local", "endpoint": "http://127.0.0.1:1/ask"},
        {"name": "peer", "endpoint": "http://127.0.0.1:2/ask",
         "grant": {"types": ["question", "notification"], "max_per_day": 5,
                   "thread_depth": 3, "expires": "2099-01-01"}},
        {"name": "expired-peer", "endpoint": "http://127.0.0.1:3/ask",
         "grant": {"types": ["question"], "expires": "2020-01-01"}},
    ]}, f)

os.environ["STATE_DIR"] = _tmp
os.environ["AGENTS_JSON"] = _agents
os.environ.setdefault("ENDPOINT_TOKEN", "test")
os.environ.setdefault("GW_BEARER_TOKEN", "test")

spec = importlib.util.spec_from_file_location("gateway", os.path.join(HERE, "gateway.py"))
gw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gw)


class GrantCheck(unittest.TestCase):
    def setUp(self):
        # Deterministic counters: no db rows in play unless a test overrides.
        self._depth = gw._thread_depth
        self._daily = gw._msgs_last_day_edge
        gw._thread_depth = lambda t: 0
        gw._msgs_last_day_edge = lambda a: 0

    def tearDown(self):
        gw._thread_depth = self._depth
        gw._msgs_last_day_edge = self._daily

    def test_ungranted_edge_passes(self):
        self.assertIsNone(gw._grant_check("local", "local", "action_request", "t1"))

    def test_allowed_type_passes(self):
        self.assertIsNone(gw._grant_check("local", "peer", "question", "t1"))

    def test_disallowed_type_403(self):
        code, reason = gw._grant_check("local", "peer", "action_request", "t1")
        self.assertEqual(code, 403)
        self.assertIn("not allowed", reason)

    def test_expired_grant_403(self):
        code, reason = gw._grant_check("local", "expired-peer", "question", "t1")
        self.assertEqual(code, 403)
        self.assertIn("expired", reason)

    def test_daily_cap_429(self):
        gw._msgs_last_day_edge = lambda a: 5   # == max_per_day
        code, reason = gw._grant_check("local", "peer", "question", "t1")
        self.assertEqual(code, 429)
        self.assertIn("rate cap", reason)

    def test_thread_depth_429_at_grant_limit(self):
        gw._thread_depth = lambda t: 3         # == grant thread_depth (< global 6)
        code, reason = gw._grant_check("local", "peer", "question", "t1")
        self.assertEqual(code, 429)
        self.assertIn("thread-depth", reason)

    def test_thread_depth_under_limit_passes(self):
        gw._thread_depth = lambda t: 2
        self.assertIsNone(gw._grant_check("local", "peer", "question", "t1"))

    def test_thread_depth_ignored_without_thread_id(self):
        gw._thread_depth = lambda t: 99
        self.assertIsNone(gw._grant_check("local", "peer", "question", ""))

    def test_grant_default_depth_is_6(self):
        # Grant without thread_depth field -> default 6 (matches mailbox _grant_gate).
        gw.AGENTS["peer"]["grant"].pop("thread_depth")
        try:
            gw._thread_depth = lambda t: 6
            code, _ = gw._grant_check("local", "peer", "question", "t1")
            self.assertEqual(code, 429)
            gw._thread_depth = lambda t: 5
            self.assertIsNone(gw._grant_check("local", "peer", "question", "t1"))
        finally:
            gw.AGENTS["peer"]["grant"]["thread_depth"] = 3


if __name__ == "__main__":
    unittest.main(verbosity=1)
