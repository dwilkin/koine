#!/usr/bin/env python3
"""Unit tests for gateway._client_to_agent — the STRICT azp->agent resolution (2026-07-26).
A client that doesn't resolve via the explicit map or the `agent-<name>` convention must
return None, so a Keycloak client literally named like an agent can't authn AS that agent.
No pip deps, no network. Run: python3 gateway/test_client_to_agent.py
"""
import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_tmp = tempfile.mkdtemp(prefix="gwtest-")
_agents = os.path.join(_tmp, "agents.json")
with open(_agents, "w") as f:
    json.dump({"agents": [{"name": "atlas", "endpoint": "http://127.0.0.1:1/ask"}]}, f)
os.environ["STATE_DIR"] = _tmp
os.environ["AGENTS_JSON"] = _agents
os.environ.setdefault("ENDPOINT_TOKEN", "test")
os.environ.setdefault("GW_BEARER_TOKEN", "test")
os.environ.pop("OIDC_CLIENT_MAP", None)  # default-convention mode

spec = importlib.util.spec_from_file_location("gateway", os.path.join(HERE, "gateway.py"))
gw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gw)


class TestClientToAgent(unittest.TestCase):
    def test_convention_maps_agent_prefix(self):
        self.assertEqual(gw._client_to_agent("agent-atlas"), "atlas")
        self.assertEqual(gw._client_to_agent("agent-genie"), "genie")

    def test_bare_agent_name_does_not_resolve(self):
        # the whole point: a client literally named "atlas" must NOT become agent atlas
        self.assertIsNone(gw._client_to_agent("atlas"))
        self.assertIsNone(gw._client_to_agent("genie"))

    def test_unrelated_client_does_not_resolve(self):
        self.assertIsNone(gw._client_to_agent("some-other-client"))
        self.assertIsNone(gw._client_to_agent(""))


if __name__ == "__main__":
    unittest.main(verbosity=1)
