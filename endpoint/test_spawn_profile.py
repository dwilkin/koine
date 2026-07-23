#!/usr/bin/env python3
"""KO-M2 unit tests — ops-channel spawn de-privileged (2026-07-23).

Asserts on the CONSTRUCTED `claude -p` argv (endpoint._build_cmd / _spawn_profile):
  * ops spawns are NOT bypassPermissions and do NOT get the human tool surface — they run
    the restricted peer profile (peer disallowed set) PLUS the pending-actions ledger.
  * the human channel is UNTOUCHED: bypassPermissions (when configured), no allowed-tools
    restriction, DISALLOWED_TOOLS_HUMAN (empty by default).
  * the peer profile is unchanged.

Run directly: python3 endpoint/test_spawn_profile.py
"""
import os
import pathlib
import sys
import unittest

# Mirror a deployment with Telegram-execution parity ON for the human channel.
os.environ["PERMISSION_MODE_HUMAN"] = "bypassPermissions"
os.environ.setdefault("AGENT_NAME", "atlas-test")
os.environ.setdefault("AUTH_TOKEN", "test-token")
os.environ.setdefault("OPS_TOKEN", "ops-token")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import endpoint  # noqa: E402


def _msg(channel="", sender="cid"):
    m = {"from": sender, "type": "question", "id": "m-1", "body": "hello"}
    if channel:
        m["channel"] = channel
    return m


class OpsDeprivileged(unittest.TestCase):
    def test_ops_cmd_has_no_bypass_and_restricted_tools(self):
        cmd, _timeout = endpoint._build_cmd(_msg("ops", sender="gatus"), "opus")
        self.assertNotIn("--permission-mode", cmd)
        self.assertNotIn("bypassPermissions", cmd)
        # restricted (peer) disallow set, not the human one
        self.assertIn("--disallowedTools", cmd)
        disallowed = cmd[cmd.index("--disallowedTools") + 1]
        for tool in ("mcp__ask-peer__ask_peer", "Edit", "Write", "WebFetch", "WebSearch"):
            self.assertIn(tool, disallowed)
        # ledger-capable: allowed tools = the pending-actions ledger script
        self.assertIn("--allowedTools", cmd)
        self.assertIn("pending_actions.py", cmd[cmd.index("--allowedTools") + 1])

    def test_ops_keeps_human_model_and_timeout(self):
        prof = endpoint._spawn_profile(_msg("ops"))
        self.assertEqual(prof["model"], endpoint.MODEL_HUMAN)
        self.assertEqual(prof["timeout"], endpoint.ANSWER_TIMEOUT_HUMAN)

    def test_ops_token_authn_unchanged(self):
        self.assertEqual(endpoint._auth_class({"Authorization": "Bearer ops-token"}), "ops")
        self.assertEqual(endpoint._auth_class({"Authorization": "Bearer test-token"}), "main")
        self.assertIsNone(endpoint._auth_class({"Authorization": "Bearer wrong"}))


class HumanChannelUntouched(unittest.TestCase):
    def test_human_cmd_keeps_bypass_and_full_tools(self):
        cmd, timeout = endpoint._build_cmd(_msg("human", sender="darian"), "opus")
        self.assertIn("--permission-mode", cmd)
        self.assertEqual(cmd[cmd.index("--permission-mode") + 1], "bypassPermissions")
        # no allowed-tools restriction and no peer disallow set (DISALLOWED_TOOLS_HUMAN
        # defaults to empty -> the flag is omitted entirely)
        self.assertNotIn("--allowedTools", cmd)
        self.assertNotIn("--disallowedTools", cmd)
        self.assertEqual(timeout, endpoint.ANSWER_TIMEOUT_HUMAN)

    def test_human_profile_model(self):
        self.assertEqual(endpoint._spawn_profile(_msg("human"))["model"],
                         endpoint.MODEL_HUMAN)


class PeerProfileUnchanged(unittest.TestCase):
    def test_peer_cmd_restricted(self):
        cmd, timeout = endpoint._build_cmd(_msg(), "sonnet")
        self.assertNotIn("--permission-mode", cmd)
        self.assertIn("--disallowedTools", cmd)
        self.assertIn("Edit", cmd[cmd.index("--disallowedTools") + 1])
        self.assertIn("--allowedTools", cmd)
        self.assertIn("pending_actions.py", cmd[cmd.index("--allowedTools") + 1])
        self.assertEqual(timeout, endpoint.ANSWER_TIMEOUT)

    def test_peer_profile_model(self):
        self.assertEqual(endpoint._spawn_profile(_msg())["model"], endpoint.MODEL)


if __name__ == "__main__":
    unittest.main(verbosity=1)
