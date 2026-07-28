#!/usr/bin/env python3
"""Retrieval-augmented spawn (2026-07-28).

An answerer running the Phase-B sandbox profile has no shell, no fetch and no search tool, so
it answered from parametric knowledge even when its domain HAD a knowledge base. Retrieval is
therefore done by the ENDPOINT and injected into the prompt — the sandboxed model gains no new
tool surface, and retrieval becomes deterministic rather than something the model may forget.

These tests pin the three properties that make that safe:
  1. FAIL-OPEN — a dead/slow/garbage retriever must never turn a question into an error.
  2. OUTSIDE THE FENCE — retrieved material is the agent's OWN, so it must not be pasted inside
     the untrusted-peer fence where the prompt tells the model to treat everything as data.
  3. OFF BY DEFAULT — no RAG_URL configured means byte-identical behaviour to before.

Run: python3 endpoint/test_kb_lookup.py
"""
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
_tmp = tempfile.mkdtemp(prefix="kbtest-")
os.environ.setdefault("AGENT_NAME", "testagent")
os.environ.setdefault("AUTH_TOKEN", "t")
os.environ.setdefault("STATE_DIR", _tmp)
os.environ.setdefault("WORKDIR", _tmp)


def _load(**env):
    for k in ("RAG_URL", "RAG_KEY", "RAG_TOP_K", "RAG_COLLECTION"):
        os.environ.pop(k, None)
    os.environ.update(env)
    spec = importlib.util.spec_from_file_location("ep_kb", HERE / "endpoint.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _fake_search(results):
    """Stand in for rag-api POST /search."""
    class R:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps({"results": results}).encode()
    return lambda req, timeout=None: R()


DOCS = [{"text": "App Platform basic instances start at $5/mo.",
         "metadata": {"source": "https://docs.example.com/app-platform/pricing"}},
        {"text": "Static sites are free on the Starter tier.",
         "metadata": {"source": "https://docs.example.com/app-platform/static"}}]


class Disabled(unittest.TestCase):
    def test_no_rag_url_means_no_retrieval(self):
        """The feature must be inert unless deliberately configured."""
        m = _load()
        self.assertEqual(m._kb_lookup("anything"), ("", 0))
        self.assertEqual(m._kb_section("anything"), "")


class FailOpen(unittest.TestCase):
    def setUp(self):
        self.m = _load(RAG_URL="http://127.0.0.1:9", RAG_KEY="k")

    def test_unreachable_retriever_yields_no_context_not_an_exception(self):
        self.assertEqual(self.m._kb_lookup("q"), ("", 0))

    def test_malformed_response_is_swallowed(self):
        class R:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b"not json"
        with mock.patch.object(self.m.urllib.request, "urlopen", lambda *a, **k: R()):
            self.assertEqual(self.m._kb_lookup("q"), ("", 0))

    def test_empty_query_short_circuits(self):
        self.assertEqual(self.m._kb_lookup("   "), ("", 0))


class Injection(unittest.TestCase):
    def setUp(self):
        self.m = _load(RAG_URL="http://rag.invalid", RAG_KEY="k")

    def test_retrieved_text_and_sources_are_present(self):
        with mock.patch.object(self.m.urllib.request, "urlopen", _fake_search(DOCS)):
            block, n = self.m._kb_lookup("app platform cost")
        self.assertEqual(n, 2)
        self.assertIn("$5/mo", block)
        self.assertIn("docs.example.com/app-platform/pricing", block)

    def test_section_is_labelled_as_the_agents_own_material(self):
        with mock.patch.object(self.m.urllib.request, "urlopen", _fake_search(DOCS)):
            sec = self.m._kb_section("q")
        self.assertIn("YOUR OWN KNOWLEDGE BASE", sec)
        self.assertIn("BEGIN REFERENCE MATERIAL", sec)
        self.assertIn("END REFERENCE MATERIAL", sec)

    def test_reference_material_sits_OUTSIDE_the_untrusted_peer_fence(self):
        """The load-bearing one. The peer fence is a random nonce and everything inside it is
        declared untrusted data; retrieved KB material must land BEFORE that fence, or the
        model is told to distrust its own sources."""
        msg = {"from": "somepeer", "type": "question", "body": "app platform cost"}
        with mock.patch.object(self.m.urllib.request, "urlopen", _fake_search(DOCS)):
            prompt = self.m._build_prompt(msg)
        i_ref = prompt.find("BEGIN REFERENCE MATERIAL")
        i_fence = prompt.find("UNTRUSTED DATA")
        self.assertGreater(i_ref, -1, "reference material missing from the prompt")
        self.assertGreater(i_fence, -1, "peer fence missing from the prompt")
        self.assertLess(i_ref, i_fence, "KB material must precede the untrusted-peer fence")

    def test_chunks_are_size_capped(self):
        big = [{"text": "x" * 5000, "metadata": {"source": "s%d" % i}} for i in range(10)]
        m = _load(RAG_URL="http://rag.invalid", RAG_KEY="k", RAG_MAX_CHARS="6000")
        with mock.patch.object(m.urllib.request, "urlopen", _fake_search(big)):
            block, n = m._kb_lookup("q")
        self.assertLessEqual(len(block), 12000)
        self.assertLess(n, 10)

    def test_no_results_means_no_section(self):
        with mock.patch.object(self.m.urllib.request, "urlopen", _fake_search([])):
            self.assertEqual(self.m._kb_section("q"), "")


if __name__ == "__main__":
    unittest.main()
