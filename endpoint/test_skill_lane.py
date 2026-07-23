#!/usr/bin/env python3
"""koine/skill/v1 machine lane (G-1): a peer discovers + fetches a CATALOGED, pre-scrubbed
skill bundle deterministically ($0, no LLM), served from a published SKILLS_CTX. Non-cataloged
fetches are refused. No pip deps, no network. Run: python3 endpoint/test_skill_lane.py
"""
import base64
import hashlib
import importlib.util
import io
import json
import os
import sys
import tarfile
import tempfile

_ctx = tempfile.mkdtemp(prefix="skillctx-")
# a minimal published bundle (what the cc-01 builder writes)
_bundle = io.BytesIO()
_man = json.dumps({"kind": "skill-bundle", "scrubbed": True,
                   "skills": [{"name": "demo", "version": "2026.01.01"}]}).encode()
_body = b"# demo skill\nrebind example.com and 192.0.2.10 to your world.\n"
with tarfile.open(fileobj=_bundle, mode="w:gz") as t:
    for arc, data in (("MANIFEST.json", _man), ("demo/SKILL.md", _body)):
        ti = tarfile.TarInfo(arc); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
_blob = _bundle.getvalue()
open(os.path.join(_ctx, "demo.tgz"), "wb").write(_blob)
json.dump({"as_of": "2026-01-01T00:00:00Z", "skills": {"demo": {
    "version": "2026.01.01", "bytes": len(_blob),
    "bundle_sha256": "deadbeef", "file": "demo.tgz",
    "content_hash": "c0ffee", "pitch": "a demo"}}},
    open(os.path.join(_ctx, "index.json"), "w"))

os.environ["SKILLS_CTX"] = _ctx
os.environ["AGENT_NAME"] = "atlas"
os.environ.setdefault("AUTH_TOKEN", "x")
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("endpoint", os.path.join(HERE, "endpoint.py"))
ep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ep)

_fails = []


def ck(name, cond):
    print(("  ok  " if cond else "FAIL  ") + name)
    if not cond:
        _fails.append(name)


def _peer(body):
    return {"from": "stranger", "type": "question", "channel": "peer",
            "body": json.dumps(body)}


def main():
    r = ep._machine_answer(_peer({"coord": "koine/skill/v1", "kind": "catalog"}))
    ck("catalog served (machine lane)", r is not None)
    text, meta = r
    ck("catalog is $0 machine lane", meta["cost_usd"] == 0.0 and meta["machine_lane"])
    d = json.loads(text)
    ck("catalog lists demo, marked scrubbed",
       [s["name"] for s in d["skills"]] == ["demo"] and d["skills"][0]["scrubbed"])

    r = ep._machine_answer(_peer({"coord": "koine/skill/v1", "kind": "fetch", "skill": "demo"}))
    text, _ = r
    d = json.loads(text)
    ck("fetch returns a skill_bundle", d["kind"] == "skill_bundle" and d["skill"] == "demo")
    blob = base64.b64decode(d["bundle_b64"])
    ck("file_sha256 matches delivered bytes",
       hashlib.sha256(blob).hexdigest() == d["file_sha256"] and blob == _blob)
    ck("install_note present (peer fetch is not authority)", "not authority" in d["install_note"])

    r = ep._machine_answer(_peer({"coord": "koine/skill/v1", "kind": "fetch", "skill": "secret-ops"}))
    text, _ = r
    d = json.loads(text)
    ck("non-cataloged fetch refused with available list",
       d["kind"] == "error" and d["available"] == ["demo"])

    # a peer can't reach a non-machine coord through this lane
    r = ep._machine_answer(_peer({"coord": "caldera/v1", "kind": "catalog"}))
    ck("other coord not mis-served by the skill lane", r is None)  # no caldera ctx here

    print("\n" + ("ALL SKILL-LANE TESTS PASSED" if not _fails else f"FAILURES: {_fails}"))
    sys.exit(1 if _fails else 0)


if __name__ == "__main__":
    main()
