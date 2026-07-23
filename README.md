# Koine — the agent-to-agent protocol + reference implementation

> κοινή, "the common tongue" — the shared language Greek city-states used across their
> borders. Koine is what agents in different trust domains speak to each other.

**Spec: [`docs/SPEC.md`](docs/SPEC.md) — `koine/1` (normative).** This public repo carries
the protocol spec + reference implementation only; each operating domain keeps its own
(private) design/ops docs, grants, and deploy overlays. Extracted from the wilkin-lab ops
repo at extraction step E1 (2026-07-21); the Atlas↔Genie↔Poseidon↔cid federation runs on
this code.

Koine connects agents across **trust domains** — households, workplaces, friends — such that
every link is safe for *both* humans: consented (peering grants), scoped, audited, revocable.
Permanent non-goals: **no mandatory hub, no agent-to-agent authority, no autonomous peering.**

### Isn't this Google's Agent2Agent?

No — different layer. Google's **A2A** is task-delegation plumbing: *how* two agents exchange
work, so a client can hand a task to a remote agent that runs it. Koine is the **consent-and-
governance layer for personally-owned agents**: *my* agent and *your* agent may talk only because
we both signed off on that specific edge, under caps we set, and **neither can ever command the
other** — an "action request" lands in the other human's approval queue, it doesn't execute.
That's not A2A's problem space. Koine is also transport-agnostic: if A2A wins as the wire format,
Koine grants can ride on it. See [SPEC.md → "What Koine is"](docs/SPEC.md).

**New here? → [JOINING.md](docs/JOINING.md)** walks two strangers from "nice to meet you" to two
agents talking, step by step. **Prefer to run it all yourself? →
[SELF-HOSTING.md](docs/SELF-HOSTING.md)** — mailbox, registry, keys, and agents from this repo
alone; no hosted service involved.

## Layout

| Dir | What | Runs where |
|---|---|---|
| `docs/` | The normative spec (`koine/1`) | — |
| `gateway/` | The domain gateway: authn (OIDC JWT / bearer), grant + cap enforcement, audit, routing, mailbox pollers, kill switch, LangFuse emitter | one per domain (Docker) |
| `endpoint/` | The per-agent answerer: `/ask` daemon, machine lane, pending-actions ledger, redaction/tripwires; systemd units for both the full-context human-channel daemon and the sandboxed peer daemon (Phase-B pattern) | every agent host |
| `askpeer/` | The `ask_peer` MCP stdio server — the reference **send** client | every initiating agent |
| `mailbox/` | The **recommended default transport**: a public store-and-forward rendezvous for one edge (peer polls outbound; no inbound hole at home) | a domain that accepts inbound (or the koine.network service) |

## Code vs. domain config (the deployment contract)

This repo is **protocol code only**. Everything domain-specific stays in the domain's own
ops repo and is overlaid at deploy time:

- **`agents.json`** (the agent-card directory + peering grants) — domain data, never here.
- **Pinned peer certs, bearer tokens, Vault wiring, `.env`** — domain data.
- **Curated peer-context** for sandboxed answerers — domain data.

The wilkin-lab domain keeps these in `dwilkin/nucleus` (`stacks/agent-gateway/` = gateway ops
overlay + deploy, `deploy/agent-peer/` = answerer refresh scripts); its deploy scripts stage
code from this checkout (`~/koine`) and overlay domain config. A joining domain mirrors that
pattern with its own ops repo.

## Versioning

- Protocol: `koine/1` (see spec §0 — additive within a major; receivers ignore unknown fields).
- Applications declare `depends: koine >= N`. First reference app: **Caldera**
  (`dwilkin/Caldera`, `caldera/v1` — GPU rental as a `coord` extension).

## Tests

All stdlib, no deps — six files:

- `python3 test_crypto.py` — E2E envelope crypto (repo root).
- `python3 gateway/test_grant_check.py` — SPEC §5 grant hard-field enforcement
  (types / max_per_day / thread_depth / expires).
- `cd endpoint && python3 test_machine_lane.py && python3 test_escalation.py` — answerer
  machine lane + model-escalation policy.
- `cd mailbox && python3 test_relay.py && python3 test_multitenant.py` — relay contract +
  multi-tenant account/edge isolation.

The gateway is exercised by its live health/deny paths; domain ops repos carry integration
checks (the lab: Gatus probes + guard-hook suite).

## Roadmap (extraction plan E2/E3)

- **E2** — shared capability lib: the declarative node-capability descriptor + reconciler
  (today in Caldera's worker) extracts here as a library both Koine and apps import.
- **E3** — config marketplace: an optional, grant-governed registry of tested capability
  descriptors agents fetch by `applies_to` hardware. Rides the same envelope/transport;
  never mandatory, never authoritative (spec §1).
