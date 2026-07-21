# Koine — the agent-to-agent protocol + reference implementation

> κοινή, "the common tongue" — the shared language Greek city-states used across their
> borders. Koine is what agents in different trust domains speak to each other.

**Spec: [`docs/SPEC.md`](docs/SPEC.md) — `koine/1` (normative).** This public repo carries
the protocol spec + reference implementation only; each operating domain keeps its own
(private) design/ops docs, grants, and deploy overlays. Extracted from the wilkin-lab ops
repo at extraction step E1 (2026-07-21); the Atlas↔Genie↔Poseidon↔cid federation runs on
this code.

A2A connects agents across **trust domains** — households, workplaces, friends — such that
every link is safe for *both* humans: consented (peering grants), scoped, audited, revocable.
Permanent non-goals: **no mandatory hub, no agent-to-agent authority, no autonomous peering.**

## Layout

| Dir | What | Runs where |
|---|---|---|
| `docs/` | The normative spec (`koine/1`) | — |
| `gateway/` | The domain gateway: authn (OIDC JWT / bearer), grant + cap enforcement, audit, routing, mailbox pollers, kill switch, LangFuse emitter | one per domain (Docker; the lab's runs on infra-host) |
| `endpoint/` | The per-agent answerer: `/ask` daemon, machine lane, pending-actions ledger, redaction/tripwires; systemd units for both the full-context human-channel daemon and the sandboxed peer daemon (Phase-B pattern) | every agent host |
| `askpeer/` | The `ask_peer` MCP stdio server — the reference **send** client | every initiating agent |

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
- Applications declare `depends: a2a >= N`. First reference app: **Caldera**
  (`dwilkin/Caldera`, `caldera/v1` — GPU rental as a `coord` extension).

## Tests

`cd endpoint && python3 test_machine_lane.py && python3 test_escalation.py` (stdlib, no deps).
The gateway is exercised by its live health/deny paths; domain ops repos carry integration
checks (the lab: Gatus probes + guard-hook suite).

## Roadmap (extraction plan E2/E3)

- **E2** — shared capability lib: the declarative node-capability descriptor + reconciler
  (today in Caldera's worker) extracts here as a library both A2A and apps import.
- **E3** — config marketplace: an optional, grant-governed registry of tested capability
  descriptors agents fetch by `applies_to` hardware. Rides the same envelope/transport;
  never mandatory, never authoritative (spec §1).
