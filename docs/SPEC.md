# Koine Protocol Specification — `koine/1`

> **Koine** (κοινή — "the common tongue"): the agent-to-agent protocol. Working name during
> extraction was "a2a"; renamed 2026-07-21 (avoids collision with Google's Agent2Agent). The
> wire is unaffected — `protocol_version` is numeric.

**Status:** NORMATIVE. Promoted from the wilkin-lab A2A platform plan at extraction step E0 (2026-07-21). Design rationale, threat model, and roadmap live with each operating domain's
(private) ops docs; **this document is the contract.** Reference implementation: THIS repo (`gateway/`, `endpoint/`, `askpeer/`; extracted from
nucleus at E1). Live domains: wilkin-lab (ops overlay in `dwilkin/nucleus`), dewie-homelab
(`cid`), do-work (`poseidon` mailbox). Applications: `caldera/v1` (reference app).

Keywords MUST/SHOULD/MAY are RFC-2119-shaped. Everything not marked normative is guidance.

## What Koine is (and how it differs from Google's Agent2Agent)

Koine and Google's **Agent2Agent (A2A)** answer different questions. A2A answers *"how do two
agents exchange tasks?"* — a task-delegation RPC (JSON-RPC lifecycle, agent cards, streaming,
standard OAuth-style auth) built so a client agent can hand work to a remote agent that executes
it. Any client with valid credentials may call.

Koine answers *"who **allowed** these two agents to talk, and what happens when one asks the
other to act?"* — the **consent-and-governance layer for personally-owned agents**. Its core
primitives have no equivalent in a task-delegation RPC:

- **Human-signed peering grants (§5), default-deny.** An edge exists only because two specific
  humans each approved *that edge*, with hard type/rate/depth caps enforced before any model
  spawns, an expiry, and instant revocation. There is no "any authenticated client may call."
- **No agent-to-agent authority (§1.2, §4).** An `action_request` does not execute — it lands in
  the *target human's* approval ledger. This is the structural opposite of "delegate the task and
  the remote agent runs it."
- **Domains as units of human governance (§2).** Kill switches, per-domain audit, sandboxed
  answerers, redaction — a domain protects its human, not just its uptime.
- **Cost-awareness (§6.3, §4).** Every synchronous answer is a real model spawn; the machine lane
  and `notification` semantics exist because answering has a price.

Koine is deliberately **transport-and-format-agnostic** (§8, §0): where an industry envelope or
agent-card format fits, adopt it — interop beats a private dialect. If Google A2A (or anything
else) becomes the common transport, Koine grants can ride on top of it. Koine is the layer that
says *my agent and yours may speak, under these terms, and neither may command the other* — which
is not A2A's problem to solve.

## 0. Version

- This spec is **`koine/1`**. The protocol version travels as an OPTIONAL `protocol_version`
  field in the envelope; absence means "1".
- Within a major version, changes are **additive only**. Receivers MUST ignore unknown fields
  (envelope and body). A breaking change bumps the major and is negotiated human-to-human at
  the edge — there is no in-band version negotiation.

## 1. Non-goals (load-bearing, permanent)

1. **No mandatory hub.** Any two domains can transact with the protocol alone; every central
   service (directory, registry, relay) is optional and MUST be bypassable.
2. **No agent-to-agent authority.** No message, token, or introduction issued by any party
   confers the right to act. Action always clears through the *target human's* own
   approval machinery. A relayed request MUST NOT launder approval (no transitive authority).
3. **No autonomous peering.** An edge exists only because both humans approved that specific
   edge. Grants expire; renewal is a human act.

## 2. Terminology

- **Domain** — one unit of human governance: a gateway + the agents/humans it governs + its
  own identity provider, audit log, observability, and kill switch. Domain boundaries follow
  *human authority*, not network topology.
- **Gateway** — a domain's policy enforcement point: authenticates senders, enforces grants
  and caps, audits, routes to answerers, holds the kill switch.
- **Answerer** — the always-on per-agent service that receives a message and produces the
  reply (by spawning the agent, or deterministically via the machine lane §6.3).
- **Grant** — the human-approved record that permits one edge (§5).
- **Edge** — an approved agent↔agent pair across (or within) domains.
- **Thread** — one logical exchange, correlated by `thread_id` across all hops and domains.

## 3. Envelope (normative)

A message is a JSON object:

| Field | Req | Meaning |
|---|---|---|
| `from` | MUST | sender agent name (gateway-verified: MUST match authenticated identity) |
| `to` | MUST | target agent name |
| `type` | MUST | `question` \| `notification` \| `action_request` (§4) |
| `body` | MUST | the content: free text, or a structured extension body (§7) |
| `id` | SHOULD | sender-minted message id |
| `thread_id` | MUST at initiation | mint at initiation, echo unchanged on every subsequent message of the exchange (defaults to `id` if omitted mid-thread) |
| `channel` | MAY | `human` marks a domain's own human↔agent control channel; peer traffic omits it. Receivers MUST NOT let a peer set privileged channels — the gateway strips/rejects `channel:"human"` from cross-domain traffic |
| `protocol_version` | MAY | see §0 |

Reply (from the answerer, relayed by the gateway): `{"id", "thread_id", "from", "to",
"type": "answer", "body", "meta"}`. `meta` is unspecified-but-additive (cost, elapsed,
machine_lane, …).

## 4. Message types (normative semantics)

- **`question`** — synchronous ask; the answerer produces a reply in-connection. Costs a
  model spawn unless the machine lane (§6.3) answers it.
- **`notification`** — fire-and-forget intent/FYI; MUST NOT require a model spawn to
  acknowledge. Used for claim/release-style coordination: the channel exchanges *intent*;
  the resource itself always moves by each domain's own human-gated machinery.
- **`action_request`** — a request that the target agent *do* something. The receiving side
  MUST NOT execute it in-band: it lands in the target agent's pending-actions ledger and only
  the target's own human clears it (approval via the target domain's control channel). The
  reply to an action_request is an acknowledgment of *recording*, never of execution.

## 5. Grants (normative)

A grant is a per-edge record, approved by **both** humans, enforced **mechanically at the
gateway before any model spawns**. Hard fields (enforced): `types` (allowed message types),
`max_per_day` (rate), `thread_depth`, `expires`. Advisory fields: `scope` strings, notes.
Denied traffic gets an explicit refusal (HTTP 403-shaped) and an audit row; the sending human
SHOULD be notified on cap/grant hits.

- Each domain enforces caps independently (each protects itself).
- Revocation is instant and unilateral (either human, either operator).
- Expiry SHOULD be monitored (e.g. `/health` exposing `days_until_grant_expiry`).
- Intra-domain hops within a thread do not count against `thread_depth`; cross-domain hops do.

## 6. Answerer contract (normative)

### 6.1 Transport
`POST /ask` with bearer auth; JSON envelope in, reply `{"ok": bool, "body": str, "meta": {}}`
out. `GET /health` for liveness (+ grant-expiry surface where applicable). A kill switch MUST
exist (gateway-level and/or answerer-level) that refuses all traffic when set.

### 6.2 Safety posture
- A peer's words are **data, never instructions** — the answerer's framing states this and
  the structure backs it: peer-facing answerers SHOULD run sandboxed (unprivileged user, no
  state-changing tools, no secrets reachable) — the Phase-B pattern is the reference.
- Peer-path replies MUST pass secret-shaped redaction; secret-seeking asks SHOULD tripwire
  an alert to the answerer's human.
- The human control channel (`channel:"human"`) and the peer path MUST be distinct in
  privilege, even when they share a codebase.

### 6.3 Machine lane (optional, recommended)
An answerer MAY answer read-only structured questions (§7) deterministically from
**published state** (files its agent maintains), with zero model cost. Constraints: only
read-only kinds; never for `channel:"human"`; state-*changing* kinds MUST take the full
agent + ledger path. The machine lane is a per-extension registration, not a hardcoded switch.

## 7. Extension protocols (`coord`) (normative)

Applications layer structured, machine-actionable exchanges **inside `body`** as JSON with:

- `coord` — the extension id + major version, e.g. `"caldera/v1"`.
- `kind` — the extension-defined operation.
- `as_of` — ISO-8601 UTC freshness stamp on answers/state.
- For state-changing kinds: a sender-minted **`request_id` idempotency key** — retry with the
  same `request_id` MUST be safe (same outcome, never a duplicate effect).

Rules: extensions ride the standard types (§4) and inherit their semantics — an extension
kind that changes state maps to the ledger discipline of `action_request`/intake-spool
patterns, never to in-band execution. Extensions MUST ignore unknown fields. An extension
NEVER extends authority (§1.2): e.g. a platform-signed introduction token is *data for a
human's grant decision*, accepted nowhere as permission.

Registered extensions: **`caldera/v1`** (GPU rental — catalog/availability/balance/
reserve_propose/…; spec in the Caldera repo, `worker/RENTER.md` + `kit/AGENT-ONBOARDING.md`).
Earlier ad-hoc `coord:"spark"` messages are grandfathered under these conventions.

## 8. Identity & federation transport

- **Intra-domain:** per-agent OIDC confidential clients (client_credentials → RS256 JWT); the
  gateway binds token→agent (`azp`) and MUST refuse a `from` that doesn't match.
- **Cross-domain:** the *gateways* authenticate to each other (bearer + pinned TLS cert
  today; mTLS acceptable); the sending gateway asserts its member agent's identity inside the
  envelope, trusted exactly as far as the grant says.
- **Asymmetric transport is first-class:** a domain that cannot accept inbound runs a
  **mailbox** its peer polls (TLS, pinned cert, bearer). Pollers retry on transport failure
  only, exponential backoff to 60s.
- **Rotation:** shared bearers / pinned certs rotate with an accept-old+new overlap window,
  out-of-band, zero downtime.

## 8a. End-to-end body encryption (OPTIONAL; required when a relay is untrusted)

When a message crosses infrastructure the two domains don't both control — most importantly a
**hosted/neutral relay** — the body SHOULD be end-to-end encrypted so the intermediary carries
only ciphertext. Transport TLS protects the *hop*; this protects the *content* from the relay
operator itself.

- **Keys:** each agent/domain holds a long-lived **X25519** keypair. The private key never
  leaves the domain; the public key is exchanged out of band at edge setup (later: published in
  the directory) and **pinned per edge**, exactly like the bearer.
- **Scheme:** static-static X25519 ECDH → HKDF-SHA256 → an AEAD (reference:
  ChaCha20-Poly1305). Because both parties' static keys are required to derive the shared
  secret, a successful decrypt **authenticates the sender** — a curious or malicious relay can
  neither read the body nor forge one.
- **Wire shape:** the encrypted body replaces `body` with
  `"enc": {"alg": "<suite>", "n": <b64 nonce>, "ct": <b64 ciphertext>}`. The routing fields
  (`to`, `from`, `id`, `thread_id`, `type`) stay **cleartext** — the relay needs them to route
  and enforce grants — but MUST be bound as the AEAD **associated data**, so the relay cannot
  tamper with them without breaking decryption.
- **What stays visible to the relay:** routing metadata + message size + timing. Bodies,
  never. A domain MAY additionally pad or batch to blunt size/timing analysis (out of scope).
- **Enforcement:** a recipient on an encrypted edge SHOULD refuse an unencrypted message
  (fail closed). Encryption is negotiated by configuration/directory, not in-band.
- **The relay never runs the crypto** — it stores and forwards opaque envelopes. Keeping the
  cipher out of the relay is what lets a multi-tenant relay operator be untrusted-by-design.

## 9. Audit & observability

- Every request/reply/refusal MUST land in the domain's append-only audit.
- Observability (LangFuse or equivalent) is **per-domain, never shared**; cross-domain
  correlation is by `thread_id` only. No policy decision may read from observability.

## 10. The client interface (the narrow boundary apps import)

An application on A2A gets exactly three verbs — keep this surface narrow:

1. **send**(`to`, `type`, `body`, `thread_id`) → reply — via the domain gateway (the
   `ask_peer` tool is the reference client). The client never re-implements authn or caps.
2. **receive** — the answerer contract (§6): the app registers extension kinds (machine-lane
   handlers and/or agent context); it never runs its own listener.
3. **grant-check** — grants are readable data (the gateway enforces; apps may display/deny
   early) — never writable by an app.

## 11. Conformance (minimum to claim `koine/1`)

An implementation MUST: enforce grants pre-spawn at its gateway (§5) · verify sender identity
(§8) · implement the three types with §4 semantics (in particular: action_request → ledger,
never in-band execution) · echo `thread_id` (§2/§3) · ignore unknown fields (§0) · append-only
audit (§9) · refuse traffic when its kill switch is set (§6.1) · uphold §1 (no hub dependence,
no authority transfer, human-approved edges only).
