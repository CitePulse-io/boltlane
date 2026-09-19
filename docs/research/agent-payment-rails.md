# Inbound agent-payment rails: L402 vs x402

Research ticket: [CitePulse-io/boltlane#7](https://github.com/CitePulse-io/boltlane/issues/7)
Date: 2026-09-18. Sources are primary: protocol specs, IETF drafts, and implementation repos.

## The question

The Boltlane coordinating server must support an "x402-shaped" payment gate for requestors
(pre-paid or pay-per-request), **default OFF for self-hosters**, with **Bitcoin Lightning strongly
preferred over USDC/Solana inbound**. Which protocol should the gate implement first: L402
(Lightning-native HTTP 402) or x402 (the Coinbase/USDC-ecosystem protocol)? Can an L402-style flow
satisfy "x402-like" gating while staying Lightning-native, and how do MCP/agent clients consume
each?

## Findings

### 1. L402 — spec status, Go implementations, production users

**Spec.** L402 (formerly LSAT) is an open protocol maintained by Lightning Labs in
[`lightninglabs/L402`](https://github.com/lightninglabs/L402). The
[protocol specification](https://github.com/lightninglabs/L402/blob/master/protocol-specification.md)
defines a challenge–response flow over standard HTTP auth machinery:

```
WWW-Authenticate: L402 macaroon="<base64>", invoice="<bolt11>"
Authorization:    L402 <base64(macaroon)>:<hex(preimage)>
```

The server mints a macaroon whose identifier commits to the invoice's payment hash; the client
pays the BOLT 11 invoice over Lightning and presents macaroon + preimage. Verification is
stateless (`H == sha256(preimage)`) — no payment database lookup needed
([protocol-specification.md §6.1](https://github.com/lightninglabs/L402/blob/master/protocol-specification.md)).
The spec covers HTTP and gRPC flows (gRPC encodes the challenge in `grpc-status-details-bin`),
credential reuse/revocation, TLS requirements, and backwards compatibility with the `LSAT` scheme
name. There is also a
[~560-token agent spec](https://github.com/lightninglabs/L402/blob/master/agent-spec.md) written
specifically for AI-agent integration, and a
[macaroon technical spec](https://github.com/lightninglabs/L402/blob/master/macaroon-spec.md).
Lightning Labs documents L402 as "the standard for selling and buying digital resources… built
with a focus on agentic commerce" ([Lightning docs](https://docs.lightning.engineering/the-lightning-network/l402)).

**Go implementations.**
- [lightninglabs/aperture](https://github.com/lightninglabs/aperture) — the reference L402 reverse
  proxy in Go: "L402 (Lightning HTTP 402) API Key proxy". MIT-licensed, ~609 commits, actively
  developed (Go 1.25). It is not just a proxy: recent versions include **metered pricing**
  (prepaid usage bundles drawn down per request, `docs/metering.md`, reference price server
  `meterd`), **rate limiting** per token, an admin API, a dashboard, and an **MCP server**
  (`aperturecli mcp serve`) for agent-driven management. This maps almost 1:1 onto Boltlane's
  "pre-paid or pay-per-request" gate requirement.
- Macaroons in Go: [`lightninglabs/macaroons`](https://github.com/lightninglabs/macaroons) (the
  library underlying lnd/aperture; the GitHub 404 above is a fetch artifact — the package is at
  `github.com/lightninglabs/macaroons` and used by aperture's `l402` package) and the original
  [`go-macaroon`](https://github.com/rogpeppe/go-macaroon). Aperture's `l402/` package implements
  mint/verify/challenge handling directly.
- The Lightning node integration is pluggable: aperture talks to `lnd` for invoice creation and
  preimage lookup ([aperture README](https://github.com/lightninglabs/aperture)).

**Production users.**
- **Lightning Loop** — Lightning Labs' non-custodial on/off-ramp — authenticates all client
  requests through Aperture in production
  ([aperture README](https://github.com/lightninglabs/aperture),
  [loop repo](https://github.com/lightninglabs/loop)).
- Lightning Labs' docs state "Aperture is used today by Lightning Loop, a non-custodial swap
  service for Bitcoin and Lightning"
  ([docs.lightning.engineering](https://docs.lightning.engineering/the-lightning-network/l402)).
- Historical ecosystem clients: Tierion's [lsat-js](https://github.com/Tierion/lsat-js) and
  [boltwall](https://github.com/tierion/boltwall) (Node.js middleware), listed as implementations
  in the L402 spec repo.

**Payment schemes Aperture already speaks.** Aperture 0.2.x+ carries *two* doors in one 402
response: L402 (default) and the IETF **Payment HTTP Authentication Scheme**
([`draft-httpauth-payment-00/01`](https://datatracker.ietf.org/doc/draft-httpauth-payment/),
co-authored by Stripe and Tempo, `--authenticator.enablempp`), which supports a `charge` intent
(single request) and a `session` intent (deposit drawn down per request, refunded on close).
This is directly relevant: the *IETF Payment scheme is payment-method-agnostic* (its method
registry could host a Lightning method), and Aperture already proves a dual-offer 402 works.

### 2. x402 — spec, maturity, USDC/Base/Solana coupling

**Spec.** x402 is an open standard for HTTP-native payments, now governed by the
[x402 Foundation](https://github.com/x402-foundation/x402) (Coinbase's
[coinbase/x402](https://github.com/coinbase/x402) is a development fork of it; 724 commits, 6.6k
stars on the foundation repo). Spec lives in
[`specs/`](https://github.com/x402-foundation/x402/tree/main/specs). The flow:

1. Client requests a resource.
2. Server replies `402` with a `PAYMENT-REQUIRED` header (base64 JSON: accepted
   scheme/network/asset/amount).
3. Client builds a `PaymentPayload` for one offered `(scheme, network)` and retries with a
   `PAYMENT-SIGNATURE` header.
4. Server verifies (locally or via a **facilitator** `/verify` endpoint), does the work, then
   settles via `/settle` and returns `200` + `PAYMENT-RESPONSE` header.

**Maturity.** Substantial real-world traction: the Coinbase Developer Platform facilitator
"[has processed more than 100 million x402 payments across Base and Solana](https://docs.cdp.coinbase.com/x402/docs/welcome)".
SDKs are mature and multi-language: TypeScript (core, evm, svm, axios/fetch/express/fastify/hono/next,
[MCP package](https://github.com/x402-foundation/x402/tree/main/typescript/packages/mcp)) and Go
(`github.com/x402-foundation/x402/go/v2` — framework-agnostic client/server/facilitator, HTTP
wrappers, Gin middleware, plus a dedicated
[Go MCP package](https://github.com/x402-foundation/x402/tree/main/go/mcp)).

**Coupling.** The *envelope* (402 + headers + facilitator) is chain-agnostic, but every shipping
**scheme is a stablecoin scheme**:
- `exact` on EVM = EIP-3009 `transferWithAuthorization` (USDC-compatible) —
  [Go README](https://github.com/x402-foundation/x402/tree/main/go)
- `exact` on SVM = SPL token transfer (USDC) with networks `solana:…`
- The extension ecosystem (`@x402/evm|svm|stellar|cardano|aptos|avm|casper`) adds more
  non-Bitcoin chains — but **no Lightning/Bitcoin scheme exists in the standard** (checked
  [`specs/schemes/`](https://github.com/x402-foundation/x402/tree/main/specs/schemes): `exact`,
  `upto`, `auth-capture`, `batch-settlement`).
- Client spend controls default to a **$1 USD cap and default-asset allowlist** — USD-denominated
  thinking is baked into client defaults.
- Operationally, an x402 server either runs its own on-chain settlement or depends on a
  facilitator (CDP's, or self-hosted) — for a self-hostable, Bitcoin-first project that means
  either adding stablecoin custody/verification to the Go server or a third-party dependency.

### 3. Can an L402-style flow satisfy "x402-like" gating while staying Lightning-native?

Yes, with one structural caveat. Structurally both protocols are the same shape:

| | L402 | x402 |
|---|---|---|
| Status code | `402 Payment Required` | `402 Payment Required` |
| Challenge header | `WWW-Authenticate: L402 macaroon=…, invoice=…` | `WWW-Authenticate`/`PAYMENT-REQUIRED` (b64 JSON offers) |
| Proof header | `Authorization: L402 <macaroon>:<preimage>` | `PAYMENT-SIGNATURE` (b64 JSON payload) |
| Proof of payment | Lightning preimage (stateless `H == sha256(preimage)` check) | Scheme-specific signature / facilitator verify+settle |
| Settlement | Instant (LN invoice paid → preimage = receipt) | Facilitator or server-side on-chain settle, then 200 |
| Credential reuse | Macaroon cached & reused until revoked | Per-request payloads (no persistent credential) |

Differences that matter for "x402-shaped" compatibility:

- **Machine-readable offer block.** x402's `PAYMENT-REQUIRED` header is a b64 JSON document with
  `accepts[]` offers, descriptions, and extensions (e.g. Bazaar discovery). L402's challenge is
  two string params. An L402 server that wants "x402-shaped" machine-readability can *also*
  emit a `PAYMENT-REQUIRED`-style JSON offer block (amount in msat, scheme `l402`, invoice URL)
  alongside the `WWW-Authenticate` header — additive, no spec conflict.
- **Facilitator vs stateless.** x402 outsources verify/settle to a facilitator; L402 verifies
  statelessly in-process. For Boltlane this is a *win*: the coordinating server already runs
  Lightning (payouts), so minting invoices and checking preimages needs no third party.
- **Pre-paid vs per-request.** x402 `exact` is strictly per-request. L402's macaroon caveats
  (usage counts, expiry, tiers) plus Aperture's metering mode give both pay-per-request *and*
  pre-paid balance semantics natively — matching Boltlane's requirement exactly.
- **MCP consumption** (see below) is x402's strongest agent story today, but L402 is pure HTTP
  auth: any agent with an HTTP client and a Lightning wallet (LNURL, BOLT11, NWC) can consume it
  with ~40 lines of client code per the agent spec.

The honest gap: an L402-only gate is not *wire-compatible* with x402 clients. x402 clients
(`@x402/fetch`, Go `x402http.HTTPClient`) look for `PAYMENT-REQUIRED`/`PAYMENT-SIGNATURE`
headers and EVM/SVM schemes; they will not pay a BOLT 11 invoice. "x402-like" can mean
*protocol-shape* parity (402, offer block, retry-with-proof, receipt), not byte-level
interoperability — unless the hybrid below is used.

### 4. How MCP/agent clients consume each

**x402 has first-class MCP integration, both directions:**
- TypeScript: [`@x402/mcp`](https://github.com/x402-foundation/x402/tree/main/typescript/packages/mcp)
  — "MCP server integration for x402" (paid tool calls with a `PaymentWrapper`; JSON-RPC error
  code 402; payment metadata under MCP `_meta` keys `x402/payment`).
- Go: [`go/v2/mcp`](https://github.com/x402-foundation/x402/tree/main/go/mcp) — server
  `PaymentWrapper` around tool handlers for `modelcontextprotocol/go-sdk`, and client
  `NewX402MCPClientFromConfig` with `AutoPayment` default true. An x402-enabled MCP client pays
  a paid tool call automatically after receiving the payment-required error.
- Coinbase CDP offers agentic accounts + hosted facilitator so agents can pay x402 resources
  with a custodial balance (https://docs.cdp.coinbase.com/x402/docs/welcome).

**L402/MCP consumption today:**
- No MCP SDK package exists for L402. But L402 is ordinary HTTP auth: an MCP server behind
  L402 gating is consumed by any client that can (a) parse `WWW-Authenticate: L402`, (b) pay a
  BOLT 11 invoice, (c) resend with `Authorization`. The
  [agent spec](https://github.com/lightninglabs/L402/blob/master/agent-spec.md) is ~560 tokens
  precisely so an agent harness can implement the client inline.
- Lightning Labs ships an **MCP server for Aperture administration** (`aperturecli mcp serve`)
  — agent-managed paid APIs — and aperture's CLI is explicitly designed for AI agents
  (JSON output, semantic exit codes, `schema --all` discovery command).
- The Lightning wallet side is what agents need: NWC (Nostr Wallet Connect) or an embedded
  LND/CLN node lets an agent pay invoices programmatically without custody UI.
- Client libraries: lsat-js / boltwall (JS, Tierion), aperture's own Go client paths, plus
  generic `l402` Go client code in lightninglabs repos.

### 5. Hybrid options: accept both, or translate

Three viable seams, in increasing effort:

1. **Dual-offer 402 (recommended, proven pattern).** Return both challenges on the same 402:
   `WWW-Authenticate: L402 macaroon="…", invoice="…"` *and* an x402-style `PAYMENT-REQUIRED`
   offer block whose `accepts[]` describes a Lightning scheme (`scheme: "l402"`,
   `network: "lightning"`, invoice in the request). Aperture already ships exactly this pattern
   (L402 + IETF Payment scheme offers in one response). x402-aware clients that ignore unknown
   schemes degrade gracefully; Lightning-native agents use L402. No translation logic; the
   requestor picks the door it understands.
2. **IETF Payment scheme with a Lightning method.** The
   [draft-httpauth-payment](https://datatracker.ietf.org/doc/draft-httpauth-payment/) is
   method-agnostic with an IANA method registry; a `lightning/charge` method spec could carry
   BOLT 11. Aperture can serve this today (`--authenticator.enablempp`). Cost: the draft is
   young (v01, Sept 2026, expires Mar 2027) and no client tooling exists yet.
3. **Translation via a Lightning facilitator.** Register an x402 `lightning` mechanism that
   internally mints/pays invoices (client-side x402 libraries support registering custom
   schemes). This makes x402 clients able to pay Lightning without knowing it — but it is the
   most work, the facilitator semantics (verify/settle split) don't map cleanly onto
   pay-then-present-preimage, and it drags in x402's USD-denominated type system.

## Comparison table

| Criterion | L402 | x402 | Weight for Boltlane |
|---|---|---|---|
| Inbound rail | Bitcoin Lightning (BOLT 11) | USDC on Base/EVM/Solana (+ other chains) | **Decisive** — project is Lightning-first |
| Spec status | Open spec (lightninglabs/L402), HTTP+gRPC, stable | Open standard (x402 Foundation), v2, active | L402 adequate |
| Go server story | First-class (aperture, macaroons, l402 pkg) | Official Go SDK exists, but needs EVM/SVM verification machinery | L402 |
| Self-hosting | Needs a Lightning node only — already required for payouts | Needs on-chain stablecoin settlement or third-party facilitator | **Decisive** |
| State | Stateless verify (preimage) | Facilitator verify/settle or server-side chain access | L402 |
| Pre-paid + per-request | Both, natively (caveats + metering in aperture) | Per-request (`exact`); `upto` is SVM-only | L402 |
| Default-off fit | Gate is opt-in middleware | Gate is opt-in middleware | Tie |
| Agent/MCP tooling | HTTP-auth simplicity; agent spec; aperture MCP admin; wallet needed | First-class MCP packages (TS+Go), auto-pay clients, hosted facilitator | x402 |
| Production usage | Lightning Loop (production), aperture | 100M+ payments via CDP (Base/Solana) | Tie |
| Wire-compat with x402 clients | None | Native | x402 |
| Bitcoin-native values | Yes | No (stablecoin rails) | **Decisive** |

## Recommendation

**Implement the payment gate first as an L402 gate — Lightning-native HTTP 402 with macaroon +
preimage credentials — and document an x402-shaped offer block (dual-offer 402) as the second
seam for later x402/stablecoin support.**

Rationale:

1. **Rail alignment is the hard constraint.** Boltlane is Bitcoin Lightning-first; every x402
   shipping scheme is a stablecoin transfer. Choosing x402 first means building USDC/Base/Solana
   settlement into a Go server whose operators may have no stablecoin exposure, and either
   self-hosting a facilitator or depending on CDP.
2. **Self-hostability.** L402 needs exactly one new dependency: the Lightning node Boltlane
   already runs for payouts. x402 needs chain RPC, EIP-3009 verification, gasless-transfer
   semantics, or a third-party facilitator — all new trust and ops surface, contradicting the
   default-off, self-hostable posture.
3. **Pre-paid and per-request both fall out natively** from macaroon caveats (and Aperture's
   metering proves the prepaid-bundle pattern in the same Go ecosystem).
4. **The "x402-shaped" requirement is about protocol shape, not wire bytes:** 402 status,
   machine-readable offer, retry-with-proof, receipt. L402 delivers that shape over standard
   HTTP auth (RFC 7235), and the dual-offer pattern (already shipped by Aperture with the IETF
   Payment scheme) lets one 402 carry both an L402 challenge and an x402-style JSON offer — so
   the x402 seam can be added later without re-architecting.
5. **Agent story is fine, not perfect.** x402's MCP packages are the strongest agent tooling,
   but L402's ~560-token agent spec means an MCP-capable agent harness implements the client in
   tens of lines, and any Lightning-capable wallet (NWC) pays the invoice. If x402's agent
   network effects become decisive later, the dual-offer seam makes adding an x402
   `lightning`-scheme (or even USDC) mechanism additive.

**Second seam (documented, not built):** extend the same gate to emit an x402-compatible
`PAYMENT-REQUIRED` offer block alongside `WWW-Authenticate: L402` — via a custom x402
`lightning` scheme, and/or by adopting the IETF Payment scheme (`draft-httpauth-payment`)
method-agnostic envelope with a Lightning method, following Aperture's dual-offer implementation
as prior art.

## Key sources

- L402 protocol spec: https://github.com/lightninglabs/L402/blob/master/protocol-specification.md
- L402 agent spec: https://github.com/lightninglabs/L402/blob/master/agent-spec.md
- Aperture (Go L402 proxy): https://github.com/lightninglabs/aperture
- Aperture metering docs (prepaid bundles): https://github.com/lightninglabs/aperture/blob/master/docs/metering.md
- Lightning Labs L402 overview (production use by Loop): https://docs.lightning.engineering/the-lightning-network/l402
- Lightning Loop (production L402 consumer): https://github.com/lightninglabs/loop
- x402 standard (x402 Foundation): https://github.com/x402-foundation/x402
- x402 Go SDK: https://github.com/x402-foundation/x402/tree/main/go
- x402 Go MCP package: https://github.com/x402-foundation/x402/tree/main/go/mcp
- x402 TS MCP package: https://github.com/x402-foundation/x402/tree/main/typescript/packages/mcp
- x402 schemes (no Lightning): https://github.com/x402-foundation/x402/tree/main/specs/schemes
- Coinbase CDP x402 facilitator (100M+ payments): https://docs.cdp.coinbase.com/x402/docs/welcome
- IETF Payment auth scheme draft (Stripe/Tempo): https://datatracker.ietf.org/doc/draft-httpauth-payment/
- lsat-js (JS L402 client): https://github.com/Tierion/lsat-js
- boltwall (Node L402 middleware): https://github.com/tierion/boltwall