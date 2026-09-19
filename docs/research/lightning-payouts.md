# Lightning payout rails for Boltlane (node vs custodial, LNURL vs BOLT12)

**Ticket:** [CitePulse-io/boltlane#5](https://github.com/CitePulse-io/boltlane/issues/5)
**Branch:** `research/lightning-payouts` · **Date:** 2026-09-18

## The question

A Boltlane Server pays Peers per GB served, in Bitcoin via Lightning. Payouts are
unattended (no human in the loop), per-device amounts are small (satoshis-to-cents
per payout), and Devices may be offline when the payout is due. What should the
Server use as the payout rail — and what does each choice cost the SaaS operator vs
a self-hoster?

## Findings

### 1. Own node vs custodial payout provider

**Running your own node (LND / Core Lightning / lnbits / Alby Hub / Phoenixd):**

- The Server needs to *send* only. Sending is the cheap, easy side of Lightning: an
  LND node just needs outbound channels with outbound liquidity and `dest_custom_records`
  / keysend support for spontaneous payments (`lightning.proto` exposes `dest_custom_records`
  on `SendRequest` and `is_keysend` on invoices —
  [lnd/lnrpc/lightning.proto](https://github.com/lightningnetwork/lnd/blob/master/lnrpc/lightning.proto)).
  No inbound liquidity, no channel management beyond keeping channel balances topped up.
- Core Lightning ships keysend as a plugin (`plugins/keysend.c`, TLV type
  `5482373484` = the preimage, feature bit 55) and has BOLT12 offer support built in
  ([CLN plugins tree](https://github.com/ElementsProject/lightning/tree/master/plugins),
  [keysend schema](https://github.com/ElementsProject/lightning/blob/master/doc/schemas/keysend.json)).
- Alby Hub is a self-hostable node-management layer (Go, runs in Docker or desktop)
  that sits in front of embedded LDK, LND, CLN, Phoenixd or Cashu backends and speaks
  [NWC](https://nwc.dev/) — this is the closest existing open-source template for
  "server with a wallet" ([getAlby/hub README](https://github.com/getAlby/hub)).
- lnbits turns an LN node (or custodial wallet) into a user/wallet/account API with
  LNURL-pay and LNURL-withdraw built in — the standard self-hosted choice when you
  want per-peer wallet balances without each peer running a node
  ([lnbits/lnbits](https://github.com/lnbits/lnbits)).
- Failure mode you own: the node keys, channel balance exhaustion, and on-chain
  channel management. With payments **default OFF** for self-hosters this is opt-in
  complexity, which is exactly what the glossary intends (`CONTEXT.md`: x402 gating
  and Lightning payouts "default off when self-hosting").

**Custodial / hosted payout providers:**

- **Alby (NWC):** wallet-connector protocol — peers link a wallet, server pays via
  NWC. SaaS-friendly, but each peer needs an NWC-compatible wallet.
- **Strike API:** `POST /v1/payment-quotes/lightning` + execute pays any BOLT11
  invoice, and `POST /v1/payment-quotes/lightning/lnurl` pays an **LN Address /
  LNURL directly with no invoice needed**
  ([Strike API docs](https://docs.strike.me/api/), added Sep 2023). Strike is a
  regulated money transmitter: KYC'd payout rail with fiat and BTC support,
  idempotency keys, webhooks. Good SaaS option; a custodial dependency.
- **ZBD:** now positions itself as licensed financial infrastructure for games
  (US MTL NMLS 2188007, EU EMI/MiCAR) — rewards balances, withdrawal limits, KYC
  handled by ZBD, cash-out via ZBD modal/gift cards/Cash App
  ([ZBD Earn SDK docs](https://docs.zbdpay.com/rewards/sdk)). That is a full
  custodial rewards account, not a thin payout API; heavier than Boltlane needs.
- General custodial trade-off: someone else holds the float and can gate payouts;
  every payout crosses a company. Fine as a SaaS fallback, anti-thetical to the
  self-hosted story.

**Comparison:**

| Rail | Unattended sends | Offline peer | Self-host cost | Custody | Best fit |
|---|---|---|---|---|---|
| Own node (LND/CLN) + BOLT12/keysend | yes (async for offline) | holds HTLC / retries | run node + liquidity | self | SaaS *and* self-hoster |
| lnbits on top of node | yes (server-side pay) | server queues | + lnbits | self | self-hoster wanting wallet UX |
| Strike API (lnurl quote) | yes (invoice-less) | peer must come online | API key only | custodial | SaaS |
| ZBD / rewards accounts | balances, cash-out flow | n/a (balance waits) | partner integration | custodial | game-style rewards, not us |
| Raw BOLT11 invoices only | no — needs fresh invoice per payout | no | low | self | fallback |

### 2. Payout message formats for server→peer

**Raw BOLT11 invoices** are the wrong primitive for a *server-initiated* payout: the
peer must mint a fresh invoice every time, and a BOLT11 invoice is single-use
("Invoices must be given per user and are actively dangerous if two payment
attempts are made for the same user" —
[BOLT 12 spec](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)).
For unattended micro-payouts, that handshake is exactly the friction to avoid.

**Keysend (spontaneous payments)** works invoice-less: the payer picks the preimage
and sends directly to the payee's node pubkey, provided the payee's node has public
channels and keysend enabled (`accept-keysend=true` in LND —
[LND keysend docs](https://docs.lightning.engineering/lightning-network-tools/lnd/send-messages-with-keysend);
CLN `keysend`/`xkeysend` RPC —
[schema](https://github.com/ElementsProject/lightning/blob/master/doc/schemas/keysend.json)).
Catch: keysend pays a **node**, so the peer must run a public-channel Lightning node
24/7 — wrong audience for a Raspberry Pi peer running a wallet app.

**BOLT12 offers** are the modern primitive and the best fit:

- An offer is a *static* payment code (reusable, offline-safe) — unlike BOLT11 there
  is no per-payment invoice minting and no double-use hazard
  ([BOLT 12: Negotiation Protocol for Lightning Payments](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)).
- It natively covers the **merchant-pays-user flow** the ticket asks about
  ("e.g. ATM or refund"): the *payee* publishes an `invoice_request` for an amount;
  the *payer* fetches an invoice from it and pays
  ([BOLT 12 payment flows](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md#payment-flow-scenarios)).
- In practice the lighter pattern is: peer registers a **static offer / LN Address**
  once at enrollment; the Server calls `offer`→`fetch invoice`→`pay` (CLN
  `fetchinvoice`, [offers plugin](https://github.com/ElementsProject/lightning/tree/master/plugins))
  whenever it wants to pay — unattended, retryable, no keysend required.
- Node support: CLN has offers in-tree
  ([offers.c … offers_proof.c](https://github.com/ElementsProject/lightning/tree/master/plugins));
  LND is mid-rollout — v0.22.0 adds the BOLT12 offer/invoice_request/invoice codecs
  ([LND 0.22.0 release notes](https://github.com/lightningnetwork/lnd/blob/master/docs/release-notes/release-notes-0.22.0.md)),
  so treat LND+BOLT12 as *landing*, not landed. Eclair/Phoenix/Phoenixd speak
  BOLT12 offers today (ACINQ stack) — good for mobile peers.

**LNURL-pay** is payer-initiated wallet→service (the wallet requests an invoice from
a `payRequest` endpoint and pays it —
[LUD-06/lnurl-pay](https://github.com/lnurl/luds/blob/legacy/lnurl-pay.md)). For a
Server paying *Peers*, LNURL-pay points the wrong way: it is how the Server would
*receive* money, not how it sends. Do not use it for payouts.

### 3. Offline peers — the payout queue problem

Three options, in order of fit:

1. **Peer pulls (best): LNURL-withdraw.** The Server exposes a per-peer
   `withdrawRequest` endpoint (`k1` + `minWithdrawable`/`maxWithdrawable` +
   `balanceCheck`); the peer's wallet pulls whenever it comes online
   ([LUD-03/lnurl-withdraw](https://github.com/lnurl/luds/blob/legacy/lnurl-withdraw.md)).
   The spec's own `balanceCheck`/`balanceNotify` extension is designed exactly for
   "auto-delivery of funds from services to wallets": wallets re-check the URL
   (e.g. every 24 h) and auto-withdraw — unattended accrual, peer-initiated pull,
   server never races an offline device
   ([balanceCheck](https://github.com/lnurl/luds/blob/legacy/lnurl-withdraw.md#balancecheck)).
   Peer-side friction is a single QR/`lightning:` link.
2. **Server pushes async: BOLT12 offer.** Offer stays valid while the peer is
   offline; when the Server pays, the invoice request + invoice dance completes over
   the network when the peer's node (or wallet provider holding the offer) responds.
   Hodl invoices can absorb a slow responder on the server's *receiving* side, but
   for *sending* the practical async primitive is the offer.
3. **Hold/hodl invoices** (LND `AddHoldInvoice`/`SettleInvoice` —
   [invoicesrpc](https://github.com/lightningnetwork/lnd/blob/master/lnrpc/invoicesrpc/invoices.proto))
   are an inbound mechanism (receiver holds the HTLC until a preimage appears) —
   useful for inbound x402/L402 flows, **not** for paying an offline peer.

So: **balance ledger on the Server; peer claims via LNURL-withdraw (wallet peers) or
static BOLT12 offer (node peers); server-side push attempts as opportunistic
optimization.** This matches how custodial "rewards" systems already work — e.g.
ZBD's rewards balance + cash-out modal
([ZBD Earn](https://docs.zbdpay.com/rewards/sdk)) — but keeps custody on the server
operator until claim time.

### 4. Friction-minimal peer receiving

- **LN Address (LNURL-pay static address)** — peers paste `peer@boltlane.example`
  at enrollment; supported natively by Strike
  (`payment-quotes/lightning/lnurl`, [Strike API](https://docs.strike.me/api/)) and
  by most wallets. Zero-key enrollment, works with custodial wallets.
- **Static BOLT12 offer** — one reusable string (`lno…`); supported by CLN, Eclair,
  Phoenix, LDK-based wallets; LND still landing. Best for non-custodial peers
  ([BOLT 12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)).
- **LNURL-withdraw code** — best for wallet-app peers on a Raspberry Pi / phone: the
  Server shows a code; the wallet pulls. `balanceCheck` makes it recurring
  ([LUD-03](https://github.com/lnurl/luds/blob/legacy/lnurl-withdraw.md)).

Recommend a peer-side registry entry: `payout_target` = one of
{LN address | BOLT12 offer | LNURL-withdraw code}, resolved at payout time.

### 5. Self-hoster's payments-on story

Flipping payments on should require **exactly two** things:

1. **A funding wallet or node connection** — either point the Server at any
   NWC-compatible wallet (`nostr+walletconnect://…`, i.e. Alby Hub /
   Phoenixd / any LND/CLN) or run Phoenixd. This is the "configure wallet" step;
   NWC keeps it out of the Go binary and matches the Alby Hub/NWC ecosystem
   ([NWC](https://nwc.dev/), [getAlby/hub](https://github.com/getAlby/hub)).
2. **A payout target per peer** (from §3) — LN address, BOLT12 offer, or
   LNURL-withdraw code pasted at enrollment.

Everything else — balance accrual, per-device metering, claim records — is already
Server-local bookkeeping and runs with payments off. The SaaS operator runs the
*same* software with its own node or Strike API for fiat-out.

### 6. What competitors pay out with

| Network | Rail | Min / cadence | Source |
|---|---|---|---|
| **Mysterium** | MYST token on Ethereum/Polygon, payment-channel "Hermes" promises settled on-chain (invoice/promise/`hermes` protocol in node source) | per-session accrual, settled in batches | [mysteriumnetwork/node payments proto](https://github.com/mysteriumnetwork/node/blob/master/pb/payment.proto), [hermes flags](https://github.com/mysteriumnetwork/node/blob/master/config/flags_payments.go) |
| **Honeygain** | PayPal (via Tipalti) and JumpTask gift cards/crypto — no Lightning | $20-ish thresholds, manual claim | [Payout methods](https://support.honeygain.com/hc/en-us/articles/4412730790674-What-are-the-payout-methods) |
| **EarnApp (Bright Data)** | PayPal / Wise ($10 min), Amazon gift cards ($50 min); up to 10 business days | daily batch Mon–Thu | [Payment methods](https://help.earnapp.com/hc/en-us/articles/10147246886801--What-are-the-available-payment-methods-and-processing-time) |
| **Grass** | Points → GRASS token (Solana), seasonal claims | claim windows | [grass.io](https://www.grass.io/) ("Earn Points", "Grass Token") |

All three big competitors are either custodial-fiat (PayPal/gift cards) or
own-token; **none pays instant Lightning**. Instant sat-denominated payouts are the
differentiator the glossary already claims (`CONTEXT.md` "the differentiating rail").

## Failure modes

| Failure | What happens | Mitigation |
|---|---|---|
| **Peer offline at payout time** | push (keysend/offer) can't deliver | accrue in Server ledger; peer claims on next connect via LNURL-withdraw `balanceCheck`, or BOLT12 offer completes when their node is back |
| **Channel liquidity dry on Server** | outbound payment fails transiently | retry queue with backoff; keep 2–3 funded channels; for self-hosters, alert in UI; small sat amounts make rebalancing rare |
| **Routing fees** | per-payout fee can exceed tiny payout | batch payouts (e.g. daily claim ≥ threshold, like EarnApp's $10 floor); fee-limit per payment (LND default 100% small / 5% large — [SendRequest](https://github.com/lightningnetwork/lnd/blob/master/lnrpc/lightning.proto)) |
| **Peer's wallet can't receive keysend** | spontaneous payment rejected | never keysend to wallets; keysend only to nodes, offers/withdraw to wallets |
| **Stale/revoked LNURL-withdraw k1** | claim rejected | rotate k1 per claim; treat as auth, not storage |
| **Custodial provider outage** (Strike/ZBD path) | payouts queue until API recovers | idempotency keys + webhook reconciliation (both documented at Strike); self-hosters unaffected |

## Recommendation

**Payout rail: server-side Lightning payments against a per-peer balance ledger,
with peer-side claim via static identifier.** Concretely:

- **Server:** accrue per-device balance in its own ledger (sat-denominated). Push
  attempts happen opportunistically; the ledger is the source of truth, so an
  offline peer loses nothing.
- **SaaS deployment:** run the same Server with an attached LND or CLN node (offers +
  keysend + LNURL-withdraw service); offer LNURL-pay *inbound* via Strike/ZBD only
  if/when fiat in/out is needed. Custodial is a fallback rail behind the same
  interface, not the default.
- **Self-hoster:** payments **off by default**. Flipping on = paste an NWC string
  (Alby Hub / Phoenixd / own LND/CLN) — no node required to *receive* payouts on the
  peer side if peers claim via LNURL-withdraw.
- **Peer enrollment:** accept {LN address | BOLT12 offer | LNURL-withdraw code};
  wallets get withdraw-code flow, non-custodial nodes get offers, custodial-wallet
  peers get LN addresses.
- **Do not build payouts on** raw BOLT11 invoice collection or keysend-to-wallets;
  do not use LNURL-pay as the payout rail (it is payer-initiated, wrong direction);
  do not use hodl invoices for outbound payouts (inbound mechanism).

## Key sources

- BOLT 12 (offers, invoice_request, merchant-pays-user):
  https://github.com/lightning/bolts/blob/master/12-offer-encoding.md
- LNURL-pay (LUD-06/09): https://github.com/lnurl/luds/blob/legacy/lnurl-pay.md
- LNURL-withdraw + balanceCheck (LUD-03): https://github.com/lnurl/luds/blob/legacy/lnurl-withdraw.md
- LND keysend: https://docs.lightning.engineering/lightning-network-tools/lnd/send-messages-with-keysend
- LND hold invoices: https://github.com/lightningnetwork/lnd/blob/master/lnrpc/invoicesrpc/invoices.proto
- LND BOLT12 codec landing (0.22.0): https://github.com/lightningnetwork/lnd/blob/master/docs/release-notes/release-notes-0.22.0.md
- CLN keysend/xkeysend + offers plugins: https://github.com/ElementsProject/lightning/tree/master/plugins
- CLN keysend schema: https://github.com/ElementsProject/lightning/blob/master/doc/schemas/keysend.json
- Alby Hub (NWC, self-host node front-end): https://github.com/getAlby/hub
- Strike API (LNURL quote, idempotency, payouts): https://docs.strike.me/api/
- ZBD Earn (rewards balance + KYC): https://docs.zbdpay.com/rewards/sdk
- Mysterium payment proto: https://github.com/mysteriumnetwork/node/blob/master/pb/payment.proto
- Honeygain payouts: https://support.honeygain.com/hc/en-us/articles/4412730790674-What-are-the-payout-methods
- EarnApp payouts: https://help.earnapp.com/hc/en-us/articles/10147246886801--What-are-the-available-payment-methods-and-processing-time