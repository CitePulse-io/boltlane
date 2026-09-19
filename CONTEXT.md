# Boltlane — Domain Glossary

Open-source, self-hostable residential-IP proxy network. This file is the glossary only — no specs, no implementation.

## Core terms

**Peer** — a person (or org) running Boltlane client software on a device they own, contributing their device's residential or mobile IP to a Server. Peers are paid per byte served, in Bitcoin via Lightning.

**Device** — a registered client runtime: laptop, desktop, Raspberry Pi, or phone (later). Has a residential or mobile IP, is cryptographically pinned to exactly one Server, and carries an operator-set traffic policy.

**Server** — the coordinating node. Routes requestor traffic out through Devices, maps requestor identities to traffic types and Devices, meters per-Device contribution, and (when payments are on) pays Peers. Anyone can self-host one; the SaaS is one deployment of the same software.

**Peer client** — the Go program (plus later mobile apps) a Peer runs. Maintains an outbound persistent link to its pinned Server; accepts only that Server's traffic; never inspects or stores payload content beyond what TLS routing requires.

**Requestor** — an application consuming the network's proxy capacity. First Requestors are CitePulse and geo_optimize. A Requestor may be the Server operator's own app (dogfood) or a paying customer.

**Traffic policy** — the rules a Peer sets limiting what their Device will carry (e.g. only the operator's own apps, only search-engine requests). Enforced and verified Server-side, not in the client.

**Pinning** — the enrollment act binding a Device to one Server identity (TLS cert fingerprint / Ed25519 key), confirmed by the human at enrollment. The client refuses any connection whose identity is not the pinned one.

## Money

**Lightning payouts** — per-GB (or per-request) payments from a Server to a Peer's wallet over the Lightning network. The differentiating rail; USDC/Solana rails are explicitly secondary.

**x402 gating** — the payment-plug-in point on the Server: a Requestor must be pre-paid (invoice paid via Lightning/L402) or pay-per-request (x402-style) before traffic is routed. Default off when self-hosting.

**L402** — Lightning-native paid-API protocol (402 + macaroon + invoice). Candidate inbound rail for agent customers; x402's Lightning-native analog.
