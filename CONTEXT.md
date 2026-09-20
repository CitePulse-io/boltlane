# Boltlane — Domain Glossary

Open-source, self-hostable residential-IP proxy network. This file is the glossary only — no specs, no implementation.

## Core terms

**Peer** — a person (or org) running Boltlane client software on a device they own, contributing their device's residential or mobile IP to a Server. Peers are paid per byte served, in Bitcoin via Lightning.

**Device** — a registered client runtime: laptop, desktop, Raspberry Pi, or phone (later). Has a residential or mobile IP, is cryptographically pinned to exactly one Server, and enforces its Peer's traffic policy and resource allowance.

**Server** — the coordinating node. Routes requestor traffic out through Devices, maps requestor identities to traffic types and Devices, meters per-Device contribution, and (when payments are on) pays Peers. Anyone can self-host one; the SaaS is one deployment of the same software.

**Peer client** — the Go program (plus later mobile apps) a Peer runs. Maintains an outbound persistent link to its pinned Server; accepts only that Server's permitted traffic; may inspect HTTP and TLS routing metadata to enforce local policy, but never stores payload content or decrypts end-to-end TLS.

**Account** — an organization-level security, quota, and billing boundary on a Server. An Account owns one or more Requestors. A self-hosted Server has an operator Account even when multi-tenant features are disabled.

**Requestor** — an application or workload consuming the network's proxy capacity, owned by one Account. CitePulse and geo_optimize are separate Requestors even when they share the Server operator's Account.

**Credential** — an independently scoped, rotatable, and revocable machine secret through which a Server authenticates one Requestor. A Credential is local to the issuing Server, not a network-wide Requestor identity.

**Session** — an optional, expiring routing lease that keeps a Requestor on one eligible Device across multiple proxy connections. A Session exposes no stable Device identity to the Requestor.

**Route constraints** — Requestor-supplied requirements for an eligible exit, such as geography, network type, carrier, or required capabilities. Each constraint is required, preferred, or unrestricted. Route constraints never identify a specific Peer or Device.

**Service tier** — an operator-defined quality or cost treatment applied while routing Requestor traffic.

**Workload class** — a declared Requestor traffic purpose linked to Server-side destination and protocol permissions.

**Exit observation** — a short-lived, signed statement from a Server-trusted public observer identifying the public IP from which a Device reached it. A Server enriches this observation with approximate geographic and network metadata; the Device's own location claim is not authoritative.

**Traffic policy** — rules over locally observable destination and connection attributes that a Peer sets for what their Device will carry. The Server filters traffic before routing it, and the Device independently enforces the Peer's policy, rejecting traffic it cannot verify without decrypting end-to-end TLS.

**Policy profile** — a named, reusable set of traffic-policy and resource-allowance defaults owned by a Peer. A profile is independent of any Server or Device and can be saved, exported, and applied during enrollment.

**Policy category** — a versioned, reviewable collection of concrete destination and protocol rules used to build a policy profile. Updating a category never silently changes an active Device policy.

**Resource allowance** — the operating limits a Peer sets for a Device, such as bandwidth, concurrency, data volume, and active hours. The Device enforces these limits independently of the Server.

**Pinning** — the enrollment act binding a Device to one Server's long-lived Ed25519 identity key, confirmed by the Peer. The client refuses connections that cannot prove possession of that identity, independently of replaceable TLS credentials.

## Money

**Lightning payouts** — per-GB (or per-request) payments from a Server to a Peer's wallet over the Lightning network. The differentiating rail; USDC/Solana rails are explicitly secondary.

**x402 gating** — the payment-plug-in point on the Server: a Requestor must be pre-paid (invoice paid via Lightning/L402) or pay-per-request (x402-style) before traffic is routed. Default off when self-hosting.

**L402** — Lightning-native paid-API protocol (402 + macaroon + invoice). Candidate inbound rail for agent customers; x402's Lightning-native analog.
