# Boltlane — Domain Glossary

Open-source, self-hostable residential-IP proxy network. This file is the glossary only — no specs, no implementation.

## Core terms

**Provider** — a person or organization supplying network capacity through Devices they control. A Provider owns its Device policies, pools earnings across its Devices on one Server, and receives payouts in Bitcoin via Lightning.

**Device** — a registered installation and cryptographic identity on a laptop, desktop, Raspberry Pi, or phone (later). Has a residential or mobile IP, belongs to one Provider on its Server, is cryptographically pinned to exactly one Server, and enforces its Provider's traffic policy and resource allowance.

**Server** — the coordinating node. Routes requestor traffic out through Devices, maps requestor identities to traffic types and Devices, meters per-Device contribution, and (when payments are on) pays Providers. Anyone can self-host one; the SaaS is one deployment of the same software.

**Operator** — the person or organization administering one Server deployment. The Operator controls Requestor access, routing policy, compensation rates, Provider enrollment, authoritative accounting, and payout infrastructure. One actor may be both an Operator and a Provider, but the roles have separate authority.

**Device agent** — the Go program, or a later mobile app, running for one Device. Maintains an outbound persistent link to its pinned Server; accepts only that Server's permitted traffic; may inspect HTTP and TLS routing metadata to enforce local policy, but never stores payload content or decrypts end-to-end TLS.

**Account** — an organization-level security, quota, and billing boundary on a Server. An Account owns one or more Requestors. A self-hosted Server has an operator Account even when multi-tenant features are disabled.

**Requestor** — an application or workload consuming the network's proxy capacity, owned by one Account. CitePulse is the initial Requestor; `geo_optimize` is the local repository name for the same product, not a separate Requestor.

**Credential** — an independently scoped, rotatable, and revocable machine secret through which a Server authenticates one Requestor. A Credential is local to the issuing Server, not a network-wide Requestor identity.

**Session** — an optional, expiring routing lease that keeps a Requestor on one eligible Device across multiple proxy connections. A Session exposes no stable Device identity to the Requestor.

**Route constraints** — Requestor-supplied requirements for an eligible exit, such as geography, network type, carrier, or required capabilities. Each constraint is required, preferred, or unrestricted. Route constraints never identify a specific Provider or Device.

**Service tier** — an operator-defined quality or cost treatment applied while routing Requestor traffic.

**Workload class** — a declared Requestor traffic purpose linked to Server-side destination and protocol permissions.

**Exit observation** — a short-lived, signed statement from a Server-trusted public observer identifying the public IP from which a Device reached it. A Server enriches this observation with approximate geographic and network metadata; the Device's own location claim is not authoritative.

**Traffic policy** — rules over locally observable destination and connection attributes that a Provider sets for what their Device will carry. The Server filters traffic before routing it, and the Device independently enforces the Provider's policy, rejecting traffic it cannot verify without decrypting end-to-end TLS.

**Policy profile** — a named, reusable set of traffic-policy and resource-allowance defaults owned by a Provider. A profile is independent of any Server or Device and can be saved, exported, and applied during enrollment.

**Policy category** — a versioned, reviewable collection of concrete destination and protocol rules used to build a policy profile. Updating a category never silently changes an active Device policy.

**Resource allowance** — the operating limits a Provider sets for a Device, such as bandwidth, concurrency, data volume, and active hours. The Device enforces these limits independently of the Server.

**Pinning** — the enrollment act binding a Device to one Server's long-lived Ed25519 identity key, confirmed by the Provider. The Device agent refuses connections that cannot prove possession of that identity, independently of replaceable TLS credentials.

## Money

**Lightning payouts** — per-GB (or per-request) payments from a Server to a Provider's wallet over the Lightning network. The differentiating rail; USDC/Solana rails are explicitly secondary.

**Contribution** — destination-facing TCP payload bytes a Device carries for a Requestor after accepting a proxy connection. Upload and download bytes both count, including bytes carried before a later destination failure; tunnel and TLS framing overhead does not.

**Consumption** — destination-facing TCP payload bytes charged to a Requestor after a Device accepts its proxy connection. It uses the same byte boundary as Contribution in the MVP, but belongs to Requestor billing rather than Provider compensation.

**Usage receipt** — a Server identity-signed statement of a Device's measured Contribution and its snapshotted compensation rate. A Provider compares receipts with the Device's independent counters to audit reported earnings.

**Available earnings** — finalized, undisputed sat-denominated credit that a Provider may claim once the Server's payout threshold is met. This is an accounting balance, not a completed Lightning payment.

**Payout** — a transfer of Available earnings from the Server to a Provider's configured Lightning destination. A payout is distinct from metering, earnings finalization, and the Lightning network's settlement of the transfer.

**Payment gate** — the Server boundary that decides whether an authenticated Requestor is financially authorized to open a proxy connection. It does not authenticate Requestors, select Devices, enforce traffic policy, or meter Contribution.

**Service credit** — non-transferable, non-redeemable value denominated in millisatoshis that an Account's Requestors may spend only on proxy service. It is an accounting balance, not segregated Bitcoin or a claim that can be withdrawn, and is separate from Provider earnings and payouts.

**Payment reservation** — Service credit temporarily committed when a proxy connection is admitted. Consumption settles against the reservation at the connection's snapshotted Requestor price, and any unused remainder is released.

**Billing policy** — the payment treatment assigned to a Requestor: ungated access or consumption from prepaid Service credit. An Account may provide the default, but each Requestor has an explicit effective policy.

**Requestor price** — the Operator-set rate at which Consumption uses Service credit. It is independent of the compensation rate paid to the selected Device's Provider and is snapshotted when a proxy connection begins.

**Payment quote** — an expiring offer to grant a stated amount of Service credit in exchange for payment through one of the offered rails. Paying a quote grants credit at most once and does not lock a future Requestor price.

**L402** — Lightning-native paid-API protocol (402 + macaroon + invoice). Candidate inbound rail for agent customers; x402's Lightning-native analog.
