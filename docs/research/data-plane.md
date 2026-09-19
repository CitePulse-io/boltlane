# Data-Plane Transport & Proxy Protocol — Prior-Art Research

Ticket: [#3](https://github.com/CitePulse-io/boltlane/issues/3) · Status: research complete (no code) · Date: 2026-09-18

## The question

Boltlane needs a **persistent, outbound, client→server tunnel** (peer dials the coordinating server — never the reverse, because peers sit behind NAT) that carries **full-duplex proxied traffic** (requestor ⇄ peer) with backpressure, multiplexing many concurrent proxied connections over one link, on hardware from a Raspberry Pi up. Which transport (WebSocket / HTTP/2 / gRPC / raw TLS / QUIC/WebTransport) and which internal proxy protocol?

## 1. Persistent outbound tunnels: the transport candidates

| Transport | Multiplexing | Flow control / backpressure | NAT/corp. firewall traversal | Go ecosystem cost | RPi cost |
|---|---|---|---|---|---|
| **WebSocket (RFC 6455)** | ❌ single stream (spec explicitly deferred multiplexing; §1.5) | ❌ none; TCP buffer only (§5.2 basic framing) | ✅ HTTP/1.1 Upgrade, survives most proxies (§4.1.3) | gorilla/websocket or nhooyr — mature | ✅ tiny |
| **HTTP/2 (h2, raw with prior knowledge)** | ✅ unlimited bidirectional streams (RFC 9113 §5.1.2) | ✅ per-stream + connection WINDOW_UPDATE (RFC 9113 §5.2) | ⚠️ needs ALPN "h2" over TLS or prior-knowledge h2c — many middleboxes only know h1 | ✅ stdlib `golang.org/x/net/http2` | ✅ cheap |
| **gRPC (over h2)** | ✅ HTTP/2 streams, per-RPC | ✅ bidirectional streaming RPCs (grpc.io core concepts) | ⚠️ same as h2, plus protobuf framing overhead | ✅ grpc-go, heavy but proven | ⚠️ runtime + codegen weight |
| **Raw TLS (TCP) + custom framing** | via smux/yamux layered on top | yamux/smux: per-stream windows, token-bucket recv (READMEs) | ✅ port 443 + ALPN looks like normal HTTPS | stdlib `crypto/tls` + smux | ✅ cheapest |
| **QUIC / HTTP/3 / WebTransport** | ✅ native, per-stream, no HOL blocking (RFC 9114 §1.2) | ✅ per-stream flow control in transport (RFC 9114 §1.2) | ❌ UDP often blocked by ISPs/corp networks; needs fallback | quic-go — good but user-space UDP | ❌ UDP buffer tuning (see below), CPU cost on RPi |

Sources: [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html) · [RFC 9113 (HTTP/2)](https://httpwg.org/specs/rfc7540.html) · [RFC 9114 (HTTP/3)](https://www.rfc-editor.org/rfc/rfc9114.html) · [grpc.io core concepts](https://grpc.io/docs/what-is-grpc/core-concepts/) · [hashicorp/yamux](https://github.com/hashicorp/yamux) · [xtaci/smux](https://github.com/xtaci/smux) · [quic-go UDP buffers wiki](https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes)

Key points:

- **WebSocket** is intentionally a thin framing layer — "conceptually just a layer on top of TCP" ([RFC 6455 §1.5](https://www.rfc-editor.org/rfc/rfc6455.html#section-1.5)). No built-in multiplexing or flow control; the spec explicitly says "future versions will likely introduce additional concepts such as multiplexing" but never shipped it. A WebSocket tunnel carrying N proxied connections means N WebSockets (N sockets, N handshakes, N TLS sessions) or custom framing inside one.
- **HTTP/2 with prior knowledge** ("h2c" style, no upgrade dance) gives raw bidirectional byte streams with per-stream and connection-level flow control via WINDOW_UPDATE — this *is* backpressure, end to end (RFC 7540 §5.2). Streams may be opened by either endpoint, so the server can push work to the peer and the peer can push data back concurrently (RFC 7540 §5.1 "established and used unilaterally or shared by either client or server").
- **gRPC bidirectional streaming** is h2 with a strict message envelope (length-prefixed protobuf) — fine, but the frame format is dictated by gRPC, not by us; no raw byte-stream mode without hacks ([grpc.io core concepts](https://grpc.io/docs/what-is-grpc/core-concepts/)).
- **QUIC** gives the best transport semantics (per-stream flow control, no head-of-line blocking — RFC 9114 §1.2) but quic-go explicitly requires tuning OS-level UDP buffers to avoid kernel packet loss at high bandwidth ([quic-go wiki](https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes)), and UDP egress is unreliable from restrictive networks — a dealbreaker for a "works everywhere" residential-peer network without a fallback.

## 2. What existing peer-bandwidth / proxy networks actually use

| Network | Open-source? | Data-plane transport | Notes |
|---|---|---|---|
| **Mysterium Network** | ✅ [mysteriumnetwork/node](https://github.com/mysteriumnetwork/node) (Go, GPL) | WireGuard-based dVPN tunnels (README: "Currently node supports WireGuard as its underlying VPN transport") | Full-VPN model, not per-request proxy. Uses a NAT-traversal/p2p handshake, then tunnels IP packets. Residential IP network sold through GoProxies. |
| **Orchid** | ✅ [OrchidTechnologies/orchid](https://github.com/OrchidTechnologies/orchid) | OpenVPN / WireGuard / [Stunnel](https://www.stunnel.org/) / [libuv-based custom protocol](https://github.com/OrchidTechnologies/orchid), tunneled over a circuit of multi-hop providers | Circuit-based hop routing; the *tunnel* is a VPN, not per-request. |
| **Honeygain** | ❌ closed-source | (undocumented; [docs.honeygain.com](https://docs.honeygain.com/) unreachable — closed protocol) | Windows/macOS/Linux/Android/desktop-JS apps; pays per GB. Not inspectable. |
| **Grass (Wynd Network)** | ❌ closed-source | (undocumented; [grassdocs.io](https://grassdocs.io/) / getgrass.io unreachable) | Residential IP network with node rewards. Not inspectable. |
| **PacketStream / IPRoyal Pawns / Traffmonetizer** | ❌ closed-source | — | Commercial peer-bandwidth marketplaces; no public protocol docs. |
| **Kaleido / Sentinel dVPN** | partially | libp2p-style p2p streams over TCP/WS | Sentinel uses gRPC + custom framing; not directly reusable. |

**Takeaway:** nobody in the open-source peer-bandwidth space publishes a clean "per-request proxy over one tunnel" design. Mysterium (the closest open-source analog) is a **full-tunnel VPN** (WireGuard), not a per-request HTTP proxy — it doesn't multiplex concurrent proxied connections over one link, it encapsulates IP packets. That leaves the design space open for Boltlane.

## 3. How multiplexing-over-one-link is done in practice

Three proven patterns, all Go:

1. **HTTP/2 streams** — built into stdlib (`golang.org/x/net/http2`), per-stream + connection flow control via WINDOW_UPDATE (RFC 9113 §5.2). Zero extra deps if using the stdlib h2 transport directly.
2. **yamux** (hashicorp) — SPDY-inspired, used by Nomad/Consul/serf. Bidirectional streams (both sides can open), per-stream flow control with backpressure, keepalives, "thousands of logical streams with low overhead" ([yamux README](https://github.com/hashicorp/yamux)).
3. **smux** (xtaci) — used by kcp-go / v2ray ecosystem. 8-byte header, token-bucket receive, session-wide shared receive buffer, per-stream sliding-window congestion control v2 ([smux README](https://github.com/xtaci/smux)).

Both 2 and 3 implement `net.Conn` per stream, so a proxied TCP connection can be `io.Copy`ed straight onto a stream — no HTTP framing overhead. If we want *per-request* HTTP proxying (not raw CONNECT-tunnel per connection), we'd frame each proxied request/response over a stream.

## 4. Raspberry Pi / low-power constraints

- **CPU:** TLS over TCP (h2 / TLS+smux) is cheap; QUIC's userspace congestion control + per-packet crypto is measurably heavier on ARM. QUIC also needs **UDP send/recv buffer tuning** on Linux (`sysctl net.core.rmem_max=7500000`) or kernel packet loss at throughput ([quic-go wiki](https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes)) — not something we want peers to have to configure.
- **Memory:** smux was designed around "session-wide receive buffer shared among streams for fully controlled overall memory usage" ([smux README](https://github.com/xtaci/smux)) — directly relevant when a Pi has 512 MB–1 GB and dozens of concurrent streams.
- **Battery/CPU idle:** persistent WebSocket or h2 connection with periodic ping is cheap; QUIC keepalive is also cheap but the userspace UDP loop burns more cycles than kernel TCP.

## 5. Comparison & recommendation

| Axis | WebSocket | HTTP/2 (raw, prior knowledge) | gRPC | TLS+smux/yamux | QUIC/WebTransport |
|---|---|---|---|---|---|
| One socket for everything | ✅ | ✅ | ✅ | ✅ | ✅ |
| Server can initiate streams | ❌ | ✅ | ✅ | ✅ (yamux/smux both sides open) | ✅ |
| Per-stream backpressure | ❌ | ✅ | ✅ | ✅ | ✅ |
| Survives UDP-blocked networks | ✅ | ✅ | ✅ | ✅ | ❌ |
| Go stdlib, no heavy deps | ✅ | ✅ | ❌ (grpc-go + protobuf) | ✅ (smux dep only) | ❌ (quic-go) |
| Pi-friendly | ✅ | ✅ | ⚠️ | ✅ | ❌ |
| Effort to build internal proxy protocol | medium (roll our own frame format over WS) | **low** (reuse HTTP semantics per stream) | medium (protos, but no raw-stream escape hatch) | medium (roll our own frame format) | medium |

### Recommendation

**HTTP/2 (raw, "prior knowledge" / h2c over TLS ALPN) as the transport, with a custom internal proxy protocol layered on h2 streams.**

Concretely:

- **Transport:** peer dials `wss://`-style `https://server/boltlane/v1/tunnel` over TLS with ALPN forcing `h2`. We bypass the HTTP/1.1 upgrade dance by opening h2 with prior knowledge ([RFC 7540 §3.4](https://httpwg.org/specs/rfc7540.html#known-http)). The coordinating server speaks h2 directly — no reverse-proxy needed for the data plane (a separate HTTP/1.1 frontend for the dashboard/API can coexist on a different port or route).
- **Tunnel RPC:** a single **bidirectional gRPC-style stream** (one h2 stream per proxied request, opened *by the server* to the peer for outbound work, *by the peer* for keepalive/control). Server-initiated h2 streams are first-class (RFC 7540 §5.1) — this is what WebSocket cannot do.
- **Backpressure:** h2 per-stream + connection-level WINDOW_UPDATE is end-to-end flow control — when a Pi is slow, the server's `SendWindow` fills and the requestor's `CONNECT` tunnel naturally stalls instead of buffering unboundedly (RFC 9113 §5.2).
- **Multiplexing:** one TCP+TLS+h2 connection per peer carries unlimited concurrent proxied connections as h2 streams. No yamux/smux needed, because h2 *is* the multiplexer.
- **Why not QUIC:** right transport semantics, wrong deployment reality for v1 — UDP egress is flaky behind many corporate/ISP NATs, and quic-go needs OS tuning we can't ask Pi owners to do. Revisit later as an optional upgrade path; the custom proxy protocol over h2 streams ports to HTTP/3 (h3 streams) with minimal change if we ever want it.
- **Why not gRPC proper:** gRPC bidirectional streaming works, but the protobuf envelope is a poor fit for raw byte-stream proxying (you'd base64- or chunk-encode bytes into protobuf messages). Raw h2 gives us streams without the envelope.
- **Why not WebSocket:** no built-in multiplexing/backpressure; we'd be re-inventing HTTP/2 framing on top of it ([RFC 6455 §1.5](https://www.rfc-editor.org/rfc/rfc6455.html#section-1.5)).

**Internal proxy protocol sketch (per proxied connection = one h2 stream):**

1. Server opens an h2 stream with a small protobuf/JSON header: `{request_id, method, url, headers}` (or CONNECT-style target host:port).
2. Peer dials the target from its residential IP, streams the response status/headers back on the same stream, then pipes body bytes.
3. Either side RST_STREAMs to abort; h2 GOAWAY handles graceful peer drain.
4. A control stream (opened by peer at connect) carries keepalive, capacity advertisement, and payout-relevant stats (bytes served).

This gives: one persistent outbound connection per peer, N concurrent proxied requests per peer, end-to-end backpressure, and no third-party mux dependency.