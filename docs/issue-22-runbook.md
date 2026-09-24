# Issue #22: single-Device proxy path

This is a one-Server, one-Device proof path. The Server filters Requestor
destinations and authenticates proxy Basic credentials. The Device independently
checks its approved hostname/port policy, resolves DNS locally, refuses private,
loopback, link-local, metadata, shared and reserved ranges, and checks HTTP Host
or TLS SNI before forwarding. It permits at most eight concurrent streams, 64 MiB
per direction for CONNECT, 8 MiB for an absolute-form HTTP response, and five
minutes per connection. HTTP responses are buffered to reject oversized bodies
before sending a success status. It does not decrypt HTTPS.

## Enrollment on a trusted workstation

Build with `go build -o boltlane ./cmd/boltlane`. Generate two separate identities:

```
./boltlane keygen server.key
./boltlane keygen device.key
```

Keep each private key in its owner's service-account-only file (mode 0600).
Record the two public keys; independently confirm the Server public key's
SHA-256 fingerprint with the Operator before starting the Device. Configure
the Server with the Device public key, and the Device with the Server public key.
The keys are never passed through URLs or committed to the repository.

The Operator and Provider each review their own copy of
`examples/quikrstuff-policy.json`. This exact hostname does not include
subdomains. To deny HTTP entirely, remove port 80 from the Device policy.
No policy is loaded implicitly; unknown fields and empty policies are rejected.

## Server in the CitePulse Railway project/environment

The production service is declared in the existing CitePulse IaC file at
`geo_optimize/.railway/railway.ts`; run `railway config plan` there before
applying changes. Build the Boltlane Dockerfile in that project/environment.
Set the Server identity as a protected Railway variable and use the image's
narrow example policy:

```
BOLTLANE_SERVER_KEY_B64=<base64-private-key-in-Railway-variables>
BOLTLANE_DEVICE_PUBLIC_KEY=<base64-public-key>
BOLTLANE_POLICY_FILE=/etc/boltlane/quikrstuff-policy.json
BOLTLANE_PROXY_USER=<credential-id>
BOLTLANE_PROXY_PASSWORD=<random-secret-at-least-24-characters>
BOLTLANE_LISTEN=:8080
BOLTLANE_UNSAFE_TRUSTED_PRIVATE_LISTENER=yes
```

The unsafe option is for a listener reached only through Railway's TLS edge
and trusted private network. Do not publish the raw listener as an unsecured
TCP proxy. Create a Railway HTTPS domain for the Device tunnel; the public
edge terminates TLS and forwards WebSocket Upgrade requests to port 8080.
Railway IaC cannot register a new custom domain; create a Railway-generated
HTTPS domain on port 8080 separately and verify it with `railway domain list`.
The proxy client connects to the Server via its private Railway address on
port 8080. For a directly public listener outside Railway, omit the unsafe
option and set `BOLTLANE_TLS_CERT` and `BOLTLANE_TLS_KEY` instead.

The image contains only the public hostname policy; it does not contain any
keys or proxy credentials. The Server can alternatively use a protected
`BOLTLANE_SERVER_KEY_FILE` (mode 0600), but never configure both sources.
Do not deploy an unconfigured service into production merely to obtain a
public domain; arrange secret provisioning first.

## Device on the Operator Mac

Install the binary locally, set `BOLTLANE_DEVICE_KEY_FILE` to the Mac-local
private key, `BOLTLANE_SERVER_PUBLIC_KEY` to the independently confirmed
base64 public key, `BOLTLANE_POLICY_FILE` to the reviewed local policy file,
and `BOLTLANE_TUNNEL_URL` to
`wss://<railway-public-domain>/boltlane/v1/tunnel`. Then start:

```
./boltlane device --approve-fingerprint <confirmed-sha256-fingerprint> --approve-policy
```

The Device opens no listener. It uses system TLS certificate verification and
then mutual Ed25519 challenge authentication. A mismatched Server identity
stops the connection. A transient disconnect reconnects after five seconds;
stop the process to pause. Remove the registered Device public key on the
Server to revoke it; remove the local private key only after revocation.

## Controlled check and live acceptance

First run `go test ./...` and verify a controlled HTTPS target through the
private proxy with standard proxy Basic credentials, then verify a deliberate
denied hostname returns 403, invalid credentials return 407, and an offline
Device returns 503. Confirm the TLS Server Name matches the approved hostname
and that the target observes the Device public exit IP through a trusted
observer (not the tunnel source IP). Verify WebSocket Upgrade succeeds against
the **deployed Railway edge**; the local WebSocket tests do not establish that.

Only after that, request the four URLs from issue #21 through the private
proxy, one at a time. Inspect final URL, content type, page identity and HTML
for a challenge. An origin 403/429, CAPTCHA or other challenge ends the live
canary; do not rotate exits or retry around a block. A 200 CONNECT alone proves
no HTML was retrieved. Keep response content and credentials out of proxy logs.
`boltlane probe https://quikrstuff.com/` from the Boltlane Railway container
uses ordinary proxy Basic authentication against its local private listener
and prints only status, final URL, content type, body size and title. It is a
diagnostic, not proof of a trusted exit IP or of CitePulse ingestion. Stop on
any suspicious challenge indication and inspect existing evidence rather
than blindly repeating a live request.

This first slice uses WebSocket binary messages with yamux multiplexing and a
versioned bounded per-stream opening frame. It does not implement raw ALPN h2
or h2 Upgrade negotiation. The actual Railway edge and the live Mac residential
exit must be tested before claiming the issue's retrieval acceptance. Enrollment
here uses manually exchanged keys, not one-time invitations, issued short-lived
certificates, key rotation or a control API. CitePulse's Python fetch integration
is in a separate repository and is not implemented here.

## Exit-IP observation record (2026-09-23)

Trusted observer: `api.ipify.org` (public echo, Operator-approved). Baseline
taken directly on the Mac outside the tunnel; observation fetched through the
deployed proxy path (probe in the Boltlane container → Server → tunnel → Mac
Device → residential exit) after PR #33 added the observer to the probe and
both policies.

- Baseline (Mac, direct): `167.224.189.201`
- Observed through the tunnel: `167.224.189.201` — **match**
- Deployment: `7cf0ac67` (SUCCESS); Device log confirms approved policy
  `hosts=[quikrstuff.com api.ipify.org] ports=[80 443]`

This satisfies the runbook's trusted-exit-IP-observation check: the target
observer saw the Device public exit IP, not the tunnel source IP.
