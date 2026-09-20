# Device-agent UX prototype

This is throwaway code for the decision ticket **Prototype: Device-agent enrollment & running UX**. It asks whether setup establishes informed trust while ordinary operation stays quiet, legible, and safe on a computer someone is actively using.

It does not connect to a network, persist data, or propose production code structure.

## Run

```sh
go run ./prototypes/device-agent-cli/main.go
```

Try these paths:

1. Enroll, inspect the Server identity, and accept the balanced work-computer policy.
2. Simulate traffic, pause, resume, and change to the quiet preset.
3. Preview an update and a Server identity mismatch.
4. Uninstall and inspect what gets revoked, removed, or preserved.
5. Restart, then preview non-interactive Raspberry Pi enrollment.

## Proposed operating shape

### Desktop

- One background system service owns keys, the tunnel, policy enforcement, metering, updates, and reconnects. It starts after login by default, not before the Provider has approved a policy.
- A small unprivileged CLI and later tray process talk to that service locally. Closing the terminal or tray does not kill active traffic.
- The tray stays visually quiet in normal operation. It shows `Available`, `Active`, `Paused`, or `Needs attention`; its primary actions are status, pause/resume, limits, and diagnostics.
- Notifications are reserved for Provider action: policy approval, identity mismatch, quarantine, prolonged offline state, update restart, or payout failure. Routine connections and earnings changes do not notify.
- `Pause` drains current connections and rejects new ones. A separate emergency stop, if testing shows it is needed, would terminate traffic immediately.
- Work-computer defaults are intentionally conservative: low bandwidth and concurrency ceilings, pause on battery, and no sharing until a policy is explicitly approved.

### Updates

- Signed updates may download in the background but do not silently interrupt active connections.
- Normal updates ask to drain and restart, with an operator-configurable maintenance window for unattended Devices.
- A successful update preserves the Server pin, Device key, policy snapshot, accounting state, and Provider preferences.
- A rollback never weakens pinning or policy. Security updates may become required by the Server, but the Device fails closed rather than installing an unverified binary.

### Uninstall and forgetting

- Uninstall first stops new work and attempts immediate remote Device revocation.
- If the Server is unreachable, the UI must say that its registration remains until separately revoked or its credential expires; local secrets are still removed after explicit confirmation.
- Server pins, Device credentials, assignments, and reconnect state are removed. Reusable policy profiles and explicitly exported receipts or diagnostics can be preserved.
- The OS package manager removes the binary and service only after the agent completes or records the revocation attempt.

### Raspberry Pi and other headless Devices

- The same service and CLI run without a tray.
- Interactive enrollment prints the Server name, address, and fingerprint before confirmation.
- Automation requires `--expect-server <fingerprint>`; it cannot auto-accept the fingerprint supplied by the invitation itself.
- When an OS-backed non-exportable key store is unavailable, a service-account-only key file is allowed only with a prominent warning and explicit acceptance. There is no silent fallback.
- `boltlane status --json` should eventually expose the same state as the human-readable status for home automation and fleet monitoring; its schema is deliberately outside this UX prototype.

## Feedback prompts

- Is fingerprint confirmation understandable, or should enrollment require a stronger out-of-band comparison?
- Should pause drain existing connections, stop them immediately, or offer both actions?
- Are earnings useful in the primary status, especially when payments are disabled for dogfood?
- Should updates be automatic after draining, scheduled, or always explicitly approved?
- Which events deserve a desktop notification rather than only a changed tray state?
