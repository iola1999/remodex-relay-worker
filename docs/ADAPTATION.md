# Worker Adaptation Notes

This package was derived from the Remodex `relay/` Node runtime, but it is not a direct bundle of `server.js`.

## What Changed

- Replaced Node `http` upgrade handling with the Worker `fetch()` entrypoint and `WebSocketPair`.
- Replaced the `ws` package with native Cloudflare Worker WebSockets.
- Moved per-session socket state into `RelaySession` Durable Objects.
- Moved cross-session lookup state into one `RelayDirectory` Durable Object.
- Replaced Node `crypto.createHash()` log labels with Web Crypto `crypto.subtle.digest()`.
- Replaced Node Ed25519 `crypto.verify()` with Web Crypto Ed25519 verification.
- Replaced `Buffer` length-prefix helpers with `Uint8Array`/`DataView`.
- Replaced process-level runtime health metrics with Worker-safe minimal health and DO stats.
- Kept relay session identifiers out of logs by logging only a short SHA-256 hash label.

## What Is Preserved

- `/relay/{sessionId}` route shape.
- `x-role: mac`, `x-role: iphone`, and `x-role: android`.
- One live Mac socket per session.
- One live mobile client per session.
- Mac replacement close code `4001`.
- unavailable-session close code `4002`.
- mobile replacement close code `4003`.
- Mac-absence send rejection close code `4004`.
- Short manual pairing-code resolution.
- Trusted-session resolution with timestamp skew check, nonce replay protection, trusted-phone matching, and Ed25519 signature verification.
- Default disabled push endpoints.

## What Is Not Included

- APNs delivery.
- File-backed push session persistence.
- Node `http2`.
- Node `fs`, `os`, `path`, or process memory/event-loop health.
- Any hosted production domain in the Remodex app repo.

## Why Durable Objects Are Required

A regular Worker invocation cannot safely coordinate long-lived sockets and mutable session membership through global in-memory maps. Durable Objects provide a single coordination point for each relay session and a small global directory for trusted reconnect and pairing-code lookups.

## Deployment Configuration

`wrangler.jsonc` declares:

```jsonc
{
  "durable_objects": {
    "bindings": [
      { "name": "REMODEX_RELAY_SESSION", "class_name": "RelaySession" },
      { "name": "REMODEX_RELAY_DIRECTORY", "class_name": "RelayDirectory" }
    ]
  },
  "migrations": [
    {
      "tag": "v1",
      "new_sqlite_classes": ["RelaySession", "RelayDirectory"]
    }
  ]
}
```

If these classes are ever renamed or split, add a new Durable Object migration instead of editing the historical `v1` migration after deployment.
