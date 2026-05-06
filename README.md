# Remodex Relay Worker

Cloudflare Worker deployment package for the Remodex relay transport.

This directory is intentionally separate from the local-first Remodex app repo. It contains only source code, Worker configuration, and documentation for the Cloudflare Worker adaptation of the relay. Build output is generated into `dist/` and is not part of the source tree.

## Runtime Shape

- Worker source: `src/index.mjs`
- Worker build output: `dist/worker.mjs`
- WebSocket path: `/relay/{sessionId}`
- Health path: `/health`
- Trusted reconnect lookup: `POST /v1/trusted/session/resolve`
- Manual pairing lookup: `POST /v1/pairing/code/resolve`
- Durable Object classes:
  - `RelaySession`: one object per relay session
  - `RelayDirectory`: global lookup index for trusted-session and pairing-code resolution

Push/APNs endpoints are present only as disabled 404-compatible routes. The Node relay's APNs helper uses `http2` and file-backed state, so it is not bundled in this Worker package.

## Deploy

```sh
npm install
npm run build
npm run deploy
```

Default Worker name:

```txt
remodex-relay-worker
```

The default `wrangler.jsonc` includes the required Durable Object bindings and the initial migration:

```txt
REMODEX_RELAY_SESSION -> RelaySession
REMODEX_RELAY_DIRECTORY -> RelayDirectory
```

## Local Development

```sh
npm install
npm run build
npm run dev
```

Then probe:

```sh
curl http://127.0.0.1:8787/health
```

Expected minimal response:

```json
{"ok":true}
```

## Verification

```sh
npm run check
npm run build
npm run deploy:dry-run
```

For a real smoke test, connect one Mac WebSocket and one mobile WebSocket to the same `/relay/{sessionId}` path, with headers:

```txt
x-role: mac
x-role: iphone
```

Messages sent by the Mac socket should be forwarded to the mobile socket, and mobile messages should be forwarded back to the live Mac socket.

## Current Production Deployment

The first deployment made from this package was:

```txt
https://remodex-relay-worker.viola.workers.dev
```

Version ID:

```txt
59fb6baf-fe90-4c90-94de-d8e4b9549481
```

## Boundaries

This package preserves the relay as a transport hop. It does not run Codex, does not execute git commands, does not store the user's repo checkout, and does not decrypt Remodex application payloads after the secure application session is established.

Do not add application-server behavior here. Keep local bridge, QR pairing, trusted reconnect, and encrypted forwarding responsibilities separated.
