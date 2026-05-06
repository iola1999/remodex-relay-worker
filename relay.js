// Cloudflare Worker artifact for the Remodex relay core.
//
// Required Durable Object bindings:
// - REMODEX_RELAY_SESSION -> RelaySession
// - REMODEX_RELAY_DIRECTORY -> RelayDirectory
//
// This keeps the default push endpoints disabled, matching the local relay
// default. The APNs/file-backed push helper in the Node relay is not bundled.

import { DurableObject } from "cloudflare:workers";

const CLEANUP_DELAY_MS = 60_000;
const HEARTBEAT_INTERVAL_MS = 30_000;
const CLOSE_CODE_SESSION_UNAVAILABLE = 4002;
const CLOSE_CODE_IPHONE_REPLACED = 4003;
const CLOSE_CODE_MAC_ABSENCE_BUFFER_FULL = 4004;
const MAC_ABSENCE_GRACE_MS = 15_000;
const TRUSTED_SESSION_RESOLVE_TAG = "remodex-trusted-session-resolve-v1";
const TRUSTED_SESSION_RESOLVE_SKEW_MS = 90_000;
const SHORT_PAIRING_CODE_MIN_LENGTH = 8;
const SHORT_PAIRING_CODE_MAX_LENGTH = 12;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/internal/")) {
      return json({ ok: false, error: "Not found" }, 404);
    }

    if (url.pathname.startsWith("/relay/")) {
      const sessionId = relaySessionIdFromPath(url.pathname);
      if (!sessionId) {
        return json({ ok: false, error: "Missing sessionId" }, 400);
      }
      const stub = env.REMODEX_RELAY_SESSION.get(
        env.REMODEX_RELAY_SESSION.idFromName(sessionId)
      );
      return stub.fetch(request);
    }

    if (request.method === "GET" && url.pathname === "/health") {
      const exposeDetailedHealth = readOptionalBooleanEnv(
        ["REMODEX_EXPOSE_DETAILED_HEALTH", "PHODEX_EXPOSE_DETAILED_HEALTH"],
        env
      ) ?? false;
      if (!exposeDetailedHealth) {
        return json({ ok: true });
      }
      const directory = directoryStub(env);
      return directory.fetch(new Request("https://remodex.internal/internal/directory/stats"));
    }

    const directory = directoryStub(env);
    return directory.fetch(request);
  },
};

export class RelaySession extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.startedAt = Date.now();
    this.upgradeRateLimiter = createFixedWindowRateLimiter({
      windowMs: 60_000,
      maxRequests: 60,
    });
    this.metrics = {
      acceptedConnections: 0,
      closedConnections: 0,
      macMessagesRelayed: 0,
      mobileMessagesRelayed: 0,
      mobileMessagesRejectedDuringMacAbsence: 0,
    };
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/internal/session/active") {
      const currentMacConnectionId = await this.ctx.storage.get("currentMacConnectionId");
      return json({
        ok: true,
        active: Boolean(currentMacConnectionId && this.findOpenSocket("mac", currentMacConnectionId)),
      });
    }

    if (request.method === "GET" && url.pathname === "/internal/session/stats") {
      return json({
        ok: true,
        relay: this.sessionStats(),
      });
    }

    if (!url.pathname.startsWith("/relay/")) {
      return json({ ok: false, error: "Not found" }, 404);
    }

    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return json({ ok: false, error: "Expected WebSocket upgrade" }, 426, {
        upgrade: "websocket",
      });
    }

    if (!this.upgradeRateLimiter.allow(clientAddressKey(request))) {
      return new Response(null, {
        status: 429,
        headers: { "retry-after": "60" },
      });
    }

    const sessionId = relaySessionIdFromPath(url.pathname);
    const role = normalizeRelayRole(request.headers.get("x-role"));
    this.metrics.acceptedConnections += 1;

    if (!sessionId || (role !== "mac" && !isRelayMobileRole(role))) {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.accept();
      server.close(4000, "Missing sessionId or invalid x-role header");
      return new Response(null, { status: 101, webSocket: client });
    }

    await this.ctx.storage.put("sessionId", sessionId);

    if (isRelayMobileRole(role) && !(await this.canAcceptMobileClientConnection())) {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.accept();
      server.close(CLOSE_CODE_SESSION_UNAVAILABLE, "Mac session not available");
      return new Response(null, { status: 101, webSocket: client });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const connectionId = crypto.randomUUID();
    server.serializeAttachment({ sessionId, role, connectionId });

    if (role === "mac") {
      await this.acceptMacSocket(server, request, sessionId, connectionId);
    } else {
      await this.acceptMobileSocket(server, sessionId, role, connectionId);
    }

    this.ctx.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  async acceptMacSocket(server, request, sessionId, connectionId) {
    const previousMacConnectionId = await this.ctx.storage.get("currentMacConnectionId");
    const previousMac = previousMacConnectionId
      ? this.findOpenSocket("mac", previousMacConnectionId)
      : null;
    if (previousMac) {
      previousMac.close(4001, "Replaced by new Mac connection");
    }

    const previousRegistration = await this.ctx.storage.get("macRegistration");
    if (previousRegistration?.macDeviceId) {
      await this.unregisterDirectory(previousRegistration, sessionId);
    }

    const notificationSecret = readHeaderString(request.headers.get("x-notification-secret"));
    const macRegistration = normalizeMacRegistration({
      macDeviceId: readHeaderString(request.headers.get("x-mac-device-id")),
      macIdentityPublicKey: readHeaderString(request.headers.get("x-mac-identity-public-key")),
      displayName: readHeaderString(request.headers.get("x-machine-name")),
      trustedPhoneDeviceId: readHeaderString(request.headers.get("x-trusted-phone-device-id")),
      trustedPhonePublicKey: readHeaderString(request.headers.get("x-trusted-phone-public-key")),
      pairingCode: readHeaderString(request.headers.get("x-pairing-code")),
      pairingVersion: readHeaderString(request.headers.get("x-pairing-version")),
      pairingExpiresAt: readHeaderString(request.headers.get("x-pairing-expires-at")),
    }, sessionId);

    await this.ctx.storage.put({
      currentMacConnectionId: connectionId,
      notificationSecret,
      macRegistration,
      macAbsentUntil: 0,
      cleanupAfter: 0,
    });
    await this.ctx.storage.deleteAlarm();
    await this.registerDirectory(macRegistration);
    console.log(`[relay] Mac connected -> ${await relaySessionLogLabel(sessionId)}`);
  }

  async acceptMobileSocket(server, sessionId, role, connectionId) {
    for (const socket of this.mobileSockets()) {
      socket.close(CLOSE_CODE_IPHONE_REPLACED, "Replaced by newer mobile connection");
    }
    server.serializeAttachment({ sessionId, role, connectionId });
    await this.ctx.storage.put("cleanupAfter", 0);
    console.log(`[relay] Mobile connected (${role}) -> ${await relaySessionLogLabel(sessionId)}`);
  }

  async webSocketMessage(ws, message) {
    const attachment = ws.deserializeAttachment() || {};
    const role = normalizeRelayRole(attachment.role);
    const sessionId = readHeaderString(attachment.sessionId)
      || await this.ctx.storage.get("sessionId")
      || "";

    if (role === "mac") {
      if (await this.applyMacRegistrationMessage(sessionId, message)) {
        return;
      }
      for (const client of this.mobileSockets()) {
        if (isOpenSocket(client)) {
          this.metrics.macMessagesRelayed += 1;
          client.send(message);
        }
      }
      return;
    }

    const currentMacConnectionId = await this.ctx.storage.get("currentMacConnectionId");
    const mac = currentMacConnectionId ? this.findOpenSocket("mac", currentMacConnectionId) : null;
    if (mac) {
      this.metrics.mobileMessagesRelayed += 1;
      mac.send(message);
      return;
    }

    this.metrics.mobileMessagesRejectedDuringMacAbsence += 1;
    ws.close(CLOSE_CODE_MAC_ABSENCE_BUFFER_FULL, "Mac temporarily unavailable");
  }

  async webSocketClose(ws) {
    this.metrics.closedConnections += 1;
    const attachment = ws.deserializeAttachment() || {};
    const role = normalizeRelayRole(attachment.role);
    const sessionId = readHeaderString(attachment.sessionId)
      || await this.ctx.storage.get("sessionId")
      || "";

    if (role === "mac") {
      const currentMacConnectionId = await this.ctx.storage.get("currentMacConnectionId");
      if (currentMacConnectionId !== attachment.connectionId) {
        return;
      }

      const registration = await this.ctx.storage.get("macRegistration");
      await this.unregisterDirectory(registration, sessionId);
      await this.ctx.storage.put({
        currentMacConnectionId: "",
        macAbsentUntil: Date.now() + MAC_ABSENCE_GRACE_MS,
      });
      await this.ctx.storage.setAlarm(Date.now() + MAC_ABSENCE_GRACE_MS);
      console.log(`[relay] Mac disconnected -> ${await relaySessionLogLabel(sessionId)}`);
      return;
    }

    console.log(`[relay] Mobile disconnected (${role}) -> ${await relaySessionLogLabel(sessionId)}`);
    if (!this.hasAnyOpenSocket()) {
      await this.scheduleCleanup();
    }
  }

  async webSocketError(ws, error) {
    const attachment = ws.deserializeAttachment() || {};
    console.error(
      `[relay] WebSocket error (${normalizeRelayRole(attachment.role) || "unknown"}, `
      + `${await relaySessionLogLabel(attachment.sessionId || "")}): ${error?.message || error}`
    );
  }

  async alarm() {
    const currentMacConnectionId = await this.ctx.storage.get("currentMacConnectionId");
    if (currentMacConnectionId && this.findOpenSocket("mac", currentMacConnectionId)) {
      return;
    }

    const macAbsentUntil = Number(await this.ctx.storage.get("macAbsentUntil") || 0);
    if (macAbsentUntil && Date.now() >= macAbsentUntil) {
      for (const client of this.mobileSockets()) {
        client.close(CLOSE_CODE_SESSION_UNAVAILABLE, "Mac disconnected");
      }
      await this.ctx.storage.put({
        notificationSecret: "",
        macAbsentUntil: 0,
      });
    }

    if (!this.hasAnyOpenSocket()) {
      const cleanupAfter = Number(await this.ctx.storage.get("cleanupAfter") || 0);
      if (cleanupAfter && Date.now() >= cleanupAfter) {
        await this.ctx.storage.deleteAll();
      }
    }
  }

  async canAcceptMobileClientConnection() {
    const currentMacConnectionId = await this.ctx.storage.get("currentMacConnectionId");
    if (currentMacConnectionId && this.findOpenSocket("mac", currentMacConnectionId)) {
      return true;
    }

    const macAbsentUntil = Number(await this.ctx.storage.get("macAbsentUntil") || 0);
    return Boolean(macAbsentUntil && Date.now() < macAbsentUntil);
  }

  async applyMacRegistrationMessage(sessionId, rawMessage) {
    const rawText = messageToText(rawMessage);
    if (!rawText) {
      return false;
    }

    const parsed = safeParseJSON(rawText);
    if (parsed?.kind !== "relayMacRegistration" || typeof parsed.registration !== "object") {
      return false;
    }

    const previousRegistration = await this.ctx.storage.get("macRegistration");
    if (previousRegistration?.macDeviceId) {
      await this.unregisterDirectory(previousRegistration, sessionId);
    }

    const macRegistration = normalizeMacRegistration(parsed.registration, sessionId);
    await this.ctx.storage.put("macRegistration", macRegistration);
    await this.registerDirectory(macRegistration);
    return true;
  }

  async registerDirectory(registration) {
    if (!registration?.macDeviceId) {
      return;
    }
    const response = await directoryStub(this.env).fetch(new Request(
      "https://remodex.internal/internal/directory/register",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(registration),
      }
    ));
    if (!response.ok) {
      console.error(`[relay] directory registration failed: ${response.status}`);
    }
  }

  async unregisterDirectory(registration, sessionId) {
    if (!registration?.macDeviceId) {
      return;
    }
    await directoryStub(this.env).fetch(new Request(
      "https://remodex.internal/internal/directory/unregister",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          macDeviceId: registration.macDeviceId,
          pairingCode: registration.pairingCode || "",
          sessionId,
        }),
      }
    ));
  }

  findOpenSocket(role, connectionId) {
    for (const socket of this.ctx.getWebSockets()) {
      const attachment = socket.deserializeAttachment() || {};
      if (
        attachment.role === role
        && attachment.connectionId === connectionId
        && isOpenSocket(socket)
      ) {
        return socket;
      }
    }
    return null;
  }

  mobileSockets() {
    return this.ctx.getWebSockets().filter((socket) => {
      const attachment = socket.deserializeAttachment() || {};
      return isRelayMobileRole(normalizeRelayRole(attachment.role)) && isOpenSocket(socket);
    });
  }

  hasAnyOpenSocket() {
    return this.ctx.getWebSockets().some(isOpenSocket);
  }

  async scheduleCleanup() {
    const cleanupAfter = Date.now() + CLEANUP_DELAY_MS;
    await this.ctx.storage.put("cleanupAfter", cleanupAfter);
    await this.ctx.storage.setAlarm(cleanupAfter);
  }

  sessionStats() {
    let totalClients = 0;
    let sessionsWithOpenMac = 0;
    for (const socket of this.ctx.getWebSockets()) {
      const attachment = socket.deserializeAttachment() || {};
      if (!isOpenSocket(socket)) {
        continue;
      }
      if (attachment.role === "mac") {
        sessionsWithOpenMac = 1;
      } else if (isRelayMobileRole(attachment.role)) {
        totalClients += 1;
      }
    }

    return {
      activeSessions: this.hasAnyOpenSocket() ? 1 : 0,
      sessionsWithMac: sessionsWithOpenMac,
      sessionsWithOpenMac,
      sessionsWithStaleMac: 0,
      sessionsWithClients: totalClients > 0 ? 1 : 0,
      totalClients,
      uptimeSeconds: Math.round((Date.now() - this.startedAt) / 1000),
      acceptedConnections: this.metrics.acceptedConnections,
      closedConnections: this.metrics.closedConnections,
      heartbeatTerminations: 0,
      macMessagesRelayed: this.metrics.macMessagesRelayed,
      mobileMessagesRelayed: this.metrics.mobileMessagesRelayed,
      mobileMessagesRejectedDuringMacAbsence: this.metrics.mobileMessagesRejectedDuringMacAbsence,
    };
  }
}

export class RelayDirectory extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.startedAt = Date.now();
    this.httpRateLimiter = createFixedWindowRateLimiter({
      windowMs: 60_000,
      maxRequests: 120,
    });
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/internal/directory/stats") {
      return json({
        ok: true,
        relay: await this.stats(),
        push: {
          enabled: false,
          registeredSessions: 0,
          deliveredDedupeKeys: 0,
          apnsConfigured: false,
        },
        runtime: {
          uptimeSeconds: Math.round((Date.now() - this.startedAt) / 1000),
        },
      });
    }

    if (request.method === "POST" && url.pathname === "/internal/directory/register") {
      const registration = normalizeMacRegistration(await readJSONBody(request), "");
      if (!registration.macDeviceId || !registration.sessionId) {
        return json({ ok: false, error: "Invalid registration" }, 400);
      }
      await this.registerMacSession(registration);
      return json({ ok: true });
    }

    if (request.method === "POST" && url.pathname === "/internal/directory/unregister") {
      const body = await readJSONBody(request);
      await this.unregisterMacSession({
        macDeviceId: readHeaderString(body.macDeviceId),
        pairingCode: normalizeShortPairingCode(body.pairingCode),
        sessionId: readHeaderString(body.sessionId),
      });
      return json({ ok: true });
    }

    if (!this.httpRateLimiter.allow(clientAddressKey(request))) {
      return json({ ok: false, error: "Too many requests", code: "rate_limited" }, 429, {
        "retry-after": "60",
      });
    }

    if (request.method === "POST" && url.pathname === "/v1/trusted/session/resolve") {
      return this.handleJSONRoute(request, (body) => this.resolveTrustedMacSession(body));
    }

    if (request.method === "POST" && url.pathname === "/v1/pairing/code/resolve") {
      return this.handleJSONRoute(request, (body) => this.resolvePairingCode(body));
    }

    if (
      request.method === "POST"
      && (
        url.pathname === "/v1/push/session/register-device"
        || url.pathname === "/v1/push/session/notify-completion"
      )
    ) {
      return json({ ok: false, error: "Not found" }, 404);
    }

    return json({ ok: false, error: "Not found" }, 404);
  }

  async handleJSONRoute(request, handler) {
    try {
      const body = await readJSONBody(request);
      const result = await handler(body);
      return json(result);
    } catch (error) {
      return json({
        ok: false,
        error: error.message || "Internal server error",
        code: error.code || "internal_error",
      }, error.status || 500);
    }
  }

  async registerMacSession(registration) {
    const existing = await this.ctx.storage.get(`mac:${registration.macDeviceId}`);
    if (
      existing?.pairingCode
      && existing.pairingCode !== registration.pairingCode
    ) {
      await this.ctx.storage.delete(`pair:${existing.pairingCode}`);
    }

    await this.ctx.storage.put(`mac:${registration.macDeviceId}`, registration);
    if (registration.pairingCode && Number.isFinite(registration.pairingExpiresAt)) {
      await this.ctx.storage.put(`pair:${registration.pairingCode}`, registration);
    }
  }

  async unregisterMacSession({ macDeviceId, pairingCode, sessionId }) {
    if (macDeviceId) {
      const existing = await this.ctx.storage.get(`mac:${macDeviceId}`);
      if (existing?.sessionId === sessionId) {
        await this.ctx.storage.delete(`mac:${macDeviceId}`);
      }
    }

    if (pairingCode) {
      const existingPairingCode = await this.ctx.storage.get(`pair:${pairingCode}`);
      if (existingPairingCode?.sessionId === sessionId) {
        await this.ctx.storage.delete(`pair:${pairingCode}`);
      }
    }
  }

  async resolveTrustedMacSession({
    macDeviceId,
    phoneDeviceId,
    phoneIdentityPublicKey,
    timestamp,
    nonce,
    signature,
  } = {}) {
    const normalizedMacDeviceId = normalizeNonEmptyString(macDeviceId);
    const normalizedPhoneDeviceId = normalizeNonEmptyString(phoneDeviceId);
    const normalizedPhoneIdentityPublicKey = normalizeNonEmptyString(phoneIdentityPublicKey);
    const normalizedNonce = normalizeNonEmptyString(nonce);
    const normalizedSignature = normalizeNonEmptyString(signature);
    const normalizedTimestamp = Number(timestamp);
    const now = Date.now();

    if (
      !normalizedMacDeviceId
      || !normalizedPhoneDeviceId
      || !normalizedPhoneIdentityPublicKey
      || !normalizedNonce
      || !normalizedSignature
      || !Number.isFinite(normalizedTimestamp)
    ) {
      throw createRelayError(400, "invalid_request", "The trusted-session resolve request is missing required fields.");
    }

    if (Math.abs(now - normalizedTimestamp) > TRUSTED_SESSION_RESOLVE_SKEW_MS) {
      throw createRelayError(401, "resolve_request_expired", "This trusted-session resolve request has expired.");
    }

    await this.pruneUsedResolveNonces(now);
    const nonceKey = `nonce:${normalizedMacDeviceId}|${normalizedPhoneDeviceId}|${normalizedNonce}`;
    if (await this.ctx.storage.get(nonceKey)) {
      throw createRelayError(409, "resolve_request_replayed", "This trusted-session resolve request was already used.");
    }

    const liveSession = await this.ctx.storage.get(`mac:${normalizedMacDeviceId}`);
    if (!liveSession || !(await this.hasActiveMacSession(liveSession.sessionId))) {
      throw createRelayError(404, "session_unavailable", "The trusted Mac is offline right now.");
    }

    if (
      liveSession.trustedPhoneDeviceId !== normalizedPhoneDeviceId
      || liveSession.trustedPhonePublicKey !== normalizedPhoneIdentityPublicKey
    ) {
      throw createRelayError(403, "phone_not_trusted", "This iPhone is not trusted for the requested Mac.");
    }

    const transcriptBytes = buildTrustedSessionResolveBytes({
      macDeviceId: normalizedMacDeviceId,
      phoneDeviceId: normalizedPhoneDeviceId,
      phoneIdentityPublicKey: normalizedPhoneIdentityPublicKey,
      nonce: normalizedNonce,
      timestamp: normalizedTimestamp,
    });
    if (!await verifyTrustedSessionResolveSignature(
      normalizedPhoneIdentityPublicKey,
      transcriptBytes,
      normalizedSignature
    )) {
      throw createRelayError(403, "invalid_signature", "The trusted-session resolve signature is invalid.");
    }

    await this.ctx.storage.put(nonceKey, now + TRUSTED_SESSION_RESOLVE_SKEW_MS);
    return {
      ok: true,
      macDeviceId: normalizedMacDeviceId,
      macIdentityPublicKey: liveSession.macIdentityPublicKey,
      displayName: liveSession.displayName || null,
      sessionId: liveSession.sessionId,
    };
  }

  async resolvePairingCode({ code } = {}) {
    const normalizedCode = normalizeShortPairingCode(code);
    if (!normalizedCode) {
      throw createRelayError(400, "invalid_request", "The pairing code is missing or malformed.");
    }

    const registration = await this.ctx.storage.get(`pair:${normalizedCode}`);
    if (!registration || !(await this.hasActiveMacSession(registration.sessionId))) {
      throw createRelayError(404, "pairing_code_unavailable", "This pairing code is unavailable.");
    }

    if (
      !Number.isFinite(registration.pairingExpiresAt)
      || Date.now() > registration.pairingExpiresAt
    ) {
      await this.ctx.storage.delete(`pair:${normalizedCode}`);
      throw createRelayError(410, "pairing_code_expired", "This pairing code has expired.");
    }

    if (
      !registration.macDeviceId
      || !registration.macIdentityPublicKey
      || !Number.isFinite(registration.pairingVersion)
    ) {
      throw createRelayError(409, "pairing_code_incomplete", "The bridge pairing metadata is incomplete.");
    }

    return {
      ok: true,
      v: registration.pairingVersion,
      sessionId: registration.sessionId,
      macDeviceId: registration.macDeviceId,
      macIdentityPublicKey: registration.macIdentityPublicKey,
      expiresAt: registration.pairingExpiresAt,
    };
  }

  async hasActiveMacSession(sessionId) {
    if (!sessionId) {
      return false;
    }
    const stub = this.env.REMODEX_RELAY_SESSION.get(
      this.env.REMODEX_RELAY_SESSION.idFromName(sessionId)
    );
    const response = await stub.fetch("https://remodex.internal/internal/session/active");
    if (!response.ok) {
      return false;
    }
    const body = await response.json();
    return body.active === true;
  }

  async pruneUsedResolveNonces(now) {
    const entries = await this.ctx.storage.list({ prefix: "nonce:" });
    const deletes = [];
    for (const [key, expiresAt] of entries) {
      if (now >= Number(expiresAt || 0)) {
        deletes.push(key);
      }
    }
    if (deletes.length > 0) {
      await this.ctx.storage.delete(deletes);
    }
  }

  async stats() {
    const macEntries = await this.ctx.storage.list({ prefix: "mac:" });
    const pairEntries = await this.ctx.storage.list({ prefix: "pair:" });
    const nonceEntries = await this.ctx.storage.list({ prefix: "nonce:" });
    return {
      activeSessions: macEntries.size,
      sessionsWithMac: macEntries.size,
      sessionsWithOpenMac: macEntries.size,
      sessionsWithStaleMac: 0,
      sessionsWithClients: 0,
      totalClients: 0,
      pairingCodes: pairEntries.size,
      cleanupPending: 0,
      macAbsencePending: 0,
      uptimeSeconds: Math.round((Date.now() - this.startedAt) / 1000),
      acceptedConnections: 0,
      closedConnections: 0,
      heartbeatTerminations: 0,
      macMessagesRelayed: 0,
      mobileMessagesRelayed: 0,
      mobileMessagesRejectedDuringMacAbsence: 0,
      usedResolveNonces: nonceEntries.size,
    };
  }
}

function directoryStub(env) {
  return env.REMODEX_RELAY_DIRECTORY.get(
    env.REMODEX_RELAY_DIRECTORY.idFromName("global")
  );
}

function relaySessionIdFromPath(pathname) {
  const match = pathname.match(/^\/relay\/([^/?]+)/);
  return match?.[1] ? decodeURIComponent(match[1]) : "";
}

function normalizeRelayRole(value) {
  return readHeaderString(value).toLowerCase();
}

function isRelayMobileRole(role) {
  return role === "iphone" || role === "android";
}

function isOpenSocket(socket) {
  return socket.readyState === WebSocket.OPEN;
}

function messageToText(message) {
  if (typeof message === "string") {
    return message;
  }
  if (message instanceof ArrayBuffer) {
    return textDecoder.decode(message);
  }
  if (ArrayBuffer.isView(message)) {
    return textDecoder.decode(message);
  }
  return "";
}

async function relaySessionLogLabel(sessionId) {
  const normalizedSessionId = normalizeNonEmptyString(sessionId);
  if (!normalizedSessionId) {
    return "session=[redacted]";
  }

  const digest = await crypto.subtle.digest(
    "SHA-256",
    textEncoder.encode(normalizedSessionId)
  );
  return `session#${base16(new Uint8Array(digest)).slice(0, 8)}`;
}

function clientAddressKey(request) {
  const cfConnectingIp = readHeaderString(request.headers.get("cf-connecting-ip"));
  if (cfConnectingIp) {
    return cfConnectingIp;
  }

  const xRealIp = readHeaderString(request.headers.get("x-real-ip"));
  if (xRealIp) {
    return xRealIp;
  }

  const xForwardedFor = readHeaderString(request.headers.get("x-forwarded-for"));
  if (xForwardedFor) {
    return xForwardedFor.split(",").map((value) => value.trim()).filter(Boolean)[0] || "unknown";
  }

  return "unknown";
}

function createFixedWindowRateLimiter({ windowMs, maxRequests, now = () => Date.now() } = {}) {
  const buckets = new Map();
  const resolvedWindowMs = Number.isFinite(windowMs) && windowMs > 0 ? windowMs : 60_000;
  const resolvedMaxRequests = Number.isFinite(maxRequests) && maxRequests > 0 ? maxRequests : 60;
  let nextPruneAt = 0;

  return {
    allow(key) {
      const normalizedKey = typeof key === "string" && key.trim() ? key.trim() : "unknown";
      const timestamp = now();
      if (timestamp >= nextPruneAt) {
        nextPruneAt = timestamp + resolvedWindowMs;
        for (const [bucketKey, bucketValue] of buckets.entries()) {
          if (timestamp >= bucketValue.expiresAt) {
            buckets.delete(bucketKey);
          }
        }
      }
      const bucket = buckets.get(normalizedKey);

      if (!bucket || timestamp >= bucket.expiresAt) {
        buckets.set(normalizedKey, {
          count: 1,
          expiresAt: timestamp + resolvedWindowMs,
        });
        return true;
      }

      if (bucket.count >= resolvedMaxRequests) {
        return false;
      }

      bucket.count += 1;
      return true;
    },
  };
}

async function readJSONBody(request) {
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > 64 * 1024) {
    throw createRelayError(413, "body_too_large", "Request body too large");
  }

  const rawBody = await request.text();
  if (rawBody.length > 64 * 1024) {
    throw createRelayError(413, "body_too_large", "Request body too large");
  }
  if (!rawBody.trim()) {
    return {};
  }

  try {
    return JSON.parse(rawBody);
  } catch {
    throw createRelayError(400, "invalid_json", "Invalid JSON body");
  }
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      ...headers,
    },
  });
}

function normalizeMacRegistration(registration, sessionId) {
  return {
    sessionId: normalizeNonEmptyString(registration?.sessionId) || sessionId,
    macDeviceId: normalizeNonEmptyString(registration?.macDeviceId),
    macIdentityPublicKey: normalizeNonEmptyString(registration?.macIdentityPublicKey),
    displayName: normalizeNonEmptyString(registration?.displayName),
    trustedPhoneDeviceId: normalizeNonEmptyString(registration?.trustedPhoneDeviceId),
    trustedPhonePublicKey: normalizeNonEmptyString(registration?.trustedPhonePublicKey),
    pairingCode: normalizeShortPairingCode(registration?.pairingCode),
    pairingVersion: normalizePositiveInteger(registration?.pairingVersion),
    pairingExpiresAt: normalizePositiveInteger(registration?.pairingExpiresAt),
  };
}

function buildTrustedSessionResolveBytes({
  macDeviceId,
  phoneDeviceId,
  phoneIdentityPublicKey,
  nonce,
  timestamp,
}) {
  return concatBytes([
    encodeLengthPrefixedUTF8(TRUSTED_SESSION_RESOLVE_TAG),
    encodeLengthPrefixedUTF8(macDeviceId),
    encodeLengthPrefixedUTF8(phoneDeviceId),
    encodeLengthPrefixedData(base64ToBytes(phoneIdentityPublicKey)),
    encodeLengthPrefixedUTF8(nonce),
    encodeLengthPrefixedUTF8(String(timestamp)),
  ]);
}

async function verifyTrustedSessionResolveSignature(publicKeyBase64, transcriptBytes, signatureBase64) {
  try {
    const publicKeyJwk = {
      crv: "Ed25519",
      kty: "OKP",
      x: base64ToBase64Url(publicKeyBase64),
    };
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      publicKeyJwk,
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return await crypto.subtle.verify(
      { name: "Ed25519" },
      publicKey,
      base64ToBytes(signatureBase64),
      transcriptBytes
    );
  } catch {
    return false;
  }
}

function encodeLengthPrefixedUTF8(value) {
  return encodeLengthPrefixedData(textEncoder.encode(value));
}

function encodeLengthPrefixedData(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  const output = new Uint8Array(4 + bytes.length);
  new DataView(output.buffer).setUint32(0, bytes.length, false);
  output.set(bytes, 4);
  return output;
}

function concatBytes(chunks) {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function base64ToBytes(value) {
  const normalized = String(value || "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function base64ToBase64Url(value) {
  return String(value || "")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

function base16(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function normalizeNonEmptyString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

function normalizeShortPairingCode(value) {
  if (typeof value !== "string") {
    return "";
  }

  const normalized = value
    .trim()
    .toUpperCase()
    .replace(/[\s-]+/g, "");
  if (
    normalized.length < SHORT_PAIRING_CODE_MIN_LENGTH
    || normalized.length > SHORT_PAIRING_CODE_MAX_LENGTH
    || !/^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]+$/.test(normalized)
  ) {
    return "";
  }

  return normalized;
}

function normalizePositiveInteger(value) {
  const normalized = Number(value);
  return Number.isFinite(normalized) && normalized > 0 ? normalized : 0;
}

function createRelayError(status, code, message) {
  return Object.assign(new Error(message), {
    status,
    code,
  });
}

function readHeaderString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

function safeParseJSON(value) {
  if (typeof value !== "string" || !value.trim()) {
    return null;
  }

  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function readOptionalBooleanEnv(keys, env = {}) {
  const truthy = new Set(["1", "true", "yes", "on"]);
  const falsy = new Set(["0", "false", "no", "off"]);

  for (const key of keys) {
    const rawValue = env?.[key];
    if (typeof rawValue !== "string" || !rawValue.trim()) {
      continue;
    }
    const normalizedValue = rawValue.trim().toLowerCase();
    if (truthy.has(normalizedValue)) {
      return true;
    }
    if (falsy.has(normalizedValue)) {
      return false;
    }
  }

  return undefined;
}
