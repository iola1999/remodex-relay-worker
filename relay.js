import { DurableObject } from "cloudflare:workers";
import {
  CLEANUP_DELAY_MS,
  CLOSE_CODE_IPHONE_REPLACED,
  CLOSE_CODE_MAC_ABSENCE_BUFFER_FULL,
  CLOSE_CODE_SESSION_UNAVAILABLE,
  MAC_ABSENCE_GRACE_MS,
  clientAddressKey,
  createFixedWindowRateLimiter,
  directoryStub,
  isOpenSocket,
  isRelayMobileRole,
  json,
  messageToText,
  normalizeMacRegistration,
  normalizeRelayRole,
  readJSONBody,
  readString,
  relaySessionIdFromPath,
  relaySessionLogLabel,
  safeParseJSON,
  secretsEqual,
} from "./shared.js";

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
      return json({
        ok: true,
        active: await this.hasActiveMacConnection(),
      });
    }

    if (request.method === "POST" && url.pathname === "/internal/session/authenticated") {
      const body = await readJSONBody(request);
      return json({
        ok: true,
        authenticated: await this.hasAuthenticatedMacConnection(body.notificationSecret),
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

    const notificationSecret = readString(request.headers.get("x-notification-secret"));
    const macRegistration = normalizeMacRegistration({
      macDeviceId: readString(request.headers.get("x-mac-device-id")),
      macIdentityPublicKey: readString(request.headers.get("x-mac-identity-public-key")),
      displayName: readString(request.headers.get("x-machine-name")),
      trustedPhoneDeviceId: readString(request.headers.get("x-trusted-phone-device-id")),
      trustedPhonePublicKey: readString(request.headers.get("x-trusted-phone-public-key")),
      pairingCode: readString(request.headers.get("x-pairing-code")),
      pairingVersion: readString(request.headers.get("x-pairing-version")),
      pairingExpiresAt: readString(request.headers.get("x-pairing-expires-at")),
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
    const sessionId = readString(attachment.sessionId)
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
    const sessionId = readString(attachment.sessionId)
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

  async hasActiveMacConnection() {
    const currentMacConnectionId = await this.ctx.storage.get("currentMacConnectionId");
    return Boolean(currentMacConnectionId && this.findOpenSocket("mac", currentMacConnectionId));
  }

  async hasAuthenticatedMacConnection(notificationSecret) {
    if (!await this.hasActiveMacConnection()) {
      return false;
    }
    const storedSecret = await this.ctx.storage.get("notificationSecret");
    return secretsEqual(storedSecret, notificationSecret);
  }

  async canAcceptMobileClientConnection() {
    if (await this.hasActiveMacConnection()) {
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
