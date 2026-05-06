import { DurableObject } from "cloudflare:workers";
import { createAPNsClient, apnsConfigFromEnv } from "./apns-client.js";
import { createDurableObjectPushStateStore, createPushSessionService } from "./push-service.js";
import {
  TRUSTED_SESSION_RESOLVE_SKEW_MS,
  buildTrustedSessionResolveBytes,
  clientAddressKey,
  createFixedWindowRateLimiter,
  createRelayError,
  directoryStub,
  drainRequestBody,
  json,
  normalizeMacRegistration,
  normalizeNonEmptyString,
  normalizeShortPairingCode,
  readJSONBody,
  readOptionalBooleanEnv,
  readString,
  relaySessionIdFromPath,
  sessionStub,
  verifyTrustedSessionResolveSignature,
} from "./shared.js";

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
      return sessionStub(env, sessionId).fetch(request);
    }

    if (request.method === "GET" && url.pathname === "/health") {
      const exposeDetailedHealth = readOptionalBooleanEnv(
        ["REMODEX_EXPOSE_DETAILED_HEALTH", "PHODEX_EXPOSE_DETAILED_HEALTH"],
        env
      ) ?? false;
      if (!exposeDetailedHealth) {
        return json({ ok: true });
      }
      return directoryStub(env).fetch(
        new Request("https://remodex.internal/internal/directory/stats")
      );
    }

    return directoryStub(env).fetch(request);
  },
};

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
        push: await this.pushStats(),
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
        macDeviceId: readString(body.macDeviceId),
        pairingCode: normalizeShortPairingCode(body.pairingCode),
        sessionId: readString(body.sessionId),
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

    if (request.method === "POST" && url.pathname === "/v1/push/session/register-device") {
      if (!this.pushEnabled()) {
        await drainRequestBody(request);
        return json({ ok: false, error: "Not found" }, 404);
      }
      return this.handleJSONRoute(request, (body) => this.pushService().registerDevice(body));
    }

    if (request.method === "POST" && url.pathname === "/v1/push/session/notify-completion") {
      if (!this.pushEnabled()) {
        await drainRequestBody(request);
        return json({ ok: false, error: "Not found" }, 404);
      }
      return this.handleJSONRoute(request, (body) => this.pushService().notifyCompletion(body));
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

  pushEnabled() {
    return readOptionalBooleanEnv(
      ["REMODEX_ENABLE_PUSH_SERVICE", "PHODEX_ENABLE_PUSH_SERVICE"],
      this.env
    ) ?? false;
  }

  pushService() {
    return createPushSessionService({
      apnsClient: createAPNsClient(apnsConfigFromEnv(this.env)),
      canRegisterSession: ({ sessionId, notificationSecret }) => (
        this.hasAuthenticatedMacSession(sessionId, notificationSecret)
      ),
      canNotifyCompletion: ({ sessionId, notificationSecret }) => (
        this.hasAuthenticatedMacSession(sessionId, notificationSecret)
      ),
      stateStore: createDurableObjectPushStateStore(this.ctx.storage),
    });
  }

  async pushStats() {
    if (!this.pushEnabled()) {
      return {
        enabled: false,
        registeredSessions: 0,
        deliveredDedupeKeys: 0,
        apnsConfigured: false,
      };
    }

    return {
      enabled: true,
      ...await this.pushService().getStats(),
    };
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
    const response = await sessionStub(this.env, sessionId)
      .fetch("https://remodex.internal/internal/session/active");
    if (!response.ok) {
      return false;
    }
    const body = await response.json();
    return body.active === true;
  }

  async hasAuthenticatedMacSession(sessionId, notificationSecret) {
    if (!sessionId || !notificationSecret) {
      return false;
    }
    const response = await sessionStub(this.env, sessionId)
      .fetch(new Request("https://remodex.internal/internal/session/authenticated", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ notificationSecret }),
      }));
    if (!response.ok) {
      return false;
    }
    const body = await response.json();
    return body.authenticated === true;
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
