import { readString, secretsEqual } from "./shared.js";

const PUSH_DEDUPE_TTL_MS = 24 * 60 * 60 * 1000;
const PUSH_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const PUSH_PREVIEW_MAX_CHARS = 160;

export function createPushSessionService({
  apnsClient,
  canRegisterSession = () => true,
  canNotifyCompletion = null,
  now = () => Date.now(),
  stateStore,
} = {}) {
  const resolvedCanNotifyCompletion = typeof canNotifyCompletion === "function"
    ? canNotifyCompletion
    : canRegisterSession;

  async function registerDevice({
    sessionId,
    notificationSecret,
    deviceToken,
    alertsEnabled,
    apnsEnvironment,
  } = {}) {
    const normalizedSessionId = readString(sessionId);
    const normalizedSecret = readString(notificationSecret);
    const normalizedDeviceToken = normalizeDeviceToken(deviceToken);

    if (!normalizedSessionId || !normalizedSecret || !normalizedDeviceToken) {
      throw pushServiceError(
        "invalid_request",
        "Push registration requires sessionId, notificationSecret, and deviceToken.",
        400
      );
    }

    if (!await canRegisterSession({
      sessionId: normalizedSessionId,
      notificationSecret: normalizedSecret,
    })) {
      throw pushServiceError(
        "session_unavailable",
        "Push registration requires an active relay session.",
        403
      );
    }

    const existing = await stateStore.getSession(normalizedSessionId);
    if (existing && !await secretsEqual(existing.notificationSecret, normalizedSecret)) {
      throw pushServiceError("unauthorized", "Invalid notification secret for this session.", 403);
    }

    await stateStore.setSession(normalizedSessionId, {
      notificationSecret: normalizedSecret,
      deviceToken: normalizedDeviceToken,
      alertsEnabled: Boolean(alertsEnabled),
      apnsEnvironment: apnsEnvironment === "development" ? "development" : "production",
      updatedAt: now(),
    });
    await pruneStaleState();
    return { ok: true };
  }

  async function notifyCompletion({
    sessionId,
    notificationSecret,
    threadId,
    turnId,
    result,
    title,
    body,
    dedupeKey,
  } = {}) {
    const normalizedSessionId = readString(sessionId);
    const normalizedSecret = readString(notificationSecret);
    const normalizedThreadId = readString(threadId);
    const normalizedResult = result === "failed" ? "failed" : "completed";
    const normalizedDedupeKey = readString(dedupeKey);

    if (!normalizedSessionId || !normalizedSecret || !normalizedThreadId || !normalizedDedupeKey) {
      throw pushServiceError(
        "invalid_request",
        "Push completion requires sessionId, notificationSecret, threadId, and dedupeKey.",
        400
      );
    }

    if (!await resolvedCanNotifyCompletion({
      sessionId: normalizedSessionId,
      notificationSecret: normalizedSecret,
    })) {
      throw pushServiceError(
        "session_unavailable",
        "Push completion requires an active relay session.",
        403
      );
    }

    await pruneDeliveredDedupeKeys();
    if (await stateStore.getDedupeKey(normalizedDedupeKey)) {
      return { ok: true, deduped: true };
    }

    const session = await stateStore.getSession(normalizedSessionId);
    if (!session || !await secretsEqual(session.notificationSecret, normalizedSecret)) {
      throw pushServiceError("unauthorized", "Invalid notification secret for this session.", 403);
    }

    if (!session.alertsEnabled || !session.deviceToken) {
      return { ok: true, skipped: true };
    }

    await apnsClient.sendNotification({
      deviceToken: session.deviceToken,
      apnsEnvironment: session.apnsEnvironment,
      title: normalizePreviewText(title) || "New Thread",
      body: normalizePreviewText(body) || fallbackBodyForResult(normalizedResult),
      payload: {
        source: "codex.runCompletion",
        threadId: normalizedThreadId,
        turnId: readString(turnId) || "",
        result: normalizedResult,
      },
    });

    await stateStore.setDedupeKey(normalizedDedupeKey, now());
    return { ok: true };
  }

  async function getStats() {
    await pruneStaleState();
    return {
      registeredSessions: await stateStore.sessionCount(),
      deliveredDedupeKeys: await stateStore.dedupeKeyCount(),
      apnsConfigured: apnsClient.isConfigured(),
    };
  }

  async function pruneDeliveredDedupeKeys() {
    const cutoff = now() - PUSH_DEDUPE_TTL_MS;
    await stateStore.deleteDedupeKeysBefore(cutoff);
  }

  async function pruneSessions() {
    const cutoff = now() - PUSH_SESSION_TTL_MS;
    await stateStore.deleteSessionsBefore(cutoff);
  }

  async function pruneStaleState() {
    await pruneDeliveredDedupeKeys();
    await pruneSessions();
  }

  return {
    registerDevice,
    notifyCompletion,
    getStats,
  };
}

export function createDurableObjectPushStateStore(storage) {
  return {
    async getSession(sessionId) {
      return storage.get(sessionKey(sessionId));
    },
    async setSession(sessionId, session) {
      await storage.put(sessionKey(sessionId), session);
    },
    async getDedupeKey(dedupeKey) {
      return storage.get(dedupeKeyName(dedupeKey));
    },
    async setDedupeKey(dedupeKey, timestamp) {
      await storage.put(dedupeKeyName(dedupeKey), timestamp);
    },
    async sessionCount() {
      return (await storage.list({ prefix: "push:session:" })).size;
    },
    async dedupeKeyCount() {
      return (await storage.list({ prefix: "push:dedupe:" })).size;
    },
    async deleteDedupeKeysBefore(cutoff) {
      const entries = await storage.list({ prefix: "push:dedupe:" });
      const deletes = [];
      for (const [key, timestamp] of entries) {
        if (Number(timestamp || 0) < cutoff) {
          deletes.push(key);
        }
      }
      if (deletes.length > 0) {
        await storage.delete(deletes);
      }
    },
    async deleteSessionsBefore(cutoff) {
      const entries = await storage.list({ prefix: "push:session:" });
      const deletes = [];
      for (const [key, session] of entries) {
        if (Number(session?.updatedAt || 0) < cutoff) {
          deletes.push(key);
        }
      }
      if (deletes.length > 0) {
        await storage.delete(deletes);
      }
    },
  };
}

function sessionKey(sessionId) {
  return `push:session:${sessionId}`;
}

function dedupeKeyName(dedupeKey) {
  return `push:dedupe:${dedupeKey}`;
}

function normalizeDeviceToken(value) {
  const normalized = readString(value);
  if (!normalized) {
    return "";
  }

  return normalized.replace(/[^a-fA-F0-9]/g, "").toLowerCase();
}

function normalizePreviewText(value) {
  const normalized = readString(value).replace(/\s+/g, " ");
  if (!normalized) {
    return "";
  }

  return normalized.length > PUSH_PREVIEW_MAX_CHARS
    ? `${normalized.slice(0, PUSH_PREVIEW_MAX_CHARS - 1).trimEnd()}...`
    : normalized;
}

function fallbackBodyForResult(result) {
  return result === "failed" ? "Run failed" : "Response ready";
}

function pushServiceError(code, message, status) {
  const error = new Error(message);
  error.code = code;
  error.status = status;
  return error;
}
