export const CLEANUP_DELAY_MS = 60_000;
export const CLOSE_CODE_SESSION_UNAVAILABLE = 4002;
export const CLOSE_CODE_IPHONE_REPLACED = 4003;
export const CLOSE_CODE_MAC_ABSENCE_BUFFER_FULL = 4004;
export const MAC_ABSENCE_GRACE_MS = 15_000;
export const TRUSTED_SESSION_RESOLVE_TAG = "remodex-trusted-session-resolve-v1";
export const TRUSTED_SESSION_RESOLVE_SKEW_MS = 90_000;
export const SHORT_PAIRING_CODE_MIN_LENGTH = 8;
export const SHORT_PAIRING_CODE_MAX_LENGTH = 12;

export const textEncoder = new TextEncoder();
export const textDecoder = new TextDecoder();

export function relaySessionIdFromPath(pathname) {
  const match = pathname.match(/^\/relay\/([^/?]+)/);
  return match?.[1] ? decodeURIComponent(match[1]) : "";
}

export function sessionStub(env, sessionId) {
  return env.REMODEX_RELAY_SESSION.get(
    env.REMODEX_RELAY_SESSION.idFromName(sessionId)
  );
}

export function directoryStub(env) {
  return env.REMODEX_RELAY_DIRECTORY.get(
    env.REMODEX_RELAY_DIRECTORY.idFromName("global")
  );
}

export function normalizeRelayRole(value) {
  return readString(value).toLowerCase();
}

export function isRelayMobileRole(role) {
  return role === "iphone" || role === "android";
}

export function isOpenSocket(socket) {
  return socket.readyState === WebSocket.OPEN;
}

export function messageToText(message) {
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

export async function relaySessionLogLabel(sessionId) {
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

export function clientAddressKey(request) {
  const cfConnectingIp = readString(request.headers.get("cf-connecting-ip"));
  if (cfConnectingIp) {
    return cfConnectingIp;
  }

  const xRealIp = readString(request.headers.get("x-real-ip"));
  if (xRealIp) {
    return xRealIp;
  }

  const xForwardedFor = readString(request.headers.get("x-forwarded-for"));
  if (xForwardedFor) {
    return xForwardedFor.split(",").map((value) => value.trim()).filter(Boolean)[0] || "unknown";
  }

  return "unknown";
}

export function createFixedWindowRateLimiter({ windowMs, maxRequests, now = () => Date.now() } = {}) {
  const buckets = new Map();
  const resolvedWindowMs = Number.isFinite(windowMs) && windowMs > 0 ? windowMs : 60_000;
  const resolvedMaxRequests = Number.isFinite(maxRequests) && maxRequests > 0 ? maxRequests : 60;
  let nextPruneAt = 0;

  return {
    allow(key) {
      const normalizedKey = readString(key) || "unknown";
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

export async function readJSONBody(request) {
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

export async function drainRequestBody(request) {
  if (!request.body) {
    return;
  }
  try {
    await request.arrayBuffer();
  } catch {
    // Best-effort cleanup before returning early from routes that ignore bodies.
  }
}

export function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      ...headers,
    },
  });
}

export function normalizeMacRegistration(registration, sessionId) {
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

export function buildTrustedSessionResolveBytes({
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

export async function verifyTrustedSessionResolveSignature(
  publicKeyBase64,
  transcriptBytes,
  signatureBase64
) {
  try {
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      {
        crv: "Ed25519",
        kty: "OKP",
        x: base64ToBase64Url(publicKeyBase64),
      },
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

export function encodeLengthPrefixedUTF8(value) {
  return encodeLengthPrefixedData(textEncoder.encode(value));
}

export function encodeLengthPrefixedData(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  const output = new Uint8Array(4 + bytes.length);
  new DataView(output.buffer).setUint32(0, bytes.length, false);
  output.set(bytes, 4);
  return output;
}

export function concatBytes(chunks) {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

export function base64ToBytes(value) {
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

export function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

export function base64ToBase64Url(value) {
  return String(value || "")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

export function base16(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function normalizeNonEmptyString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

export function normalizeShortPairingCode(value) {
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

export function normalizePositiveInteger(value) {
  const normalized = Number(value);
  return Number.isFinite(normalized) && normalized > 0 ? normalized : 0;
}

export function createRelayError(status, code, message) {
  return Object.assign(new Error(message), {
    status,
    code,
  });
}

export function readString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

export function safeParseJSON(value) {
  if (typeof value !== "string" || !value.trim()) {
    return null;
  }

  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

export function readOptionalBooleanEnv(keys, env = {}) {
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

export async function secretsEqual(left, right) {
  const leftValue = readString(left);
  const rightValue = readString(right);
  if (!leftValue || leftValue.length !== rightValue.length) {
    return false;
  }

  const [leftHash, rightHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", textEncoder.encode(leftValue)),
    crypto.subtle.digest("SHA-256", textEncoder.encode(rightValue)),
  ]);
  const leftBytes = new Uint8Array(leftHash);
  const rightBytes = new Uint8Array(rightHash);
  let diff = 0;
  for (let index = 0; index < leftBytes.length; index += 1) {
    diff |= leftBytes[index] ^ rightBytes[index];
  }
  return diff === 0;
}
