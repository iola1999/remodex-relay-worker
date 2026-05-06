import { bytesToBase64Url, readString, textEncoder } from "./shared.js";

const APNS_TOKEN_TTL_SECONDS = 50 * 60;

export function createAPNsClient({
  teamId = "",
  keyId = "",
  bundleId = "",
  privateKey = "",
  now = () => Date.now(),
  fetchFn = fetch,
} = {}) {
  let cachedToken = null;
  let cachedKey = null;

  function isConfigured() {
    return Boolean(teamId && keyId && bundleId && privateKey);
  }

  async function sendNotification({
    deviceToken,
    apnsEnvironment = "production",
    title,
    body,
    payload = {},
  } = {}) {
    if (!isConfigured()) {
      throw apnsError("apns_not_configured", "APNs credentials are not configured.", 503);
    }

    const normalizedDeviceToken = normalizeDeviceToken(deviceToken);
    if (!normalizedDeviceToken) {
      throw apnsError("invalid_device_token", "A valid APNs device token is required.", 400);
    }

    const authority = apnsEnvironment === "development"
      ? "https://api.sandbox.push.apple.com"
      : "https://api.push.apple.com";
    const response = await fetchFn(`${authority}/3/device/${normalizedDeviceToken}`, {
      method: "POST",
      headers: {
        authorization: `bearer ${await authorizationToken()}`,
        "apns-topic": bundleId,
        "apns-push-type": "alert",
        "apns-priority": "10",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        aps: {
          alert: {
            title: readString(title) || "Remodex",
            body: readString(body) || "Response ready",
          },
          sound: "default",
        },
        ...payload,
      }),
    });

    if (response.status >= 400) {
      const responseBody = await safeResponseJSON(response);
      throw apnsError(
        "apns_request_failed",
        responseBody?.reason || `APNs request failed with HTTP ${response.status}.`,
        response.status
      );
    }

    return { ok: true };
  }

  async function authorizationToken() {
    const issuedAt = Math.floor(now() / 1000);
    if (cachedToken && cachedToken.expiresAt > issuedAt + 30) {
      return cachedToken.value;
    }

    const header = base64UrlJSON({ alg: "ES256", kid: keyId });
    const claims = base64UrlJSON({ iss: teamId, iat: issuedAt });
    const signingInput = `${header}.${claims}`;
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      await signingKey(),
      textEncoder.encode(signingInput)
    );
    const token = `${signingInput}.${bytesToBase64Url(new Uint8Array(signature))}`;

    cachedToken = {
      value: token,
      expiresAt: issuedAt + APNS_TOKEN_TTL_SECONDS,
    };
    return token;
  }

  async function signingKey() {
    if (cachedKey) {
      return cachedKey;
    }
    cachedKey = await crypto.subtle.importKey(
      "pkcs8",
      pemToDer(privateKey),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
    return cachedKey;
  }

  return {
    isConfigured,
    sendNotification,
  };
}

export function apnsConfigFromEnv(env = {}) {
  return {
    teamId: readFirstDefinedEnv(["REMODEX_APNS_TEAM_ID", "PHODEX_APNS_TEAM_ID"], env),
    keyId: readFirstDefinedEnv(["REMODEX_APNS_KEY_ID", "PHODEX_APNS_KEY_ID"], env),
    bundleId: readFirstDefinedEnv(["REMODEX_APNS_BUNDLE_ID", "PHODEX_APNS_BUNDLE_ID"], env),
    privateKey: readFirstDefinedEnv(["REMODEX_APNS_PRIVATE_KEY", "PHODEX_APNS_PRIVATE_KEY"], env),
  };
}

function base64UrlJSON(value) {
  return bytesToBase64Url(textEncoder.encode(JSON.stringify(value)));
}

function pemToDer(pem) {
  const base64 = String(pem || "")
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function normalizeDeviceToken(value) {
  const normalized = readString(value);
  if (!normalized) {
    return "";
  }

  return normalized.replace(/[^a-fA-F0-9]/g, "").toLowerCase();
}

function readFirstDefinedEnv(keys, env) {
  for (const key of keys) {
    const value = readString(env?.[key]);
    if (value) {
      return value;
    }
  }
  return "";
}

async function safeResponseJSON(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function apnsError(code, message, status) {
  const error = new Error(message);
  error.code = code;
  error.status = status;
  return error;
}
