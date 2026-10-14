/**
 * One device-login flow for apps on the DTC shared auth layer.
 *
 * Mirrors dtc_device_login/__init__.py. Apps mint their own credential after
 * the operator approves the code; this module owns the start, prompt, and poll.
 */

export const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
export const START_PATH = "/api/auth/device";
export const TOKEN_PATH = "/api/auth/device/token";
export const SLOW_DOWN_SECONDS = 5;

export class DeviceLoginError extends Error {
  constructor(message, code = "error") {
    super(message);
    this.name = "DeviceLoginError";
    this.code = code;
  }
}

export function absoluteVerificationUri(baseUrl, start) {
  const raw = String(
    start.verification_uri_complete || start.verification_uri || "/device",
  );
  if (raw.startsWith("http://") || raw.startsWith("https://")) return raw;
  return `${String(baseUrl).replace(/\/+$/, "")}/${raw.replace(/^\/+/, "")}`;
}

export function waitSeconds(timeout, expiresIn) {
  const lifetime = Number(expiresIn) || 0;
  if (timeout == null) return lifetime > 0 ? lifetime : 600;
  if (lifetime > 0) return Math.max(Number(timeout), lifetime + 15);
  return Number(timeout);
}

function intervalSeconds(start) {
  const interval = Number(start.interval);
  if (!Number.isFinite(interval) || interval < 1) return interval > 0 && interval < 1 ? 1 : 5;
  return interval;
}

/**
 * @param {object} options
 * @param {(url: string, body: object) => Promise<{status: number, body: object}>} options.post
 * @param {string} options.baseUrl
 */
export async function deviceLogin({
  post,
  baseUrl,
  startBody = {},
  startPath = START_PATH,
  tokenPath = TOKEN_PATH,
  prompt = null,
  presentUri = null,
  sleep = (seconds) => new Promise((resolve) => setTimeout(resolve, seconds * 1000)),
  now = () => Date.now(),
  timeout = null,
  transient = [],
}) {
  const base = String(baseUrl || "").replace(/\/+$/, "");
  if (!base) throw new DeviceLoginError("A server URL is required.", "invalid_request");
  const started = await post(`${base}${startPath}`, { ...startBody });
  const start = started.body || {};
  if (started.status !== 200 || !start.device_code || !start.user_code) {
    throw new DeviceLoginError("The server did not offer device login.", "invalid_response");
  }

  let interval = intervalSeconds(start);
  const lifetime = Number(start.expires_in) || 0;
  const deadline = now() + waitSeconds(timeout, lifetime) * 1000;
  let uri = absoluteVerificationUri(base, start);
  if (presentUri) uri = presentUri(uri);
  const minutes = Math.max(Math.floor((lifetime || (deadline - now()) / 1000) / 60), 1);
  const unit = minutes === 1 ? "minute" : "minutes";
  const text =
    `\n  Confirm this code:  ${start.user_code}\n` +
    `  Open in a browser:  ${uri}\n` +
    `\n` +
    `  Open that link on a machine you trust and sign in as usual.\n` +
    `  Waiting for confirmation (the code is valid for ${minutes} ${unit})...\n`;
  if (prompt) prompt(text);
  else console.log(text);

  while (now() < deadline) {
    await sleep(interval);
    if (now() >= deadline) break;
    let status;
    let result;
    try {
      const polled = await post(`${base}${tokenPath}`, {
        grant_type: GRANT_TYPE,
        device_code: start.device_code,
      });
      status = polled.status;
      result = polled.body || {};
    } catch (error) {
      if (transient.some((type) => error instanceof type)) continue;
      throw error;
    }
    if (status === 200 && !result.error) return result;
    const code = String(result.error || "");
    if (code === "slow_down") {
      interval += SLOW_DOWN_SECONDS;
      continue;
    }
    if (code === "authorization_pending") continue;
    if (code === "access_denied") {
      throw new DeviceLoginError("The login was denied in the browser.", code);
    }
    if (code === "expired_token") {
      throw new DeviceLoginError("The code expired. Run login again.", code);
    }
    throw new DeviceLoginError(code || `Device login failed (${status}).`, code || "error");
  }
  throw new DeviceLoginError("Timed out waiting for approval. Run login again.", "timeout");
}
