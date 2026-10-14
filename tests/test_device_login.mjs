import assert from "node:assert/strict";
import test from "node:test";

import {
  GRANT_TYPE,
  DeviceLoginError,
  deviceLogin,
  waitSeconds,
} from "../dtc_device_login/login.mjs";

function scripted(responses) {
  const calls = [];
  const post = async (url, body) => {
    calls.push({ url, body });
    return responses.shift();
  };
  return { post, calls };
}

test("waitSeconds holds for the code lifetime", () => {
  assert.equal(waitSeconds(600, 900), 915);
  assert.equal(waitSeconds(null, 120), 120);
  assert.equal(waitSeconds(0, 0), 0);
});

test("deviceLogin polls until the credential arrives", async () => {
  const { post, calls } = scripted([
    {
      status: 200,
      body: {
        device_code: "secret",
        user_code: "ABCD-EFGH",
        verification_uri_complete: "https://portal.test/device?user_code=ABCD-EFGH",
        expires_in: 600,
        interval: 1,
      },
    },
    { status: 400, body: { error: "authorization_pending" } },
    { status: 200, body: { token: "issued" } },
  ]);
  const lines = [];
  const result = await deviceLogin({
    post,
    baseUrl: "https://portal.test",
    startBody: { label: "laptop" },
    prompt: (text) => lines.push(text),
    sleep: async () => {},
    now: () => 1_000,
  });
  assert.equal(result.token, "issued");
  assert.equal(calls[0].body.label, "laptop");
  assert.deepEqual(calls[1].body, { grant_type: GRANT_TYPE, device_code: "secret" });
  assert.match(lines[0], /ABCD-EFGH/);
  assert.doesNotMatch(lines[0], /secret/);
});

test("deviceLogin stops when the browser denies the login", async () => {
  const { post } = scripted([
    {
      status: 200,
      body: { device_code: "secret", user_code: "ABCD-EFGH", expires_in: 60, interval: 1 },
    },
    { status: 400, body: { error: "access_denied" } },
  ]);
  await assert.rejects(
    () => deviceLogin({ post, baseUrl: "https://portal.test", sleep: async () => {}, now: () => 0 }),
    (error) => error instanceof DeviceLoginError && /denied in the browser/.test(error.message),
  );
});
