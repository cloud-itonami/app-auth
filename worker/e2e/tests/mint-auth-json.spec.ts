/**
 * Headless E2E equivalent of `etzhayyim authn signin`.
 *
 * Drives the full passkey register → OAuth2 PKCE round trip via CDP virtual
 * authenticator, captures the `sk_live_*` apiKey from /oauth/token, and
 * writes `~/.etzhayyim/auth.json` so the etzhayyim CLI can authenticate without an
 * interactive browser session.
 *
 * Run:
 *   cd 60-apps/etzhayyim-project-auth/worker/e2e
 *   pnpm exec playwright test tests/mint-auth-json.spec.ts
 *
 * Then any subsequent `etzhayyim ...` call uses the minted apiKey.
 */

import { test, expect, type Page } from "@playwright/test";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const AUTHN_BASE = process.env.AUTH_BASE_URL ?? "https://authn.etzhayyim.com";
const AUTH_FILE = process.env.etzhayyim_AUTH_FILE ?? join(homedir(), ".etzhayyim", "auth.json");

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function makePkce(): { verifier: string; challenge: string } {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}
async function attachVA(page: Page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable", {});
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
}

test("mint auth.json via headless WebAuthn → OAuth PKCE → apiKey", async ({ page, request }) => {
  await attachVA(page);
  // Navigate to bind navigator.credentials to the auth origin.
  // authn.etzhayyim.com 301-redirects to auth.etzhayyim.com; capture the final origin for
  // Node-side request.post calls (301 would convert POST → GET via fetch).
  await page.goto(`${AUTHN_BASE}/sign-up`, { waitUntil: "domcontentloaded" });
  const AUTH_ORIGIN = new URL(page.url()).origin; // https://auth.etzhayyim.com after redirect

  // 1. passkeyBeginRegister — Node.js side (avoids SvelteKit patched window.fetch)
  const userId = randomBytes(16).toString("hex");
  const userName = `cli-${randomBytes(4).toString("hex")}@etzhayyim.com`;
  const beginResp = await request.post(`${AUTH_ORIGIN}/xrpc/com.etzhayyim.auth.passkeyBeginRegister`, {
    data: { userId, userName },
  });
  expect(beginResp.ok(), `passkeyBeginRegister failed: ${beginResp.status()}`).toBe(true);
  const begin = await beginResp.json();

  // 2. navigator.credentials.create — browser-native WebAuthn, must run in page context
  const credResult = await page.evaluate(async (b: any) => {
    const dec = (s: string) => {
      s = s.replace(/-/g, "+").replace(/_/g, "/");
      while (s.length % 4) s += "=";
      return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    };
    const enc = (buf: ArrayBuffer) => {
      const bytes = new Uint8Array(buf);
      let s = "";
      for (const byte of bytes) s += String.fromCharCode(byte);
      return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    };
    const cred = (await navigator.credentials.create({
      publicKey: {
        challenge: dec(b.challenge),
        rp: { id: b.rp.id, name: b.rp.name },
        user: { id: dec(b.user.id), name: b.user.name, displayName: b.user.displayName },
        pubKeyCredParams: b.pubKeyCredParams.map((p: any) => ({ type: p.type, alg: p.alg })),
        timeout: b.timeout,
        attestation: b.attestation,
        authenticatorSelection: b.authenticatorSelection ?? b.authenticator_selection,
      },
    })) as PublicKeyCredential;
    const att = cred.response as AuthenticatorAttestationResponse;
    return {
      clientDataJson: enc(att.clientDataJSON),
      attestationObject: enc(att.attestationObject),
    };
  }, begin);

  // 3. passkeyVerifyRegister — Node.js side
  const verifyResp = await request.post(`${AUTH_ORIGIN}/xrpc/com.etzhayyim.auth.passkeyVerifyRegister`, {
    data: {
      challenge: begin.challenge,
      clientDataJson: credResult.clientDataJson,
      attestationObject: credResult.attestationObject,
    },
  });
  expect(verifyResp.ok(), `passkeyVerifyRegister failed: ${verifyResp.status()} ${await verifyResp.text()}`).toBe(true);
  const verifyBody = await verifyResp.json();

  const did = verifyBody.did as string;
  const handle = verifyBody.handle as string;
  expect(did).toMatch(/^did:(etzhayyim:[a-f0-9]{24}|web:authn?\.etzhayyim\.ai:user:)/);

  // 4. OAuth PKCE — Node.js side
  const { verifier, challenge } = makePkce();
  const redirectUri = "http://127.0.0.1:9876";
  const state = b64url(randomBytes(8));

  const issueResp = await request.post(`${AUTH_ORIGIN}/oauth/issue-code`, {
    data: {
      clientId: "etzhayyim-cli",
      redirectUri,
      state,
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
      did,
      handle,
    },
  });
  expect(issueResp.ok(), `oauth/issue-code failed: ${issueResp.status()} ${await issueResp.text()}`).toBe(true);
  const issueBody = await issueResp.json();

  const tokenResp = await request.post(`${AUTH_ORIGIN}/oauth/token`, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    form: {
      grant_type: "authorization_code",
      client_id: "etzhayyim-cli",
      code: issueBody.code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    },
  });
  expect(tokenResp.ok(), `oauth/token failed: ${tokenResp.status()} ${await tokenResp.text()}`).toBe(true);
  const tokenBody = await tokenResp.json();

  // ADR-2604231821 S5: authn /oauth/token response is snake_case.
  const apiKey = String(tokenBody.api_key ?? "");
  expect(apiKey).toMatch(/^sk_live_/);

  const store = {
    api_key: apiKey,
    sub: did,
    active_did: verifyBody.activeDid ?? did,
  };
  mkdirSync(join(homedir(), ".etzhayyim"), { recursive: true, mode: 0o700 });
  writeFileSync(AUTH_FILE, JSON.stringify(store, null, 2), { mode: 0o600 });
  console.log(`AUTH_JSON_WRITTEN ${AUTH_FILE} apiKey=${apiKey.slice(0, 16)}... did=${did}`);
});
