/**
 * T4 AuthZ Worker Integration Tests (ADR-0024 / T4 topology, 2026-04-16)
 *
 * Verifies accounts.etzhayyim.com (etzhayyim-authz Worker) end-to-end:
 *
 * 1. Redirect chain — accounts.etzhayyim.com root → /manage → authn sign-in (no session)
 * 2. Unauthenticated getSession returns {ok: false}
 * 3. Full passkey register (via authn.etzhayyim.com) → session cookie shared → authz getSession
 * 4. Canonical com.etzhayyim.authz.getSession works on authz
 * 5. Org management: orgCreate → orgInfo → orgList → orgInvite → orgInviteAccept → orgMembers
 */

import { test, expect, type Page, type CDPSession } from "@playwright/test";
import { randomBytes } from "node:crypto";

const AUTHN_BASE = process.env.AUTH_BASE_URL ?? "https://authn.etzhayyim.com";
// auth.etzhayyim.com is the canonical URL — authn.etzhayyim.com 301-redirects and POST→GET conversion breaks XRPC calls.
const AUTH_CANONICAL = "https://auth.etzhayyim.com";
const AUTHZ_BASE = process.env.AUTHZ_BASE_URL ?? "https://accounts.etzhayyim.com";
const ACCOUNTS_BASE = "https://accounts.etzhayyim.com";

// ── CDP Virtual Authenticator ──

async function attachVirtualAuthenticator(page: Page): Promise<CDPSession> {
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
  return cdp;
}

// ── Register a passkey and return session cookie + DID ──
// Uses Playwright `request` fixture (Node.js) for XRPC calls to avoid SvelteKit patched
// window.fetch cross-origin failures and authn.etzhayyim.com 301 POST→GET conversion.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function registerPasskeySession(page: Page, request: any): Promise<{ did: string; cookie: string }> {
  await attachVirtualAuthenticator(page);
  await page.goto(`${AUTHN_BASE}/sign-up`, { waitUntil: "domcontentloaded" });
  // Capture the canonical origin after the authn.etzhayyim.com → auth.etzhayyim.com 301 redirect.
  const AUTH_ORIGIN = new URL(page.url()).origin;

  // 1. passkeyBeginRegister — Node.js side (avoids SvelteKit patched window.fetch)
  const userId = randomBytes(16).toString("hex");
  const userName = `authz-e2e-${randomBytes(4).toString("hex")}@etzhayyim.com`;
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

  const did: string = verifyBody.did;
  expect(did).toMatch(/^did:(etzhayyim:[a-f0-9]{24}|web:auth\.etzhayyim\.ai:user:)/);

  // Extract accessJwt from response body — used as etzhayyim_session cookie value.
  // We don't read it from page.context().cookies() because the Playwright request fixture
  // cookie jar and the browser page cookie jar don't always sync for HttpOnly cookies.
  const accessJwt = String(verifyBody.accessJwt ?? "");
  expect(accessJwt, "accessJwt missing from registration result").toBeTruthy();
  const cookie = `etzhayyim_session=${accessJwt}`;

  return { did, cookie };
}

// ── Test suite ──

test.describe("T4 AuthZ Worker (authz.etzhayyim.com)", () => {
  test("1. accounts.etzhayyim.com root redirects to /manage, no-session /manage redirects to authn sign-in", async ({
    page,
  }) => {
    // Follow redirect chain without session: accounts.etzhayyim.com/ → /manage → authn sign-in
    const resp = await page.goto(ACCOUNTS_BASE + "/", {
      waitUntil: "domcontentloaded",
      timeout: 15_000,
    });
    // Final destination should be authn.etzhayyim.com/sign-in or authz.etzhayyim.com/manage (if already signed in)
    const finalUrl = page.url();
    const ok =
      finalUrl.startsWith("https://authn.etzhayyim.com/sign-in") ||
      finalUrl.startsWith("https://auth.etzhayyim.com/sign-in") ||
      finalUrl.startsWith("https://accounts.etzhayyim.com/manage");
    expect(ok, `Unexpected final URL after redirect: ${finalUrl}`).toBe(true);
  });

  test("2. getSession without auth returns {ok: false}", async ({ request }) => {
    const resp = await request.get(`${AUTHZ_BASE}/xrpc/com.etzhayyim.authz.getSession`, {
      headers: { Cookie: "etzhayyim_session=invalid_token" },
    });
    // Worker returns 200 with {ok: false} (XRPC convention — not an HTTP error)
    const body = await resp.json();
    expect(body.ok).toBe(false);
    expect(body.authenticated).toBe(false);
  });

  test("3. getSession with valid passkey session returns accountDid + linkedMethods", async ({
    page,
    request,
  }) => {
    const { did, cookie } = await registerPasskeySession(page, request);

    const resp = await request.get(`${AUTHZ_BASE}/xrpc/com.etzhayyim.authz.getSession`, {
      headers: { Cookie: cookie },
    });
    expect(resp.ok(), `getSession failed: ${await resp.text()}`).toBe(true);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.accountDid).toBe(did);
    expect(Array.isArray(body.linkedMethods)).toBe(true);
    expect(typeof body.actorScore?.score).toBe("number");
    test.info().annotations.push({ type: "did", description: did });
    test.info().annotations.push({ type: "actorScore", description: String(body.actorScore.score) });
  });

  test("4. canonical com.etzhayyim.authz.getSession works on authz", async ({ page, request }) => {
    const { cookie } = await registerPasskeySession(page, request);

    const resp = await request.get(`${AUTHZ_BASE}/xrpc/com.etzhayyim.authz.getSession`, {
      headers: { Cookie: cookie },
    });
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.ok).toBe(true);
  });

  test("5. org management: create → info → list → invite → accept → members", async ({
    page,
    browser,
    request,
  }) => {
    test.setTimeout(180_000); // 3 passkey registrations (owner + member) + org API calls
    const { did: ownerDid, cookie: ownerCookie } = await registerPasskeySession(page, request);

    // 5a. orgCreate
    const createResp = await request.post(`${AUTHZ_BASE}/xrpc/com.etzhayyim.authz.orgCreate`, {
      headers: { Cookie: ownerCookie, "Content-Type": "application/json" },
      data: { name: "E2E Test Org", domain: "e2e.etzhayyim.com", orgType: "company" },
    });
    expect(createResp.ok(), `orgCreate failed: ${await createResp.text()}`).toBe(true);
    const created = await createResp.json();
    expect(created.ok).toBe(true);
    expect(created.name).toBe("E2E Test Org");
    const orgDid: string = created.orgDid;
    expect(orgDid).toBeTruthy();
    test.info().annotations.push({ type: "orgDid", description: orgDid });

    // 5b. orgInfo — response: { ok: true, org: { orgDid, name, orgType, memberCount, ... } }
    const infoResp = await request.get(
      `${AUTHZ_BASE}/xrpc/com.etzhayyim.authz.orgInfo?orgDid=${encodeURIComponent(orgDid)}`,
      { headers: { Cookie: ownerCookie } },
    );
    expect(infoResp.ok()).toBe(true);
    const infoBody = await infoResp.json();
    const info = infoBody.org;
    expect(info.name).toBe("E2E Test Org");
    expect(info.orgType).toBe("company");
    expect(info.memberCount).toBeGreaterThanOrEqual(1);

    // 5c. orgList
    const listResp = await request.get(`${AUTHZ_BASE}/xrpc/com.etzhayyim.authz.orgList`, {
      headers: { Cookie: ownerCookie },
    });
    expect(listResp.ok()).toBe(true);
    const list = await listResp.json();
    expect(list.total).toBeGreaterThanOrEqual(1);
    const found = list.orgs.find((o: any) => o.orgDid === orgDid);
    expect(found, "orgList should contain newly created org").toBeTruthy();
    expect(found.role).toBe("owner");

    // 5d. orgInvite (invite a fake email; token is HMAC-stateless so no delivery needed)
    const inviteEmail = `e2e-invitee-${Date.now()}@etzhayyim.com`;
    const inviteResp = await request.post(`${AUTHZ_BASE}/xrpc/com.etzhayyim.authz.orgInvite`, {
      headers: { Cookie: ownerCookie, "Content-Type": "application/json" },
      data: { orgDid, email: inviteEmail, role: "member" },
    });
    expect(inviteResp.ok(), `orgInvite failed: ${await inviteResp.text()}`).toBe(true);
    const invite = await inviteResp.json();
    expect(invite.ok).toBe(true);
    test.info().annotations.push({ type: "inviteOk", description: "true" });

    // debugToken is returned only in non-production (HMAC token, no email delivery needed).
    // In production, skip invite-accept steps; they require an out-of-band token.
    const inviteToken: string | undefined = invite.debugToken;
    if (typeof inviteToken !== "string") {
      test.info().annotations.push({
        type: "inviteAcceptSkipped",
        description: "debugToken not available in production — invite-accept sub-test skipped",
      });
      return;
    }

    // 5e. Register a second account (fresh browser context — separate CDP session / cookies)
    const ctx2 = await browser.newContext();
    const page2 = await ctx2.newPage();
    const { did: memberDid, cookie: memberCookie } = await registerPasskeySession(page2, request);
    await ctx2.close();

    const acceptResp = await request.post(`${AUTHZ_BASE}/xrpc/com.etzhayyim.authz.orgInviteAccept`, {
      headers: { Cookie: memberCookie, "Content-Type": "application/json" },
      data: { token: inviteToken },
    });
    expect(acceptResp.ok(), `orgInviteAccept failed: ${await acceptResp.text()}`).toBe(true);
    const accepted = await acceptResp.json();
    expect(accepted.ok).toBe(true);
    expect(accepted.memberDid).toBe(memberDid);

    // 5f. orgMembers — should now have 2 members
    const membersResp = await request.get(
      `${AUTHZ_BASE}/xrpc/com.etzhayyim.authz.orgMembers?orgDid=${encodeURIComponent(orgDid)}`,
      { headers: { Cookie: ownerCookie } },
    );
    expect(membersResp.ok()).toBe(true);
    const members = await membersResp.json();
    expect(members.total).toBe(2);
    const memberDids = members.members.map((m: any) => m.memberDid);
    expect(memberDids).toContain(ownerDid);
    expect(memberDids).toContain(memberDid);

    // 5g. orgLeave — member leaves
    const leaveResp = await request.post(`${AUTHZ_BASE}/xrpc/com.etzhayyim.authz.orgLeave`, {
      headers: { Cookie: memberCookie, "Content-Type": "application/json" },
      data: { orgDid },
    });
    expect(leaveResp.ok(), `orgLeave failed: ${await leaveResp.text()}`).toBe(true);

    // 5h. Verify members is back to 1
    const members2Resp = await request.get(
      `${AUTHZ_BASE}/xrpc/com.etzhayyim.authz.orgMembers?orgDid=${encodeURIComponent(orgDid)}`,
      { headers: { Cookie: ownerCookie } },
    );
    expect(members2Resp.ok()).toBe(true);
    const members2 = await members2Resp.json();
    expect(members2.total).toBe(1);
  });

  test("6. authn Worker health + passkey endpoints still reachable", async ({ request }) => {
    const health = await request.get(`${AUTH_CANONICAL}/health`);
    expect(health.ok()).toBe(true);
    expect(await health.text()).toBe("ok");

    // Use AUTH_CANONICAL (auth.etzhayyim.com) — authn.etzhayyim.com 301-redirects which converts POST→GET.
    const beginAuth = await request.post(`${AUTH_CANONICAL}/xrpc/com.etzhayyim.auth.passkeyBeginAuth`, {
      headers: { "Content-Type": "application/json" },
      data: {},
    });
    expect(beginAuth.ok(), `passkeyBeginAuth failed: ${beginAuth.status()} ${await beginAuth.text()}`).toBe(true);
    const authBody = await beginAuth.json();
    expect(typeof authBody.challenge).toBe("string");
  });
});
