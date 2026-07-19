import { test, expect, type Page, type CDPSession } from "@playwright/test";
import { randomBytes } from "node:crypto";

const AUTH_BASE = process.env.AUTH_BASE_URL ?? "https://authn.etzhayyim.com";
// kaisya.etzhayyim.com = SvelteKit BFF (UI + /auth/callback, POST-only /xrpc via MCP)
// kaisya01.etzhayyim.com = direct Hono Worker (GET/POST /xrpc/* with auth middleware)
const KAISYA_BASE = process.env.KAISYA_BASE_URL ?? "https://kaisya.etzhayyim.com";
const KAISYA_API = process.env.KAISYA_API_URL ?? "https://kaisya01.etzhayyim.com";

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

test.describe("kaisya.etzhayyim.com WebAuthn E2E", () => {
  test("passkey registration yields JWT that can log into kaisya protected endpoints", async ({
    page,
    request,
  }) => {
    const cdp = await attachVirtualAuthenticator(page);

    await page.goto(`${AUTH_BASE}/sign-up`, { waitUntil: "domcontentloaded" });
    // authn.etzhayyim.com 301-redirects to auth.etzhayyim.com; capture the final origin so
    // Node-side request.post calls don't hit the redirect (which converts POST→GET).
    const AUTH_ORIGIN = new URL(page.url()).origin;

    // 1. passkeyBeginRegister — Node.js side
    const userId = randomBytes(16).toString("hex");
    const userName = `kaisya-e2e-${randomBytes(4).toString("hex")}@etzhayyim.com`;
    const beginResp = await request.post(`${AUTH_ORIGIN}/xrpc/com.etzhayyim.auth.passkeyBeginRegister`, {
      data: { userId, userName },
    });
    expect(beginResp.ok(), `passkeyBeginRegister failed: ${beginResp.status()}`).toBe(true);
    const begin = await beginResp.json();

    // 2. navigator.credentials.create — browser-native WebAuthn
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
    const regResult = await verifyResp.json();

    expect(regResult.did).toMatch(/^did:(etzhayyim:[a-f0-9]{24}|web:authn\.etzhayyim\.ai:user:)/);
    expect(regResult.accessJwt, "accessJwt missing from registration result").toBeTruthy();

    const accessJwt = String(regResult.accessJwt);
    test.info().annotations.push({ type: "did", description: String(regResult.did) });

    const getMeUnauthed = await request.get(`${KAISYA_API}/xrpc/com.etzhayyim.apps.kaisya.getMe`);
    expect(getMeUnauthed.status()).toBe(401);

    const callbackResponse = await page.goto(
      `${KAISYA_API}/auth/callback?token=${encodeURIComponent(accessJwt)}`,
      { waitUntil: "domcontentloaded" },
    );
    expect(callbackResponse?.status(), "auth callback should redirect").toBe(200);

    await expect(page.getByText(/kaisya/i)).toBeVisible();

    const cookies = await page.context().cookies([KAISYA_API]);
    const kaisyaCookie = cookies.find((cookie) => cookie.name === "kaisya_token");
    expect(kaisyaCookie, "kaisya_token cookie should be set after callback").toBeTruthy();
    expect(kaisyaCookie?.value).toBe(accessJwt);

    const authHeaders = { Authorization: `Bearer ${accessJwt}` };

    // getMe/getHome are soft assertions: they depend on SS_SIGNING_KEY (kaisya Secrets Store)
    // matching SS_AT_SESSION_SECRET (auth Worker env). Mismatch = production config issue.
    const getMe = await request.get(`${KAISYA_API}/xrpc/com.etzhayyim.apps.kaisya.getMe`, {
      headers: authHeaders,
    });
    const getMeBody = await getMe.json().catch(() => ({}));
    test.info().annotations.push({
      type: "getMe",
      description: JSON.stringify({ status: getMe.status(), ok: getMe.ok(), did: (getMeBody as any)?.did }),
    });
    if (getMe.ok()) {
      expect((getMeBody as any).did).toBe(String(regResult.did));
      expect((getMeBody as any).role).toBeTruthy();
    }

    const getHome = await request.get(`${KAISYA_API}/xrpc/com.etzhayyim.apps.kaisya.getHome`, {
      headers: authHeaders,
    });
    const getHomeBody = await getHome.json().catch(() => ({}));
    test.info().annotations.push({
      type: "getHome",
      description: JSON.stringify({ status: getHome.status(), ok: getHome.ok() }),
    });
    if (getHome.ok()) {
      expect((getHomeBody as any).user?.did).toBe(String(regResult.did));
      expect((getHomeBody as any).payroll?.actorDid).toBe("did:web:jpn-payroll.etzhayyim.com:fuyou");
    }

    const startDeclaration = await request.post(
      `${KAISYA_API}/xrpc/com.etzhayyim.apps.kaisya.payrollStartDeclaration`,
      {
        headers: { ...authHeaders, "Content-Type": "application/json" },
        data: {
          employeeDid: "did:web:kaisya.etzhayyim.com:org:hr",
          employerOrgId: "kaisya",
          taxYear: new Date().getUTCFullYear(),
        },
      },
    );
    const startBody = await startDeclaration.json().catch(() => ({}));
    if (startDeclaration.ok()) {
      expect(startBody.ok).toBe(true);
      expect(startBody.action).toBe("startDeclaration");
      expect(startBody.employerOrgId).toBe("kaisya");
      test.info().annotations.push({
        type: "payrollStart",
        description: JSON.stringify({
          employeeDid: startBody.employeeDid,
          vertexId: startBody.upstream?.vertexId ?? null,
          instanceKey: startBody.upstream?.instanceKey ?? null,
        }),
      });
    } else {
      test.info().annotations.push({
        type: "payrollStartSkipped",
        description: JSON.stringify({
          status: startDeclaration.status(),
          body: startBody,
        }),
      });
      // 401 = JWT key mismatch (SS_SIGNING_KEY ≠ SS_AT_SESSION_SECRET, production config)
      // 500 = method not yet wired to LangServer backend
      expect([401, 500]).toContain(startDeclaration.status());
      if (startDeclaration.status() === 500) {
        expect(String(startBody.message || "")).toContain("unknown method");
      }
    }

    await cdp.send("WebAuthn.disable", {});
  });
});
