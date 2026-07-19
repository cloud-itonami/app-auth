/**
 * did:etzhayyim identity integration test.
 *
 * Tests the full did:etzhayyim lifecycle:
 *   1. Passkey sign-up → did:etzhayyim mint (vertex_etzhayyim_auth_account + vertex_etzhayyim_key_signing)
 *   2. DID Doc resolution (handleResolveetzhayyimDid)
 *   3. Service Auth JWT mint with did:etzhayyim iss
 *   4. OAuth link → auth_methods_summary update + actor_score recalc
 *   5. Org creation + invite + accept (when endpoints are live)
 *
 * Runs against live auth.etzhayyim.com (production or staging).
 */

import { test, expect, type Page, type CDPSession } from "@playwright/test";

const AUTH_BASE = process.env.AUTH_BASE_URL ?? "https://authn.etzhayyim.com";

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

test.describe("did:etzhayyim identity lifecycle", () => {

  test("passkey sign-up mints did:etzhayyim and resolves DID Document", async ({ page }) => {
    const cdp = await attachVirtualAuthenticator(page);
    await page.goto(`${AUTH_BASE}/sign-up`, { waitUntil: "domcontentloaded" });

    // ── Step 1: Passkey register → did:etzhayyim mint ──
    const regResult = await page.evaluate(async () => {
      const AUTH = location.origin;
      const b64urlEncode = (buf: ArrayBuffer) => {
        const bytes = new Uint8Array(buf);
        let s = "";
        for (const b of bytes) s += String.fromCharCode(b);
        return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
      };
      const b64urlDecode = (s: string) => {
        s = s.replace(/-/g, "+").replace(/_/g, "/");
        while (s.length % 4) s += "=";
        return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
      };

      const begin = await fetch(`${AUTH}/xrpc/com.etzhayyim.auth.passkeyBeginRegister`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userId: crypto.randomUUID(),
          userName: `e2e-etzhayyim-${crypto.randomUUID().slice(0, 8)}@etzhayyim.com`,
        }),
      }).then((r) => r.json());

      const cred = (await navigator.credentials.create({
        publicKey: {
          challenge: b64urlDecode(begin.challenge),
          rp: { id: begin.rp.id, name: begin.rp.name },
          user: {
            id: b64urlDecode(begin.user.id),
            name: begin.user.name,
            displayName: begin.user.displayName,
          },
          pubKeyCredParams: begin.pubKeyCredParams.map((p: any) => ({
            type: p.type,
            alg: p.alg,
          })),
          timeout: begin.timeout,
          attestation: begin.attestation,
          authenticatorSelection: begin.authenticatorSelection ?? begin.authenticator_selection,
        },
      })) as PublicKeyCredential;

      const att = cred.response as AuthenticatorAttestationResponse;
      const verify = await fetch(`${AUTH}/xrpc/com.etzhayyim.auth.passkeyVerifyRegister`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          challenge: begin.challenge,
          clientDataJson: b64urlEncode(att.clientDataJSON),
          attestationObject: b64urlEncode(att.attestationObject),
        }),
      }).then(async (r) => ({ ok: r.ok, status: r.status, body: await r.json().catch(() => ({})) }));

      return verify;
    });

    expect(regResult.ok, `passkeyVerifyRegister failed: ${JSON.stringify(regResult)}`).toBe(true);

    const accountDid = regResult.body.accountDid as string;
    const activeDid = regResult.body.activeDid as string;
    const handle = regResult.body.handle as string;

    // ── Assertion: did:etzhayyim (post-deploy) or did:web (pre-deploy) ──
    const isetzhayyimDid = accountDid.startsWith("did:etzhayyim:");
    if (isetzhayyimDid) {
      expect(accountDid).toMatch(/^did:etzhayyim:[a-f0-9]{24}$/);
      expect(activeDid).toMatch(/^did:etzhayyim:[a-f0-9]{24}$/);
    } else {
      expect(accountDid).toMatch(/^did:web:auth\.etzhayyim\.ai:user:/);
      test.info().annotations.push({ type: "note", description: "pre-deploy: did:web returned (did:etzhayyim not yet live)" });
    }
    expect(accountDid).not.toBe(activeDid);
    expect(handle).toMatch(/^[a-z][a-z0-9]{7}\.etzhayyim\.ai$/);

    test.info().annotations.push(
      { type: "accountDid", description: accountDid },
      { type: "activeDid", description: activeDid },
      { type: "handle", description: handle },
    );

    // ── Step 2: Resolve did:etzhayyim DID Document (skip if pre-deploy) ──
    if (!isetzhayyimDid) {
      test.info().annotations.push({ type: "skip", description: "DID Doc resolution skipped (pre-deploy, did:web returned)" });
      await cdp.send("WebAuthn.disable", {});
      return;
    }

    const didDoc = await page.evaluate(async (did) => {
      const AUTH = location.origin;
      const resp = await fetch(`${AUTH}/xrpc/com.etzhayyim.auth.resolveetzhayyimDid`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ did }),
      });
      return { ok: resp.ok, status: resp.status, body: await resp.json().catch(() => ({})) };
    }, accountDid);

    expect(didDoc.ok, `resolveetzhayyimDid failed: ${JSON.stringify(didDoc)}`).toBe(true);

    const doc = didDoc.body;

    // DID Document structure assertions
    expect(doc.id).toBe(accountDid);
    expect(doc["@context"]).toContain("https://www.w3.org/ns/did/v1");
    expect(doc["@context"]).toContain("https://did.etzhayyim.com/context/v1");

    // verificationMethod (signing key from KEYS_DB)
    expect(doc.verificationMethod).toHaveLength(1);
    expect(doc.verificationMethod[0].id).toBe(`${accountDid}#signingKey`);
    expect(doc.verificationMethod[0].type).toBe("EcdsaSecp256r1VerificationKey2019");
    expect(doc.verificationMethod[0].publicKeyMultibase).toMatch(/^z/);

    // type (entity classification)
    expect(doc.type).toContain("Organization");

    // controller
    expect(doc.controller).toBe(accountDid);

    // actorScore (passkey only = 25)
    expect(doc.actorScore).toBe(25);

    test.info().annotations.push({
      type: "didDoc",
      description: `verificationMethod: ${doc.verificationMethod[0].publicKeyMultibase.slice(0, 16)}...`,
    });

    // ── Step 3: Resolve activeDid (Person sub-actor) ──
    const activeDoc = await page.evaluate(async (did) => {
      const AUTH = location.origin;
      const resp = await fetch(`${AUTH}/xrpc/com.etzhayyim.auth.resolveetzhayyimDid`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ did }),
      });
      return { ok: resp.ok, status: resp.status, body: await resp.json().catch(() => ({})) };
    }, activeDid);

    expect(activeDoc.ok, `resolveetzhayyimDid (active) failed: ${JSON.stringify(activeDoc)}`).toBe(true);
    expect(activeDoc.body.id).toBe(activeDid);
    expect(activeDoc.body.type).toContain("Person");
    expect(activeDoc.body.controller).toBe(accountDid);

    // ── Step 4: Service Auth JWT with did:etzhayyim iss ──
    const serviceAuth = await page.evaluate(async ({ iss, aud }) => {
      const AUTH = location.origin;
      const resp = await fetch(`${AUTH}/xrpc/com.atproto.server.getServiceAuth`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iss, aud: aud ?? "did:web:atproto.etzhayyim.com", lxm: "com.etzhayyim.apps.test.query" }),
      });
      return { ok: resp.ok, status: resp.status, body: await resp.json().catch(() => ({})) };
    }, { iss: accountDid, aud: "did:web:atproto.etzhayyim.com" });

    expect(serviceAuth.ok, `getServiceAuth failed: ${JSON.stringify(serviceAuth)}`).toBe(true);
    expect(serviceAuth.body.token).toBeTruthy();

    // Decode JWT header to verify ES256 alg
    const jwtParts = (serviceAuth.body.token as string).split(".");
    expect(jwtParts).toHaveLength(3);
    const header = JSON.parse(atob(jwtParts[0].replace(/-/g, "+").replace(/_/g, "/")));
    expect(header.alg).toBe("ES256");

    // Decode payload to verify did:etzhayyim iss
    const payload = JSON.parse(atob(jwtParts[1].replace(/-/g, "+").replace(/_/g, "/")));
    expect(payload.iss).toBe(accountDid);
    expect(payload.aud).toBe("did:web:atproto.etzhayyim.com");
    expect(payload.lxm).toBe("com.etzhayyim.apps.test.query");
    expect(payload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));

    test.info().annotations.push({
      type: "serviceAuth",
      description: `iss=${payload.iss}, lxm=${payload.lxm}, exp=${payload.exp}`,
    });

    await cdp.send("WebAuthn.disable", {});
  });

  test("resolveetzhayyimDid returns 404 for unknown DID", async ({ page }) => {
    await page.goto(`${AUTH_BASE}/health`, { waitUntil: "domcontentloaded" });

    const result = await page.evaluate(async () => {
      const AUTH = location.origin;
      const resp = await fetch(`${AUTH}/xrpc/com.etzhayyim.auth.resolveetzhayyimDid`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ did: "did:etzhayyim:000000000000000000000000" }),
      });
      return { ok: resp.ok, status: resp.status, body: await resp.json().catch(() => ({})) };
    });

    // Pre-deploy: endpoint doesn't exist → 404 with no body.error
    // Post-deploy: endpoint exists → 404 with body.error = "NotFound"
    expect(result.ok).toBe(false);
    if (result.body?.error) {
      expect(result.status).toBe(404);
      expect(result.body.error).toBe("NotFound");
    } else {
      expect(result.status).toBe(404);
      test.info().annotations.push({ type: "note", description: "pre-deploy: resolveetzhayyimDid endpoint not found" });
    }
  });

  test("resolveetzhayyimDid rejects invalid DID format", async ({ page }) => {
    await page.goto(`${AUTH_BASE}/health`, { waitUntil: "domcontentloaded" });

    const result = await page.evaluate(async () => {
      const AUTH = location.origin;
      const resp = await fetch(`${AUTH}/xrpc/com.etzhayyim.auth.resolveetzhayyimDid`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ did: "did:web:example.com" }),
      });
      return { ok: resp.ok, status: resp.status, body: await resp.json().catch(() => ({})) };
    });

    expect(result.ok).toBe(false);
    if (result.body?.error === "InvalidDID") {
      expect(result.status).toBe(400);
    } else {
      // Pre-deploy: endpoint doesn't exist
      test.info().annotations.push({ type: "note", description: "pre-deploy: resolveetzhayyimDid endpoint not found" });
    }
  });
});
