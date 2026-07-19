function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function renderAuthPage(mode: "sign-in" | "sign-up", request: Request): string {
  const url = new URL(request.url);
  const isSignUp = mode === "sign-up";
  const title = isSignUp ? "Create Account" : "Sign In";
  const altHref = isSignUp ? "/sign-in" : "/sign-up";
  const altLabel = isSignUp ? "Already have an account? Sign in" : "Don't have an account? Sign up";
  const search = escapeHtml(url.search);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${title} - etzhayyim</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background:
        radial-gradient(circle at top, rgba(88, 204, 2, 0.22), transparent 30%),
        linear-gradient(180deg, #06080b 0%, #10161d 100%);
      color: #ecf5ff;
      font: 16px/1.5 ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .card {
      width: min(420px, calc(100vw - 32px));
      padding: 32px;
      border-radius: 24px;
      background: rgba(9, 12, 16, 0.86);
      border: 1px solid rgba(255,255,255,0.08);
      box-shadow: 0 30px 90px rgba(0,0,0,0.45);
      backdrop-filter: blur(18px);
    }
    h1 { margin: 0 0 8px; font-size: 34px; line-height: 1.05; }
    p { margin: 0 0 20px; color: #9cb0c2; }
    button {
      width: 100%;
      min-height: 52px;
      border: 0;
      border-radius: 14px;
      background: linear-gradient(135deg, #58cc02, #2f8f16);
      color: #041406;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
    }
    button:disabled { opacity: 0.6; cursor: wait; }
    .link { display: block; margin-top: 14px; color: #9fe870; text-decoration: none; text-align: center; }
    .status { min-height: 24px; margin-top: 14px; color: #c7d6e5; font-size: 14px; }
    .status.error { color: #ff9a9a; }
    .status.success { color: #9fe870; }
    code { color: #9fe870; }
    .yoro-bubble { display: none; margin-top: 20px; padding: 0; }
    .yoro-bubble.visible { display: flex; align-items: flex-start; gap: 12px; }
    .yoro-avatar {
      flex-shrink: 0;
      width: 48px; height: 48px;
      border-radius: 50%;
      background: linear-gradient(135deg, #9fe870, #58cc02);
      display: grid; place-items: center;
      font-size: 24px; line-height: 1;
    }
    .yoro-speech {
      position: relative;
      background: rgba(88, 204, 2, 0.12);
      border: 1px solid rgba(88, 204, 2, 0.25);
      border-radius: 16px;
      padding: 14px 18px;
      color: #ecf5ff;
      font-size: 15px;
      line-height: 1.6;
    }
    .yoro-speech::before {
      content: "";
      position: absolute;
      left: -8px; top: 16px;
      border: 6px solid transparent;
      border-right-color: rgba(88, 204, 2, 0.25);
    }
    .yoro-speech .yoro-msg { margin: 0 0 10px; }
    .yoro-speech .yoro-action {
      display: inline-block;
      padding: 8px 20px;
      border-radius: 10px;
      background: linear-gradient(135deg, #58cc02, #2f8f16);
      color: #041406;
      font-weight: 700;
      font-size: 14px;
      text-decoration: none;
      transition: opacity 0.15s;
    }
    .yoro-speech .yoro-action:hover { opacity: 0.85; }
  </style>
</head>
<body>
  <main class="card">
    <h1>${title}</h1>
    <p>${isSignUp ? "Create a passkey-backed account." : "Sign in with a saved passkey."}</p>
    <button id="authBtn">${isSignUp ? "Create Account" : "Sign In with Passkey"}</button>
    <a class="link" id="altLink" href="${altHref}${search}">${altLabel}</a>
    <div class="status" id="status"></div>
    <div class="yoro-bubble" id="yoroBubble">
      <div class="yoro-avatar">Y</div>
      <div class="yoro-speech">
        <p class="yoro-msg" id="yoroMsg"></p>
        <a class="yoro-action" id="yoroAction" href="${altHref}${search}"></a>
      </div>
    </div>
  </main>
  <script>
    const API = location.origin;
    const MODE = ${JSON.stringify(mode)};
    const statusEl = document.getElementById("status");
    const button = document.getElementById("authBtn");

    function b64d(s) {
      s = s.replace(/-/g, "+").replace(/_/g, "/");
      while (s.length % 4) s += "=";
      return Uint8Array.from(atob(s), c => c.charCodeAt(0));
    }

    function b64e(buf) {
      const a = new Uint8Array(buf);
      let binary = "";
      for (const c of a) binary += String.fromCharCode(c);
      return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, "");
    }

    const yoroBubble = document.getElementById("yoroBubble");
    const yoroMsg = document.getElementById("yoroMsg");
    const yoroAction = document.getElementById("yoroAction");

    function setStatus(text, kind) {
      statusEl.textContent = text || "";
      statusEl.className = "status" + (kind ? " " + kind : "");
      if (kind !== "error") yoroBubble.className = "yoro-bubble";
    }

    function showYoroBubble(message, actionText, actionHref) {
      statusEl.textContent = "";
      statusEl.className = "status";
      yoroMsg.textContent = message;
      yoroAction.textContent = actionText;
      if (actionHref) yoroAction.href = actionHref;
      yoroBubble.className = "yoro-bubble visible";
    }

    function oauthParams() {
      const p = new URLSearchParams(location.search);
      const clientId = p.get("client_id") || p.get("clientId");
      const redirectUri = p.get("redirect_uri") || p.get("redirectUri");
      if (!clientId || !redirectUri) return null;
      return {
        clientId,
        redirectUri,
        state: p.get("state") || "",
        'codeChallenge': p.get("code_challenge") || p.get("codeChallenge") || "",
        'codeChallengeMethod': p.get("code_challenge_method") || p.get("codeChallengeMethod") || "S256",
      };
    }

    async function completeAuth(did, handle, tokens) {
      const oauth = oauthParams();
      if (oauth) {
        const issued = await fetch(API + "/oauth/issue-code", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ...oauth, did, handle }),
        }).then(r => r.json());
        if (issued.error) throw new Error(issued.message || issued.error);
        const sep = oauth.redirectUri.includes("?") ? "&" : "?";
        location.href = oauth.redirectUri + sep + "code=" + encodeURIComponent(issued.code) + "&state=" + encodeURIComponent(oauth.state);
        return;
      }

      const session = tokens || await fetch(API + "/xrpc/com.atproto.server.createSession", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ did, handle }),
      }).then(r => r.json());
      const s = {
        accessJwt: session.accessJwt,
        refreshJwt: session.refreshJwt,
        did: session.did || did,
        handle: session.handle || handle,
        expiresAt: Date.now() + 2 * 3600 * 1000 - 60000,
      };
      localStorage.setItem("etzhayyim-auth-session", JSON.stringify(s));
      localStorage.setItem("etzhayyim-auth-did", s.did);
      const target = new URLSearchParams(location.search).get("redirectUrl") || "/";
      const dest = target.startsWith("http") ? target : ("https://yoro.etzhayyim.com" + target);
      location.href = dest + "#auth=" + encodeURIComponent(JSON.stringify(s));
    }

    async function signUp() {
      const begin = await fetch(API + "/xrpc/com.etzhayyim.auth.passkeyBeginRegister", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      }).then(r => r.json());
      if (begin.error) throw new Error(begin.message || begin.error);
      const authSelRaw = begin.authenticatorSelection || begin.authenticator_selection || {};
      const authSel = {
        authenticatorAttachment: authSelRaw.authenticatorAttachment ?? authSelRaw.authenticator_attachment,
        residentKey: authSelRaw.residentKey ?? authSelRaw.resident_key,
        userVerification: authSelRaw.userVerification ?? authSelRaw.user_verification,
      };

      const cred = await navigator.credentials.create({
        publicKey: {
          challenge: b64d(begin.challenge),
          rp: { id: begin.rp.id, name: begin.rp.name },
          user: { id: b64d(begin.user.id), name: begin.user.name, displayName: begin.user.displayName },
          pubKeyCredParams: begin.pubKeyCredParams.map(p => ({ type: p.type, alg: p.alg })),
          timeout: begin.timeout,
          authenticatorSelection: authSel,
          attestation: begin.attestation,
        }
      });
      if (!cred) throw new Error("Passkey creation cancelled");

      const verify = await fetch(API + "/xrpc/com.etzhayyim.auth.passkeyVerifyRegister", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          challenge: begin.challenge,
          'clientDataJson': b64e(cred.response.clientDataJSON),
          'attestationObject': b64e(cred.response.attestationObject),
          'userId': begin.userId || "",
        }),
      }).then(r => r.json());
      if (verify.error) throw new Error(verify.message || verify.error);
      localStorage.setItem("etzhayyim-auth-credential", b64e(cred.rawId));
      await completeAuth(verify.did, verify.handle, { 'accessJwt': verify.accessJwt, 'refreshJwt': verify.refreshJwt, did: verify.did, handle: verify.handle });
    }

    async function signIn() {
      const begin = await fetch(API + "/xrpc/com.etzhayyim.auth.passkeyBeginAuth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      }).then(r => r.json());
      if (begin.error) throw new Error(begin.message || begin.error);
      const basePublicKey = {
        challenge: b64d(begin.challenge),
        rpId: begin.rpId || begin.rp_id,
        timeout: begin.timeout,
        userVerification: begin.userVerification || begin.user_verification || "required",
      };
      const assertion = await navigator.credentials.get({ publicKey: basePublicKey });
      if (!assertion) throw new Error("Passkey cancelled");
      const verified = await fetch(API + "/xrpc/com.etzhayyim.auth.passkeyVerifyAuth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          challenge: begin.challenge,
          'credentialId': b64e(assertion.rawId),
          'clientDataJson': b64e(assertion.response.clientDataJSON),
          'authenticatorData': b64e(assertion.response.authenticatorData),
          signature: b64e(assertion.response.signature),
        }),
      }).then(r => r.json());
      if (verified.error) {
        const err = new Error(verified.message || verified.error);
        err._code = verified.error;
        throw err;
      }
      localStorage.setItem("etzhayyim-auth-credential", b64e(assertion.rawId));
      await completeAuth(verified.did, verified.sessionTokens.handle || verified.did, verified.sessionTokens);
    }

    button.addEventListener("click", async () => {
      button.disabled = true;
      setStatus("Waiting for passkey...");
      try {
        if (!navigator.credentials) throw new Error("Passkey not supported");
        if (MODE === "sign-up") await signUp(); else await signIn();
      } catch (error) {
        const msg = error && error.message ? error.message : "Authentication failed";
        const code = error && error._code ? error._code : "";
        const isNotFound = code === "CredentialNotFound" || /not found|sign up first/i.test(msg);
        const isCancelled = /cancel/i.test(msg);
        const isAuthFailed = code === "AuthenticationFailed" || /authentication failed|verification failed/i.test(msg);
        if (MODE === "sign-in" && isNotFound) {
          showYoroBubble(
            "アカウントが見つからないよ\u2026\u2026 新しく作ってね!",
            "アカウントを作成する",
            document.getElementById("altLink").href
          );
        } else if (MODE === "sign-in" && isAuthFailed) {
          showYoroBubble(
            "認証に失敗しちゃった\u2026\u2026 もう一度試すか、新しいアカウントを作ってね!",
            "新規登録はこちら",
            document.getElementById("altLink").href
          );
        } else if (!isCancelled) {
          setStatus(msg, "error");
        }
        button.disabled = false;
      }
    });
  </script>
</body>
</html>`;
}

export function renderLinkResultPage(ok: boolean, provider: string, message = ""): string {
  const title = ok ? "Account Linked" : "Link Failed";
  const safeMessage = escapeHtml(message || (ok ? `${provider} account linked.` : `${provider} link failed.`));
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${title} - etzhayyim Accounts</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: radial-gradient(circle at top, rgba(34,197,94,0.18), transparent 28%), #091018;
      color: #e6eef8;
      font: 16px/1.5 ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .card {
      width: min(420px, calc(100vw - 32px));
      padding: 28px;
      border-radius: 22px;
      background: rgba(8, 13, 20, 0.92);
      border: 1px solid rgba(255,255,255,0.08);
      box-shadow: 0 24px 80px rgba(0,0,0,0.45);
    }
    h1 { margin: 0 0 10px; font-size: 28px; }
    p { margin: 0 0 18px; color: #b4c1d1; }
    a {
      display: inline-block;
      padding: 11px 18px;
      border-radius: 12px;
      background: linear-gradient(135deg, #22c55e, #16a34a);
      color: #06110a;
      text-decoration: none;
      font-weight: 700;
    }
  </style>
</head>
<body>
  <main class="card">
    <h1>${title}</h1>
    <p>${safeMessage}</p>
    <a href="https://accounts.etzhayyim.com/manage">Back to Accounts</a>
  </main>
</body>
</html>`;
}
