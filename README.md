# app-auth

**`auth.itonami.cloud` — passkey sign-in and native-app authorization for the
itonami app plane.** A
Cloudflare Worker written in ClojureScript: the ceremony crypto is
[`kotoba-lang/webauthn`](https://github.com/kotoba-lang/webauthn), the session
vocabulary is [`kotoba-lang/authentication`](https://github.com/kotoba-lang/authentication),
and the page is [`jp-go-dds`](https://github.com/kotoba-lang/jp-go-digital-design-system).

This repository previously held a TypeScript/SvelteKit auth platform extracted
from `etzhayyim/root`. It was routed at `auth.etzhayyim.com` /
`accounts.etzhayyim.com`, which no longer resolve in DNS, and its own
`MIGRATION-TODO.md` still said `🔄 TRANSFORM — codemod pending`. It was
replaced rather than ported: see ADR-2608110100.

## What it is, and what it deliberately is not

| | |
|---|---|
| **Does** | verify a WebAuthn assertion, link a verified Apple/Google/GitHub/Microsoft/Email subject to that passkey DID, issue and revoke an opaque browser session, exchange a one-minute Authorization Code + PKCE for a five-minute native-app token |
| **Does not** | enrol a passkey, mint or hold an itonami signing key, create or merge an identity from email equality |

Enrolment stays at `itonami.cloud/signin/`, which owns custody: registration
there mints a server-custodied Ed25519 key wrapped under a KEK. **This Worker
has no KEK binding, so it cannot sign as any user — by construction, not by
policy.** A second enrolment path would have required that secret here and
given the same custody two implementations.

## Email and SSO are alternate proofs, not new roots

The first sign-in remains a passkey ceremony. While that session is live, a
person may link Apple, Google, GitHub, Microsoft, or Email. A later verified
subject resolves to the same DID and may issue a `single-factor` session. An
unknown subject is sent back with `link_required`; it never creates a DID, and
an already-linked subject cannot be rebound to another DID. These decisions
are atomic in `AuthStore`, so two concurrent callbacks cannot claim one
subject for different accounts.

Every provider uses a five-minute, single-use state and Authorization Code
flow. Google, GitHub, and Microsoft use PKCE S256 in addition to their Worker
secret. Apple uses `form_post`; its client-secret JWT is generated in the
Worker from the scoped P-256 key, and Apple's ID token signature, issuer,
audience, nonce and expiry are verified before its subject is accepted.
Email links are ten-minute, single-use opaque tokens stored only by digest and
sent through the existing authenticated itonami.cloud delivery endpoint.

The callback URIs to register are:

```text
https://auth.itonami.cloud/v1/sso/callback/apple
https://auth.itonami.cloud/v1/sso/callback/google
https://auth.itonami.cloud/v1/sso/callback/github
https://auth.itonami.cloud/v1/sso/callback/microsoft
```

Provider configuration is fail-closed. A button is published only when all of
its exact Worker bindings exist:

```text
GOOGLE_CLIENT_ID       GOOGLE_CLIENT_SECRET
GITHUB_CLIENT_ID       GITHUB_CLIENT_SECRET
MICROSOFT_CLIENT_ID    MICROSOFT_CLIENT_SECRET
APPLE_CLIENT_ID        APPLE_TEAM_ID        APPLE_KEY_ID        APPLE_PRIVATE_KEY
EMAIL_DELIVERY_TOKEN
```

Values are installed with `wrangler secret put <NAME>` and are never committed.

## Why it does not have its own Relying Party

The WebAuthn RP is `itonami.cloud`, inherited — not chosen. Passkeys are scoped
by the browser to one registrable domain and changing it orphans every existing
credential. `cloud-itonami.edge.webauthn` has registered under `itonami.cloud`
since 2026-07-30 and already lists `https://app.itonami.cloud` as an allowed
origin; `auth.itonami.cloud` uses that same RP, so **an existing itonami passkey signs in
here with no re-enrolment.** The KV namespace holding those credentials is bound
by id, not copied, so the two surfaces cannot disagree about who has enrolled.

## Why it is a Worker and not a Pages Function

ADR-2607302145 records three known gaps in the Pages-hosted passkey path and
says all three are `platform の差であって設計判断ではない`:

1. the clone-detection baseline lived in KV, which has no read-your-writes — a
   **measured false negative on 2026-08-03**, where an assertion that should
   have been refused as a clone signal was accepted because the counter written
   moments earlier was not yet visible;
2. no cron rotation sweep (Cron Triggers are a Workers feature);
3. no Durable Object at all (a DO class cannot be deployed from Pages).

A Worker has Durable Objects. `itonami.auth.durable` is where the challenge
consume, the clone comparison, and session revocation each happen as one
indivisible step. `itonami.auth.store/touch-credential!` writes the accepted
count back to the shared KV record so the other surface's baseline does not go
stale while this one is in use.

## Layout

```
src/itonami/auth/config.cljc    what this service is, compiled into BOTH halves
src/itonami/auth/viewer.cljc    the decisions, with no mechanism attached
src/itonami/auth/durable.cljs   AuthStore — everything needing read-your-writes
src/itonami/auth/store.cljs     KV credentials (read-mostly) + the DO client
src/itonami/auth/passkey.cljs   the ceremony, in the order that matters
src/itonami/auth/oauth.cljs     fixed native client, code exchange, userinfo
src/itonami/auth/federated.cljs upstream OAuth, Apple token validation, Email
src/itonami/auth/worker.cljs    routes
browser/itonami/auth/app.cljs   the page's behaviour (compiled, not hand-written JS)
pages/itonami/auth/sign_in_page.cljc   the document (jp-go-dds, build-time only)
```

`config.cljc` is compiled into the Worker *and* the page bundle. Endpoint paths
and JSON field names are a contract between them, and a contract written down
twice drifts — silently, and in production.

## Build and test

```bash
npm install
npm run build      # render the page -> compile the page script -> compile the Worker
clojure -M:test    # the pure decisions, on the JVM
nbb test/worker_smoke.cljs   # the BUILT artifact against an in-memory Cloudflare
npm run deploy
```

The order in `build` is load-bearing: the Worker inlines both the rendered
document and the compiled script with `shadow.resource/inline`, so both must
exist first.

`worker_smoke.cljs` runs `js/auth-worker.js` — the exact file `wrangler deploy`
uploads — and gives it the **real** exported `AuthStore` class over a Map-backed
storage. A fake object would only prove the Worker calls something; this proves
the halves agree, including that a challenge cannot be spent twice.
