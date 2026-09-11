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
| **Does** | verify a WebAuthn assertion, issue and revoke an opaque browser session, exchange a one-minute Authorization Code + PKCE for a five-minute native-app token, bind that token to one RFC 8707 resource and answer RFC 7662 introspection about it |
| **Does not** | offer Email or upstream SSO login, enrol a passkey, mint or hold an itonami signing key, ask a person to consent to a scope (so no client holds one that would need it), refresh a token, or register a client dynamically |

Enrolment stays at `itonami.cloud/signin/`, which owns custody: registration
there mints a server-custodied Ed25519 key wrapped under a KEK. **This Worker
has no KEK binding, so it cannot sign as any user — by construction, not by
policy.** A second enrolment path would have required that secret here and
given the same custody two implementations.

Kotoba identity continuity is a separate entrance, not a second Itonami
enrolment implementation. `POST /v1/kotoba-link/complete` accepts only a
high-entropy controller code created by `auth.kotoba.cloud` for target
`itonami`. This Worker redeems it server-to-server at the fixed controller,
validates the Stable Principal plus account/active DIDs and fixed return URL,
then issues its own host-only `__Host-itonami_session`. The code is single-use;
the browser never receives an identity assertion, cookie, Passkey material or
long-lived bearer token from the controller.

`GET /v1/session` exposes only the public viewer projection to the exact
`https://itonami.cloud` origin with credentialed CORS. The host-only cookie
does not move to the apex; the apex can only render whether its own Itonami
session is connected.

## Passkey is the only login route

This is a permanent security boundary, not a product preference. The normative
decision, forbidden trust roots, no-downgrade rule, and delayed recovery
invariants are recorded in
[`docs/adr/0001-passkey-only-authentication-and-delayed-recovery.md`](docs/adr/0001-passkey-only-authentication-and-delayed-recovery.md).

The page exposes only WebAuthn, and the Worker has no route handlers for the
retired Email, Apple, Google, GitHub, or Microsoft login paths. This is an
enforced server boundary, not only hidden UI: `/v1/email/*`, `/v1/sso/*`, and
the former `/v1/methods*` management surface answer 404 even if old provider
secrets remain installed in the deployment.

Recovery has one separate, deliberately narrow route: ten 160-bit one-time
recovery keys shown only when they are generated. Only SHA-256 digests are
stored. Spending one key creates an opaque continuation and an exact 48-hour
wait; it does not create a session. After the wait the Durable Object locks old
and new sessions and gives `itonami.cloud/signin/` a 15-minute, single-purpose
ticket to enrol a replacement Passkey. Completion preserves the Stable
Principal and account DID, revokes every previous Passkey and session, consumes
the continuation, and invalidates the remaining recovery-key set. A currently
authenticated Passkey owner can cancel a pending request or replace the whole
key set. There is no Email, SMS, help-desk, or SSO override.

The page names 1Password, Bitwarden, iCloud キーチェーン and Google
パスワードマネージャー and sends enrolment to `itonami.cloud/signin/`, because
this Worker has no KEK binding and cannot mint a credential itself. Existing
legacy route records may remain in Durable Object storage until a separate
data-retention migration removes them; they are not readable or usable as
sign-in routes by this Worker.

Four more, on the authorization side, each of which is a decision and not an
oversight-in-progress:

- **No consent screen.** The one registered client is first-party, so the
  sign-in IS the authorization. That holds only while no client can request a
  scope a person would want to refuse separately — which is why
  `repository:write` is held by nobody.
- **No refresh token.** An access token lives five minutes, and the client
  gets another by asking a person again. A long-lived MCP session needs
  refresh with rotation and reuse detection, which is more surface than this
  service has justified so far.
- **No dynamic client registration.** MCP's guidance prefers RFC 7591; open
  registration decides who may ask a person for authority, and that wants an
  ADR rather than an endpoint.
- **`sub` is the Stable Principal.** New Kotoba-linked sessions use a
  `urn:kotoba:principal:*`; legacy Itonami sessions may still use a DID.
  cloud-itonami-app must map that subject to its local membership before an
  audience-correct, scope-correct token can act. Identity continuity does not
  invent membership. Measured, not assumed.

## Tokens a resource server can check

`identity:read` is answered here, by `/userinfo`. Every other scope names work
a **different** server does, and the one that exists is cloud-itonami-app's
hosted MCP (its ADR-0015): an OAuth 2.1 resource server that admits a token
only if the audience is its own `/mcp` URL and the scope is the route's.

So a request for anything beyond `identity:read` must carry an RFC 8707
`resource`, and the token is bound to exactly that one:

```text
GET /authorize?client_id=cloud-itonami-app-native
  &scope=identity%3Aread%20mcp%3Atools
  &resource=http%3A%2F%2Flocalhost%3A1338%2Fmcp
  &response_type=code&redirect_uri=…&state=…&code_challenge=…&code_challenge_method=S256
```

Without the `resource` the request is refused rather than granted broadly —
a token with no audience is a bearer credential good at every server that
trusts this issuer. The token request may repeat the value; a **different**
one answers `invalid_target`.

The resource server resolves that token through RFC 7662:

```text
POST /oauth/introspect        Authorization: Basic <id:secret>
token=<access token>          → {"active":true,"aud":…,"scope":…,"sub":…,
                                 "client_id":…,"exp":…,"iss":…}
```

Two Worker secrets, and introspection is 401 until **both** exist — an
unconfigured credential refuses rather than matching an absent header:

```text
MCP_RESOURCE_CLIENT_ID       MCP_RESOURCE_CLIENT_SECRET
```

The same pair goes to the resource server as
`CLOUD_ITONAMI_OAUTH_RESOURCE_CLIENT_ID` / `_SECRET`, with
`[:mcp :oauth :introspection-endpoint]` pointing at the endpoint above. An
unknown token is `{"active": false}`; an unknown **caller** is 401, because
the first answer is itself an oracle about somebody else's token.

`repository:read` and `repository:write` are advertised in
`scopes_supported` because the resource understands them, and are held by no
client. Writing to somebody's repository is the case that needs a consent
screen this service does not have — a scope reachable without one would be
granted by a sign-in performed for a different reason.

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
kbb -M:test    # the pure decisions, on the JVM
kbb --backend sci test/worker_smoke.cljk   # the BUILT artifact against an in-memory Cloudflare
npm run deploy     # builds, then uploads
```

The order in `build` is load-bearing: the Worker inlines both the rendered
document and the compiled script with `shadow.resource/inline`, so both must
exist first.

**Nothing under `js/` or `resources/itonami/auth/` is committed.** A fresh clone
has no bundle, and that is deliberate. `js/auth-worker.js` used to be tracked,
which meant a bare `wrangler deploy` uploaded the committed bundle and exited 0
whether or not it matched `src/` — a source change nobody rebuilt would simply
not reach production, successfully. Now the entry point is absent until you
build it, so the failure is loud:

```
✘ [ERROR] The entry-point file at "js/auth-worker.js" was not found.
```

and `npm run deploy` builds before it uploads. ADR-2608138000 records the
change; ADR-2608136200 is the survey that found this repo among 612 wrangler
configs.

A clone can build on its own — the `:cljs` and `:render-pages` dependencies are
git coordinates, not `:local/root` siblings, so no superproject checkout is
required. If you add a dependency, give it a git coordinate too, and read the
`:git/sha` from the sibling's upstream default branch rather than from whatever
your local checkout happens to be at.

`worker_smoke.cljs` runs `js/auth-worker.js` — the exact file `wrangler deploy`
uploads — and gives it the **real** exported `AuthStore` class over a Map-backed
storage. A fake object would only prove the Worker calls something; this proves
the halves agree, including that a challenge cannot be spent twice.
