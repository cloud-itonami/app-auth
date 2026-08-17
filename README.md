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
| **Does** | verify a WebAuthn assertion, attach/list/detach a verified Apple/Google/GitHub/Microsoft/Email route on that passkey DID, issue and revoke an opaque browser session, exchange a one-minute Authorization Code + PKCE for a five-minute native-app token, bind that token to one RFC 8707 resource and answer RFC 7662 introspection about it |
| **Does not** | enrol a passkey, mint or hold an itonami signing key, create or merge an identity from email equality, ask a person to consent to a scope (so no client holds one that would need it), refresh a token, or register a client dynamically |

Enrolment stays at `itonami.cloud/signin/`, which owns custody: registration
there mints a server-custodied Ed25519 key wrapped under a KEK. **This Worker
has no KEK binding, so it cannot sign as any user — by construction, not by
policy.** A second enrolment path would have required that secret here and
given the same custody two implementations.

## The key is the root; Email and SSO are routes attached to it

A passkey — held in a credential manager, which is where
`itonami.auth.config/key-managers` names 1Password, Bitwarden, iCloud
キーチェーン and Google パスワードマネージャー on the page itself — is what an
account IS. Email and SSO are **routes**: a way back in when a device is gone,
and a second way to sign in afterwards. Three rules keep that ordering true
rather than merely intended.

**Only the key may re-arrange the routes.** `viewer/key-rooted?` admits a
session only when the passkey itself authenticated it (`acr`
`phishing-resistant`). A `single-factor` session signs in, reaches the app and
holds a native-app token, but cannot attach or detach anything. Without this,
ten minutes of inbox access is enough to attach a provider the owner never
chose — and, before the index below existed, could not see or remove.

**Every route is visible.** The forward record answers `subject -> did`, which
is all a sign-in needs and nothing an owner can act on: there is no way to ask
it what a given key answers to. `AuthStore` therefore writes
`did-identity:<did>:<key>` in the same object turn as the link, for the reason
`session-put` writes its own index inline — a record without its index is a
record the management surface cannot see, and an invisible route is worse than
no route. `GET /v1/methods` returns them for a live session. Routes linked
before the index existed are healed on their next sign-in rather than by a
migration batch, the way `cloud-itonami.account/adopt-legacy-credential` does
it on the enrolment plane.

**Every route can be removed.** `POST /v1/methods/unlink` deletes both halves
atomically, and the stored record's own `did` decides — never the caller's
claim. Missing and not-yours are the same answer, so holding any session
cannot confirm whether a guessed key belongs to somebody. Detaching the *last*
route is allowed: the key is the root and a route is not, and refusing would
say otherwise (`cloud-itonami.account/detach-email` draws the line in the same
place, and refuses only for the last passkey).

An unknown subject is still sent back with `link_required`; it never creates a
DID, and an already-linked subject cannot be rebound to another DID. These
decisions are atomic in `AuthStore`, so two concurrent callbacks cannot claim
one subject for different accounts.

### What this Worker still cannot close

Recovery ends here at a link, not at a new passkey: with no KEK binding this
Worker cannot enrol, so the signed-in view sends someone to
`itonami.cloud/signin/` for a spare key. And SSO subjects are held only here —
the enrolment plane's account record tracks `:account/emails` but has no
equivalent for upstream providers, so its `recovery-posture` does not count
them. Both are noted rather than papered over.

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
- **`sub` is a `did:key`.** cloud-itonami-app looks its local user up by the
  introspected `sub`, and its memberships are keyed by a local user id. Until
  one of the two sides maps the other, an audience-correct, scope-correct
  token is still refused there as an unknown subject. Measured, not assumed.

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
