(ns itonami.auth.config
  "What this service is, as data — shared by the Worker and by the page script
  compiled from `itonami.auth.app`.

  Both halves are compiled from this one namespace on purpose. The endpoint
  paths and the JSON field names are a contract between a page and a Worker,
  and a contract written down twice is a contract that drifts: the failure is
  silent (a `fetch` to a path nobody serves is a 404 the page reports as
  \"サインインできませんでした\") and it always surfaces in production rather
  than in a test.

  ## The Relying Party ID is `itonami.cloud`, and that is a decision

  Passkeys are scoped by the browser to one registrable domain, and changing
  it orphans every credential already registered under the old value — a
  WebAuthn property, not a config nicety. `network-awai/cloud-itonami` has
  been registering credentials under `itonami.cloud` since 2026-07-30, so
  this service adopts that RP rather than minting its own: an existing
  itonami passkey signs in here on the day this deploys, with no
  re-enrolment.

  That also settles where this service may be served from. WebAuthn lets an
  origin present assertions for any registrable suffix of itself, so
  `https://auth.itonami.cloud` can use RP `itonami.cloud` — which is why the
  dedicated identity origin can reuse the existing credentials.

  ## `allowed-origins` is an explicit set, never a suffix test

  `https://evil-itonami.cloud` ends with the same characters as
  `https://itonami.cloud`; a check written as `endsWith` admits it. Adding a
  door here is a decision someone makes on purpose, in a diff. The same set,
  for the same stated reason, is in `cloud-itonami.edge.webauthn`."
  (:require [clojure.string :as str]))

(def rp-id
  "The WebAuthn Relying Party ID. See the namespace docstring: this is
  inherited from the credentials that already exist, not chosen."
  "itonami.cloud")

(def canonical-origin "https://auth.itonami.cloud")
(def legacy-origin "https://app.itonami.cloud")

(def allowed-origins
  "Origins a verified `clientDataJSON.origin` may carry."
  #{canonical-origin legacy-origin "https://itonami.cloud"})

(def mount "")
(def legacy-mount "/auth")

(def cookie-name "__Host-itonami_session")

(def cookie-domain
  "The registrable parent used only to contain post-login return URLs. The
  session cookie itself is host-only (`__Host-`); the native app crosses the
  origin boundary with Authorization Code + PKCE, never a shared cookie."
  "itonami.cloud")

(def key-rooted-acr
  "The `acr` a passkey assertion issues. Email and SSO issue `single-factor`.

  Named once because three places read it as a decision and not as a label:
  `itonami.auth.passkey/issue-session!` writes it, `itonami.auth.viewer/viewer`
  defaults it, and `itonami.auth.viewer/key-rooted?` is the rule that lets a
  session change what is attached to the key. A literal repeated in three
  files is a rule that can be relaxed in one of them by accident."
  "phishing-resistant")

(def single-factor-acr
  "What an Email or SSO proof issues. It signs in; it does not manage the key."
  "single-factor")

(def provider-labels
  "How each route is named to the person who owns it.

  Here rather than in `itonami.auth.federated` because the page needs the same
  names and `federated` is Worker-only (it carries the client secrets' env
  binding names). The page used to hold its own copy of this list; that is the
  drift this namespace exists to prevent."
  {"apple" "Apple"
   "google" "Google"
   "github" "GitHub"
   "microsoft" "Microsoft"
   "email" "Email"})

(def sso-order
  "The order the upstream providers are offered in. Fixed, so the row does not
  reshuffle between renders — `federated/providers` is a map, and map order is
  not a contract."
  ["apple" "google" "github" "microsoft"])

(def key-managers
  "The credential managers a passkey for this service is expected to live in.

  Named in the UI on purpose. A passkey is only as recoverable as the vault
  holding it, and \"パスキーを作る\" tells someone nothing about where it will
  end up — which is how a device-bound credential gets created by someone who
  believed they were creating a synced one."
  ["1Password" "Bitwarden" "iCloud キーチェーン" "Google パスワードマネージャー"])

(def session-ttl-ms (* 1000 60 60 12))
(def challenge-ttl-ms (* 1000 60 5))
(def authorization-code-ttl-ms (* 1000 60))
(def access-token-ttl-ms (* 1000 60 5))
(def federated-state-ttl-ms (* 1000 60 5))
(def email-token-ttl-ms (* 1000 60 10))

(def oauth-client
  "The one public native client, and the one loopback address it may land on.

  `localhost`, NOT `127.0.0.1`, and the difference is not cosmetic.

  RFC 8252 §7.3 prefers the IP literal for native apps in general, and this
  entry held it for that reason. It cannot here. The client is a desktop app
  whose sign-in is WebAuthn, and a WebAuthn RP ID must be a registrable domain
  — an IP literal is not one and never becomes one. So cloud-itonami-app
  serves `localhost:1338` (`:webauthn-rp-id \"localhost\"`), its window loads
  that origin, and its callback must land there too: the session cookie is set
  by whatever origin the callback hits, and a cookie in the wrong jar is a
  sign-in that succeeds and then cannot be read.

  While this said `127.0.0.1`, the two halves disagreed and /authorize
  answered `invalid_request` for every real attempt — the app asked to come
  back where it lives, and this said no. One address, chosen by the constraint
  that has no alternative.

  Deliberately still a single exact string. Accepting both loopback forms
  would give authorization codes a second place to land for the benefit of an
  origin where the app's own sign-in cannot work anyway."
  {:client-id "cloud-itonami-app-native"
   :redirect-uri "http://localhost:1338/api/auth/itonami/callback"
   :scope "identity:read"})

;; ── what a token may say, and for whom ──────────────────────────────────────

(def scopes-supported
  "Every scope this issuer will put in a token.

  The first is this service's own: `identity:read` is what `/userinfo`
  answers. The rest are read from the resource server that will be handed
  these tokens — `cloud.itonami.app.oauth-resource/scopes` in
  cloud-itonami-app — because a scope string is a contract between an issuer
  and a resource, and inventing a fifth name here would mint tokens no
  resource admits.

  `repository:read` and `repository:write` are listed because the resource
  understands them, NOT because a client may have them: no registered client
  requests them yet. Writing to somebody's repository is the case that needs
  the consent screen this service does not have, and a scope reachable without
  one would be granted by the sign-in a person performed for a different
  reason."
  ["identity:read" "mcp:tools" "tenant:connect"
   "repository:read" "repository:write"])

(def oauth-clients
  "Registered clients, by `client_id`.

  An explicit map and not dynamic registration (RFC 7591). MCP's own guidance
  prefers DCR, and this service will likely need it, but open registration
  decides who may ask a person for authority — that is a decision with an ADR
  attached, not a default acquired by writing an endpoint.

  `:resources` is what a token from this client may be audience-bound to, in
  the RFC 8707 sense. `:loopback?` admits any `http://localhost:<port>` or
  `http://127.0.0.1:<port>` resource, which is what a desktop app's own
  resource server is: cloud-itonami-app serves `/mcp` on the loopback origin
  it was started with, and the port is the operator's choice. That is a
  narrower door than it looks — an audience only means anything to a server
  that already trusts this issuer, and every such server checks that the
  audience is its own URL."
  {"cloud-itonami-app-native"
   {:redirect-uris #{"http://localhost:1338/api/auth/itonami/callback"}
    :scopes #{"identity:read" "mcp:tools" "tenant:connect"}
    :loopback? true
    :resources #{}}})

(def introspection-client-id-env
  "The resource server's own client id, as a Worker secret name.

  Introspection is not a public endpoint and must not become one: an
  unauthenticated `POST /oauth/introspect` is an oracle that tells anybody
  whether a token they hold is live, and for whom. The resource server
  authenticates with HTTP Basic — the same two values cloud-itonami-app reads
  from `CLOUD_ITONAMI_OAUTH_RESOURCE_CLIENT_ID` / `_SECRET`."
  "MCP_RESOURCE_CLIENT_ID")

(def introspection-secret-env "MCP_RESOURCE_CLIENT_SECRET")

(def enrolment-url
  "Where someone without a passkey is sent.

  This service deliberately does NOT enrol. Registration on the itonami plane
  mints a server-custodied Ed25519 key wrapped under a KEK
  (`cloud-itonami.edge.webauthn`), and duplicating that would give the same
  custody two implementations — and would require binding the KEK here, which
  is exactly the secret that lets a compromised service sign as any user.
  With no KEK binding this Worker cannot sign as anyone, by construction and
  not by policy. Enrolment stays where custody already lives."
  "https://itonami.cloud/signin/")

;; ── the wire ────────────────────────────────────────────────────────────────
;;
;; Paths are mount-relative. `endpoint` is the single place either half turns
;; one into a URL.

(def paths
  {:authorize     "/authorize"
   :token         "/oauth/token"
   ;; RFC 7662. Called by a resource server, never by a browser, and never
   ;; without HTTP Basic — see `introspection-client-id-env`.
   :introspect    "/oauth/introspect"
   :userinfo      "/userinfo"
   :metadata      "/.well-known/oauth-authorization-server"
   :login-options "/v1/passkey/login/options"
   :login-verify  "/v1/passkey/login/verify"
   :sso-start     "/v1/sso"
   :sso-callback  "/v1/sso/callback"
   :email-start   "/v1/email/start"
   :email-verify  "/v1/email/verify"
   :methods       "/v1/methods"
   ;; Detaching a route. There is no `/v1/methods/link`: linking is what the
   ;; SSO and Email flows already do when they finish inside a key-rooted
   ;; session, and a second way in would be a second place to get the
   ;; `key-rooted?` check wrong.
   :method-unlink "/v1/methods/unlink"
   :session       "/v1/session"
   ;; No `/v1/credentials` inventory yet. Listing every passkey an account
   ;; holds needs the account record, which lives in the enrolment surface's
   ;; own model — and an inventory that shows one credential because it only
   ;; knows about the one you just used is worse than no inventory, since the
   ;; page it feeds is where someone decides whether they still have a spare.
   :logout        "/v1/logout"
   :logout-all    "/v1/logout/all"
   :health        "/health"})

(defn endpoint [k] (get paths k))

(defn route
  "Full request path -> the canonical path. Also strips the former `/auth`
  compatibility mount. Host-level routing decides whether the request is ours."
  [path]
  (cond
    (or (= path "") (= path "/") (= path legacy-mount)
        (= path (str legacy-mount "/"))) "/"
    (str/starts-with? path (str legacy-mount "/"))
    (subs path (count legacy-mount))
    (str/starts-with? path "/") path
    :else nil))
