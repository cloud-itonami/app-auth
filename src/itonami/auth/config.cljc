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
  `https://app.itonami.cloud` can use RP `itonami.cloud` — which is why the
  app plane is a valid home for a sign-in surface at all.

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

(def allowed-origins
  "Origins a verified `clientDataJSON.origin` may carry."
  #{"https://app.itonami.cloud" "https://itonami.cloud"})

(def mount
  "The path prefix this Worker is routed at. Everything below is expressed
  relative to it so the same bundle is correct if the mount ever moves —
  `route` strips it once, and nothing downstream repeats the string."
  "/auth")

(def cookie-name "itonami_session")

(def cookie-domain
  "The registrable parent, so one sign-in covers `app.itonami.cloud` and
  `itonami.cloud`. A cookie cannot be set for a domain the setting host is not
  under, so this choice IS the integration design: it is what lets
  `app.itonami.cloud/kaisya` read a session this service issued without a
  cross-origin token dance."
  "itonami.cloud")

(def session-ttl-ms (* 1000 60 60 12))
(def challenge-ttl-ms (* 1000 60 5))

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
  {:login-options "/v1/passkey/login/options"
   :login-verify  "/v1/passkey/login/verify"
   :session       "/v1/session"
   ;; No `/v1/credentials` inventory yet. Listing every passkey an account
   ;; holds needs the account record, which lives in the enrolment surface's
   ;; own model — and an inventory that shows one credential because it only
   ;; knows about the one you just used is worse than no inventory, since the
   ;; page it feeds is where someone decides whether they still have a spare.
   :logout        "/v1/logout"
   :logout-all    "/v1/logout/all"
   :health        "/health"})

(defn endpoint [k] (str mount (get paths k)))

(defn route
  "Full request path -> the mount-relative path, or nil when the request is
  not ours. Returns \"/\" for the mount itself with or without its trailing
  slash, so the page has one address and not two."
  [path]
  (cond
    (= path mount) "/"
    (str/starts-with? path (str mount "/")) (let [rest (subs path (count mount))]
                                              (if (= rest "/") "/" rest))
    :else nil))
