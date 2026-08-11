(ns itonami.auth.viewer
  "The decisions this service makes, with no mechanism attached: no storage, no
  clock read, no `fetch`, no Durable Object. Everything here is a pure
  function of values the Worker hands it.

  That split is why `clojure -M:test` can check the parts most likely to be
  wrong — cookie attributes, redirect containment, what a credential record
  actually says — without a browser, an authenticator, or a deploy."
  (:require [clojure.string :as str]
            [itonami.auth.config :as config]))

;; ── cookies ─────────────────────────────────────────────────────────────────

(defn set-cookie
  "The `Set-Cookie` value for an issued session.

  `Domain` is the registrable parent (see `config/cookie-domain`) so one
  sign-in covers the app plane and the site. `SameSite=Lax` and not `Strict`:
  Strict withholds the cookie on a top-level navigation that arrives from
  another site, so a person following a link into `app.itonami.cloud/kaisya`
  from their mail would land signed-out and re-authenticate for no security
  gain — the cookie is never sent on cross-site subrequests either way, which
  is the property that matters."
  [token max-age-sec]
  (str config/cookie-name "=" token
       "; Domain=" config/cookie-domain
       "; Path=/; HttpOnly; Secure; SameSite=Lax"
       "; Max-Age=" max-age-sec))

(defn clear-cookie []
  (str config/cookie-name "=; Domain=" config/cookie-domain
       "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"))

(defn cookie-token
  "Read our token out of a raw `Cookie` header.

  Splits on \";\" and then on the FIRST \"=\" only: a cookie value may itself
  contain `=` (base64url padding is the obvious case), and splitting on every
  `=` truncates such a token to a prefix that never matches a stored digest —
  a sign-in that succeeds and then does not stick."
  [cookie-header]
  (when (string? cookie-header)
    (some (fn [pair]
            (let [pair (str/trim pair)
                  i (str/index-of pair "=")]
              (when (and i (= (subs pair 0 i) config/cookie-name))
                (let [v (subs pair (inc i))]
                  (when (seq v) v)))))
          (str/split cookie-header #";"))))

;; ── where a sign-in may send someone next ───────────────────────────────────

(defn safe-return-to
  "Contain `?return_to=`. Returns the mount itself when the request asks for
  anywhere this service is not willing to send a freshly-authenticated
  browser.

  Accepts (a) a same-site absolute URL whose host is `itonami.cloud` or a
  subdomain of it, and (b) a root-relative path. Refuses everything else,
  including protocol-relative `//evil.example` — which `starts-with? \"/\"`
  alone admits, and which a browser resolves as a different origin. An
  open redirect on a sign-in page hands an attacker a link that really does
  authenticate the victim and then delivers them somewhere else."
  [raw]
  (let [fallback config/mount]
    (cond
      (not (string? raw)) fallback
      (str/blank? raw) fallback
      (str/starts-with? raw "//") fallback
      (str/starts-with? raw "/") raw
      :else
      (let [m (re-matches #"https://([A-Za-z0-9.-]+)(/.*)?" raw)
            host (some-> m second str/lower-case)]
        (if (and host (or (= host config/cookie-domain)
                          (str/ends-with? host (str "." config/cookie-domain))))
          raw
          fallback)))))

;; ── what a stored credential says ───────────────────────────────────────────

(defn credential-record
  "Read the JSON record `cloud-itonami.edge.webauthn` writes at
  `webauthn-credential:<id>` into the few fields a login needs.

  Deliberately partial. That record also carries a sealed Ed25519 private key
  and its wrapped DEK; this service has no KEK binding, so those fields are
  unreadable here and are not surfaced — a shape it cannot use is a shape it
  cannot leak.

  `nil` for anything that is not a record with a usable public key, so a
  malformed or half-written entry fails the login rather than reaching the
  verifier as `nil` bytes."
  [m]
  (let [pub (get m "pubKeyB64")]
    (when (and (map? m) (string? pub) (seq pub))
      {:public-key-b64 pub
       :did (get m "did")
       ;; The registration ceremony's own signCount — an authenticator may
       ;; report a nonzero baseline at registration, so this is the floor a
       ;; first login must beat, not a hardcoded 0.
       :counter (let [c (get m "counter")] (if (number? c) c 0))
       :backup-eligible? (boolean (get m "backupEligible"))
       :backed-up? (boolean (get m "backupState"))})))

(defn baseline-seed
  "The clone-detection baseline this login must beat, given the count kept in
  KV by the Pages path and the count kept in the Durable Object by this one.

  Both exist and neither is going away while both sign-in surfaces are live,
  so the baseline is the HIGHER of the two. Taking only the object's value
  would make this plane the weaker door: a credential that reached count 9 at
  `itonami.cloud` could replay count 7 here and be accepted, because the
  object was seeded once at 5 and never told. A baseline may be raised by
  either side and lowered by neither — otherwise replaying an old KV record
  becomes a way to disarm the check."
  [kv-counter object-count]
  (max (or kv-counter 0) (or object-count 0)))

;; ── the payload every consumer reads ────────────────────────────────────────

(defn viewer
  "The signed-in shape. Same field names `kotobase.core/viewer-from-authn-payload`
  already parses, so an app-plane Worker that learned to read a viewer from
  `authn.kotobase.net` reads this one with no changes.

  `accountDid` is the account — one per person, minted by the identity apex —
  and `activeDid` is the credential acting right now. Keeping them separate at
  the wire is what lets a person hold several passkeys without holding several
  accounts.

  The backup pair is reported because it is a fact THIS assertion carried, and
  it is the difference between an account that survives a lost phone and one
  that does not. It is not an assurance level: nothing here has seen an
  attestation chain, and a field named `assurance` would be read as though
  something had."
  [{:keys [account-did active-did credential-id backup-eligible? backed-up? expires-at]}]
  {"valid" true
   "did" (or account-did active-did)
   "accountDid" account-did
   "activeDid" active-did
   "credentialId" credential-id
   "backupEligible" (boolean backup-eligible?)
   "backedUp" (boolean backed-up?)
   "expiresAt" expires-at})

(def anonymous {"valid" false})
