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

  `__Host-` plus no `Domain` contains the browser session to the dedicated
  authentication origin. `SameSite=Lax` and not `Strict`:
  Strict withholds the cookie on a top-level navigation that arrives from
  another site, so a person following a link into `app.itonami.cloud/kaisya`
  from their mail would land signed-out and re-authenticate for no security
  gain — the cookie is never sent on cross-site subrequests either way, which
  is the property that matters."
  [token max-age-sec]
  (str config/cookie-name "=" token
       "; Path=/; HttpOnly; Secure; SameSite=Lax"
       "; Max-Age=" max-age-sec))

(defn clear-cookie []
  (str config/cookie-name
       "=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"))

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
  (let [fallback "/"]
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

(defn oauth-request
  "Validate the one public native client and its exact loopback redirect."
  [params]
  (let [{expected-client :client-id expected-redirect :redirect-uri
         expected-scope :scope} config/oauth-client
        client-id (get params "client_id")
        redirect-uri (get params "redirect_uri")
        response-type (get params "response_type")
        scope (get params "scope")
        state (get params "state")
        challenge (get params "code_challenge")
        method (get params "code_challenge_method")]
    (when (and (= expected-client client-id)
               (= expected-redirect redirect-uri)
               (= "code" response-type)
               (= expected-scope scope)
               (= "S256" method)
               (string? state) (<= 32 (count state) 512)
               (string? challenge)
               (boolean (re-matches #"[A-Za-z0-9_-]{43,128}" challenge)))
      {:client-id client-id :redirect-uri redirect-uri :scope scope
       :state state :code-challenge challenge})))

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
  [{:keys [account-did active-did credential-id backup-eligible? backed-up?
           auth-method acr amr authenticated-at expires-at]}]
  {"valid" true
   "did" (or account-did active-did)
   "accountDid" account-did
   "activeDid" active-did
   "credentialId" credential-id
   "backupEligible" (boolean backup-eligible?)
   "backedUp" (boolean backed-up?)
   "authMethod" (or auth-method "webauthn")
   "acr" (or acr config/key-rooted-acr)
   "amr" (or amr ["webauthn"])
   "authenticatedAt" authenticated-at
   "expiresAt" expires-at})

(def anonymous {"valid" false})

;; ── the key, and the routes that hang off it ────────────────────────────────
;;
;; A passkey — held in a credential manager (`config/key-managers`) — is the
;; root. Email and SSO are ROUTES attached to that root: alternate ways to
;; prove the same DID, and the way back in when a device is gone. The rules
;; below are what keep that ordering true rather than merely intended.

(defn key-rooted?
  "May this session change what is attached to the key?

  Only a session the passkey itself authenticated. A route may not re-arrange
  the routes: Email and SSO were linked to be sign-in proofs, and letting one
  of them attach another turns ten minutes of inbox access into an attachment
  the owner never made and — before this function existed — could not see or
  remove. The escalation is quiet, which is what makes it worth a rule.

  A single-factor session still signs in, still reaches the app, still holds a
  native-app token. It just cannot decide what the key answers to."
  [session]
  (boolean (and (get session "valid")
                (= config/key-rooted-acr (get session "acr")))))

(defn- mask-part
  "Keep the first and last character, and always exactly three dots between
  them. Fixed-width on purpose: a mask that grows with the input publishes the
  length of what it is hiding."
  [s]
  (case (count s)
    0 ""
    1 "•"
    2 (str (subs s 0 1) "•")
    (str (subs s 0 1) "•••" (subs s (dec (count s))))))

(defn mask-handle
  "A route label the owner recognises and a passer-by cannot read.

  `jun@gftd.group` -> `j•••n@gftd.group`. The domain survives because that is
  the half that distinguishes two routes of the same provider from each other,
  and it is not the half that is worth reading over a shoulder.

  Returns nil for nothing usable, and the caller shows the provider name
  alone — a label is a convenience, never the identity of the route."
  [raw]
  (let [s (some-> raw str str/trim)]
    (when (seq s)
      (let [at (str/last-index-of s "@")]
        (if (and at (pos? at) (< (inc at) (count s)))
          (str (mask-part (subs s 0 at)) (subs s at))
          (mask-part s))))))

(defn routes-view
  "The rows the store returned for one account, as the page shows them.

  Sorted by provider and then label, so the list does not reorder itself
  between two reads: storage returns keys in lexical order and those keys are
  digests, which is stable but arbitrary — and it changes position the moment
  a route is added. A recovery list that reshuffles is one people stop
  reading.

  A row missing its provider is dropped rather than shown as a route nobody
  can name. That is the pre-index legacy shape (see
  `itonami.auth.durable/op-identity-complete`, which heals it on the next
  sign-in through that route), and showing an unnameable entry with a detach
  button next to it is worse than showing nothing."
  [rows]
  (->> rows
       (keep (fn [row]
               (let [key (get row "key")
                     provider (get row "provider")]
                 (when (and (string? key) (seq key)
                            (string? provider) (seq provider))
                   {"key" key
                    "provider" provider
                    "name" (get config/provider-labels provider provider)
                    "label" (let [l (get row "label")] (when (string? l) (not-empty l)))
                    "linkedAt" (get row "linkedAt")}))))
       (sort-by (juxt #(get % "provider") #(or (get % "label") "")))
       vec))

(defn methods-view
  "What `/v1/methods` answers: what this deployment can offer, what is already
  attached to this key, and whether this session may change that.

  `linked` is `[]` for an anonymous caller because there is no account to
  answer about — not because an answer is being withheld. Nothing in this
  shape depends on a secret, so there is nothing to leak by returning it.

  `canManage` is reported rather than left to the page to infer from `acr`.
  A page that infers it will one day infer it differently from the Worker
  that enforces it, and the visible half is the one that would be wrong."
  [{:keys [status routes manage?]}]
  (let [linked (routes-view routes)
        attached (set (map #(get % "provider") linked))]
    (assoc status
           "sso" (mapv #(assoc % "linked" (contains? attached (get % "id")))
                       (get status "sso"))
           "emailLinked" (contains? attached "email")
           "linked" linked
           "canManage" (boolean manage?))))
