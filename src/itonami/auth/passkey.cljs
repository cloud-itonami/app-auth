(ns itonami.auth.passkey
  "The login ceremony, orchestrated. The cryptography is
  `webauthn.adapters.edge`; the atomic decisions are `itonami.auth.durable`;
  what is left here is the ORDER, which is where WebAuthn implementations
  usually go wrong.

  Order that is load-bearing:

  1. Consume the challenge FIRST, before touching the credential or the
     signature. A challenge spent on a failed attempt is spent — otherwise an
     attacker gets unlimited signature attempts against one live challenge.
  2. Verify the assertion (origin, rpIdHash, user-verification, signature).
  3. Only then decide the clone baseline, and only inside the object.
  4. Only then issue a session.

  This service performs assertions and never registrations. See
  `itonami.auth.config/enrolment-url` for why that is a boundary and not a
  gap: with no KEK binding this Worker cannot sign as any user, and that
  property is worth more than a second enrolment path.

  ClojureScript only."
  (:require [itonami.auth.config :as config]
            [itonami.auth.store :as store]
            [itonami.auth.viewer :as viewer]
            [webauthn.adapters.edge :as edge]))

(defn- random-b64url [n]
  (let [bytes (js/crypto.getRandomValues (js/Uint8Array. n))]
    (-> (js/btoa (.apply js/String.fromCharCode nil bytes))
        (.replace (js/RegExp. "\\+" "g") "-")
        (.replace (js/RegExp. "/" "g") "_")
        (.replace (js/RegExp. "=+$" "") ""))))

(defn- sha256-hex
  "Hex, not base64: this value becomes a storage key, and hex has no `/` or
  `+` to think about in a key namespace that is split on `:`."
  [s]
  (-> (js/crypto.subtle.digest "SHA-256" (.encode (js/TextEncoder.) s))
      (.then (fn [buf]
               (->> (array-seq (js/Uint8Array. buf))
                    (map (fn [b] (.padStart (.toString b 16) 2 "0")))
                    (apply str))))))

(defn request-origin
  "The origin this ceremony must have been performed at, or nil.

  Taken from the request and then checked against the explicit allowlist —
  never derived from it by suffix. `https://evil-itonami.cloud` ends with the
  same characters as an origin we trust."
  [request]
  (let [header (js-invoke (aget request "headers") "get" "origin")
        origin (or header (str "https://" (aget (js/URL. (aget request "url")) "host")))]
    (when (contains? config/allowed-origins origin) origin)))

;; ── step 1: hand out a challenge ────────────────────────────────────────────

(defn login-options!
  "Issue a single-use challenge and the parameters the browser needs.

  `allowCredentials` is empty on purpose: itonami passkeys are discoverable
  credentials, so the browser offers the ones it holds for this RP and the
  server learns which account is signing in from the assertion rather than
  having to be told beforehand. Sending a list would leak which credential ids
  exist for a guessed account."
  [env]
  (let [challenge (random-b64url 32)]
    (-> (store/call! env "challenge-issue"
                     {:key (str "challenge:" challenge) :ttl_ms config/challenge-ttl-ms})
        (.then (fn [res]
                 (if-not (aget res "ok")
                   {:status 503 :body {"ok" false "error" "challenge store unavailable"}}
                   {:status 200
                    :body {"ok" true
                           "challenge" challenge
                           "rpId" config/rp-id
                           "timeout" config/challenge-ttl-ms
                           "userVerification" "required"
                           "allowCredentials" []}}))))))

;; ── step 2-4: verify and issue ──────────────────────────────────────────────

(defn- issue-session!
  "Mint an opaque token and store only its digest.

  The token is 32 random bytes and carries no claims, so there is nothing in
  it to verify offline and nothing to leak by decoding it. That is what makes
  `/v1/logout/all` possible: revocation is deleting a row, not waiting for an
  expiry a signature already promised."
  [env {:keys [account-did active-did credential-id backup-eligible? backed-up?]}]
  (let [token (random-b64url 32)]
    (-> (sha256-hex token)
        (.then (fn [digest]
                 (store/call! env "session-put"
                              {:key (str "session:" digest)
                               :ttl_ms config/session-ttl-ms
                               :value {"accountDid" account-did
                                       "activeDid" active-did
                                       "credentialId" credential-id
                                       "backupEligible" (boolean backup-eligible?)
                                       "backedUp" (boolean backed-up?)}})))
        (.then (fn [res] {:token token :expires-at (aget res "expires_at")})))))

(defn- decide-clone!
  "Compare and record the signCount in one object turn, seeded by the count
  the other surface keeps in KV."
  [env credential-id {:keys [counter]} sign-count]
  (store/call! env "sign-count"
               {:key (str "signcount:" credential-id)
                :value {"count" sign-count "seed" counter}}))

(defn- refuse
  "Every refusal a browser can trigger is 401 with the same body.
  `unknown credential` and `signature verification failed` are the same answer
  to someone probing which credential ids exist, so they are literally the
  same answer."
  ([] (refuse "sign-in failed"))
  ([error] {:status 401 :body {"ok" false "error" error}}))

(defn- done?
  "A step either produced a finished response (it has `:status`) or a value
  the next step consumes. Written once so the chain below reads as four steps
  rather than four nested `if`s — the shape that made an earlier version of
  this function twelve levels deep and one paren away from wrong."
  [x]
  (and (map? x) (contains? x :status)))

(defn- then-step [p f]
  (.then p (fn [x] (if (done? x) x (f x)))))

(defn login-verify!
  "The whole assertion path. Returns a Promise of `{:status :body :set-cookie}`.

  The order is the security-relevant part; see the namespace docstring."
  [env request body]
  (let [origin (request-origin request)
        credential-id (get body "credentialIdB64url")
        challenge (get body "challenge")]
    (cond
      (nil? origin)
      (js/Promise.resolve {:status 403 :body {"ok" false "error" "origin not allowed"}})

      (not (and (string? credential-id) (string? challenge)))
      (js/Promise.resolve {:status 400 :body {"ok" false "error" "malformed request"}})

      :else
      (let [state (atom {})]
        (-> (store/call! env "challenge-consume" {:key (str "challenge:" challenge)})
            ;; 1. Spend the challenge before anything else looks at the
            ;;    signature. A challenge spent on a failed attempt is spent;
            ;;    otherwise one live challenge buys unlimited attempts.
            (.then (fn [consumed]
                     (if (aget consumed "ok")
                       (store/credential! env credential-id)
                       (refuse "challenge expired or already used"))))
            ;; 2. Verify the assertion: origin, rpIdHash, user verification,
            ;;    signature.
            (then-step
             (fn [record]
               (if-not record
                 (refuse)
                 (do (swap! state assoc :record record)
                     (edge/verify-authentication!
                      {:rp-id config/rp-id
                       :origin origin
                       :user-verification :required}
                      {:client-data-json-b64url (get body "clientDataJsonB64url")
                       :authenticator-data-b64url (get body "authenticatorDataB64url")
                       :signature-b64url (get body "signatureB64url")
                       :challenge challenge
                       :public-key-b64 (:public-key-b64 record)})))))
            ;; 3. Only a verified assertion gets to move the clone baseline,
            ;;    and only inside the object.
            (then-step
             (fn [verified]
               (if-not (:ok verified)
                 (refuse)
                 (do (swap! state assoc :verified verified)
                     (decide-clone! env credential-id (:record @state)
                                    (:sign-count verified))))))
            ;; 4. Only then is there a session.
            (then-step
             (fn [clone]
               (if-not (aget clone "ok")
                 ;; Reported as itself. This is not a wrong password: the
                 ;; person needs to know a second authenticator may be
                 ;; presenting their credential.
                 (refuse "credential-clone-signal")
                 (let [{:keys [record verified]} @state
                       flags {:backup-eligible? (:backup-eligible? verified)
                              :backed-up? (:backed-up? verified)}]
                   (store/touch-credential!
                    env credential-id (assoc flags :sign-count (:sign-count verified)))
                   (-> (issue-session! env (merge flags
                                                  {:account-did (:did record)
                                                   :active-did (:did record)
                                                   :credential-id credential-id}))
                       (.then (fn [{:keys [token expires-at]}]
                                {:status 200
                                 :set-cookie (viewer/set-cookie
                                              token (quot config/session-ttl-ms 1000))
                                 :body (viewer/viewer
                                        (merge flags
                                               {:account-did (:did record)
                                                :active-did (:did record)
                                                :credential-id credential-id
                                                :expires-at expires-at}))})))))))))))) 

;; ── session reads and revocation ────────────────────────────────────────────

(defn resolve-session!
  "Cookie -> viewer payload. Resolves to `viewer/anonymous` for every failure
  mode, so a caller has exactly one shape to handle."
  [env cookie-header]
  (if-let [token (viewer/cookie-token cookie-header)]
    (-> (sha256-hex token)
        (.then (fn [digest] (store/call! env "session-get" {:key (str "session:" digest)})))
        (.then (fn [res]
                 (if-not (and (aget res "ok") (aget res "found"))
                   viewer/anonymous
                   (let [v (aget res "value")]
                     (viewer/viewer {:account-did (aget v "accountDid")
                                     :active-did (aget v "activeDid")
                                     :credential-id (aget v "credentialId")
                                     :backup-eligible? (aget v "backupEligible")
                                     :backed-up? (aget v "backedUp")
                                     :expires-at (aget res "expires_at")})))))
        (.catch (fn [_] viewer/anonymous)))
    (js/Promise.resolve viewer/anonymous)))

(defn logout!
  "Revoke this session. `all?` revokes every session the account holds.

  Always answers 200 with the cookie cleared, including when there was no
  session: a sign-out that reports failure teaches people to click it twice,
  and there is nothing an unauthenticated caller can learn from the
  difference."
  [env cookie-header all?]
  (let [cleared {:status 200 :body {"ok" true} :set-cookie (viewer/clear-cookie)}]
    (if-let [token (viewer/cookie-token cookie-header)]
      (-> (sha256-hex token)
          (.then (fn [digest]
                   (let [key (str "session:" digest)]
                     (if-not all?
                       (store/call! env "session-revoke" {:key key})
                       (-> (store/call! env "session-get" {:key key})
                           (.then (fn [res]
                                    (let [did (some-> (aget res "value") (aget "accountDid"))]
                                      (store/call! env "session-revoke-all" {:did did})))))))))
          (.then (constantly cleared))
          (.catch (constantly cleared)))
      (js/Promise.resolve cleared))))
