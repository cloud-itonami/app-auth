(ns itonami.auth.viewer-test
  "The parts most likely to be wrong, checked without a browser, an
  authenticator, a Worker, or a network.

  Every case here is a failure that has actually happened to a sign-in page
  somewhere — an open redirect on a `return_to`, a cookie truncated at its own
  padding, a clone baseline that could be lowered. They are cheap to check and
  expensive to discover in production, which is the whole reason the decisions
  live in `.cljc` and the mechanism does not."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [itonami.auth.config :as config]
            [itonami.auth.viewer :as viewer]))

(deftest cookie-token-reads-our-cookie-only
  (testing "picks ours out of a header carrying several"
    (is (= "abc" (viewer/cookie-token (str "other=1; " config/cookie-name "=abc; third=2")))))

  (testing "a value containing '=' survives"
    ;; base64url padding is the obvious case. Splitting on every '=' truncates
    ;; the token to a prefix that never matches a stored digest — a sign-in
    ;; that succeeds and then does not stick.
    (is (= "aGVsbG8=" (viewer/cookie-token (str config/cookie-name "=aGVsbG8=")))))

  (testing "absent, empty and non-string all read as no session"
    (is (nil? (viewer/cookie-token "other=1")))
    (is (nil? (viewer/cookie-token (str config/cookie-name "="))))
    (is (nil? (viewer/cookie-token nil)))))

(deftest set-cookie-carries-every-attribute-that-matters
  (let [c (viewer/set-cookie "tok" 3600)]
    (is (not (.contains c "Domain=")) "__Host- cookies are host-only")
    (is (.contains c "HttpOnly"))
    (is (.contains c "Secure"))
    (is (.contains c "SameSite=Lax"))
    (is (.contains c "Max-Age=3600")))
  (testing "clearing keeps the same host-only Path"
    (let [c (viewer/clear-cookie)]
      (is (not (.contains c "Domain=")))
      (is (.contains c "Max-Age=0")))))

(deftest safe-return-to-contains-the-redirect
  (testing "accepts what we serve"
    (is (= "/kaisya/" (viewer/safe-return-to "/kaisya/")))
    (is (= "https://itonami.cloud/os/" (viewer/safe-return-to "https://itonami.cloud/os/")))
    (is (= "https://app.itonami.cloud/kaisya"
           (viewer/safe-return-to "https://app.itonami.cloud/kaisya"))))

  (testing "refuses everything else, falling back to the mount"
    (is (= "/" (viewer/safe-return-to "https://evil.example/")))
    (is (= "/" (viewer/safe-return-to "https://evil-itonami.cloud/"))
        "a suffix test would admit this one")
    (is (= "/" (viewer/safe-return-to "//evil.example"))
        "protocol-relative resolves to another origin; starts-with \"/\" admits it")
    (is (= "/" (viewer/safe-return-to "http://itonami.cloud/")) "plaintext")
    (is (= "/" (viewer/safe-return-to "javascript:alert(1)")))
    (is (= "/" (viewer/safe-return-to "")))
    (is (= "/" (viewer/safe-return-to nil)))))

(deftest oauth-native-client-is-exactly-contained
  (let [good {"client_id" (:client-id config/oauth-client)
              "redirect_uri" (:redirect-uri config/oauth-client)
              "response_type" "code" "scope" (:scope config/oauth-client)
              "state" (apply str (repeat 32 "s"))
              "code_challenge" (apply str (repeat 43 "a"))
              "code_challenge_method" "S256"}]
    (is (some? (viewer/oauth-request good)))
    ;; The registered address is `localhost`, because the client signs in with
    ;; WebAuthn and an IP literal cannot be a WebAuthn RP ID. Pinned here so
    ;; the reason travels with the value: while this was `127.0.0.1`, every
    ;; real authorization attempt got `invalid_request`, since the app asks to
    ;; come back to the origin it actually serves.
    (is (= "http://localhost:1338/api/auth/itonami/callback"
           (:redirect-uri config/oauth-client)))
    (is (nil? (viewer/oauth-request (assoc good "redirect_uri"
                                           "http://127.0.0.1:1338/api/auth/itonami/callback")))
        "the loopback IP form is not a second registered address")
    (is (nil? (viewer/oauth-request (assoc good "redirect_uri"
                                           "http://127.0.0.1:9999/callback"))))
    (is (nil? (viewer/oauth-request (assoc good "code_challenge_method" "plain"))))
    (is (nil? (viewer/oauth-request (assoc good "state" "short"))))))

(deftest the-registered-callback-is-an-address-the-client-can-actually-serve
  ;; The bug this pins was invisible to every test that existed, in either
  ;; repository, because each one agreed with itself: the smoke test built its
  ;; request from the same config it was checking, and cloud-itonami-app
  ;; asserted its own origin without knowing what was registered here. A
  ;; disagreement between two repositories is not something either one's
  ;; fixtures can see.
  ;;
  ;; So assert the CONSTRAINT rather than the string. The client signs in with
  ;; WebAuthn; a WebAuthn RP ID must be a registrable domain and an IP literal
  ;; is not one; therefore the client cannot serve an IP literal, therefore
  ;; nothing keyed to one can be its callback. Written as a property because
  ;; the next person to reach for `127.0.0.1` here — RFC 8252 §7.3 does
  ;; recommend it for native apps in general — should be stopped by the reason
  ;; and not merely by a diff.
  (let [uri (:redirect-uri config/oauth-client)
        host (second (re-find #"^http://([^:/]+)" uri))]
    (is (not (re-matches #"\d+\.\d+\.\d+\.\d+" host))
        (str "an IP literal cannot be a WebAuthn RP ID, so the client cannot "
             "serve " host " and cannot receive a callback there"))
    (is (= "localhost" host))
    (is (str/starts-with? uri "http://")
        "loopback is the one place plaintext is admissible, and only there")
    (is (str/includes? uri ":1338/")
        "the port the client actually listens on")))

(deftest credential-record-reads-only-what-a-login-needs
  (let [record {"pubKeyB64" "BASE64" "did" "did:key:z6Mk" "counter" 7
                "backupEligible" true "backupState" false
                ;; The sealed custody fields are present in the real record and
                ;; must not come out of this function: a shape this service
                ;; cannot use is a shape it cannot leak.
                "sealedPrivB64" "…" "wrappedDekB64" "…"}
        read (viewer/credential-record record)]
    (is (= {:public-key-b64 "BASE64" :did "did:key:z6Mk" :counter 7
            :backup-eligible? true :backed-up? false}
           read)))

  (testing "a record without a usable public key is not a credential"
    (is (nil? (viewer/credential-record {"did" "did:key:z6Mk"})))
    (is (nil? (viewer/credential-record {"pubKeyB64" ""})))
    (is (nil? (viewer/credential-record nil))))

  (testing "a missing counter is 0, not nil"
    ;; nil would reach the clone comparison as a non-number and refuse a login
    ;; that is fine.
    (is (= 0 (:counter (viewer/credential-record {"pubKeyB64" "B"}))))))

(deftest baseline-seed-may-rise-and-never-fall
  (testing "the higher of the two stores wins"
    (is (= 9 (viewer/baseline-seed 9 5)) "KV ahead of the object")
    (is (= 9 (viewer/baseline-seed 5 9)) "object ahead of KV"))
  (testing "absent values are zero, not nil"
    (is (= 5 (viewer/baseline-seed nil 5)))
    (is (= 5 (viewer/baseline-seed 5 nil)))
    (is (= 0 (viewer/baseline-seed nil nil))))
  (testing "a stale KV record cannot lower an established baseline"
    ;; If it could, replaying an old record would be a way to disarm clone
    ;; detection: drop the baseline to 0 and every spent count is acceptable
    ;; again.
    (is (= 9 (viewer/baseline-seed 0 9)))))

(deftest viewer-payload-separates-account-from-credential
  (let [v (viewer/viewer {:account-did "did:web:kotobase.net:tenant:u"
                          :active-did "did:key:z6Mk"
                          :credential-id "cred"
                          :backup-eligible? true :backed-up? true
                          :expires-at 123})]
    (is (true? (get v "valid")))
    (is (= "did:web:kotobase.net:tenant:u" (get v "accountDid")))
    (is (= "did:key:z6Mk" (get v "activeDid")))
    (is (true? (get v "backedUp")))
    (testing "no assurance field"
      ;; Nothing here has seen an attestation chain. A field named `assurance`
      ;; would be read as though something had.
      (is (not (contains? v "assurance")))))
  (is (= {"valid" false} viewer/anonymous)))

(deftest route-is-mount-relative
  (is (= "/" (config/route "/")))
  (is (= "/" (config/route config/legacy-mount)))
  (is (= "/v1/session" (config/route "/v1/session")))
  (is (= "/v1/session" (config/route "/auth/v1/session")))
  (testing "the custom auth host owns its complete path space"
    (is (= "/kaisya" (config/route "/kaisya")))
    (is (= "/authority" (config/route "/authority")))))

(deftest endpoints-are-built-from-one-mount
  (is (= "/v1/session" (config/endpoint :session)))
  (is (= "/v1/passkey/login/verify" (config/endpoint :login-verify)))
  (testing "every declared path round-trips through route"
    (doseq [[k p] config/paths]
      (is (= p (config/route (config/endpoint k))) (str k)))))

;; ── the key, and the routes that hang off it ────────────────────────────────

(deftest only-the-key-may-rearrange-the-routes
  (let [passkey {"valid" true "acr" config/key-rooted-acr "accountDid" "did:key:z6Mk"}
        by-route {"valid" true "acr" config/single-factor-acr "accountDid" "did:key:z6Mk"}]
    (is (true? (viewer/key-rooted? passkey)))

    (testing "a session a route issued signs in but does not manage"
      ;; The escalation this closes: ten minutes of inbox access is enough to
      ;; attach a second provider, and before the reverse index existed the
      ;; owner could neither see that attachment nor remove it.
      (is (false? (viewer/key-rooted? by-route))))

    (testing "no session, and a session with no acr at all"
      (is (false? (viewer/key-rooted? viewer/anonymous)))
      (is (false? (viewer/key-rooted? {"valid" true})))
      (is (false? (viewer/key-rooted? nil))))

    (testing "valid alone is never enough"
      (is (false? (viewer/key-rooted? {"valid" false "acr" config/key-rooted-acr}))))))

(deftest mask-handle-is-recognisable-but-not-readable
  (is (= "j•••n@gftd.group" (viewer/mask-handle "jun@gftd.group")))
  (is (= "j•••i@example.com" (viewer/mask-handle "junkawasaki@example.com")))

  (testing "the mask is a fixed width, so it does not publish the length"
    (is (= (count (viewer/mask-handle "ab...........yz@e.com"))
           (count (viewer/mask-handle "abyz@e.com")))))

  (testing "the domain survives, because that is what tells two routes apart"
    (is (.endsWith (viewer/mask-handle "a@one.example") "@one.example"))
    (is (not= (viewer/mask-handle "jun@one.example")
              (viewer/mask-handle "jun@two.example"))))

  (testing "a bare handle (GitHub login) has no domain half"
    (is (= "o•••e" (viewer/mask-handle "octocatlike")))
    (is (= "a•" (viewer/mask-handle "ab")))
    (is (= "•" (viewer/mask-handle "a"))))

  (testing "nothing usable is nil, and the caller shows the provider alone"
    (is (nil? (viewer/mask-handle nil)))
    (is (nil? (viewer/mask-handle "")))
    (is (nil? (viewer/mask-handle "   ")))))

(deftest routes-view-is-stable-and-nameable
  (let [rows [{"key" "identity:google:bbb" "provider" "google"
               "label" "j•••n@gftd.group" "linkedAt" 2}
              {"key" "identity:email:aaa" "provider" "email"
               "label" "j•••n@gftd.group" "linkedAt" 1}]
        out (viewer/routes-view rows)]
    (testing "ordered by provider, not by the digest storage happens to return"
      (is (= ["email" "google"] (mapv #(get % "provider") out))))

    (testing "each row carries the name the page shows"
      (is (= ["Email" "Google"] (mapv #(get % "name") out))))

    (testing "an unknown provider is named by its id rather than dropped-through"
      (is (= "gitlab" (-> (viewer/routes-view [{"key" "identity:gitlab:x"
                                                "provider" "gitlab"}])
                          first (get "name")))))

    (testing "a row with no provider is dropped, not shown as an unnameable route"
      ;; The pre-index legacy shape. A detach button beside a route nobody can
      ;; name is worse than showing nothing; the store heals it on the next
      ;; sign-in through that route.
      (is (empty? (viewer/routes-view [{"key" "identity:google:x"}])))
      (is (empty? (viewer/routes-view [{"provider" "google"}])))
      (is (empty? (viewer/routes-view nil))))

    (testing "an absent label is nil, never the empty string"
      (is (nil? (-> (viewer/routes-view [{"key" "k" "provider" "email" "label" ""}])
                    first (get "label")))))))

(deftest methods-view-answers-what-is-attached
  (let [status {"email" true
                "sso" [{"id" "google" "name" "Google" "configured" true}
                       {"id" "apple" "name" "Apple" "configured" false}]}
        routes [{"key" "identity:google:bbb" "provider" "google" "linkedAt" 2}]]

    (testing "a key-rooted session sees what is attached and may change it"
      (let [v (viewer/methods-view {:status status :routes routes :manage? true})]
        (is (true? (get v "canManage")))
        (is (= ["google"] (mapv #(get % "provider") (get v "linked"))))
        (is (true? (-> v (get "sso") first (get "linked"))))
        (is (false? (-> v (get "sso") second (get "linked"))))
        (is (false? (get v "emailLinked")))))

    (testing "a single-factor session sees the same list and cannot change it"
      (let [v (viewer/methods-view {:status status :routes routes :manage? false})]
        (is (false? (get v "canManage")))
        (is (= 1 (count (get v "linked"))))))

    (testing "an anonymous caller gets configuration and an empty list"
      ;; Empty because there is no account to answer about, not because an
      ;; answer is withheld — nothing in this shape depends on a secret.
      (let [v (viewer/methods-view {:status status})]
        (is (false? (get v "canManage")))
        (is (= [] (get v "linked")))
        (is (false? (get v "emailLinked")))
        (is (every? #(false? (get % "linked")) (get v "sso")))))

    (testing "configuration survives untouched"
      (let [v (viewer/methods-view {:status status :routes routes :manage? true})]
        (is (true? (get v "email")))
        (is (true? (-> v (get "sso") first (get "configured"))))))))

(deftest email-is-a-route-like-any-other
  (let [v (viewer/methods-view
           {:status {"email" true "sso" []}
            :routes [{"key" "identity:email:aaa" "provider" "email"
                      "label" "j•••n@gftd.group" "linkedAt" 1}]
            :manage? true})]
    (is (true? (get v "emailLinked")))
    (is (= "Email" (-> v (get "linked") first (get "name"))))))
