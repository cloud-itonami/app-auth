(ns worker-smoke
  "Runs the BUILT Worker — `js/auth-worker.js`, the exact artifact `wrangler
  deploy` uploads — against an in-memory Cloudflare.

  The point is that this is not a unit test of the sources. `itonami.auth.viewer`
  is already checked on the JVM; what this checks is everything that only
  exists after a build: that the ESM exports the two names wrangler.jsonc
  names, that `shadow.resource/inline` really baked the rendered page and the
  compiled script into the bundle, that the routes match, and that the request
  path through the real Durable Object class works.

  The AuthStore here is the REAL exported class, given a Map-backed storage.
  A fake object would only prove the Worker calls something; this proves the
  two halves agree — the challenge the Worker issues is the record the object
  stores, and consuming it twice fails the second time.

    npx nbb test/worker_smoke.cljs"
  (:require ["../js/auth-worker.js" :as worker]
            [clojure.string :as str]))

;; ── an in-memory Cloudflare ─────────────────────────────────────────────────

(defn- fake-storage []
  (let [m (js/Map.)]
    #js {:get (fn [k] (js/Promise.resolve (.get m k)))
         :put (fn [k v] (.set m k v) (js/Promise.resolve nil))
         :delete (fn [k] (.delete m k) (js/Promise.resolve nil))
         :list (fn [opts]
                 (let [prefix (aget opts "prefix")
                       out (js/Map.)]
                   (.forEach m (fn [v k] (when (str/starts-with? k prefix) (.set out k v))))
                   (js/Promise.resolve out)))}))

(defn- fake-kv
  "KV pre-loaded with whatever credential records a case needs."
  [records]
  (let [m (js/Map.)]
    (doseq [[k v] records] (.set m k v))
    #js {:get (fn [k] (js/Promise.resolve (or (.get m k) nil)))
         :put (fn [k v] (.set m k v) (js/Promise.resolve nil))}))

(defn- fake-env
  "`:storage` is accepted so a case can seed a record the ops cannot write —
  the pre-index legacy shape is the only current user."
  [& {:keys [credentials bindings storage] :or {credentials {} bindings {}}}]
  (let [storage (or storage (fake-storage))
        store ((aget worker "AuthStore") #js {:storage storage} #js {})]
    (js/Object.assign
     #js {:AUTH_STORE #js {:idFromName (fn [n] n)
                           :get (fn [_] store)}
          :ITONAMI_DATA (fake-kv credentials)}
     (clj->js bindings))))

(defn- fetch! [env url & [opts]]
  ;; Cloudflare accepts either a Response or Promise<Response> from fetch.
  ;; Normalize both so the harness exercises the same contract.
  (js/Promise.resolve
   (.fetch (aget worker "default")
           (js/Request. url (clj->js (or opts {}))) env #js {})))

(defn- digest [s encoding]
  (-> (js/crypto.subtle.digest "SHA-256" (.encode (js/TextEncoder.) s))
      (.then (fn [buf]
               (let [bytes (js/Uint8Array. buf)]
                 (if (= encoding :hex)
                   (->> (array-seq bytes)
                        (map (fn [b] (.padStart (.toString b 16) 2 "0")))
                        (apply str))
                   (-> (js/btoa (.apply js/String.fromCharCode nil bytes))
                       (.replace (js/RegExp. "\\+" "g") "-")
                       (.replace (js/RegExp. "/" "g") "_")
                       (.replace (js/RegExp. "=+$" "") ""))))))))

(defn- store-call! [env body]
  (let [namespace (aget env "AUTH_STORE")
        store (.get namespace (.idFromName namespace "itonami-auth"))]
    (-> (.fetch store
                (js/Request. "https://itonami-auth.internal/store"
                             #js {:method "POST"
                                  :headers #js {"content-type" "application/json"}
                                  :body (js/JSON.stringify (clj->js body))}))
        (.then (fn [res] (.json res))))))

;; ── the harness ─────────────────────────────────────────────────────────────

(def failures (atom 0))

(defn- check [label ok?]
  (if ok?
    (println "  ok  " label)
    (do (swap! failures inc) (println "  FAIL" label))))

(defn- run-case [label f]
  (println label)
  (f))

(defn- then! [promise f]
  ;; Advanced-compiled Promises returned by the Worker can cross nbb's module
  ;; boundary without method metadata. Calling the actual JS function keeps
  ;; the test about the Worker contract rather than nbb's interop cache.
  (.call (aget promise "then") promise f))

;; ── cases ───────────────────────────────────────────────────────────────────

(defn- case-page []
  (let [env (fake-env)]
    (-> (fetch! env "https://auth.itonami.cloud/")
        (.then (fn [res]
                 (check "GET /auth is 200" (= 200 (.-status res)))
                 (check "served as HTML"
                        (str/includes? (.get (.-headers res) "content-type") "text/html"))
                 (check "CSP restricts scripts to same origin"
                        (str/includes? (.get (.-headers res) "content-security-policy")
                                       "script-src 'self'"))
                 (.text res)))
        (.then (fn [body]
                 (check "the rendered page was inlined at build time"
                        (str/includes? body "dads-button"))
                 (check "the script is referenced, not inlined"
                        (str/includes? body "src=\"/app.js\""))
                 (check "all three views are in the one document"
                        (= 3 (count (re-seq #"data-view=" body))))
                 (check "the unreplaced slot is gone"
                        (not (str/includes? body "{{RETURN_TO}}"))))))))

(defn- case-return-to []
  (let [env (fake-env)]
    (-> (fetch! env "https://auth.itonami.cloud/?return_to=https://evil.example/x")
        (.then (fn [res] (.text res)))
        (.then (fn [body]
                 (check "an off-site return_to never reaches the document"
                        (not (str/includes? body "evil.example")))
                 (check "and is replaced by the mount"
                        (str/includes? body "data-return-to=\"/\"")))))))

(defn- case-script []
  (let [env (fake-env)]
    (-> (fetch! env "https://auth.itonami.cloud/app.js")
        (.then (fn [res]
                 (check "GET /auth/app.js is 200" (= 200 (.-status res)))
                 (check "served as JavaScript"
                        (str/includes? (.get (.-headers res) "content-type")
                                       "text/javascript"))
                 (.text res)))
        (.then (fn [body]
                 (check "the compiled browser bundle was inlined, not a stub"
                        (> (count body) 10000))
                 ;; The path constants come from `itonami.auth.config`,
                 ;; compiled into this bundle and into the Worker. The mount is
                 ;; joined at runtime, so what proves the shared contract is
                 ;; the mount-relative half being present verbatim.
                 (check "and it speaks the shared endpoint paths"
                        (str/includes? body "/v1/passkey/login/verify")))))))

(defn- case-anonymous-session []
  (let [env (fake-env)]
    (-> (fetch! env "https://auth.itonami.cloud/v1/session")
        (.then (fn [res] (.json res)))
        (.then (fn [body]
                 (check "no cookie reads as no session" (false? (aget body "valid"))))))))

(defn- case-challenge-is-single-use []
  (let [env (fake-env)
        opts #js {:method "POST"}]
    (-> (fetch! env "https://auth.itonami.cloud/v1/passkey/login/options" opts)
        (.then (fn [res] (.json res)))
        (.then (fn [body]
                 (check "login/options issues a challenge" (aget body "ok"))
                 (check "with the itonami RP" (= "itonami.cloud" (aget body "rpId")))
                 (check "and no allowCredentials list to enumerate"
                        (zero? (.-length (aget body "allowCredentials"))))
                 ;; Spend it twice with a body the verifier will reject anyway.
                 ;; The SECOND attempt must fail on the challenge, before the
                 ;; signature is ever considered — that is what makes a
                 ;; sign-in un-replayable.
                 (let [challenge (aget body "challenge")
                       attempt (fn []
                                 (-> (fetch! env "https://auth.itonami.cloud/v1/passkey/login/verify"
                                             {:method "POST"
                                              :headers {"content-type" "application/json"}
                                              :body (js/JSON.stringify
                                                     #js {:credentialIdB64url "nope"
                                                          :challenge challenge})})
                                     (.then (fn [res] (.then (.json res) #(vector (.-status res) %))))))]
                   (-> (attempt)
                       (.then (fn [[status first-body]]
                                (check "first attempt gets past the challenge and fails on the credential"
                                       (and (= 401 status)
                                            (= "sign-in failed" (aget first-body "error"))))
                                (attempt)))
                       (.then (fn [[status second-body]]
                                (check "the same challenge cannot be spent again"
                                       (and (= 401 status)
                                            (= "challenge expired or already used"
                                               (aget second-body "error")))))))))))))

(defn- case-origin-is-checked []
  (let [env (fake-env)]
    (-> (fetch! env "https://auth.itonami.cloud/v1/passkey/login/verify"
                {:method "POST"
                 :headers {"content-type" "application/json"
                           ;; ends with the same characters as an origin we
                           ;; trust; a suffix test would admit it
                           "origin" "https://evil-itonami.cloud"}
                 :body (js/JSON.stringify #js {:credentialIdB64url "x" :challenge "y"})})
        (.then (fn [res]
                 (check "an origin outside the explicit allowlist is refused"
                        (= 403 (.-status res))))))))

(defn- case-logout-always-clears []
  (let [env (fake-env)]
    (-> (fetch! env "https://auth.itonami.cloud/v1/logout" {:method "POST"})
        (.then (fn [res]
                 (check "logout without a session still answers 200" (= 200 (.-status res)))
                 (check "and clears the cookie"
                        (str/includes? (or (.get (.-headers res) "set-cookie") "")
                                       "Max-Age=0")))))))

(defn- case-not-found []
  (let [env (fake-env)]
    (-> (fetch! env "https://auth.itonami.cloud/authority")
        (.then (fn [res]
                 (check "a path that merely shares a prefix is not ours"
                        (= 404 (.-status res))))))))

(defn- case-health []
  (let [env (fake-env)]
    (-> (fetch! env "https://auth.itonami.cloud/health")
        (.then (fn [res] (.json res)))
        (.then (fn [body]
                 (check "health names the RP it is serving"
                        (= "itonami.cloud" (aget body "rpId"))))))))

(defn- case-federated-methods-and-linking []
  (let [env (fake-env :bindings {"EMAIL_DELIVERY_TOKEN" "delivery"
                                 "GOOGLE_CLIENT_ID" "google-client"
                                 "GOOGLE_CLIENT_SECRET" "google-secret"})
        key "identity:google:subject-digest"]
    (-> (fetch! env "https://auth.itonami.cloud/v1/methods")
        (.then (fn [res] (.json res)))
        (.then
         (fn [body]
           (check "email is advertised only when its delivery secret exists"
                  (true? (aget body "email")))
           (let [providers (array-seq (aget body "sso"))
                 configured (fn [id]
                              (some-> (some #(when (= id (aget % "id")) %) providers)
                                      (aget "configured")))]
             (check "Google is enabled by its exact client bindings" (configured "google"))
             (check "Apple stays disabled without all signing bindings"
                    (false? (configured "apple"))))))
        (.then (fn [_]
                 (store-call! env {:op "identity-complete" :key key})))
        (.then (fn [unlinked]
                 (check "an external subject cannot create a DID"
                        (= "link-required" (aget unlinked "reason")))
                 (store-call! env {:op "identity-complete" :key key
                                   :did "did:key:z6MkRoot"})))
        (.then (fn [linked]
                 (check "a passkey DID can link the subject" (aget linked "linked"))
                 (store-call! env {:op "identity-complete" :key key})))
        (.then (fn [login]
                 (check "the linked subject resolves to the same DID"
                        (= "did:key:z6MkRoot" (aget login "did")))
                 (store-call! env {:op "identity-complete" :key key
                                   :did "did:key:z6MkOther"})))
        (.then (fn [conflict]
                 (check "a subject cannot be rebound to another DID"
                        (= "already-bound" (aget conflict "reason"))))))))

(defn- case-oauth-pkce-is-single-use []
  (let [env (fake-env)
        cookie-token "central-session-token"
        verifier (apply str (repeat 43 "v"))
        state (apply str (repeat 32 "s"))]
    (-> (js/Promise.all #js [(digest cookie-token :hex)
                             (digest verifier :base64url)])
        (.then
         (fn [values]
           (let [session-digest (aget values 0)
                 challenge (aget values 1)]
             (-> (store-call! env {:op "session-put"
                                   :key (str "session:" session-digest)
                                   :ttl_ms 60000 :now_ms (js/Date.now)
                                   :value {"accountDid" "did:web:kotobase.net:person:1"
                                           "activeDid" "did:key:z6Mk1"}})
                 (.then
                  (fn [_]
                    (let [authorize (str "https://auth.itonami.cloud/authorize"
                                         "?client_id=cloud-itonami-app-native"
                                         "&redirect_uri=" (js/encodeURIComponent
                                                            "http://localhost:1338/api/auth/itonami/callback")
                                         "&response_type=code&scope=identity%3Aread"
                                         "&state=" state
                                         "&code_challenge=" challenge
                                         "&code_challenge_method=S256")]
                      (fetch! env authorize
                              {:headers {"cookie" (str "__Host-itonami_session=" cookie-token)}}))))
                 (.then
                  (fn [res]
                    (check "authorize redirects to the exact loopback callback" (= 303 (.-status res)))
                    (let [location (.get (.-headers res) "location")
                          callback (js/URL. location)
                          code (.get (.-searchParams callback) "code")
                          form (str "grant_type=authorization_code"
                                    "&client_id=cloud-itonami-app-native"
                                    "&redirect_uri=" (js/encodeURIComponent
                                                       "http://localhost:1338/api/auth/itonami/callback")
                                    "&code=" (js/encodeURIComponent code)
                                    "&code_verifier=" verifier)
                          exchange (fn []
                                     (let [result (fetch! env "https://auth.itonami.cloud/oauth/token"
                                                          {:method "POST"
                                                           :headers {"content-type" "application/x-www-form-urlencoded"}
                                                           :body form})]
                                       result))]
                      (-> (then! (exchange)
                                 (fn [token-res]
                                   (check "a correct verifier exchanges the code" (= 200 (.-status token-res)))
                                   (.json token-res)))
                          (then! (fn [token-body]
                                   (let [access (aget token-body "access_token")]
                                     (-> (fetch! env "https://auth.itonami.cloud/userinfo"
                                                 {:headers {"authorization" (str "Bearer " access)}})
                                         (.then (fn [userinfo-res]
                                                  (check "access token resolves at userinfo"
                                                         (= 200 (.-status userinfo-res)))))))))
                          (then! (fn [_] (exchange)))
                          (then! (fn [replay]
                                   (check "authorization code replay is refused"
                                          (= 400 (.-status replay))))))))))))))))


(defn- sso-row
  "One provider row out of a /v1/methods body.

  Written as a lookup rather than `(some #(when (= id ...) (aget % \"linked\")))`:
  that form returns nil for a row whose `linked` is false, which is
  indistinguishable from no row at all — so `(false? ...)` reads as a failure
  whether the flag was cleared or the provider vanished from the answer."
  [body id]
  (first (filter #(= id (aget % "id")) (array-seq (aget body "sso")))))

(defn- session-cookie!
  "Put a session straight into the object and hand back its cookie header."
  [env token {:keys [did acr]}]
  (-> (digest token :hex)
      (.then (fn [d]
               (store-call! env {:op "session-put"
                                 :key (str "session:" d)
                                 :ttl_ms 60000 :now_ms (js/Date.now)
                                 :value {"accountDid" did "activeDid" did
                                         "acr" acr "authMethod" "test"}})))
      (.then (fn [_] {"cookie" (str "__Host-itonami_session=" token)}))))

(defn- methods! [env headers]
  (-> (fetch! env "https://auth.itonami.cloud/v1/methods" {:headers headers})
      (.then (fn [res] (.json res)))))

(defn- unlink! [env headers key]
  (-> (fetch! env "https://auth.itonami.cloud/v1/methods/unlink"
              {:method "POST"
               :headers (js/Object.assign #js {"content-type" "application/json"}
                                          (clj->js headers))
               :body (js/JSON.stringify #js {:key key})})
      (.then (fn [res] (.then (.json res) #(vector (.-status res) %))))))

(defn- case-routes-are-manageable []
  ;; The whole point of the reverse index: a route that was attached can be
  ;; SEEN and REMOVED by the person who owns the key. Before it, the store
  ;; only answered `subject -> did`, so a link could be made and then never
  ;; enumerated or undone.
  (let [env (fake-env :bindings {"EMAIL_DELIVERY_TOKEN" "delivery"
                                 "GOOGLE_CLIENT_ID" "id"
                                 "GOOGLE_CLIENT_SECRET" "secret"})
        did "did:key:z6MkRoot"
        key "identity:google:deadbeef"
        state (atom {})]
    (-> (session-cookie! env "passkey-token" {:did did :acr "phishing-resistant"})
        (.then (fn [headers]
                 (swap! state assoc :key-rooted headers)
                 (store-call! env {:op "identity-complete" :key key :did did
                                   :provider "google" :label "j•••n@gftd.group"})))
        (.then (fn [linked]
                 (check "the key attaches the route" (aget linked "linked"))
                 (methods! env (:key-rooted @state))))
        (.then (fn [body]
                 (let [routes (array-seq (aget body "linked"))
                       route (first routes)]
                   (check "the attached route is now visible" (= 1 (count routes)))
                   (check "named for the person who owns it"
                          (= "Google" (aget route "name")))
                   (check "carrying only a masked label"
                          (= "j•••n@gftd.group" (aget route "label")))
                   (check "and the key may manage it" (true? (aget body "canManage")))
                   (check "the provider row says it is linked"
                          (true? (aget (sso-row body "google") "linked")))
                   (swap! state assoc :route-key (aget route "key")))
                 (session-cookie! env "route-token" {:did did :acr "single-factor"})))
        (.then (fn [headers]
                 (swap! state assoc :single-factor headers)
                 (methods! env headers)))
        (.then (fn [body]
                 (check "a session a route issued sees the same list"
                        (= 1 (.-length (aget body "linked"))))
                 (check "but is told it may not change it"
                        (false? (aget body "canManage")))
                 (unlink! env (:single-factor @state) (:route-key @state))))
        (.then (fn [[status body]]
                 (check "and is refused when it tries, with a reason it can act on"
                        (and (= 403 status) (= "passkey_required" (aget body "error"))))
                 (unlink! env (:key-rooted @state) "identity:google:notmine")))
        (.then (fn [[status body]]
                 ;; Missing and not-yours answer identically, so holding any
                 ;; session cannot confirm whether a guessed key is attached
                 ;; to somebody. An Email route's key is a digest of an
                 ;; address the guesser may already know.
                 (check "a key this account does not hold is simply not linked"
                        (and (= 404 status) (= "not_linked" (aget body "error"))))
                 (unlink! env (:key-rooted @state) (:route-key @state))))
        (.then (fn [[status _]]
                 (check "the key detaches its own route" (= 200 status))
                 (methods! env (:key-rooted @state))))
        (.then (fn [body]
                 (check "and the route is gone from the list"
                        (zero? (.-length (aget body "linked"))))
                 (check "and from the provider row"
                        (false? (aget (sso-row body "google") "linked")))
                 (store-call! env {:op "identity-complete" :key (:route-key @state)})))
        (.then (fn [resolved]
                 ;; Detaching removed the forward record too, not only the
                 ;; index entry — otherwise the route would keep signing in
                 ;; while claiming to be detached.
                 (check "a detached route no longer resolves to the account"
                        (= "link-required" (aget resolved "reason"))))))))

(defn- case-legacy-link-heals []
  ;; A route linked before the index existed has no entry, so it would be
  ;; invisible and un-detachable forever. The next sign-in through it writes
  ;; the entry, without a migration batch that must land before the code
  ;; reading the new shape.
  (let [storage (fake-storage)
        env (fake-env :storage storage)
        did "did:key:z6MkLegacy"
        key "identity:github:0ldl1nk"]
    (-> (.put storage key #js {:did did :linked_at 1700000000000})
        (.then (fn [_] (store-call! env {:op "identity-list" :did did})))
        (.then (fn [before]
                 (check "a pre-index route is invisible to start with"
                        (zero? (.-length (aget before "routes"))))
                 ;; A sign-in through it: no did (nothing is being linked),
                 ;; but the caller knows which provider it is.
                 (store-call! env {:op "identity-complete" :key key
                                   :provider "github" :label "o•••t"})))
        (.then (fn [resolved]
                 (check "the sign-in still resolves to the same account"
                        (and (= did (aget resolved "did"))
                             (false? (aget resolved "linked"))))
                 (store-call! env {:op "identity-list" :did did})))
        (.then (fn [after]
                 (let [route (first (array-seq (aget after "routes")))]
                   (check "and it is now visible" (some? route))
                   (check "named by the provider the sign-in knew"
                          (= "github" (aget route "provider")))
                   (check "keeping the moment it was originally attached"
                          (= 1700000000000 (aget route "linkedAt")))))))))

(defn- authorize-url
  [{:keys [scope resource challenge state]}]
  (str "https://auth.itonami.cloud/authorize"
       "?client_id=cloud-itonami-app-native"
       "&redirect_uri=" (js/encodeURIComponent
                         "http://localhost:1338/api/auth/itonami/callback")
       "&response_type=code"
       "&scope=" (js/encodeURIComponent scope)
       (if resource (str "&resource=" (js/encodeURIComponent resource)) "")
       "&state=" state
       "&code_challenge=" challenge
       "&code_challenge_method=S256"))

(defn- introspect!
  "POST /oauth/introspect, with whatever credential the case wants to present."
  [env token authorization]
  (-> (fetch! env "https://auth.itonami.cloud/oauth/introspect"
              {:method "POST"
               :headers (cond-> {"content-type" "application/x-www-form-urlencoded"}
                          authorization (assoc "authorization" authorization))
               :body (str "token=" (js/encodeURIComponent token))})
      (.then (fn [res] (.then (.json res) #(vector (.-status res) %))))))

(defn- case-mcp-token-is-audience-bound-and-introspectable
  "The whole hosted-MCP path, in one case: a person authorizes, a token comes
  back bound to ONE resource, and the resource server — and nobody else — can
  ask what it says.

  The refusals matter as much as the issue. A `mcp:tools` request with no
  `resource` must not produce a token, because a token for every resource is
  what an audience exists to prevent; and introspection with no credential, or
  the wrong one, must not answer even `active: false` truthfully — that answer
  is itself an oracle."
  []
  (let [secret "resource-server-secret"
        env (fake-env :bindings {"MCP_RESOURCE_CLIENT_ID" "itonami-mcp-resource"
                                 "MCP_RESOURCE_CLIENT_SECRET" secret})
        basic (str "Basic " (js/btoa (str "itonami-mcp-resource:" secret)))
        resource "http://localhost:1338/mcp"
        verifier (apply str (repeat 43 "m"))
        state (apply str (repeat 32 "t"))
        seen (atom {})]
    (-> (js/Promise.all #js [(digest "mcp-cookie" :hex) (digest verifier :base64url)])
        (.then
         (fn [values]
           (let [session-digest (aget values 0)]
             (swap! seen assoc :challenge (aget values 1))
             (store-call! env {:op "session-put"
                               :key (str "session:" session-digest)
                               :ttl_ms 60000 :now_ms (js/Date.now)
                               :value {"accountDid" "did:key:z6MkMcp"
                                       "activeDid" "did:key:z6MkMcp"
                                       "acr" "phishing-resistant"
                                       "authenticatedAt" 1700000000000}}))))
        ;; The direction that must NOT work, first — so a later pass cannot be
        ;; read as "audience binding is on" when it is only "nothing is checked".
        (.then (fn [_]
                 (fetch! env (authorize-url {:scope "mcp:tools"
                                             :challenge (:challenge @seen)
                                             :state state})
                         {:headers {"cookie" "__Host-itonami_session=mcp-cookie"}})))
        (.then (fn [res]
                 (check "mcp:tools without a resource is refused"
                        (= 400 (.-status res)))
                 (fetch! env (authorize-url {:scope "identity:read mcp:tools"
                                             :resource resource
                                             :challenge (:challenge @seen)
                                             :state state})
                         {:headers {"cookie" "__Host-itonami_session=mcp-cookie"}})))
        (.then (fn [res]
                 (check "with one it authorizes" (= 303 (.-status res)))
                 (let [callback (js/URL. (.get (.-headers res) "location"))]
                   (fetch! env "https://auth.itonami.cloud/oauth/token"
                           {:method "POST"
                            :headers {"content-type" "application/x-www-form-urlencoded"}
                            :body (str "grant_type=authorization_code"
                                       "&client_id=cloud-itonami-app-native"
                                       "&redirect_uri="
                                       (js/encodeURIComponent
                                        "http://localhost:1338/api/auth/itonami/callback")
                                       "&code=" (js/encodeURIComponent
                                                 (.get (.-searchParams callback) "code"))
                                       "&code_verifier=" verifier)}))))
        (.then (fn [res]
                 (check "the code exchanges" (= 200 (.-status res)))
                 (.json res)))
        (.then (fn [body]
                 (check "and the token carries both scopes"
                        (= "identity:read mcp:tools" (aget body "scope")))
                 (swap! seen assoc :access (aget body "access_token"))
                 (introspect! env (:access @seen) nil)))
        (.then (fn [[status _]]
                 (check "introspection with no credential is 401" (= 401 status))
                 (introspect! env (:access @seen)
                              (str "Basic " (js/btoa "itonami-mcp-resource:wrong")))))
        (.then (fn [[status _]]
                 (check "and with the wrong secret is 401" (= 401 status))
                 (introspect! env (:access @seen) basic)))
        (.then (fn [[status body]]
                 (check "the resource server gets 200" (= 200 status))
                 (check "the token is active" (true? (aget body "active")))
                 (check "bound to the one resource asked for"
                        (= resource (aget body "aud")))
                 (check "carrying the scopes" (= "identity:read mcp:tools"
                                                 (aget body "scope")))
                 (check "the subject cloud-itonami-app will look up"
                        (= "did:key:z6MkMcp" (aget body "sub")))
                 (check "the client, which that app requires"
                        (= "cloud-itonami-app-native" (aget body "client_id")))
                 (check "an expiry, so a stale token is refused before use"
                        (number? (aget body "exp")))
                 (check "and this issuer" (= "https://auth.itonami.cloud" (aget body "iss")))
                 (introspect! env "a-token-nobody-issued" basic)))
        (.then (fn [[status body]]
                 (check "a token this issuer never minted is inactive, not an error"
                        (and (= 200 status) (false? (aget body "active")))))))))

;; ── run ─────────────────────────────────────────────────────────────────────

(defn- run []
  (-> (js/Promise.resolve nil)
      (.then #(run-case "page" case-page))
      (.then #(run-case "return_to containment" case-return-to))
      (.then #(run-case "script" case-script))
      (.then #(run-case "anonymous session" case-anonymous-session))
      (.then #(run-case "challenge single-use" case-challenge-is-single-use))
      (.then #(run-case "origin allowlist" case-origin-is-checked))
      (.then #(run-case "logout" case-logout-always-clears))
      (.then #(run-case "routing" case-not-found))
      (.then #(run-case "health" case-health))
      (.then #(run-case "federated methods and linking" case-federated-methods-and-linking))
      (.then #(run-case "OAuth PKCE" case-oauth-pkce-is-single-use))
      (.then #(run-case "MCP token: audience and introspection"
                        case-mcp-token-is-audience-bound-and-introspectable))
      (.then #(run-case "routes are visible and removable" case-routes-are-manageable))
      (.then #(run-case "a legacy link heals its index" case-legacy-link-heals))
      (.then (fn [_]
               (if (zero? @failures)
                 (println "\nworker smoke: all checks passed")
                 (do (println "\nworker smoke:" @failures "FAILED")
                     (set! (.-exitCode js/process) 1)))))
      ;; A case that THROWS must not look like a case that passed. Without
      ;; this the chain rejects, the summary above never runs, and the script
      ;; exits 0 having printed some oks and no verdict — the failure mode
      ;; this whole file exists to catch, in the file itself. Observed while
      ;; adding the routes cases: breaking the reverse index on purpose
      ;; produced one FAIL line, no summary, and a successful exit.
      (.catch (fn [e]
                (println "\nworker smoke: ABORTED —" (or (aget e "message") e))
                (println "worker smoke: no verdict; treat as failed")
                (set! (.-exitCode js/process) 1)))))

(run)
