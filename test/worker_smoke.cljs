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

(defn- fake-env [& {:keys [credentials] :or {credentials {}}}]
  (let [store ((aget worker "AuthStore") #js {:storage (fake-storage)} #js {})]
    #js {:AUTH_STORE #js {:idFromName (fn [n] n)
                          :get (fn [_] store)}
         :ITONAMI_DATA (fake-kv credentials)}))

(defn- fetch! [env url & [opts]]
  (.fetch (aget worker "default")
          (js/Request. url (clj->js (or opts {}))) env #js {}))

;; ── the harness ─────────────────────────────────────────────────────────────

(def failures (atom 0))

(defn- check [label ok?]
  (if ok?
    (println "  ok  " label)
    (do (swap! failures inc) (println "  FAIL" label))))

(defn- run-case [label f]
  (println label)
  (f))

;; ── cases ───────────────────────────────────────────────────────────────────

(defn- case-page []
  (let [env (fake-env)]
    (-> (fetch! env "https://app.itonami.cloud/auth")
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
                        (str/includes? body "src=\"/auth/app.js\""))
                 (check "all three views are in the one document"
                        (= 3 (count (re-seq #"data-view=" body))))
                 (check "the unreplaced slot is gone"
                        (not (str/includes? body "{{RETURN_TO}}"))))))))

(defn- case-return-to []
  (let [env (fake-env)]
    (-> (fetch! env "https://app.itonami.cloud/auth?return_to=https://evil.example/x")
        (.then (fn [res] (.text res)))
        (.then (fn [body]
                 (check "an off-site return_to never reaches the document"
                        (not (str/includes? body "evil.example")))
                 (check "and is replaced by the mount"
                        (str/includes? body "data-return-to=\"/auth\"")))))))

(defn- case-script []
  (let [env (fake-env)]
    (-> (fetch! env "https://app.itonami.cloud/auth/app.js")
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
    (-> (fetch! env "https://app.itonami.cloud/auth/v1/session")
        (.then (fn [res] (.json res)))
        (.then (fn [body]
                 (check "no cookie reads as no session" (false? (aget body "valid"))))))))

(defn- case-challenge-is-single-use []
  (let [env (fake-env)
        opts #js {:method "POST"}]
    (-> (fetch! env "https://app.itonami.cloud/auth/v1/passkey/login/options" opts)
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
                                 (-> (fetch! env "https://app.itonami.cloud/auth/v1/passkey/login/verify"
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
    (-> (fetch! env "https://app.itonami.cloud/auth/v1/passkey/login/verify"
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
    (-> (fetch! env "https://app.itonami.cloud/auth/v1/logout" {:method "POST"})
        (.then (fn [res]
                 (check "logout without a session still answers 200" (= 200 (.-status res)))
                 (check "and clears the cookie"
                        (str/includes? (or (.get (.-headers res) "set-cookie") "")
                                       "Max-Age=0")))))))

(defn- case-not-found []
  (let [env (fake-env)]
    (-> (fetch! env "https://app.itonami.cloud/authority")
        (.then (fn [res]
                 (check "a path that merely shares a prefix is not ours"
                        (= 404 (.-status res))))))))

(defn- case-health []
  (let [env (fake-env)]
    (-> (fetch! env "https://app.itonami.cloud/auth/health")
        (.then (fn [res] (.json res)))
        (.then (fn [body]
                 (check "health names the RP it is serving"
                        (= "itonami.cloud" (aget body "rpId"))))))))

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
      (.then (fn [_]
               (if (zero? @failures)
                 (println "\nworker smoke: all checks passed")
                 (do (println "\nworker smoke:" @failures "FAILED")
                     (set! (.-exitCode js/process) 1)))))))

(run)
