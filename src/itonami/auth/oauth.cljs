(ns itonami.auth.oauth
  "Authorization Code + PKCE for the installed Cloud Itonami app. Codes and
  access tokens are opaque; only their SHA-256 digests reach storage."
  (:require [clojure.string :as str]
            [itonami.auth.config :as config]
            [itonami.auth.store :as store]
            [itonami.auth.viewer :as viewer]))

(defn- random-b64url [n]
  (let [bytes (js/crypto.getRandomValues (js/Uint8Array. n))]
    (-> (js/btoa (.apply js/String.fromCharCode nil bytes))
        (.replace (js/RegExp. "\\+" "g") "-")
        (.replace (js/RegExp. "/" "g") "_")
        (.replace (js/RegExp. "=+$" "") ""))))

(defn- digest [s encoding]
  (-> (js/crypto.subtle.digest "SHA-256" (.encode (js/TextEncoder.) s))
      (.then
       (fn [buf]
         (let [bytes (js/Uint8Array. buf)]
           (case encoding
             :hex (->> (array-seq bytes)
                       (map (fn [b] (.padStart (.toString b 16) 2 "0")))
                       (apply str))
             :base64url (-> (js/btoa (.apply js/String.fromCharCode nil bytes))
                            (.replace (js/RegExp. "\\+" "g") "-")
                            (.replace (js/RegExp. "/" "g") "_")
                            (.replace (js/RegExp. "=+$" "") ""))))))))

(defn authorize! [env params session]
  (if-let [request (viewer/oauth-request params)]
    (let [code (random-b64url 32)
          value (merge request
                       {:account-did (get session "accountDid")
                        :active-did (get session "activeDid")
                        :acr (get session "acr")
                        :amr (get session "amr")
                        :authenticated-at (or (get session "authenticatedAt")
                                              (js/Date.now))})]
      (-> (digest code :hex)
          (.then (fn [d]
                   (store/call! env "code-put"
                                {:key (str "code:" d)
                                 :ttl_ms config/authorization-code-ttl-ms
                                 :value value})))
          (.then (fn [stored]
                   (if-not (aget stored "ok")
                     {:status 503 :body {"error" "temporarily_unavailable"}}
                     {:status 303
                      :location (str (:redirect-uri request)
                                     "?code=" (js/encodeURIComponent code)
                                     "&state=" (js/encodeURIComponent (:state request)))})))))
    (js/Promise.resolve {:status 400 :body {"error" "invalid_request"}})))

(defn- issue-token! [env value audience]
  (let [token (random-b64url 32)
        expires-at (+ (js/Date.now) config/access-token-ttl-ms)]
    (-> (digest token :hex)
        (.then
         (fn [token-digest]
           (store/call!
            env "session-put"
            {:key (str "access:" token-digest)
             :ttl_ms config/access-token-ttl-ms
             :value (cond-> {"accountDid" (:account-did value)
                             "activeDid" (:active-did value)
                             "clientId" (:client-id value)
                             "scope" (:scope value)
                             "acr" (:acr value)
                             "amr" (:amr value)
                             "authenticatedAt" (:authenticated-at value)
                             ;; Stored, not derived from the Durable Object's
                             ;; TTL: introspection has to answer `exp`, and a
                             ;; record that only knows it will vanish
                             ;; eventually cannot say when.
                             "expiresAt" expires-at}
                      audience (assoc "aud" audience))})))
        (.then
         (fn [_]
           {:status 200
            :body {"access_token" token
                   "token_type" "Bearer"
                   "expires_in" (quot config/access-token-ttl-ms 1000)
                   "scope" (:scope value)}})))))

(defn- verify-and-issue! [env form verifier value]
  (let [audience (viewer/token-request-resource (:resource value)
                                                (get form "resource"))]
    (-> (digest verifier :base64url)
        (.then
         (fn [actual]
           (cond
             (not= actual (:code-challenge value))
             {:status 400 :body {"error" "invalid_grant"}}

             ;; RFC 8707 §2.2. The client asked to be handed a token for
             ;; somewhere else than it authorized; answering with the
             ;; authorized audience anyway would give it a token it will
             ;; present to a server that rejects it, and no way to see why.
             (= :mismatch audience)
             {:status 400 :body {"error" "invalid_target"}}

             :else (issue-token! env value audience)))))))

(defn exchange! [env form]
  (let [client-id (get form "client_id")
        client (get config/oauth-clients client-id)
        code (get form "code") verifier (get form "code_verifier")]
    (if-not (and (= "authorization_code" (get form "grant_type"))
                 client
                 (contains? (:redirect-uris client) (get form "redirect_uri"))
                 (string? code) (string? verifier)
                 (boolean (re-matches #"[A-Za-z0-9._~-]{43,128}" verifier)))
      (js/Promise.resolve {:status 400 :body {"error" "invalid_request"}})
      (-> (digest code :hex)
          (.then #(store/call! env "code-consume" {:key (str "code:" %)}))
          (.then
           (fn [consumed]
             (if-not (aget consumed "ok")
               {:status 400 :body {"error" "invalid_grant"}}
               (let [value (js->clj (aget consumed "value") :keywordize-keys true)]
                 ;; The code belongs to the client that asked for it. Without
                 ;; this, one registered client could redeem another's code —
                 ;; the redirect check above only proves the caller knows a
                 ;; registered address, and with a second client registered it
                 ;; stops being the same fact.
                 (if-not (= client-id (:client-id value))
                   {:status 400 :body {"error" "invalid_grant"}}
                   (verify-and-issue! env form verifier value))))))))))

(defn userinfo! [env bearer]
  (if-not (and (string? bearer) (str/starts-with? bearer "Bearer "))
    (js/Promise.resolve {:status 401 :body {"error" "invalid_token"}})
    (let [token (subs bearer 7)]
      (-> (digest token :hex)
          (.then (fn [d]
                   (store/call! env "session-get" {:key (str "access:" d)})))
          (.then
           (fn [res]
             (if-not (and (aget res "ok") (aget res "found"))
               {:status 401 :body {"error" "invalid_token"}}
               (let [v (aget res "value")]
                 {:status 200
                  :body {"iss" config/canonical-origin
                         "sub" (aget v "accountDid")
                         "active_did" (aget v "activeDid")
                         "client_id" (aget v "clientId")
                         "scope" (aget v "scope")
                         "acr" (or (aget v "acr") "phishing-resistant")
                         "amr" (js->clj (or (aget v "amr") #js ["webauthn"]))
                         "auth_time" (quot (aget v "authenticatedAt") 1000)}}))))))))

;; ── RFC 7662 introspection ──────────────────────────────────────────────────

(defn- constant-time= [a b]
  (and (string? a) (string? b)
       (= (count a) (count b))
       (zero? (reduce (fn [acc i]
                        (bit-or acc (bit-xor (.charCodeAt a i) (.charCodeAt b i))))
                      0
                      (range (count a))))))

(defn- resource-server?
  "Whether this caller is the registered resource server.

  Both halves of the credential must be configured. A missing secret cannot be
  matched by an absent header — it is refused explicitly, because the shape
  that ends `(= stored supplied)` with both nil is how an unconfigured service
  becomes an open one."
  [env authorization]
  (let [expected-id (aget env config/introspection-client-id-env)
        expected-secret (aget env config/introspection-secret-env)]
    (when (and (string? expected-id) (seq expected-id)
               (string? expected-secret) (seq expected-secret)
               (string? authorization)
               (str/starts-with? authorization "Basic "))
      (let [decoded (try (js/atob (subs authorization 6)) (catch :default _ nil))
            [supplied-id supplied-secret]
            (when decoded
              (let [i (.indexOf decoded ":")]
                (when (pos? i) [(subs decoded 0 i) (subs decoded (inc i))])))]
        (and (constant-time= expected-id supplied-id)
             (constant-time= expected-secret supplied-secret))))))

(defn introspect!
  "Answer RFC 7662 for the resource server, and nobody else.

  Two different refusals, and the difference is the specification's: a caller
  who is not the resource server gets 401 and learns nothing about the token,
  while the resource server asking about a token that is unknown, consumed or
  expired gets 200 `{\"active\": false}` — the answer to its question.

  `aud` is present only for a token that was bound to one. A token issued
  before this service could bind an audience has none, so a resource server
  checking its own URL refuses it. That is the intended direction: the tokens
  that predate audience binding stop working at MCP rather than working
  everywhere."
  [env authorization form]
  (if-not (resource-server? env authorization)
    (js/Promise.resolve
     {:status 401 :body {"error" "invalid_client"}})
    (let [token (get form "token")]
      (if-not (and (string? token) (seq token))
        (js/Promise.resolve {:status 400 :body {"error" "invalid_request"}})
        (-> (digest token :hex)
            (.then (fn [d] (store/call! env "session-get" {:key (str "access:" d)})))
            (.then
             (fn [res]
               (if-not (and (aget res "ok") (aget res "found"))
                 {:status 200 :body {"active" false}}
                 (let [v (aget res "value")
                       expires-at (aget v "expiresAt")
                       expired? (and (number? expires-at)
                                     (<= expires-at (js/Date.now)))]
                   (if expired?
                     {:status 200 :body {"active" false}}
                     {:status 200
                      :body (cond-> {"active" true
                                     "iss" config/canonical-origin
                                     "sub" (aget v "accountDid")
                                     "client_id" (aget v "clientId")
                                     "scope" (aget v "scope")
                                     "token_type" "Bearer"
                                     "acr" (or (aget v "acr") config/key-rooted-acr)}
                              (number? expires-at)
                              (assoc "exp" (quot expires-at 1000))

                              (aget v "authenticatedAt")
                              (assoc "auth_time" (quot (aget v "authenticatedAt") 1000))

                              ;; A single string, not an array. Both are legal
                              ;; and cloud-itonami-app reads either, but one
                              ;; audience written two ways is two things to
                              ;; keep in step across a deployment boundary.
                              (aget v "aud")
                              (assoc "aud" (aget v "aud")))}))))))))))

(def metadata
  {"issuer" config/canonical-origin
   "authorization_endpoint" (str config/canonical-origin (get config/paths :authorize))
   "token_endpoint" (str config/canonical-origin (get config/paths :token))
   "introspection_endpoint" (str config/canonical-origin (get config/paths :introspect))
   "userinfo_endpoint" (str config/canonical-origin (get config/paths :userinfo))
   "response_types_supported" ["code"]
   "grant_types_supported" ["authorization_code"]
   "token_endpoint_auth_methods_supported" ["none"]
   "introspection_endpoint_auth_methods_supported" ["client_secret_basic"]
   "code_challenge_methods_supported" ["S256"]
   "scopes_supported" config/scopes-supported})
