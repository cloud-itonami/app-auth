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

(defn- issue-token! [env value]
  (let [token (random-b64url 32)]
    (-> (digest token :hex)
        (.then
         (fn [token-digest]
           (store/call!
            env "session-put"
            {:key (str "access:" token-digest)
             :ttl_ms config/access-token-ttl-ms
             :value {"accountDid" (:account-did value)
                     "activeDid" (:active-did value)
                     "clientId" (:client-id value)
                     "scope" (:scope value)
                     "acr" (:acr value)
                     "amr" (:amr value)
                     "authenticatedAt" (:authenticated-at value)}})))
        (.then
         (fn [_]
           {:status 200
            :body {"access_token" token
                   "token_type" "Bearer"
                   "expires_in" (quot config/access-token-ttl-ms 1000)
                   "scope" (:scope value)}})))))

(defn- verify-and-issue! [env verifier value]
  (-> (digest verifier :base64url)
      (.then
       (fn [actual]
         (if-not (= actual (:code-challenge value))
           {:status 400 :body {"error" "invalid_grant"}}
           (issue-token! env value))))))

(defn exchange! [env form]
  (let [{expected-client :client-id expected-redirect :redirect-uri} config/oauth-client
        code (get form "code") verifier (get form "code_verifier")]
    (if-not (and (= "authorization_code" (get form "grant_type"))
                 (= expected-client (get form "client_id"))
                 (= expected-redirect (get form "redirect_uri"))
                 (string? code) (string? verifier)
                 (boolean (re-matches #"[A-Za-z0-9._~-]{43,128}" verifier)))
      (js/Promise.resolve {:status 400 :body {"error" "invalid_request"}})
      (-> (digest code :hex)
          (.then #(store/call! env "code-consume" {:key (str "code:" %)}))
          (.then
           (fn [consumed]
             (if-not (aget consumed "ok")
               {:status 400 :body {"error" "invalid_grant"}}
               (verify-and-issue!
                env verifier
                (js->clj (aget consumed "value") :keywordize-keys true)))))))))

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

(def metadata
  {"issuer" config/canonical-origin
   "authorization_endpoint" (str config/canonical-origin (get config/paths :authorize))
   "token_endpoint" (str config/canonical-origin (get config/paths :token))
   "userinfo_endpoint" (str config/canonical-origin (get config/paths :userinfo))
   "response_types_supported" ["code"]
   "grant_types_supported" ["authorization_code"]
   "token_endpoint_auth_methods_supported" ["none"]
   "code_challenge_methods_supported" ["S256"]
   "scopes_supported" [(:scope config/oauth-client)]})
