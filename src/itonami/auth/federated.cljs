(ns itonami.auth.federated
  "Email and upstream OAuth proofs for a passkey-rooted itonami identity.

  A verified external subject can sign in only after a live passkey session
  has linked it to an account DID. Email equality is never account equality,
  and an upstream provider can therefore neither create nor merge roots."
  (:require [clojure.string :as str]
            [itonami.auth.config :as config]
            [itonami.auth.passkey :as passkey]
            [itonami.auth.store :as store]
            [itonami.auth.viewer :as viewer]))

(def providers
  {:google {:label "Google"
            :client-id "GOOGLE_CLIENT_ID" :client-secret "GOOGLE_CLIENT_SECRET"
            :authorize "https://accounts.google.com/o/oauth2/v2/auth"
            :token "https://oauth2.googleapis.com/token"
            :profile "https://openidconnect.googleapis.com/v1/userinfo"
            :scope "openid profile email"}
   :github {:label "GitHub"
            :client-id "GITHUB_CLIENT_ID" :client-secret "GITHUB_CLIENT_SECRET"
            :authorize "https://github.com/login/oauth/authorize"
            :token "https://github.com/login/oauth/access_token"
            :profile "https://api.github.com/user"
            :scope "read:user"}
   :microsoft {:label "Microsoft"
               :client-id "MICROSOFT_CLIENT_ID" :client-secret "MICROSOFT_CLIENT_SECRET"
               :authorize "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
               :token "https://login.microsoftonline.com/common/oauth2/v2.0/token"
               :profile "https://graph.microsoft.com/oidc/userinfo"
               :scope "openid profile email"}
   :apple {:label "Apple"
           :client-id "APPLE_CLIENT_ID"
           :authorize "https://appleid.apple.com/auth/authorize"
           :token "https://appleid.apple.com/auth/token"
           :scope "name email"}})

(defn- env-value [env k]
  (let [v (aget env k)] (when (and (string? v) (not (str/blank? v))) v)))

(defn configured? [env provider]
  (when-let [p (get providers provider)]
    (boolean
     (if (= provider :apple)
       (every? #(env-value env %) ["APPLE_CLIENT_ID" "APPLE_TEAM_ID"
                                   "APPLE_KEY_ID" "APPLE_PRIVATE_KEY"])
       (and (env-value env (:client-id p))
            (env-value env (:client-secret p)))))))

(defn method-status [env]
  {"email" (boolean (env-value env "EMAIL_DELIVERY_TOKEN"))
   "sso" (mapv (fn [[id p]]
                  {"id" (name id) "name" (:label p)
                   "configured" (boolean (configured? env id))})
                providers)})

(defn- random-b64url [n]
  (let [bytes (js/crypto.getRandomValues (js/Uint8Array. n))]
    (-> (js/btoa (.apply js/String.fromCharCode nil bytes))
        (.replace (js/RegExp. "\\+" "g") "-")
        (.replace (js/RegExp. "/" "g") "_")
        (.replace (js/RegExp. "=+$" "") ""))))

(defn- b64url [bytes]
  (-> (js/btoa (.apply js/String.fromCharCode nil bytes))
      (.replace (js/RegExp. "\\+" "g") "-")
      (.replace (js/RegExp. "/" "g") "_")
      (.replace (js/RegExp. "=+$" "") "")))

(defn- digest [s encoding]
  (-> (js/crypto.subtle.digest "SHA-256" (.encode (js/TextEncoder.) s))
      (.then (fn [buf]
               (let [bytes (js/Uint8Array. buf)]
                 (if (= encoding :hex)
                   (->> (array-seq bytes)
                        (map (fn [b] (.padStart (.toString b 16) 2 "0")))
                        (apply str))
                   (b64url bytes)))))))

(defn- form-body [m]
  (let [p (js/URLSearchParams.)]
    (doseq [[k v] m :when (some? v)] (.set p (name k) (str v)))
    (.toString p)))

(defn- callback-uri [provider]
  (str config/canonical-origin (config/endpoint :sso-callback) "/" (name provider)))

(defn- transaction-key [state] (str "fstate:" state))

(defn start!
  [env provider return-to session]
  (if-not (configured? env provider)
    (js/Promise.resolve {:status 503 :body {"ok" false "error" "provider_not_configured"}})
    (let [p (get providers provider)
          state (random-b64url 32)
          verifier (random-b64url 48)
          nonce (random-b64url 32)
          challenge* (atom nil)
          return-to (viewer/safe-return-to return-to)]
      (-> (digest verifier :base64url)
          (.then
           (fn [challenge]
             (reset! challenge* challenge)
             (store/call! env "code-put"
                          {:key (transaction-key state)
                           :ttl_ms config/federated-state-ttl-ms
                           :value {:provider (name provider) :verifier verifier
                                   :nonce nonce :return-to return-to
                                   :did (when (get session "valid")
                                          (get session "accountDid"))}})))
          (.then
           (fn [stored]
             (if-not (aget stored "ok")
               {:status 503 :body {"ok" false "error" "temporarily_unavailable"}}
               (let [params (cond-> {:client_id (env-value env (:client-id p))
                                     :redirect_uri (callback-uri provider)
                                     :response_type "code" :scope (:scope p)
                                     :state state :nonce nonce
                                     :code_challenge_method "S256"}
                              (not= provider :apple)
                              (assoc :code_challenge @challenge*)
                              (= provider :apple)
                              (assoc :response_mode "form_post"))]
                 {:status 303 :location (str (:authorize p) "?" (form-body params))}))))))))

(defn- json-fetch! [url options]
  (-> (js/fetch url options)
      (.then (fn [res]
               (if (.-ok res)
                 (.json res)
                 (js/Promise.reject (js/Error. (str "upstream " (.-status res)))))))))

(defn- pem-bytes [pem]
  (let [raw (-> pem
                (str/replace "-----BEGIN PRIVATE KEY-----" "")
                (str/replace "-----END PRIVATE KEY-----" "")
                (str/replace #"\s" ""))
        bin (js/atob raw)]
    (.-buffer (js/Uint8Array.from bin #(.charCodeAt % 0)))))

(defn- json-segment [m]
  (b64url (.encode (js/TextEncoder.) (js/JSON.stringify (clj->js m)))))

(defn- apple-client-secret! [env]
  (let [now (quot (js/Date.now) 1000)
        header (json-segment {:alg "ES256" :kid (env-value env "APPLE_KEY_ID")})
        claims (json-segment {:iss (env-value env "APPLE_TEAM_ID") :iat now
                              :exp (+ now (* 60 60 24 30))
                              :aud "https://appleid.apple.com"
                              :sub (env-value env "APPLE_CLIENT_ID")})
        input (str header "." claims)]
    (-> (js/crypto.subtle.importKey
         "pkcs8" (pem-bytes (env-value env "APPLE_PRIVATE_KEY"))
         #js {:name "ECDSA" :namedCurve "P-256"} false #js ["sign"])
        (.then #(js/crypto.subtle.sign #js {:name "ECDSA" :hash "SHA-256"}
                                          % (.encode (js/TextEncoder.) input)))
        (.then (fn [signature]
                 (str input "." (b64url (js/Uint8Array. signature))))))))

(defn- token! [env provider transaction code]
  (let [p (get providers provider)
        body (fn [secret]
               (form-body {:grant_type "authorization_code" :code code
                           :client_id (env-value env (:client-id p))
                           :client_secret secret
                           :redirect_uri (callback-uri provider)
                           :code_verifier (get transaction "verifier")}))
        secret (if (= provider :apple)
                 (apple-client-secret! env)
                 (js/Promise.resolve (env-value env (:client-secret p))))]
    (-> secret
        (.then (fn [s]
                 (json-fetch! (:token p)
                              #js {:method "POST"
                                   :headers #js {"content-type" "application/x-www-form-urlencoded"
                                                 "accept" "application/json"}
                                   :body (body s)}))))))

(defn- decode-segment [segment]
  (let [s (-> segment (str/replace "-" "+") (str/replace "_" "/"))
        s (str s (case (mod (count s) 4) 2 "==" 3 "=" ""))]
    (js/JSON.parse (.decode (js/TextDecoder.)
                            (js/Uint8Array.from (js/atob s) #(.charCodeAt % 0))))))

(defn- apple-profile! [env transaction id-token]
  (let [[header payload signature] (str/split id-token #"\.")
        h (decode-segment header)
        claims (decode-segment payload)
        input (.encode (js/TextEncoder.) (str header "." payload))
        signature-bytes (let [s (-> signature (str/replace "-" "+") (str/replace "_" "/"))
                              s (str s (case (mod (count s) 4) 2 "==" 3 "=" ""))]
                          (js/Uint8Array.from (js/atob s) #(.charCodeAt % 0)))]
    (-> (json-fetch! "https://appleid.apple.com/auth/keys" #js {})
        (.then
         (fn [jwks]
           (let [kid (aget h "kid")
                 key (some #(when (= kid (aget % "kid")) %) (array-seq (aget jwks "keys")))]
             (if-not key
               (js/Promise.reject (js/Error. "apple key not found"))
               (-> (js/crypto.subtle.importKey "jwk" key
                                               #js {:name "RSASSA-PKCS1-v1_5" :hash "SHA-256"}
                                               false #js ["verify"])
                   (.then #(js/crypto.subtle.verify #js {:name "RSASSA-PKCS1-v1_5"}
                                                       % signature-bytes input)))))))
        (.then
         (fn [valid]
           (let [aud (aget claims "aud")]
             (if-not (and valid (= "https://appleid.apple.com" (aget claims "iss"))
                          (= (env-value env "APPLE_CLIENT_ID") aud)
                          (= (get transaction "nonce") (aget claims "nonce"))
                          (> (aget claims "exp") (quot (js/Date.now) 1000)))
               (js/Promise.reject (js/Error. "invalid apple identity token"))
               claims)))))))

(defn- profile! [env provider transaction token]
  (if (= provider :apple)
    (apple-profile! env transaction (aget token "id_token"))
    (json-fetch! (:profile (get providers provider))
                 #js {:headers #js {"authorization" (str "Bearer " (aget token "access_token"))
                                    "accept" "application/json"
                                    "user-agent" "itonami-app-auth"}})))

(defn- subject [provider profile]
  (some-> (if (= provider :github) (aget profile "id") (aget profile "sub")) str not-empty))

(defn- identity-key! [provider subject]
  (-> (digest (str (name provider) ":" subject) :hex)
      (.then #(str "identity:" (name provider) ":" %))))

(defn- finish-identity! [env provider subject did]
  (-> (identity-key! provider subject)
      (.then #(store/call! env "identity-complete" {:key % :did did}))))

(defn- issued! [env provider did linked? return-to]
  (-> (passkey/issue-session!
       env {:account-did did :active-did did :auth-method (name provider)
            :acr "single-factor" :amr [(name provider)]})
      (.then (fn [{:keys [token]}]
               {:status 303 :location return-to :linked linked?
                :set-cookie (viewer/set-cookie token (quot config/session-ttl-ms 1000))}))))

(defn callback!
  [env provider {:strs [state code error]}]
  (if (or error (str/blank? state) (str/blank? code))
    (js/Promise.resolve {:status 303 :location "/?error=provider_cancelled"})
    (-> (store/call! env "code-consume" {:key (transaction-key state)})
        (.then
         (fn [consumed]
           (if-not (aget consumed "ok")
             (js/Promise.reject (js/Error. "invalid state"))
             (let [transaction (js->clj (aget consumed "value"))]
               (if-not (= (name provider) (get transaction "provider"))
                 (js/Promise.reject (js/Error. "provider mismatch"))
                 (-> (token! env provider transaction code)
                     (.then #(profile! env provider transaction %))
                     (.then
                      (fn [profile]
                        (if-let [sub (subject provider profile)]
                          (finish-identity! env provider sub (get transaction "did"))
                          (js/Promise.reject (js/Error. "missing subject")))))
                     (.then
                      (fn [result]
                        (if-not (aget result "ok")
                          {:status 303 :location "/?error=link_required"}
                          (issued! env provider (aget result "did")
                                   (aget result "linked")
                                   (get transaction "return-to")))))))))))
        (.catch (fn [_] {:status 303 :location "/?error=provider_failed"})))))

(defn- normalize-email [value]
  (let [email (some-> value str str/trim str/lower-case)]
    (when (and email (<= 3 (count email) 254)
               (re-matches #"[^\s@]+@[^\s@]+\.[^\s@]+" email)) email)))

(defn email-start!
  [env email return-to session]
  (let [accepted {:status 202 :body {"ok" true "accepted" true}}
        email (normalize-email email)
        delivery-token (env-value env "EMAIL_DELIVERY_TOKEN")]
    (if-not (and email delivery-token)
      (js/Promise.resolve accepted)
      (-> (identity-key! :email email)
          (.then #(store/call! env "identity-complete"
                              {:key % :did (when (get session "valid")
                                             (get session "accountDid"))}))
          (.then
           (fn [identity]
             (if-not (aget identity "ok")
               accepted
               (let [token (random-b64url 32)]
                 (-> (digest token :hex)
                     (.then #(store/call! env "code-put"
                                         {:key (str "email:" %)
                                          :ttl_ms config/email-token-ttl-ms
                                          :value {:email email
                                                  :return-to (viewer/safe-return-to return-to)
                                                  :did (aget identity "did")}}))
                     (.then
                      (fn [stored]
                        (when (aget stored "ok")
                          (js/fetch
                           "https://itonami.cloud/api/auth/magic-link/deliver"
                           #js {:method "POST"
                                :headers #js {"authorization" (str "Bearer " delivery-token)
                                              "content-type" "application/json"}
                                :body (js/JSON.stringify
                                       #js {:template "cloud-itonami-email-login"
                                            :to email
                                            :magicLink (str config/canonical-origin
                                                            (config/endpoint :email-verify)
                                                            "?token=" (js/encodeURIComponent token))
                                            :expiresAt "10 分"})})))
                     (.then (constantly accepted))))))))
          (.catch (constantly accepted))))))

(defn email-verify! [env token]
  (if (str/blank? token)
    (js/Promise.resolve {:status 303 :location "/?error=email_invalid"})
    (-> (digest token :hex)
        (.then #(store/call! env "code-consume" {:key (str "email:" %)}))
        (.then
         (fn [consumed]
           (if-not (aget consumed "ok")
             {:status 303 :location "/?error=email_invalid"}
             (let [transaction (js->clj (aget consumed "value"))]
               (-> (finish-identity! env :email (get transaction "email")
                                     (get transaction "did"))
                   (.then (fn [identity]
                            (if-not (aget identity "ok")
                              {:status 303 :location "/?error=link_required"}
                              (issued! env :email (aget identity "did")
                                       (aget identity "linked")
                                       (get transaction "return-to")))))))))
        (.catch (fn [_] {:status 303 :location "/?error=email_invalid"}))))))
