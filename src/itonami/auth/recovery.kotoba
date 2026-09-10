(ns itonami.auth.recovery
  "One-time recovery keys and the 48-hour recovery ceremony.

  Plain recovery keys are returned once and never stored. AuthStore receives
  only SHA-256 digests and serializes consumption. Finishing the delay issues
  a 15-minute ticket for the existing KEK-owning enrolment surface; it never
  creates a normal session and never gives this Worker custody of signing
  keys."
  (:require [kotoba.lang.text :as str]
            [itonami.auth.config :as config]
            [itonami.auth.store :as store]
            [itonami.auth.viewer :as viewer]))

(def recovery-delay-ms (* 48 60 60 1000))
(def recovery-request-ttl-ms (* 7 24 60 60 1000))
(def recovery-enrollment-ttl-ms (* 15 60 1000))
(def recovery-key-count 10)
(def recent-auth-window-ms (* 10 60 1000))

(defn- random-hex [n]
  (->> (array-seq (js/crypto.getRandomValues (js/Uint8Array. n)))
       (map (fn [b] (.padStart (.toString b 16) 2 "0")))
       (apply str)
       str/upper))

(defn- format-key [hex]
  (str "ITONAMI-" (str/join "-" (map #(apply str %) (partition 4 hex)))))

(defn- new-recovery-key [] (format-key (random-hex 20)))

(defn normalize-key [s]
  (when (string? s)
    (let [compact (-> s str/upper (str/replace #"[\s-]" ""))]
      (when (re-matches #"ITONAMI[0-9A-F]{40}" compact) compact))))

(defn sha256-hex [s]
  (-> (js/crypto.subtle.digest "SHA-256" (.encode (js/TextEncoder.) s))
      (.then (fn [buf]
               (->> (array-seq (js/Uint8Array. buf))
                    (map (fn [b] (.padStart (.toString b 16) 2 "0")))
                    (apply str))))))

(defn- continuation-token []
  (-> (js/btoa (.apply js/String.fromCharCode nil
                       (js/crypto.getRandomValues (js/Uint8Array. 32))))
      (str/replace "+" "-")
      (str/replace "/" "_")
      (str/replace #"=+$" "")))

(defn- recent-session? [session now]
  (let [at (get session "authenticatedAt")]
    (and (get session "valid")
         (= "webauthn" (get session "authMethod"))
         (number? at)
         (<= 0 (- now at) recent-auth-window-ms))))

(defn replace-keys!
  [env session]
  (let [now (js/Date.now)]
    (if-not (recent-session? session now)
      (js/Promise.resolve
       {:status 401 :body {"ok" false "error" "reauthentication-required"}})
      (let [keys (vec (repeatedly recovery-key-count new-recovery-key))]
        (-> (store/principal! env (get session "activeDid"))
            (.then
             (fn [{:keys [principal-id account-did tenant address]}]
               (if-not (and (= principal-id (get session "principalId")) tenant address)
                 {:status 409 :body {"ok" false "error" "account-location-unavailable"}}
                 (-> (js/Promise.all (clj->js (map #(sha256-hex (normalize-key %)) keys)))
                     (.then
                      (fn [digests]
                        (-> (store/call! env "recovery-keys-replace"
                                         {:principal_id principal-id
                                          :account_did account-did
                                          :tenant tenant
                                          :address address
                                          :generation (str (js/crypto.randomUUID))
                                          :key_digests (vec (array-seq digests))})
                            (.then
                             (fn [result]
                               (if-not (aget result "ok")
                                 {:status 503 :body {"ok" false "error" "recovery-store-unavailable"}}
                                 {:status 201
                                  :body {"ok" true
                                         "keys" keys
                                         "issuedAt" (aget result "issued_at")
                                         "oneTime" true}})))))))))))))))

(defn start!
  [env body]
  (if-let [normalized (normalize-key (get body "recoveryKey"))]
    (let [continuation (continuation-token)]
      (-> (js/Promise.all #js [(sha256-hex normalized) (sha256-hex continuation)])
          (.then
           (fn [digests]
             (-> (store/call! env "recovery-start"
                              {:key_digest (aget digests 0)
                               :continuation_digest (aget digests 1)
                               :delay_ms recovery-delay-ms
                               :request_ttl_ms recovery-request-ttl-ms})
                 (.then
                  (fn [result]
                    (if-not (aget result "ok")
                      {:status 401 :body {"ok" false "error" "invalid-recovery-key"}}
                      {:status 202
                       :body {"ok" true
                              "recoveryToken" continuation
                              "availableAt" (aget result "available_at")
                              "expiresAt" (aget result "expires_at")}}))))))))
    (js/Promise.resolve
     {:status 401 :body {"ok" false "error" "invalid-recovery-key"}})))

(defn- with-request-digest [body f]
  (let [token (get body "recoveryToken")]
    (if-not (and (string? token) (<= 32 (count token) 128))
      (js/Promise.resolve
       {:status 401 :body {"ok" false "error" "invalid-recovery-request"}})
      (-> (sha256-hex token) (.then #(f token %))))))

(defn status!
  [env body]
  (with-request-digest
    body
    (fn [_ digest]
      (-> (store/call! env "recovery-status" {:continuation_digest digest})
          (.then
           (fn [result]
             (if-not (aget result "ok")
               {:status 401 :body {"ok" false "error" "invalid-recovery-request"}}
               {:status 200
                :body {"ok" true
                       "state" (aget result "state")
                       "startedAt" (aget result "started_at")
                       "availableAt" (aget result "available_at")
                       "expiresAt" (aget result "expires_at")}})))))))

(defn begin-enrolment!
  [env body]
  (with-request-digest
    body
    (fn [_ digest]
      (-> (store/call! env "recovery-begin-enrolment"
                       {:continuation_digest digest})
          (.then
           (fn [result]
             (cond
               (= "recovery-delay-active" (aget result "reason"))
               {:status 425
                :body {"ok" false "error" "recovery-delay-active"
                       "availableAt" (aget result "available_at")}}

               (not (aget result "ok"))
               {:status 401 :body {"ok" false "error" "invalid-recovery-request"}}

               :else
               (let [enrollment-token (continuation-token)
                     exp (+ (js/Date.now) recovery-enrollment-ttl-ms)
                     claim {:tenant (aget result "tenant")
                            :address (aget result "address")
                            :principal-id (aget result "principal_id")
                            :account-did (aget result "account_did")
                            :request-digest digest
                            :exp exp}]
                 (-> (store/issue-recovery-enrollment! env enrollment-token claim)
                     (.then
                      (fn [_]
                        {:status 200
                         :set-cookie (viewer/clear-cookie)
                         :body {"ok" true
                                "enrollmentToken" enrollment-token
                                "tenant" (:tenant claim)
                                "address" (:address claim)
                                "recoveryRequestDigest" digest
                                "enrolmentUrl" config/enrolment-url
                                "expiresAt" exp}})))))))))))

(defn finalize!
  [env body]
  (with-request-digest
    body
    (fn [_ digest]
      (-> (store/call! env "recovery-begin-enrolment"
                       {:continuation_digest digest})
          (.then
           (fn [result]
             (if-not (aget result "ok")
               {:status 401 :body {"ok" false "error" "invalid-recovery-request"}}
               (let [claim {:tenant (aget result "tenant")
                            :address (aget result "address")
                            :principal-id (aget result "principal_id")
                            :request-digest digest
                            :started-at (aget result "started_at")}]
                 (-> (store/recovery-enrolment-finished! env claim)
                     (.then
                      (fn [finished?]
                        (if-not finished?
                          {:status 409 :body {"ok" false "error" "replacement-passkey-required"}}
                          (-> (store/call! env "recovery-finalize"
                                           {:continuation_digest digest
                                            :principal_id (:principal-id claim)})
                              (.then
                               (fn [finalized]
                                 (if (aget finalized "ok")
                                   {:status 200
                                    :set-cookie (viewer/clear-cookie)
                                    :body {"ok" true "finalized" true}}
                                   {:status 409
                                    :body {"ok" false "error" "recovery-not-finalized"}}))))))))))))))))

(defn cancel!
  [env session]
  (let [now (js/Date.now)]
    (if-not (recent-session? session now)
      (js/Promise.resolve
       {:status 401 :body {"ok" false "error" "reauthentication-required"}})
      (-> (store/call! env "recovery-cancel"
                       {:principal_id (get session "principalId")})
          (.then (fn [_] {:status 200 :body {"ok" true}}))))))
