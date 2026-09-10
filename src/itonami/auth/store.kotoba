(ns itonami.auth.store
  "The two places state lives, behind functions the rest of the Worker calls.

  **KV `ITONAMI_DATA`** is the credential store, and it is the SAME namespace
  `network-awai/cloud-itonami` writes at `itonami.cloud/signin/`
  (`e9857fe8617440e59f9720293dc53afd`, key `webauthn-credential:<id>`). Binding
  it rather than starting a fresh one is what makes an existing itonami passkey
  work here on day one: this service does not have its own idea of who has
  enrolled, so there is no set of users for the two surfaces to disagree about.

  **The Durable Object** holds everything whose correctness needs
  read-your-writes — see `itonami.auth.durable`.

  This namespace reads credential and account records and never changes their
  identity. Enrolment belongs to the surface that owns custody
  (`config/enrolment-url`); the one KV write here is the shared clone baseline,
  kept in step so the other surface's check does not go stale while this one
  is in use.

  ClojureScript only."
  (:require [itonami.auth.viewer :as viewer]))

(defn- store-stub [env]
  (let [ns (aget env "AUTH_STORE")]
    (js-invoke ns "get" (js-invoke ns "idFromName" "itonami-auth"))))

(defn call!
  "One request to the Durable Object. The URL is a formality — a DO stub
  routes by object, not by host — but it must parse, so it is a stable
  internal name rather than anything a caller could influence."
  [env op args]
  (let [body (js/Object.assign (js-obj) (clj->js args)
                               #js {:op op :now_ms (js/Date.now)})]
    (-> (js-invoke (store-stub env) "fetch"
                   (js/Request. "https://itonami-auth.internal/store"
                                #js {:method "POST"
                                     :body (js/JSON.stringify body)
                                     :headers #js {"content-type" "application/json"}}))
        (.then (fn [res] (js-invoke res "json"))))))

;; ── credentials (read-only) ─────────────────────────────────────────────────

(defn credential!
  "The stored credential for a base64url credential id, as
  `viewer/credential-record` reads it, or nil.

  A `JSON.parse` failure resolves to nil rather than rejecting: a corrupt
  record must fail this login, not this Worker."
  [env credential-id]
  (-> (js-invoke (aget env "ITONAMI_DATA") "get" (str "webauthn-credential:" credential-id))
      (.then (fn [raw]
               (when raw
                 (try (viewer/credential-record (js->clj (js/JSON.parse raw)))
                      (catch :default _ nil)))))))

(defn- parse-json [raw]
  (when raw
    (try (js/JSON.parse raw) (catch :default _ nil))))

(defn- account-credential-active?
  "Does this account still authorize the presented credential?

  Recovery writes revocation into the account before deleting the older
  WebAuthn KV rows. Reading this authoritative state closes the failure window
  where a best-effort cleanup could leave an old credential record usable."
  [account account-did active-did credential-id]
  (let [raw (or (aget account "account/credentials")
                (aget account "credentials"))
        credentials (if (array? raw) (array-seq raw) [])]
    (if (seq credentials)
      (boolean
       (some (fn [c]
               (and (= credential-id (or (aget c "credential/id") (aget c "id")))
                    (= active-did (or (aget c "credential/did") (aget c "did")))
                    (nil? (or (aget c "credential/revoked-at")
                              (aget c "revoked-at")))))
             credentials))
      ;; Before the credential collection existed, the account DID itself was
      ;; the one controller. Preserve that explicit legacy shape only.
      (= active-did account-did))))

(defn principal!
  "Resolve an acting credential DID to the account's stable Principal.

  The enrolment plane stores `account-did:<controller DID>` -> tenant/address,
  then the account record. A new account carries a random
  `urn:kotoba:principal:*`; a legacy account deliberately keeps its original
  account DID as the stable id. Missing/corrupt linkage falls back to the
  acting DID, preserving old standalone credentials without inventing a new
  identity on login."
  ([env active-did] (principal! env active-did nil))
  ([env active-did credential-id]
  (let [kv (aget env "ITONAMI_DATA")
        fallback {:principal-id active-did :account-did active-did
                  :credential-active? true}
        unavailable {:principal-id active-did :account-did active-did
                     :credential-active? false}]
    (-> (js-invoke kv "get" (str "account-did:" active-did))
        (.then
         (fn [raw-link]
           (if-not raw-link
             {:standalone? true}
             (if-let [link (parse-json raw-link)]
               (let [tenant (aget link "tenant")
                     address (aget link "address")]
                 (if (and (string? tenant) (seq tenant)
                          (string? address) (seq address))
                   (-> (js-invoke kv "get" (str "account:" tenant ":" address))
                       (.then (fn [raw-account]
                                {:raw-account raw-account
                                 :tenant tenant
                                 :address address})))
                   {:invalid? true}))
               {:invalid? true}))))
        (.then
         (fn [{:keys [raw-account tenant address standalone? invalid?]}]
           (cond
             standalone? fallback
             invalid? unavailable
             :else
             (if-let [account (parse-json raw-account)]
               (let [account-did (or (aget account "account/did")
                                     (aget account "did")
                                     active-did)
                     principal-id (or (aget account "account/principal-id")
                                      (aget account "principal-id")
                                      account-did)]
                 (if (and (viewer/principal-id? principal-id)
                          (viewer/principal-id? account-did))
                   {:principal-id principal-id :account-did account-did
                    :tenant tenant :address address
                    :credential-active?
                    (if credential-id
                      (account-credential-active?
                       account account-did active-did credential-id)
                      true)}
                   unavailable))
               unavailable))))
        ;; A linked credential whose account cannot be checked must not fall
        ;; back into a fresh standalone identity. Fail closed.
        (.catch (constantly unavailable))))))

(defn issue-recovery-enrollment!
  "Write the short-lived ticket the KEK-owning enrolment surface consumes.

  This Worker still cannot create a credential or sign as the account: the
  value authorizes exactly one registration at the existing custody surface.
  The recovery request digest binds the later account write back to the
  delayed request that authorized it."
  [env token {:keys [tenant address principal-id account-did request-digest exp]}]
  (js-invoke (aget env "ITONAMI_DATA") "put" (str "enroll:" token)
             (js/JSON.stringify
              #js {:tenant tenant
                   :address address
                   :principalId principal-id
                   :accountDid account-did
                   :recoveryRequestDigest request-digest
                   :kind "recovery"
                   :exp exp})
             #js {:expirationTtl 900}))

(defn delete-recovery-enrollment! [env token]
  (js-invoke (aget env "ITONAMI_DATA") "delete" (str "enroll:" token)))

(defn recovery-enrolment-finished!
  "Did the custody surface commit the replacement passkey for this request?"
  [env {:keys [tenant address principal-id request-digest started-at]}]
  (-> (js-invoke (aget env "ITONAMI_DATA") "get"
                 (str "account:" tenant ":" (.toLowerCase address)))
      (.then
       (fn [raw]
         (when-let [account (parse-json raw)]
           (let [stored-principal (or (aget account "account/principal-id")
                                      (aget account "principal-id")
                                      (aget account "account/did")
                                      (aget account "did"))
                 recovered-at (or (aget account "account/recovered-at")
                                  (aget account "recovered-at"))
                 stored-request (or (aget account "account/recovery-request-digest")
                                    (aget account "recovery-request-digest"))]
             (boolean (and (= principal-id stored-principal)
                           (= request-digest stored-request)
                           (number? recovered-at)
                           (<= started-at recovered-at)))))))
      (.catch (constantly false))))

(defn touch-credential!
  "Write back the accepted signCount, and the backup flags this assertion
  actually carried, to the shared KV record.

  Two reasons, and neither is bookkeeping. The count keeps the OTHER
  surface's baseline current, so a session here does not leave a lower
  baseline behind for `itonami.cloud/signin/` to accept a replay against.
  The backup flags must be re-read on every login and not only at enrolment:
  backup state moves when someone changes passkey provider or turns sync off,
  so a value written once describes a recovery posture the account may no
  longer have.

  Best-effort by design. The authoritative baseline for THIS surface is
  already committed inside the Durable Object by the time we get here; if this
  write fails the login is still correctly decided, and the next one re-seeds
  from the object's higher value anyway."
  [env credential-id {:keys [sign-count backup-eligible? backed-up?]}]
  (let [kv (aget env "ITONAMI_DATA")
        key (str "webauthn-credential:" credential-id)]
    (-> (js-invoke kv "get" key)
        (.then (fn [raw]
                 (when raw
                   (let [record (js/JSON.parse raw)]
                     (aset record "counter" sign-count)
                     (aset record "backupEligible" (boolean backup-eligible?))
                     (aset record "backupState" (boolean backed-up?))
                     (js-invoke kv "put" key (js/JSON.stringify record))))))
        (.catch (fn [_] nil)))))
