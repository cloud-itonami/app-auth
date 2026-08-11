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

  This namespace reads credential records and never writes one. Enrolment
  belongs to the surface that owns custody (`config/enrolment-url`); the one
  KV write here is the shared clone baseline, kept in step so the other
  surface's check does not go stale while this one is in use.

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
