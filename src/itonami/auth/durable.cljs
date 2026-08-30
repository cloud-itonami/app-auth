(ns itonami.auth.durable
  "AuthStore — the Durable Object holding every record whose correctness
  depends on a read seeing the write before it.

  There are four, and each one is a bug in the KV-backed Pages path that this
  object exists to close (ADR-2607302145 lists all three as known gaps and
  says they are `platform の差であって設計判断ではない` — Pages Functions
  cannot bind a Durable Object at all):

  1. **A sign-in challenge must be single-use.** Read-then-delete from a
     Worker lets two racing replays both read the live challenge. Here they
     cannot: nothing else runs while this does.

  2. **Clone detection must compare and record atomically.** The baseline
     lived in KV, which is eventually consistent by design. That produced a
     measured false negative on 2026-08-03: an assertion that should have been
     refused as a clone signal was accepted because the counter written
     moments earlier was not visible yet, and a re-run refused it correctly.
     A check that intermittently passes what it exists to catch is worse than
     no check, because it is reported as one.

  3. **Revocation must be immediate and complete.** `/v1/logout/all` means
     every session an account holds, including one issued a second ago in
     another tab. That needs an index that cannot be stale.

  4. **A recovery key and recovery continuation are single-use.** Recovery is
     deliberately delayed for 48 hours, but the delay is useful only if two
     racing requests cannot both redeem the same key. The same object also
     locks ordinary sessions between recovery approval and the replacement
     passkey being enrolled.

  One instance holds all records (`idFromName \"itonami-auth\"`). A real
  serialization point, and the right trade at this scale: writes are
  per-sign-in, and a session read is one storage get on a warm object. Shard
  by key prefix if that stops being true; nothing above depends on there being
  one instance.

  Records carry their own `expires_at` and are treated as absent past it
  rather than relying on storage TTL, so expiry means the same thing to this
  object and to the caller that wrote the record, and clock skew between them
  can never resurrect a record the caller considers dead.

  `deftype` plus an explicitly-returning 2-arg factory is the shape Cloudflare
  requires: it calls `new Ctor(state, env)` with exactly two arguments, which
  a ClojureScript deftype constructor does not have. Storage access goes
  through `aget`/`js-invoke` because DurableObjectState has no Closure
  externs.

  ClojureScript only."
  (:require [clojure.string :as str]
            [itonami.auth.viewer :as viewer]
            [webauthn.adapters.edge :as edge]))

(defn- storage [state] (aget state "storage"))
(defn- sget [state k] (js-invoke (storage state) "get" k))
(defn- sput [state k v] (js-invoke (storage state) "put" k v))
(defn- sdelete [state k] (js-invoke (storage state) "delete" k))
(defn- slist [state prefix] (js-invoke (storage state) "list" #js {:prefix prefix}))

(defn- json-response [body status]
  (js/Response. (js/JSON.stringify body)
                #js {:status status :headers #js {"content-type" "application/json"}}))

(defn- live?
  "A stored record is live when it exists and has not passed its own
  `expires_at`. A record with no `expires_at` never expires — that is how a
  clone baseline sits in the same object as the ephemeral records without
  needing a second store."
  [record now-ms]
  (and (some? record)
       (let [exp (aget record "expires_at")]
         (or (not (js/Number.isFinite exp)) (> exp now-ms)))))

;; ── operations ──────────────────────────────────────────────────────────────
;;
;; Each takes (state, args) and returns Promise<Response>. They run inside the
;; object's single-threaded execution, so a read-then-write pair here is atomic
;; with respect to every other request to this object — the property the whole
;; namespace exists for.

(defn- op-challenge-issue
  "Record a challenge this service just handed a browser. `put-once`: if a
  live record already sits on the key we refuse rather than overwrite, so a
  collision is reported instead of silently losing one of two sign-ins."
  [state {:keys [key ttl-ms now-ms]}]
  (-> (sget state key)
      (.then (fn [existing]
               (if (live? existing now-ms)
                 (json-response #js {:ok false :reason "exists"} 200)
                 (-> (sput state key #js {:expires_at (+ now-ms ttl-ms)})
                     (.then (fn [_] (json-response #js {:ok true} 200)))))))))

(defn- op-challenge-consume
  "Read and delete in one indivisible step. Two racing consumers both see the
  record; only the one whose delete runs first inside this object gets
  `ok true`. That is what makes a sign-in un-replayable."
  [state {:keys [key now-ms]}]
  (-> (sget state key)
      (.then (fn [record]
               (if-not (live? record now-ms)
                 (json-response #js {:ok false :reason "missing"} 200)
                 (-> (sdelete state key)
                     (.then (fn [_] (json-response #js {:ok true} 200)))))))))

(defn- op-code-put
  "Store an authorization code exactly once with its PKCE binding."
  [state {:keys [key value ttl-ms now-ms]}]
  (-> (sget state key)
      (.then (fn [existing]
               (if (live? existing now-ms)
                 (json-response #js {:ok false :reason "exists"} 200)
                 (-> (sput state key #js {:value value
                                          :expires_at (+ now-ms ttl-ms)})
                     (.then (fn [_] (json-response #js {:ok true} 200)))))))))

(defn- op-code-consume
  "Consume before checking PKCE so a wrong verifier also spends the code."
  [state {:keys [key now-ms]}]
  (-> (sget state key)
      (.then (fn [record]
               (if-not (live? record now-ms)
                 (json-response #js {:ok false :reason "missing"} 200)
                 (-> (sdelete state key)
                     (.then (fn [_]
                              (json-response #js {:ok true
                                                  :value (aget record "value")}
                                             200)))))))))

;; ── delayed recovery -------------------------------------------------------

(defn- recovery-key-key [digest] (str "recovery-key:" digest))
(defn- recovery-set-key [principal-id] (str "recovery-set:" principal-id))
(defn- recovery-request-key [digest] (str "recovery-request:" digest))
(defn- recovery-request-index-key [principal-id digest]
  (str "did-recovery-request:" principal-id ":" digest))
(defn- recovery-lock-key [principal-id] (str "recovery-lock:" principal-id))

(declare op-session-revoke-all)

(defn- js-values [xs]
  (if (array? xs) (array-seq xs) []))

(defn- delete-recovery-set!
  [state principal-id]
  (-> (sget state (recovery-set-key principal-id))
      (.then
       (fn [record]
         (js/Promise.all
          (clj->js
           (concat
            (map #(sdelete state (recovery-key-key %))
                 (js-values (some-> record (aget "key_digests"))))
            [(sdelete state (recovery-set-key principal-id))])))))))

(defn- delete-recovery-requests!
  [state principal-id]
  (let [prefix (recovery-request-index-key principal-id "")]
    (-> (slist state prefix)
        (.then
         (fn [rows]
           (let [digests (atom [])]
             (js-invoke rows "forEach"
                        (fn [_ k] (swap! digests conj (subs k (count prefix)))))
             (js/Promise.all
              (clj->js
               (mapcat (fn [digest]
                         [(sdelete state (recovery-request-key digest))
                          (sdelete state (recovery-request-index-key principal-id digest))])
                       @digests)))))))))

(defn- op-recovery-keys-replace
  "Replace every recovery key and cancel every older pending recovery.

  Only SHA-256 digests enter this object. Plain recovery keys exist for one
  response in the Worker and are never storage values."
  [state {:keys [principal-id account-did tenant address generation key-digests now-ms]}]
  (if-not (and (string? principal-id) (string? account-did)
               (string? tenant) (string? address) (string? generation)
               (= 10 (count key-digests))
               (every? #(boolean (re-matches #"[0-9a-f]{64}" %)) key-digests))
    (js/Promise.resolve (json-response #js {:ok false :reason "invalid-recovery-set"} 400))
    (-> (js/Promise.all
         #js [(delete-recovery-set! state principal-id)
              (delete-recovery-requests! state principal-id)
              (sdelete state (recovery-lock-key principal-id))])
        (.then
         (fn [_]
           (let [set-record #js {:principal_id principal-id
                                 :account_did account-did
                                 :tenant tenant
                                 :address address
                                 :generation generation
                                 :key_digests (clj->js key-digests)
                                 :issued_at now-ms}]
             (js/Promise.all
              (clj->js
               (cons
                (sput state (recovery-set-key principal-id) set-record)
                (map (fn [digest]
                       (sput state (recovery-key-key digest)
                             #js {:principal_id principal-id
                                  :account_did account-did
                                  :tenant tenant
                                  :address address
                                  :generation generation
                                  :issued_at now-ms}))
                     key-digests)))))))
        (.then (fn [_] (json-response #js {:ok true :issued_at now-ms} 200))))))

(defn- write-recovery-request!
  [state record key-digest continuation-digest delay-ms request-ttl-ms now-ms]
  (let [principal-id (aget record "principal_id")
        generation (aget record "generation")
        available-at (+ now-ms delay-ms)
        expires-at (+ available-at request-ttl-ms)
        request #js {:principal_id principal-id
                     :account_did (aget record "account_did")
                     :tenant (aget record "tenant")
                     :address (aget record "address")
                     :generation generation
                     :started_at now-ms
                     :available_at available-at
                     :expires_at expires-at}]
    ;; Delete first. A failed later write spends the key rather than leaving a
    ;; key that may already have been copied by an observer usable again.
    (-> (sdelete state (recovery-key-key key-digest))
        (.then (fn [_]
                 (js/Promise.all
                  #js [(sput state (recovery-request-key continuation-digest) request)
                       (sput state
                             (recovery-request-index-key principal-id continuation-digest)
                             #js {:expires_at expires-at})])))
        (.then (fn [_]
                 (json-response #js {:ok true
                                     :available_at available-at
                                     :expires_at expires-at}
                                200))))))

(defn- op-recovery-start
  "Consume one recovery-key digest and create one delayed continuation."
  [state {:keys [key-digest continuation-digest delay-ms request-ttl-ms now-ms]}]
  (-> (sget state (recovery-key-key key-digest))
      (.then
       (fn [record]
         (if-not record
           (json-response #js {:ok false :reason "invalid-recovery-key"} 200)
           (let [principal-id (aget record "principal_id")
                 generation (aget record "generation")]
             (-> (sget state (recovery-set-key principal-id))
                 (.then
                  (fn [set-record]
                    (if-not (and set-record (= generation (aget set-record "generation")))
                      (json-response #js {:ok false :reason "invalid-recovery-key"} 200)
                      (write-recovery-request! state record key-digest continuation-digest
                                               delay-ms request-ttl-ms now-ms)))))))))))

(defn- op-recovery-status
  [state {:keys [continuation-digest now-ms]}]
  (-> (sget state (recovery-request-key continuation-digest))
      (.then
       (fn [record]
         (if-not (live? record now-ms)
           (json-response #js {:ok false :reason "invalid-recovery-request"} 200)
           (json-response #js {:ok true
                               :state (if (< now-ms (aget record "available_at"))
                                        "waiting" "ready")
                               :started_at (aget record "started_at")
                               :available_at (aget record "available_at")
                               :expires_at (aget record "expires_at")}
                          200))))))

(defn- op-recovery-begin-enrolment
  "After the delay, lock ordinary sessions and return the enrolment target.

  The request remains live so a failed browser ceremony can obtain another
  short-lived enrolment ticket. Only `recovery-finalize` consumes it."
  [state {:keys [continuation-digest now-ms]}]
  (-> (sget state (recovery-request-key continuation-digest))
      (.then
       (fn [record]
         (cond
           (not (live? record now-ms))
           (json-response #js {:ok false :reason "invalid-recovery-request"} 200)

           (< now-ms (aget record "available_at"))
           (json-response #js {:ok false :reason "recovery-delay-active"
                               :available_at (aget record "available_at")} 200)

           :else
           (let [principal-id (aget record "principal_id")]
             (-> (sput state (recovery-lock-key principal-id)
                       #js {:request_digest continuation-digest
                            :since now-ms
                            :expires_at (aget record "expires_at")})
                 (.then
                  (fn [_]
                    (json-response #js {:ok true
                                        :principal_id principal-id
                                        :account_did (aget record "account_did")
                                        :tenant (aget record "tenant")
                                        :address (aget record "address")
                                        :started_at (aget record "started_at")
                                        :available_at (aget record "available_at")
                                        :expires_at (aget record "expires_at")}
                                   200))))))))))

(defn- op-recovery-finalize
  [state {:keys [continuation-digest principal-id now-ms]}]
  (-> (js/Promise.all
       #js [(sget state (recovery-request-key continuation-digest))
            (sget state (recovery-lock-key principal-id))])
      (.then
       (fn [records]
         (let [request (aget records 0)
               lock (aget records 1)]
           (if-not (and (live? request now-ms) lock
                        (= principal-id (aget request "principal_id"))
                        (= continuation-digest (aget lock "request_digest")))
             (json-response #js {:ok false :reason "invalid-recovery-request"} 200)
             (-> (js/Promise.all
                  #js [(delete-recovery-set! state principal-id)
                       (delete-recovery-requests! state principal-id)
                       (op-session-revoke-all state {:did principal-id})
                       (sdelete state (recovery-lock-key principal-id))])
                 (.then (fn [_]
                          (json-response #js {:ok true :finalized_at now-ms} 200))))))))))

(defn- op-recovery-cancel
  [state {:keys [principal-id]}]
  (-> (js/Promise.all
       #js [(delete-recovery-requests! state principal-id)
            (sdelete state (recovery-lock-key principal-id))])
      (.then (fn [_] (json-response #js {:ok true} 200)))))

(defn- identity-index-key
  "The reverse index entry for one route. Mirrors `did-session:` — same shape,
  same reason."
  [did key]
  (str "did-identity:" did ":" key))

(defn- op-identity-complete
  "Resolve or link one verified external subject atomically.

  An unlinked subject never creates an account DID. A key-rooted session is
  the only caller allowed to supply `did` (`itonami.auth.viewer/key-rooted?`);
  this keeps Email and OAuth as alternate proofs for an existing
  passkey-rooted identity rather than silent new identity roots.

  ## The index is written here, not by the caller

  The forward record answers `subject -> did`, which is all a sign-in needs
  and nothing an owner can act on: there is no way to ask it what a given key
  answers to. So a route could be attached and then neither seen nor removed
  — an account accumulating doors nobody can enumerate.

  `did-identity:<did>:<key>` closes that, and it is written in the same object
  turn as the link for exactly the reason `op-session-put` gives: a record
  that exists without its index is a record the management surface cannot see,
  and an invisible route is worse than no route.

  ## A legacy link heals on its next sign-in

  Routes linked before this index existed have no entry. Rather than a
  migration batch — which must run before the code that reads the new shape
  deploys, and in between reports an account's real routes as none — the
  `bound` branch writes the entry it finds missing. The enrolment plane makes
  the same call for pre-D3 credentials
  (`cloud-itonami.account/adopt-legacy-credential`).

  `linked_at` is taken from the existing record so healing does not restamp an
  attachment as though it had just been made."
  [state {:keys [key did provider label now-ms]}]
  (-> (sget state key)
      (.then
       (fn [record]
         (let [bound (when record (aget record "did"))]
           (cond
             (and (string? bound) (string? did) (not= bound did))
             (json-response #js {:ok false :reason "already-bound"} 200)

             (string? bound)
             (-> (sput state (identity-index-key bound key)
                       #js {:provider (or (aget record "provider") provider)
                            :label (or (aget record "label") label)
                            :linked_at (or (aget record "linked_at") now-ms)})
                 (.then (fn [_]
                          (json-response #js {:ok true :did bound :linked false} 200))))

             (string? did)
             (-> (sput state key #js {:did did :linked_at now-ms
                                      :provider provider :label label})
                 (.then (fn [_]
                          (sput state (identity-index-key did key)
                                #js {:provider provider :label label
                                     :linked_at now-ms})))
                 (.then (fn [_]
                          (json-response #js {:ok true :did did :linked true} 200))))

             :else
             (json-response #js {:ok false :reason "link-required"} 200)))))))

(defn- op-identity-list
  "Every route attached to one account. Reads the index, not a scan, so the
  cost is proportional to the account's own routes."
  [state {:keys [did]}]
  (if-not (string? did)
    (js/Promise.resolve (json-response #js {:ok false :reason "no-did"} 400))
    (let [prefix (identity-index-key did "")]
      (-> (slist state prefix)
          (.then (fn [rows]
                   (let [out (atom [])]
                     (js-invoke rows "forEach"
                                (fn [v k]
                                  (swap! out conj
                                         #js {:key (subs k (count prefix))
                                              :provider (aget v "provider")
                                              :label (aget v "label")
                                              :linkedAt (aget v "linked_at")})))
                     (json-response #js {:ok true :routes (to-array @out)} 200))))))))

(defn- op-identity-unlink
  "Detach one route from the key.

  The stored record's own `did` decides, never the caller's claim about which
  account the key belongs to. Both halves are deleted in one object turn, for
  the same reason both are written in one: an index entry outliving its
  forward record is a route the owner is told they have and cannot use, and a
  forward record outliving its index entry is one they cannot remove twice.

  **Missing and not-yours are the same answer.** Telling them apart would let
  anyone holding any session confirm whether a guessed key — and an Email
  route's key is a digest of an address someone may already know — is attached
  to somebody. `itonami.auth.passkey/refuse` collapses its cases for the same
  reason.

  **Removing the last route is allowed.** The key is the root; a route is not,
  and refusing here would say otherwise. The enrolment plane draws the line in
  the same place: `cloud-itonami.account/detach-email` permits detaching the
  last address and `revocation-problems` refuses only the last passkey."
  [state {:keys [key did]}]
  (if-not (and (string? key) (string? did)
               (str/starts-with? key "identity:"))
    (js/Promise.resolve (json-response #js {:ok false :reason "not-linked"} 200))
    (-> (sget state key)
        (.then (fn [record]
                 (let [bound (when record (aget record "did"))]
                   (if-not (and (string? bound) (= bound did))
                     (json-response #js {:ok false :reason "not-linked"} 200)
                     (-> (js/Promise.all
                          #js [(sdelete state key)
                               (sdelete state (identity-index-key did key))])
                         (.then (fn [_]
                                  (json-response #js {:ok true} 200)))))))))))

(defn- op-sign-count
  "WebAuthn L2 §7.2 step 19, decided and recorded in one indivisible step.

  The RULE is `webauthn.adapters.edge/sign-count-ok?` and is not restated
  here; the seed rule is `itonami.auth.viewer/baseline-seed`. This function is
  only the mechanism: read, decide, write.

  `seed` is the count the Pages path keeps in KV. It can raise a baseline and
  never lower one — a credential that already signed in must not restart from
  zero, and replaying an old KV record must not pull an established baseline
  down so that a spent count becomes acceptable again."
  [state {:keys [key value now-ms]}]
  (-> (sget state key)
      (.then (fn [record]
               (let [presented (aget value "count")
                     baseline (viewer/baseline-seed (aget value "seed")
                                                    (when record (aget record "count")))]
                 (cond
                   (not (and (number? presented) (<= 0 presented)))
                   (json-response #js {:ok false :reason "invalid-count" :baseline baseline} 200)

                   ;; Both zero: this authenticator does not implement a
                   ;; counter (the common platform-authenticator case) and the
                   ;; check is skipped, as every mainstream implementation does.
                   (not (edge/sign-count-ok? baseline presented))
                   (json-response #js {:ok false :reason "not-increased" :baseline baseline} 200)

                   (and (zero? baseline) (zero? presented))
                   (json-response #js {:ok true :counters false} 200)

                   :else
                   (-> (sput state key #js {"count" presented "at" now-ms})
                       (.then (fn [_]
                                (json-response #js {:ok true :counters true
                                                    :baseline baseline} 200))))))))))

(defn- op-session-put
  "Store a session by the SHA-256 digest of its opaque token, plus a reverse
  index under the account DID.

  The index is written here, in the same object turn as the session, and not
  by the caller afterwards: a session that exists without its index is a
  session `/v1/logout/all` cannot see, which is the one failure mode a
  sign-out-everywhere button must not have."
  [state {:keys [key value ttl-ms now-ms]}]
  (let [expires (+ now-ms ttl-ms)
        did (or (aget value "principalId") (aget value "accountDid"))]
    (-> (if (string? did) (sget state (recovery-lock-key did)) (js/Promise.resolve nil))
        (.then
         (fn [lock]
           (if (live? lock now-ms)
             (json-response #js {:ok false :reason "recovery-in-progress"} 200)
             (-> (sput state key #js {:value value :expires_at expires})
                 (.then (fn [_]
                          (if-not (string? did)
                            (js/Promise.resolve nil)
                            (sput state (str "did-session:" did ":" key)
                                  #js {:expires_at expires}))))
                 (.then (fn [_]
                          (json-response #js {:ok true :expires_at expires} 200))))))))))

(defn- op-session-get [state {:keys [key now-ms]}]
  (-> (sget state key)
      (.then (fn [record]
               (if-not (live? record now-ms)
                 (json-response #js {:ok true :found false} 200)
                 (let [value (aget record "value")
                       did (or (aget value "principalId") (aget value "accountDid"))]
                   (-> (if (string? did)
                         (sget state (recovery-lock-key did))
                         (js/Promise.resolve nil))
                       (.then
                        (fn [lock]
                          (if (live? lock now-ms)
                            (json-response #js {:ok true :found false
                                                :reason "recovery-in-progress"} 200)
                            (json-response #js {:ok true :found true
                                                :value value
                                                :expires_at (aget record "expires_at")}
                                           200)))))))))))

(defn- delete-session! [state key did]
  (js/Promise.all
   #js [(sdelete state key)
        (if (string? did)
          (sdelete state (str "did-session:" did ":" key))
          (js/Promise.resolve nil))]))

(defn- op-session-revoke
  "Revoke one session. The DID is read from the record rather than taken from
  the caller, so a caller cannot orphan an index entry by naming the wrong
  account."
  [state {:keys [key]}]
  (-> (sget state key)
      (.then (fn [record]
               (let [value (some-> record (aget "value"))
                     did (or (some-> value (aget "principalId"))
                             (some-> value (aget "accountDid")))]
                 (.then (delete-session! state key did)
                        (fn [_] (json-response #js {:ok true} 200))))))))

(defn- op-session-revoke-all
  "Every session this account holds. Reads the index, not a scan, so the cost
  is proportional to the account's own sessions."
  [state {:keys [did]}]
  (if-not (string? did)
    (js/Promise.resolve (json-response #js {:ok false :reason "no-did"} 400))
    (let [prefix (str "did-session:" did ":")]
      (-> (slist state prefix)
          (.then (fn [rows]
                   (let [keys (atom [])]
                     (js-invoke rows "forEach"
                                (fn [_ k] (swap! keys conj (subs k (count prefix)))))
                     (-> (js/Promise.all
                          (clj->js (mapcat (fn [k] [(sdelete state k)
                                                    (sdelete state (str prefix k))])
                                           @keys)))
                         (.then (fn [_]
                                  (json-response #js {:ok true :revoked (count @keys)} 200)))))))))))

(defn- dispatch [state body]
  (let [op (aget body "op")
        args {:key (aget body "key")
              :value (aget body "value")
              :did (aget body "did")
              :provider (aget body "provider")
              :label (aget body "label")
              :principal-id (aget body "principal_id")
              :account-did (aget body "account_did")
              :tenant (aget body "tenant")
              :address (aget body "address")
              :generation (aget body "generation")
              :key-digests (js->clj (or (aget body "key_digests") #js []))
              :key-digest (aget body "key_digest")
              :continuation-digest (aget body "continuation_digest")
              :delay-ms (aget body "delay_ms")
              :request-ttl-ms (aget body "request_ttl_ms")
              :ttl-ms (aget body "ttl_ms")
              :now-ms (aget body "now_ms")}]
    (case op
      "challenge-issue"    (op-challenge-issue state args)
      "challenge-consume"  (op-challenge-consume state args)
      "code-put"           (op-code-put state args)
      "code-consume"       (op-code-consume state args)
      "identity-complete"  (op-identity-complete state args)
      "identity-list"      (op-identity-list state args)
      "identity-unlink"    (op-identity-unlink state args)
      "sign-count"         (op-sign-count state args)
      "session-put"        (op-session-put state args)
      "session-get"        (op-session-get state args)
      "session-revoke"     (op-session-revoke state args)
      "session-revoke-all" (op-session-revoke-all state args)
      "recovery-keys-replace" (op-recovery-keys-replace state args)
      "recovery-start" (op-recovery-start state args)
      "recovery-status" (op-recovery-status state args)
      "recovery-begin-enrolment" (op-recovery-begin-enrolment state args)
      "recovery-finalize" (op-recovery-finalize state args)
      "recovery-cancel" (op-recovery-cancel state args)
      (js/Promise.resolve (json-response #js {:ok false :reason "unknown-op"} 400)))))

(deftype AuthStore [state env]
  Object
  (fetch [_ request]
    (-> (js-invoke request "json")
        (.then (fn [body] (dispatch state body)))
        (.catch (fn [e]
                  (json-response #js {:ok false :reason (str "store error: " (aget e "message"))}
                                 500))))))

(defn make-auth-store
  "The 2-arg factory wrangler.jsonc's `class_name` is bound to. Returns
  explicitly: Cloudflare uses the return value of `new Ctor(state, env)`, and
  a deftype constructor called with two arguments is not that."
  [state env]
  (AuthStore. state env))
