(ns itonami.auth.durable
  "AuthStore — the Durable Object holding every record whose correctness
  depends on a read seeing the write before it.

  There are three, and each one is a bug in the KV-backed Pages path that this
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
  (:require [itonami.auth.viewer :as viewer]
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

(defn- op-identity-complete
  "Resolve or link one verified external subject atomically.

  An unlinked subject never creates an account DID. A live passkey session is
  the only caller allowed to supply `did`; this keeps Email and OAuth as
  alternate proofs for an existing passkey-rooted identity rather than silent
  new identity roots."
  [state {:keys [key did now-ms]}]
  (-> (sget state key)
      (.then
       (fn [record]
         (let [bound (when record (aget record "did"))]
           (cond
             (and (string? bound) (string? did) (not= bound did))
             (json-response #js {:ok false :reason "already-bound"} 200)

             (string? bound)
             (json-response #js {:ok true :did bound :linked false} 200)

             (string? did)
             (-> (sput state key #js {:did did :linked_at now-ms})
                 (.then (fn [_]
                          (json-response #js {:ok true :did did :linked true} 200))))

             :else
             (json-response #js {:ok false :reason "link-required"} 200)))))))

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
        did (aget value "accountDid")]
    (-> (sput state key #js {:value value :expires_at expires})
        (.then (fn [_]
                 (if-not (string? did)
                   (js/Promise.resolve nil)
                   (sput state (str "did-session:" did ":" key) #js {:expires_at expires}))))
        (.then (fn [_] (json-response #js {:ok true :expires_at expires} 200))))))

(defn- op-session-get [state {:keys [key now-ms]}]
  (-> (sget state key)
      (.then (fn [record]
               (if-not (live? record now-ms)
                 (json-response #js {:ok true :found false} 200)
                 (json-response #js {:ok true :found true
                                     :value (aget record "value")
                                     :expires_at (aget record "expires_at")}
                                200))))))

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
               (let [did (some-> record (aget "value") (aget "accountDid"))]
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
              :ttl-ms (aget body "ttl_ms")
              :now-ms (aget body "now_ms")}]
    (case op
      "challenge-issue"    (op-challenge-issue state args)
      "challenge-consume"  (op-challenge-consume state args)
      "code-put"           (op-code-put state args)
      "code-consume"       (op-code-consume state args)
      "identity-complete"  (op-identity-complete state args)
      "sign-count"         (op-sign-count state args)
      "session-put"        (op-session-put state args)
      "session-get"        (op-session-get state args)
      "session-revoke"     (op-session-revoke state args)
      "session-revoke-all" (op-session-revoke-all state args)
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
