(ns itonami.auth.issuer
  "`/v1/biscuit/token` at this apex — forwarded to the one issuer, never minted
  here.

  Measured 2026-08-31 (ADR-2608311600): this apex answered 404. It has the
  most advanced passkey plane in the fleet -- its own RP, and a WebAuthn
  P-256 key that owns a deterministic ERC-4337 account -- and could not obtain
  a capability at all.

  ## Why a forward and not a mint

  Minting needs `BISCUIT_ROOT_SEED_B64URL`, and ADR-2608261300 gives that to
  `kotobase-authn` and to nothing else. A second issuer would be a second
  place for scope, expiry and attenuation rules to drift, and the root would
  then exist in two Workers instead of one. So this route carries the request
  to the issuer and carries its answer back verbatim -- including its refusals,
  which are already named.

  ## What is deliberately NOT forwarded

  **The cookie.** authn's session cookie is `gftd_session`, scoped to its own
  apex; this Worker's sessions are itonami's. Forwarding a Cookie header would
  ask the issuer to interpret one apex's session names in another apex's
  namespace, which is the confused-deputy shape this whole design exists to
  avoid. A caller mints with a credential they present in `Authorization`, or
  they get the issuer's own 403.

  That has a consequence worth stating rather than hiding: **an itonami-only
  passkey session cannot mint through here today.** Service accounts and
  bearer holders can. Linking an itonami Principal to an authn one is
  ADR-0082's controller question and is not solved by a proxy -- a WebAuthn
  credential is RP-scoped, so no amount of forwarding makes one apex's
  ceremony valid at another's."
  (:require [kotoba.lang.text :as str]))

(def ^:private issuer-url "https://authn.internal/v1/biscuit/token")

(def ^:private forwarded-headers
  "Everything the issuer needs, and nothing that names a session here."
  ["authorization" "content-type"])

(def ^:private tenant-header "x-kotobase-tenant")
(def ^:private tenant-pattern #"^t_[a-z0-9]{12,48}$")

(defn- json [body status]
  (js/Response. (js/JSON.stringify (clj->js body))
                #js {:status status
                     :headers #js {"content-type" "application/json; charset=utf-8"
                                   "cache-control" "no-store"}}))

(defn forwardable-headers
  "The header map this Worker will send on. Pure, so the cookie exclusion is
  a thing a test can assert rather than a thing a comment claims."
  [request]
  (let [get-header #(some-> (.. request -headers (get %)) str)
        base (reduce (fn [acc h]
                       (if-let [v (get-header h)] (assoc acc h v) acc))
                     {}
                     forwarded-headers)
        tenant (some-> (get-header tenant-header) str/trim)]
    (cond-> base
      ;; Bounded on the way out. An unbounded value here would be this
      ;; Worker asking the issuer to trust a string it never checked.
      (and tenant (re-matches tenant-pattern tenant))
      (assoc tenant-header tenant))))

(defn mint!
  "Promise<Response>. The issuer's status and body, unchanged.

  `set-cookie` is stripped on the way back for the mirror of the reason the
  Cookie is stripped on the way out: the issuer must not be able to set a
  session on this apex's domain."
  [env request]
  (let [service (aget env "AUTHN_SERVICE")]
    (if-not service
      ;; Not 401 and not 404. The operator has not bound the issuer, so this
      ;; Worker cannot answer the question -- saying "unauthorized" would send
      ;; a caller to fix a credential that is fine, and saying "not found"
      ;; would say this apex does not issue capabilities, which is a
      ;; deployment fact reported as a design one.
      (js/Promise.resolve
       (json {"ok" false
              "error" "issuer is not configured"
              "details" "this apex forwards /v1/biscuit/token to kotobase-authn and no AUTHN_SERVICE binding is present"}
             503))
      ;; The body is READ, not streamed on. A mint request is a small JSON
      ;; object, and passing a ReadableStream into a second Request needs
      ;; `duplex: "half"` -- which workerd and Node disagree about, so a
      ;; stream here would work in production and throw in the smoke test, or
      ;; the reverse. Neither is a thing to find out later.
      (-> (js-invoke request "text")
          (.then (fn [body]
                   (js-invoke service "fetch"
                              (js/Request. issuer-url
                                           #js {:method "POST"
                                                :headers (clj->js (forwardable-headers request))
                                                :body body}))))
          (.then (fn [^js upstream]
                   (-> (js-invoke upstream "text")
                       (.then (fn [text]
                                (js/Response.
                                 text
                                 #js {:status (.-status upstream)
                                      :headers #js {"content-type" "application/json; charset=utf-8"
                                                    "cache-control" "no-store"}}))))))
          (.catch (fn [^js e]
                    (json {"ok" false
                           "error" "issuer unreachable"
                           "details" (str (.-message e))}
                          502)))))))
