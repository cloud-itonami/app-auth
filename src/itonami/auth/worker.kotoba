(ns itonami.auth.worker
  "auth.itonami.cloud — the fetch handler, with app.itonami.cloud/auth as a
  compatibility route.

  Routing is mount-relative (`config/route`), so the string \"/auth\" appears
  once in this repo and moving the mount is a one-line change rather than a
  search-and-replace across handlers and a page script that would silently
  disagree with each other.

  Two static assets are inlined at build time — the rendered sign-in shell and
  the compiled page script. Neither depends on the request, so neither has any
  reason to cost an isolate a render or a fetch, and the design system stays
  entirely out of the Worker bundle (`scripts/render_pages.clj`).

  ClojureScript only."
  (:require [kotoba.lang.text :as str]
            [itonami.auth.config :as config]
            [itonami.auth.issuer :as issuer]
            [itonami.auth.oauth :as oauth]
            [itonami.auth.passkey :as passkey]
            [itonami.auth.recovery :as recovery]
            [itonami.auth.viewer :as viewer]
            [shadow.resource :as rc]))

(def ^:private sign-in-html (rc/inline "itonami/auth/sign-in.html"))
(def ^:private app-js (rc/inline "itonami/auth/app.js"))

;; ── responses ───────────────────────────────────────────────────────────────

(defn- json
  ([body status] (json body status nil))
  ([body status set-cookie]
   (let [headers (js/Headers. #js {"content-type" "application/json; charset=utf-8"
                                   ;; Never cached anywhere: every one of these
                                   ;; answers is about one browser's session.
                                   "cache-control" "no-store"})]
     (when set-cookie (js-invoke headers "append" "set-cookie" set-cookie))
     (js/Response. (js/JSON.stringify (clj->js body))
                   #js {:status status :headers headers}))))

(def ^:private page-csp
  ;; `script-src 'self'` because the page script is served from its own route
  ;; rather than inlined — an inline-script hash would have to be recomputed
  ;; by hand every time the script changes, and the day someone forgets is the
  ;; day the sign-in page silently stops working. Everything else is 'none': a
  ;; sign-in page is the highest-value XSS target on any origin, and it needs
  ;; no images, no frames, and no third-party anything.
  (str "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "
       "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"))

(defn- html-response [body]
  (js/Response. body
                #js {:status 200
                     :headers #js {"content-type" "text/html; charset=utf-8"
                                   "cache-control" "no-store"
                                   "content-security-policy" page-csp
                                   "referrer-policy" "same-origin"
                                   "x-content-type-options" "nosniff"}}))

(defn- script-response [body]
  (js/Response. body
                #js {:status 200
                     :headers #js {"content-type" "text/javascript; charset=utf-8"
                                   ;; Immutable for an hour and no longer: the
                                   ;; file has no content hash in its name, so
                                   ;; a long TTL would pin a stale sign-in
                                   ;; script into caches after a deploy.
                                   "cache-control" "public, max-age=3600"
                                   "x-content-type-options" "nosniff"}}))

(defn- redirect-response
  ([location] (redirect-response location nil))
  ([location set-cookie]
   (let [headers (js/Headers. #js {"location" location
                                   "cache-control" "no-store"
                                   "referrer-policy" "no-referrer"})]
     (when set-cookie (.append headers "set-cookie" set-cookie))
     (js/Response. nil #js {:status 303 :headers headers}))))

;; ── handlers ────────────────────────────────────────────────────────────────

(defn- read-json
  "Body as a Clojure map with string keys, or nil. A malformed body is a 400,
  never a 500."
  [request]
  (-> (js-invoke request "json")
      (.then (fn [body] (js->clj body)))
      (.catch (fn [_] nil))))

(defn- cookie-header [request]
  (js-invoke (aget request "headers") "get" "cookie"))

(defn- query-map [url]
  (let [out (atom {})]
    (js-invoke (aget url "searchParams") "forEach"
               (fn [value key] (swap! out assoc key value)))
    @out))

(defn- read-form [request]
  (-> (js-invoke request "text")
      (.then (fn [body]
               (let [params (js/URLSearchParams. body)
                     out (atom {})]
                 (js-invoke params "forEach"
                            (fn [value key] (swap! out assoc key value)))
                 @out)))
      (.catch (fn [_] nil))))

(defn- authorization-header [request]
  (js-invoke (aget request "headers") "get" "authorization"))

(defn- respond [{:keys [status body set-cookie]}]
  (json body status set-cookie))

(defn- session-json
  "Expose the public viewer to the Itonami apex and to no other web origin.

  The cookie remains host-only at auth.itonami.cloud. A credentialed GET from
  the first-party apex is the projection bridge; this does not share or move
  the cookie itself."
  [request body]
  (let [response (json body 200)
        origin (js-invoke (aget request "headers") "get" "origin")]
    (when (= "https://itonami.cloud" origin)
      (doto (aget response "headers")
        (.set "access-control-allow-origin" "https://itonami.cloud")
        (.set "access-control-allow-credentials" "true")
        (.set "vary" "Origin")))
    response))

(defn- redeem-kotoba-controller-link!
  "Redeem a target-bound, single-use controller code over the server channel.

  The browser only carries the opaque code. The identity projection comes
  directly from the fixed Kotoba controller origin and is checked again here
  before this RP issues its own host-only session."
  [code]
  (-> (js/fetch (str config/kotoba-controller-origin
                     "/v1/controller-link/redeem")
                #js {:method "POST"
                     :headers #js {"accept" "application/json"
                                   "content-type" "application/json"}
                     :body (js/JSON.stringify
                            #js {:code code
                                 :target config/kotoba-controller-target})})
      (.then (fn [response]
               (if (= 200 (aget response "status"))
                 (js-invoke response "json")
                 (js/Promise.reject (js/Error. "controller link refused")))))))

(defn- controller-identity
  [payload]
  (let [identity (js->clj (aget payload "identity"))
        return-to (aget payload "returnTo")
        principal-id (get identity "principalId")
        account-did (get identity "accountDid")
        active-did (get identity "activeDid")]
    (when (and (= true (get identity "valid"))
               (viewer/principal-id? principal-id)
               (viewer/did? account-did)
               (viewer/did? active-did)
               (= config/kotoba-controller-return-to return-to))
      {:principal-id principal-id
       :account-did account-did
       :active-did active-did})))

(defn- issue-controller-session!
  [env identity]
  (-> (passkey/issue-session!
       env (merge identity
                  {:auth-method "kotoba-passkey-link"
                   :acr config/key-rooted-acr
                   :amr ["webauthn" "kotoba-controller-link"]}))
      (.then
       (fn [{:keys [token]}]
         (redirect-response
          config/kotoba-controller-return-to
          (viewer/set-cookie token (quot config/session-ttl-ms 1000)))))))

(defn- complete-kotoba-controller-link!
  [request env]
  (let [origin (js-invoke (aget request "headers") "get" "origin")]
    (if-not (= config/kotoba-controller-origin origin)
      (js/Promise.resolve
       (json {"ok" false "error" "controller link origin refused"} 403))
      (-> (read-form request)
          (.then
           (fn [form]
             (let [code (get form "code")]
               (if-not (and (string? code) (<= 32 (count code) 256))
                 (json {"ok" false "error" "invalid controller link"} 400)
                 (-> (redeem-kotoba-controller-link! code)
                     (.then
                      (fn [payload]
                        (if-let [identity (controller-identity payload)]
                          (issue-controller-session! env identity)
                          (json {"ok" false "error" "invalid controller identity"}
                                502)))))))))))))

(defn- handle [request env]
  (let [url (js/URL. (aget request "url"))
        host (aget url "host")
        method (aget request "method")
        path (config/route (aget url "pathname"))
        p (fn [k] (get config/paths k))]
    (cond
      (nil? path)
      (js/Promise.resolve (json {"ok" false "error" "not found"} 404))

      ;; The former path surface remains a navigation alias. API calls under
      ;; it continue to work during the migration, but the human-facing page
      ;; acquires only the host-only cookie at the canonical origin.
      (and (= host "app.itonami.cloud") (= method "GET") (= path "/"))
      (js/Promise.resolve (redirect-response config/canonical-origin))

      ;; The page. `?return_to=` is contained before it is written into the
      ;; document, so the sign-in page cannot be turned into an open redirect
      ;; by a link.
      (and (= method "GET") (= path "/"))
      (js/Promise.resolve
       (html-response (str/replace sign-in-html "{{RETURN_TO}}"
                                   (viewer/safe-return-to
                                    (js-invoke (aget url "searchParams") "get" "return_to")))))

      (and (= method "GET") (= path "/app.js"))
      (js/Promise.resolve (script-response app-js))

      (and (= method "GET") (= path (p :health)))
      (js/Promise.resolve (json {"ok" true "service" "itonami-app-auth" "rpId" config/rp-id} 200))

      (and (= method "GET") (= path (p :metadata)))
      (js/Promise.resolve (json oauth/metadata 200))

      (and (= method "GET") (= path (p :authorize)))
      (-> (passkey/resolve-session! env (cookie-header request))
          (.then (fn [session]
                   (if-not (get session "valid")
                     (redirect-response
                      (str config/canonical-origin
                           "/?return_to="
                           (js/encodeURIComponent (aget url "href"))))
                     (-> (oauth/authorize! env (query-map url) session)
                         (.then (fn [result]
                                  (if-let [location (:location result)]
                                    (redirect-response location)
                                    (respond result)))))))))

      (and (= method "POST") (= path (p :token)))
      (-> (read-form request)
          (.then (fn [form]
                   (if-not (map? form)
                     (json {"error" "invalid_request"} 400)
                     (.then (oauth/exchange! env form) respond)))))

      ;; RFC 7662, for the resource server holding the other half of a Basic
      ;; credential. Never reached by a browser, so no Origin dance and no
      ;; cookie: the caller is a server, and the only thing that admits it is
      ;; the secret.
      (and (= method "POST") (= path (p :introspect)))
      (-> (read-form request)
          (.then (fn [form]
                   (if-not (map? form)
                     (json {"error" "invalid_request"} 400)
                     (.then (oauth/introspect! env (authorization-header request) form)
                            respond)))))

      (and (= method "GET") (= path (p :userinfo)))
      (.then (oauth/userinfo! env (authorization-header request)) respond)

      (and (= method "POST") (= path (p :login-options)))
      (.then (passkey/login-options! env) respond)

      (and (= method "POST") (= path (p :login-verify)))
      (.then (read-json request)
             (fn [body]
               (if-not (map? body)
                 (json {"ok" false "error" "malformed request"} 400)
                 (.then (passkey/login-verify! env request body) respond))))

      (and (= method "POST") (= path (p :kotoba-link-complete)))
      (complete-kotoba-controller-link! request env)

      (and (= method "POST") (= path (p :biscuit-token)))
      (issuer/mint! env request)

      (and (= method "GET") (= path (p :session)))
      (.then (passkey/resolve-session! env (cookie-header request))
             (fn [v] (session-json request v)))

      (and (= method "POST") (= path (p :recovery-keys)))
      (-> (passkey/resolve-session! env (cookie-header request))
          (.then (fn [session] (.then (recovery/replace-keys! env session) respond))))

      (and (= method "POST") (= path (p :recovery-start)))
      (-> (read-json request)
          (.then (fn [body]
                   (if-not (map? body)
                     (json {"ok" false "error" "malformed request"} 400)
                     (.then (recovery/start! env body) respond)))))

      (and (= method "POST") (= path (p :recovery-status)))
      (-> (read-json request)
          (.then (fn [body]
                   (if-not (map? body)
                     (json {"ok" false "error" "malformed request"} 400)
                     (.then (recovery/status! env body) respond)))))

      (and (= method "POST") (= path (p :recovery-complete)))
      (-> (read-json request)
          (.then (fn [body]
                   (if-not (map? body)
                     (json {"ok" false "error" "malformed request"} 400)
                     (.then (recovery/begin-enrolment! env body) respond)))))

      (and (= method "POST") (= path (p :recovery-finalize)))
      (-> (read-json request)
          (.then (fn [body]
                   (if-not (map? body)
                     (json {"ok" false "error" "malformed request"} 400)
                     (.then (recovery/finalize! env body) respond)))))

      (and (= method "POST") (= path (p :recovery-cancel)))
      (-> (passkey/resolve-session! env (cookie-header request))
          (.then (fn [session] (.then (recovery/cancel! env session) respond))))

      (and (= method "POST") (= path (p :logout)))
      (.then (passkey/logout! env (cookie-header request) false) respond)

      (and (= method "POST") (= path (p :logout-all)))
      (.then (passkey/logout! env (cookie-header request) true) respond)

      :else
      (js/Promise.resolve (json {"ok" false "error" "not found"} 404)))))

(def app
  #js {:fetch
       (fn [request env _ctx]
         (-> (handle request env)
             (.catch (fn [e]
                       ;; The message is logged, never returned: an internal
                       ;; error string on a sign-in endpoint is free
                       ;; reconnaissance.
                       (js/console.error "itonami-app-auth" (aget e "message"))
                       (json {"ok" false "error" "internal error"} 500)))))})
