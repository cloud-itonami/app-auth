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
  (:require [clojure.string :as str]
            [itonami.auth.config :as config]
            [itonami.auth.federated :as federated]
            [itonami.auth.oauth :as oauth]
            [itonami.auth.passkey :as passkey]
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

(defn- redirect-result [{:keys [location set-cookie]}]
  (redirect-response location set-cookie))

(defn- provider-from [path prefix]
  (let [raw (when (str/starts-with? path (str prefix "/"))
              (subs path (inc (count prefix))))
        provider (some-> raw keyword)]
    (when (contains? federated/providers provider) provider)))

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

      ;; Configuration AND, for a live session, the routes attached to that
      ;; key. One round trip: the page draws the key and what hangs off it in
      ;; the same paint, so a route never appears a frame after the button
      ;; that would detach it.
      (and (= method "GET") (= path (p :methods)))
      (-> (passkey/resolve-session! env (cookie-header request))
          (.then #(federated/methods! env %))
          (.then respond))

      (and (= method "POST") (= path (p :method-unlink)))
      (-> (js/Promise.all #js [(read-json request)
                               (passkey/resolve-session! env (cookie-header request))])
          (.then (fn [values]
                   (let [body (aget values 0) session (aget values 1)]
                     (if-not (map? body)
                       (json {"ok" false "error" "malformed request"} 400)
                       (.then (federated/unlink! env session (get body "key"))
                              respond))))))

      (and (= method "GET") (provider-from path (p :sso-start)))
      (let [provider (provider-from path (p :sso-start))]
        (-> (passkey/resolve-session! env (cookie-header request))
            (.then #(federated/start! env provider
                                      (js-invoke (aget url "searchParams") "get" "return_to") %))
            (.then (fn [result]
                     (if (:location result) (redirect-result result) (respond result))))))

      (and (contains? #{"GET" "POST"} method)
           (provider-from path (p :sso-callback)))
      (let [provider (provider-from path (p :sso-callback))]
        (-> (if (= method "POST") (read-form request)
                (js/Promise.resolve (query-map url)))
            (.then #(federated/callback! env provider %))
            (.then redirect-result)))

      (and (= method "POST") (= path (p :email-start)))
      (-> (js/Promise.all #js [(read-json request)
                               (passkey/resolve-session! env (cookie-header request))])
          (.then (fn [values]
                   (let [body (aget values 0) session (aget values 1)]
                     (if-not (map? body)
                       (json {"ok" false "error" "malformed request"} 400)
                       (-> (federated/email-start! env (get body "email")
                                                   (get body "returnTo")
                                                   (js->clj session))
                           (.then respond)))))))

      (and (= method "GET") (= path (p :email-verify)))
      (-> (federated/email-verify!
           env (js-invoke (aget url "searchParams") "get" "token"))
          (.then redirect-result))

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

      (and (= method "GET") (= path (p :session)))
      (.then (passkey/resolve-session! env (cookie-header request))
             (fn [v] (json v 200)))

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
