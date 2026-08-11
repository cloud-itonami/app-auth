(ns itonami.auth.worker
  "app.itonami.cloud/auth — the fetch handler.

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

(defn- respond [{:keys [status body set-cookie]}]
  (json body status set-cookie))

(defn- handle [request env]
  (let [url (js/URL. (aget request "url"))
        method (aget request "method")
        path (config/route (aget url "pathname"))
        p (fn [k] (get config/paths k))]
    (cond
      (nil? path)
      (js/Promise.resolve (json {"ok" false "error" "not found"} 404))

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
