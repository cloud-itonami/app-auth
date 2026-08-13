(ns itonami.auth.app
  "The sign-in page's behaviour — one document, one bundle, one mount
  (ADR-2608080100). Moving between `サインイン` and `サインイン済み` changes
  state, not location.

  Compiled ClojureScript, not a hand-written `.js`: the workspace prohibits
  new loose JavaScript, and here it also buys correctness. `itonami.auth.config`
  is compiled into BOTH this bundle and the Worker, so the endpoint paths and
  JSON field names this page speaks cannot drift from the ones the Worker
  answers — the classic failure of a page scripted by hand, and a silent one
  (a `fetch` to a path nobody serves reads to the user as `サインインできませんでした`).

  ## The DOM contract

  The document is rendered by `itonami.auth.sign-in-page` with every view
  present and inert. This namespace only flips `data-active`, fills text, and
  runs the ceremony. Change the markup and this file together.

    [data-view=\"sign-in\"|\"signed-in\"|\"unsupported\"]
    [data-act=\"passkey\"|\"logout\"|\"logout-all\"]
    #auth-status  #auth-identity  #auth-backup  [data-return-to]
    #auth-routes  #auth-routes-empty  #auth-method-mode  #auth-manage-note
    #sso-methods [data-sso]  #email-form #email-address

  ## The key is the root; the routes hang off it

  A passkey held in a credential manager is what this account IS. Email and
  SSO are routes attached to it — a way back in, and a second way to sign in.
  Two consequences show up here: the routes list is drawn from what the
  account actually has (`GET /v1/methods`) rather than from what the server
  could offer, and the detach control appears only when `canManage` says this
  session was authenticated by the key itself."
  (:require [clojure.string :as str]
            [itonami.auth.config :as config]))

;; ── base64url, the encoding every WebAuthn value crosses the wire in ────────

(defn- ab->b64url [buf]
  (-> (js/btoa (.apply js/String.fromCharCode nil (js/Uint8Array. buf)))
      (str/replace "+" "-") (str/replace "/" "_") (str/replace #"=+$" "")))

(defn- b64url->ab [s]
  (let [pad (case (mod (count s) 4) 2 "==" 3 "=" "")
        bin (js/atob (str (-> s (str/replace "-" "+") (str/replace "_" "/")) pad))]
    (.-buffer (js/Uint8Array.from bin #(.charCodeAt % 0)))))

;; ── DOM ─────────────────────────────────────────────────────────────────────

(defn- $ [sel] (js/document.querySelector sel))
(defn- $$ [sel] (array-seq (js/document.querySelectorAll sel)))

(def views
  "Views as data, and the nav is generated from this — a view added to the
  dispatch and forgotten in the nav is dead code that looks live
  (ADR-2608080100). The fragment, not a path: this Worker serves one document
  at one address, and a `pushState` URL that 404s on reload is worse than no
  deep link."
  [{:id "sign-in"    :fragment "#sign-in"}
   {:id "signed-in"  :fragment "#signed-in"}
   {:id "unsupported" :fragment "#unsupported"}])

(defn- show! [id]
  (doseq [el ($$ "[data-view]")]
    (.setAttribute el "data-active" (str (= id (.getAttribute el "data-view")))))
  (when-let [target (some #(when (= id (:id %)) %) views)]
    (set! (.-hash js/location) (:fragment target))))

(defn- status! [message tone]
  (when-let [el ($ "#auth-status")]
    (set! (.-textContent el) (or message ""))
    (if tone (.setAttribute el "data-tone" tone) (.removeAttribute el "data-tone"))))

(defn- return-to []
  (or (some-> ($ "[data-return-to]") (.getAttribute "data-return-to")) config/mount))

;; ── the wire ────────────────────────────────────────────────────────────────

(defn- post [path body]
  (-> (js/fetch path #js {:method "POST"
                          :credentials "same-origin"
                          :headers #js {"content-type" "application/json"}
                          :body (js/JSON.stringify (clj->js (or body {})))})
      (.then (fn [res] (.then (.json res) #(js->clj %))))))

(defn- get-json [path]
  (-> (js/fetch path #js {:credentials "same-origin"})
      (.then (fn [res] (.then (.json res) #(js->clj %))))))

;; ── the ceremony ────────────────────────────────────────────────────────────

(defn- signed-in! [viewer]
  (when-let [el ($ "#auth-identity")]
    (set! (.-textContent el) (str (get viewer "activeDid"))))
  (when-let [el ($ "#auth-backup")]
    (set! (.-textContent el)
          (if (get viewer "backedUp")
            "このパスキーは同期されています。端末を1台失っても入れます。"
            (str "このパスキーは同期されていません。"
                 (str/join " / " config/key-managers)
                 " のいずれかに保存した予備を作っておくと、端末を失っても入れます。"))))
  (show! "signed-in"))

(declare setup-methods!)

(defn- unlink! [key]
  (status! "経路を外しています…" nil)
  (-> (post (config/endpoint :method-unlink) {"key" key})
      (.then (fn [result]
               (if (get result "ok")
                 (do (status! "経路を外しました。" "ok") (setup-methods! nil))
                 (status! (case (get result "error")
                            "passkey_required"
                            "経路を外すにはパスキーでサインインしてください。"
                            "not_linked" "その経路はもう繋がっていません。"
                            "経路を外せませんでした。")
                          "error"))))
      (.catch (fn [_] (status! "経路を外せませんでした。" "error")))))

(defn- render-routes!
  "Draw one `<li>` per attached route.

  Built with `createElement` and `textContent`, never by assigning a string to
  `innerHTML`: `label` is derived from a value an upstream provider returned,
  and the one page on this origin that must never interpret provider-supplied
  text as markup is this one."
  [routes can-manage?]
  (when-let [list ($ "#auth-routes")]
    (set! (.-textContent list) "")
    (doseq [route routes]
      (let [li (js/document.createElement "li")
            what (js/document.createElement "div")
            name (js/document.createElement "span")]
        (set! (.-className li) "auth-route")
        (set! (.-className what) "auth-route__what")
        (set! (.-textContent name) (get route "name"))
        (.appendChild what name)
        (when-let [label (get route "label")]
          (let [el (js/document.createElement "span")]
            (set! (.-className el) "auth-route__label")
            (set! (.-textContent el) label)
            (.appendChild what el)))
        (.appendChild li what)
        ;; The detach control is present only when this session may actually
        ;; use it. A disabled button that never enables reads as broken, and
        ;; the reason it is absent is said once in #auth-manage-note.
        (when can-manage?
          (let [button (js/document.createElement "button")]
            (set! (.-type button) "button")
            ;; DADS styles a button by `class="dads-button"` plus the
            ;; `data-type`/`data-size` ATTRIBUTES — not by modifier classes
            ;; (`jp-go-dds.core/button`). A `dads-button--outline` here would
            ;; render an unstyled control that still looked right in the
            ;; source. This is the one place the page builds that markup
            ;; without the component, because the rows are dynamic.
            (set! (.-className button) "dads-button")
            (.setAttribute button "data-type" "outline")
            (.setAttribute button "data-size" "sm")
            (set! (.-textContent button) "外す")
            (.setAttribute button "data-unlink" (get route "key"))
            (.addEventListener button "click" #(unlink! (get route "key")))
            (.appendChild li button)))
        (.appendChild list li)))
    (when-let [empty ($ "#auth-routes-empty")]
      (set! (.-hidden empty) (boolean (seq routes))))))

(defn- setup-methods!
  "Draw the key's routes and the ways to attach another.

  `viewer` may be nil, which means \"re-read it\" — after a detach the page
  must not redraw from the session it captured at load, or the list shows the
  route it just removed."
  [viewer]
  (-> (get-json (config/endpoint :methods))
      (.then
       (fn [methods]
         (let [signed-in? (if (nil? viewer)
                            (seq (get methods "linked"))
                            (get viewer "valid"))
               can-manage? (get methods "canManage")]
           (doseq [provider (get methods "sso")]
             (when-let [el ($ (str "[data-sso=\"" (get provider "id") "\"]"))]
               ;; Offered when this deployment has the bindings AND this
               ;; session may attach. An anonymous visitor still sees them:
               ;; a linked provider is a way to sign in, not only a way to
               ;; attach.
               (set! (.-hidden el) (not (get provider "configured")))
               (.setAttribute el "href"
                              (str (config/endpoint :sso-start) "/" (get provider "id")
                                   "?return_to=" (js/encodeURIComponent (return-to))))
               (set! (.-textContent el)
                     (cond
                       (get provider "linked") (str (get provider "name") " は連携済み")
                       can-manage? (str (get provider "name") " を繋ぐ")
                       :else (str (get provider "name") " で続ける")))))
           (when-let [form ($ "#email-form")]
             (set! (.-hidden form) (not (get methods "email"))))
           (render-routes! (get methods "linked") can-manage?)
           (when-let [mode ($ "#auth-method-mode")]
             (set! (.-textContent mode)
                   (cond
                     can-manage?
                     "パスキーが本人の根です。ここに繋いだ Email / SSO は、端末を失ったときの復旧経路であり、次回からの別のサインイン方法にもなります。"
                     signed-in?
                     "いまは Email / SSO でサインインしています。経路の追加・解除はパスキーでサインインしているときだけできます。"
                     :else
                     "連携済みの Email / SSO でもサインインできます。最初の 1 回はパスキーが必要です。")))
           (when-let [note ($ "#auth-manage-note")]
             (set! (.-hidden note) (boolean can-manage?))))))
      (.catch (fn [_] nil))))

(defn- email! [event]
  (.preventDefault event)
  (status! "確認リンクを送っています…" nil)
  (-> (post (config/endpoint :email-start)
            {"email" (some-> ($ "#email-address") .-value)
             "returnTo" (return-to)})
      (.then (fn [_]
               (status! "手続きできるアドレスには、10分有効なリンクを送りました。" "ok")))
      (.catch (fn [_] (status! "リンクを送れませんでした。" "error")))))

(defn- sign-in! []
  (status! "パスキーを確認しています…" nil)
  (-> (post (config/endpoint :login-options) {})
      (.then
       (fn [options]
         (if-not (get options "ok")
           (status! "いまサインインできません。しばらくしてからもう一度お試しください。" "error")
           (-> (js/navigator.credentials.get
                #js {:publicKey #js {:challenge (b64url->ab (get options "challenge"))
                                     :rpId (get options "rpId")
                                     :timeout (get options "timeout")
                                     :userVerification (get options "userVerification")
                                     :allowCredentials #js []}})
               (.then
                ;; `^js` on both bindings: under :advanced these are external
                ;; objects, and without the hint the compiler renames
                ;; `.clientDataJSON` and friends to short names the browser has
                ;; never heard of. The failure is invisible in development
                ;; (where nothing is renamed) and total in production.
                (fn [^js assertion]
                  (let [^js r (.-response assertion)]
                    (post (config/endpoint :login-verify)
                          {"credentialIdB64url" (.-id assertion)
                           "challenge" (get options "challenge")
                           "clientDataJsonB64url" (ab->b64url (.-clientDataJSON r))
                           "authenticatorDataB64url" (ab->b64url (.-authenticatorData r))
                           "signatureB64url" (ab->b64url (.-signature r))}))))
               (.then
                (fn [viewer]
                  (cond
                    (get viewer "valid")
                    (do (signed-in! viewer)
                        (status! "" nil)
                        (set! (.-href js/location) (return-to)))

                    (= "credential-clone-signal" (get viewer "error"))
                    (status! (str "このパスキーの署名カウンタが進んでいません。"
                                  "別の端末が同じ鍵を提示している可能性があります。"
                                  "itonami.cloud のサポートに連絡してください。")
                             "error")

                    :else
                    (status! "サインインできませんでした。もう一度お試しください。" "error"))))
               (.catch
                (fn [e]
                  ;; A person who dismisses the system passkey sheet has not
                  ;; failed at anything, and telling them they did is how a
                  ;; sign-in page teaches people it is broken.
                  (if (= "NotAllowedError" (.-name e))
                    (status! "" nil)
                    (status! "この端末でパスキーを使えませんでした。" "error"))))))))
      (.catch (fn [_] (status! "ネットワークに接続できませんでした。" "error")))))

(defn- logout! [all?]
  (-> (post (config/endpoint (if all? :logout-all :logout)) {})
      (.then (fn [_]
               (show! "sign-in")
               (status! "サインアウトしました。" "ok")
               ;; Redraw: `canManage` is now false, so the detach controls
               ;; must go. Leaving them would offer an action that 401s.
               (setup-methods! {"valid" false})))
      (.catch (fn [_] (status! "サインアウトできませんでした。" "error")))))

;; ── init ────────────────────────────────────────────────────────────────────

(defn init []
  (do
    (when (and js/window.PublicKeyCredential js/navigator.credentials)
      (some-> ($ "[data-act=\"passkey\"]") (.addEventListener "click" #(sign-in!)))
      )
    (some-> ($ "[data-act=\"logout\"]") (.addEventListener "click" #(logout! false)))
    (some-> ($ "[data-act=\"logout-all\"]") (.addEventListener "click" #(logout! true)))
    (some-> ($ "#email-form") (.addEventListener "submit" email!))
    ;; Ask who is already here before offering to sign anyone in: arriving
    ;; at a sign-in page with a live session and being asked to authenticate
    ;; again is the most common way a session silently is not working.
    (-> (get-json (config/endpoint :session))
        (.then (fn [viewer]
                 (if (get viewer "valid") (signed-in! viewer) (show! "sign-in"))
                 (setup-methods! viewer)
                 (when-let [error (.get (js/URLSearchParams. (.-search js/location)) "error")]
                   (status! (case error
                              "link_required" "この方法はまだ DID に連携されていません。先にパスキーでサインインしてください。"
                              "email_invalid" "Email リンクが無効または期限切れです。"
                              "provider_cancelled" "プロバイダーでのサインインを中止しました。"
                              "サインインを完了できませんでした。") "error"))))
        (.catch (fn [_] (show! "sign-in"))))))
