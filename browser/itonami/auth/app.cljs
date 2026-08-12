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
    #auth-status  #auth-identity  [data-return-to]"
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
            "このパスキーは同期されていません。2本目を作っておくと、端末を失っても入れます。")))
  (show! "signed-in"))

(defn- setup-methods! [viewer]
  (-> (get-json (config/endpoint :methods))
      (.then
       (fn [methods]
         (doseq [provider (get methods "sso")]
           (when-let [el ($ (str "[data-sso=\"" (get provider "id") "\"]"))]
             (when (get provider "configured")
               (set! (.-hidden el) false)
               (.setAttribute el "href"
                              (str (config/endpoint :sso-start) "/" (get provider "id")
                                   "?return_to=" (js/encodeURIComponent (return-to)))))))
         (when-let [form ($ "#email-form")]
           (set! (.-hidden form) (not (get methods "email"))))
         (when-let [mode ($ "#auth-method-mode")]
           (set! (.-textContent mode)
                 (if (get viewer "valid")
                   "この DID に Email / SSO を連携します。連携後は次回からその方法でサインインできます。"
                   "連携済みの Email / SSO でサインインできます。初回はパスキーが必要です。")))))))

(defn- email! [event]
  (.preventDefault event)
  (status! "サインインリンクを送っています…" nil)
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
      (.then (fn [_] (show! "sign-in") (status! "サインアウトしました。" "ok")))
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
