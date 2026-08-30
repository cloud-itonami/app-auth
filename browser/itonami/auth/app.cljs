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

    [data-view=\"sign-in\"|\"signed-in\"|\"recovery\"|\"unsupported\"]
    [data-act=\"passkey\"|\"logout\"|\"logout-all\"]
    #auth-status  #auth-identity  #auth-backup  [data-return-to]

  Passkey is the only interactive sign-in route. The Worker also refuses the
  retired Email and upstream-SSO endpoints, so removing their controls here is
  not a presentation-only policy."
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
   {:id "recovery"   :fragment "#recovery"}
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
      (.then (fn [res]
               (.then (.json res)
                      #(assoc (js->clj %) "_status" (.-status res)))))))

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

;; ── delayed recovery ───────────────────────────────────────────────────────

(def recovery-token-storage "itonami.auth.recovery-token")

(defn- stored-recovery-token []
  (try (js/localStorage.getItem recovery-token-storage)
       (catch :default _ nil)))

(defn- save-recovery-token! [token]
  (try (js/localStorage.setItem recovery-token-storage token)
       (catch :default _ nil)))

(defn- clear-recovery-token! []
  (try (js/localStorage.removeItem recovery-token-storage)
       (catch :default _ nil)))

(defn- recovery-message! [message]
  (when-let [el ($ "#auth-recovery-wait")]
    (set! (.-textContent el) (or message ""))))

(defn- ready-button! [ready?]
  (when-let [el ($ "[data-act=\"recovery-complete\"]")]
    (set! (.-disabled el) (not ready?))))

(defn- format-time [ms]
  (.toLocaleString (js/Date. ms) "ja-JP"))

(defn- recovery-status! []
  (if-let [token (stored-recovery-token)]
    (-> (post (config/endpoint :recovery-status) {"recoveryToken" token})
        (.then
         (fn [body]
           (if-not (get body "ok")
             (do (clear-recovery-token!)
                 (ready-button! false)
                 (recovery-message! "この復旧申請は無効か期限切れです。"))
             (let [ready? (= "ready" (get body "state"))]
               (ready-button! ready?)
               (recovery-message!
                (if ready?
                  "待機が完了しました。新しいパスキーを登録できます。"
                  (str (format-time (get body "availableAt"))
                       " まで待機します。この間、パスキーを持つ本人は申請を取り消せます。")))))))
        (.catch (fn [_] (status! "復旧状態を確認できませんでした。" "error"))))
    (do (ready-button! false)
        (recovery-message! "復旧キーを入力して待機を開始してください。"))))

(defn- recovery-start! []
  (let [key (some-> ($ "#auth-recovery-key") .-value str/trim)]
    (if (str/blank? key)
      (status! "復旧キーを入力してください。" "error")
      (-> (post (config/endpoint :recovery-start) {"recoveryKey" key})
          (.then
           (fn [body]
             (if-not (get body "ok")
               (status! "復旧キーを確認できませんでした。" "error")
               (do (save-recovery-token! (get body "recoveryToken"))
                   (set! (.-value ($ "#auth-recovery-key")) "")
                   (status! "48時間の待機を開始しました。" "ok")
                   (recovery-status!)))))
          (.catch (fn [_] (status! "復旧を開始できませんでした。" "error")))))))

(defn- recovery-complete! []
  (if-let [token (stored-recovery-token)]
    (-> (post (config/endpoint :recovery-complete) {"recoveryToken" token})
        (.then
         (fn [body]
           (cond
             (= 425 (get body "_status")) (recovery-status!)
             (not (get body "ok")) (status! "復旧を続けられませんでした。" "error")
             :else
             (let [params (js/URLSearchParams.)]
               (.set params "token" (get body "enrollmentToken"))
               (.set params "tenant" (get body "tenant"))
               (.set params "address" (get body "address"))
               (.set params "continuation" token)
               (set! (.-href js/location)
                     (str (get body "enrolmentUrl")
                          "#recovery-enroll?" (.toString params)))))))
        (.catch (fn [_] (status! "復旧を続けられませんでした。" "error"))))
    (status! "先に復旧キーを確認してください。" "error")))

(defn- replace-recovery-keys! []
  (-> (post (config/endpoint :recovery-keys) {})
      (.then
       (fn [body]
         (if-not (get body "ok")
           (status! (if (= "reauthentication-required" (get body "error"))
                      "復旧キーの作成には、直前のパスキー確認が必要です。サインアウトして入り直してください。"
                      "復旧キーを作成できませんでした。") "error")
           (do (set! (.-textContent ($ "#auth-recovery-key-list"))
                     (str/join "\n" (get body "keys")))
               (set! (.-hidden ($ "#auth-recovery-keys")) false)
               (status! "以前の復旧キーを無効化し、新しい10個を作成しました。" "ok")))))
      (.catch (fn [_] (status! "復旧キーを作成できませんでした。" "error")))))

(defn- copy-recovery-keys! []
  (when-let [value (some-> ($ "#auth-recovery-key-list") .-textContent)]
    (-> (js/navigator.clipboard.writeText value)
        (.then (fn [_] (status! "復旧キーをコピーしました。" "ok")))
        (.catch (fn [_] (status! "コピーできませんでした。手動で選択してください。" "error"))))))

(defn- cancel-recovery! []
  (-> (post (config/endpoint :recovery-cancel) {})
      (.then (fn [body]
               (if (get body "ok")
                 (do (clear-recovery-token!) (status! "復旧申請を取り消しました。" "ok"))
                 (status! "復旧申請を取り消せませんでした。" "error"))))
      (.catch (fn [_] (status! "復旧申請を取り消せませんでした。" "error")))))

(defn- finalize-recovery! [token]
  (-> (post (config/endpoint :recovery-finalize) {"recoveryToken" token})
      (.then (fn [body]
               (if (get body "ok")
                 (do (clear-recovery-token!)
                     (show! "sign-in")
                     (status! "復旧が完了しました。新しいパスキーでサインインしてください。" "ok"))
                 (do (show! "recovery")
                     (status! "新しいパスキーの登録を確認できませんでした。" "error")))))
      (.catch (fn [_]
                (show! "recovery")
                (status! "復旧の完了を確認できませんでした。" "error")))))

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
               (status! "サインアウトしました。" "ok")))
      (.catch (fn [_] (status! "サインアウトできませんでした。" "error")))))

;; ── init ────────────────────────────────────────────────────────────────────

(defn init []
  (do
    (when (and js/window.PublicKeyCredential js/navigator.credentials)
      (some-> ($ "[data-act=\"passkey\"]") (.addEventListener "click" #(sign-in!)))
      )
    (some-> ($ "[data-act=\"logout\"]") (.addEventListener "click" #(logout! false)))
    (some-> ($ "[data-act=\"logout-all\"]") (.addEventListener "click" #(logout! true)))
    (some-> ($ "[data-act=\"recovery-open\"]")
            (.addEventListener "click" #(do (show! "recovery") (recovery-status!))))
    (some-> ($ "[data-act=\"recovery-back\"]")
            (.addEventListener "click" #(show! "sign-in")))
    (some-> ($ "[data-act=\"recovery-start\"]")
            (.addEventListener "click" #(recovery-start!)))
    (some-> ($ "[data-act=\"recovery-status\"]")
            (.addEventListener "click" #(recovery-status!)))
    (some-> ($ "[data-act=\"recovery-complete\"]")
            (.addEventListener "click" #(recovery-complete!)))
    (some-> ($ "[data-act=\"recovery-keys-replace\"]")
            (.addEventListener "click" #(replace-recovery-keys!)))
    (some-> ($ "[data-act=\"recovery-keys-copy\"]")
            (.addEventListener "click" #(copy-recovery-keys!)))
    (some-> ($ "[data-act=\"recovery-cancel\"]")
            (.addEventListener "click" #(cancel-recovery!)))
    ;; Ask who is already here before offering to sign anyone in: arriving
    ;; at a sign-in page with a live session and being asked to authenticate
    ;; again is the most common way a session silently is not working.
    (if (str/starts-with? (.-hash js/location) "#recovery-finalize=")
      (finalize-recovery!
       (js/decodeURIComponent
        (subs (.-hash js/location) (count "#recovery-finalize="))))
      (-> (get-json (config/endpoint :session))
          (.then (fn [viewer]
                   (if (get viewer "valid") (signed-in! viewer) (show! "sign-in"))
                   (when (.get (js/URLSearchParams. (.-search js/location)) "error")
                     (status! "サインインを完了できませんでした。" "error"))))
          (.catch (fn [_] (show! "sign-in")))))))
