(ns itonami.auth.sign-in-page
  "The document served at `app.itonami.cloud/auth`, built from the Digital
  Agency Design System (`jp-go-dds`) — the workspace's base design system
  since 2026-08-05.

  `render` produces `resources/itonami/auth/sign-in.html`; regenerate with
  `clojure -M:render-pages`, then rebuild the Worker. The Worker inlines the
  file and performs exactly one runtime substitution, `{{RETURN_TO}}`.

  ## Authoring-only

  This namespace reads a jp-go-dds resource, so it must never be required from
  a Worker runtime namespace or the whole design system lands in the isolate.
  That is the same split net-kotobase/authn uses, and it is why a page that
  renders identically on every request costs the isolate nothing.

  ## One document, three views

  ADR-2608080100: kotoba-lang UI is single-page. All three views are rendered
  here, inert, and `itonami.auth.app` flips `data-active` — moving between
  them changes state, not location. There is no second HTML file, so there is
  no second app shell to fall behind the first one during a design-system
  migration.

  ## The DOM contract is load-bearing

  `itonami.auth.app` selects `[data-view]`, `[data-act]`, `#auth-status`,
  `#auth-identity`, `#auth-backup`, `#auth-routes`, `#auth-routes-empty`,
  `#auth-manage-note`, `[data-unlink]` and `[data-return-to]`. DADS's `button`
  renders `<a>` when given `:href` and `<button>` otherwise, and passes
  `:attrs` through untouched — that passthrough is why `data-act` can sit on a
  real DADS button instead of forcing a hand-rolled one. Change the markup
  only together with the script.

  ## No dark mode

  DADS ships no dark palette, so `jp-go-dds.page` stamps `color-scheme: light`.
  A real regression for dark-mode users and the price of the design system the
  owner chose; written down so the next reader sees a decision rather than a
  bug."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [itonami.auth.config :as config]
            [jp-go-dds.core :as dds]
            [jp-go-dds.page :as page]
            [jp-go-dds.tokens :as dds-tokens]))

(def ^:private dds-css
  (str (slurp (io/resource "jp_go_dds/dds.css")) "\n" dds-tokens/a11y-css))

(def ^:private app-css
  "Unlayered app CSS on the token contract — no hex, no px font-size, no
  font-family — so a re-vendor of upstream carries through. `bridge-css`
  publishes the `--hig-*` contract on top of DADS, so anything written against
  it (here, and in any view this page ever grows) follows DADS unmodified.

  Everything DADS ships a component for is absent on purpose. What is left is
  the three shapes it has none for."
  (str dds-tokens/bridge-css "\n"
       ;; Views are all present in the document and only one is active. Not a
       ;; `hidden` attribute: an inactive view must be out of the a11y tree and
       ;; out of the tab order, and `display:none` is the only thing that does
       ;; both in every browser this must work in.
       "[data-view]{display:none;}\n"
       "[data-view][data-active=\"true\"]{display:block;}\n"
       ;; The status line keeps its height while empty, so filling it mid-
       ;; ceremony does not reflow the button under the cursor.
       ".auth-status{min-height:1.4em;margin:var(--hig-spacing-3) 0 0;}\n"
       ;; `--hig-palette-*`, not `--hig-color-red`/`-green`: those two are not
       ;; in the bridge and are defined nowhere in DADS, so they resolved to
       ;; nothing and an error was painted in the same colour as a success —
       ;; a status line that cannot show a failure, reported as one that can.
       ".auth-status[data-tone=\"error\"]{color:var(--hig-palette-red);}\n"
       ".auth-status[data-tone=\"ok\"]{color:var(--hig-palette-green);}\n"
       ".auth-mut{color:var(--hig-color-secondary-label);}\n"
       ".auth-did{font-family:var(--hig-font-mono);overflow-wrap:anywhere;}\n"
       ".auth-actions{display:flex;gap:var(--hig-spacing-3);flex-wrap:wrap;"
       "align-items:center;margin-top:var(--hig-spacing-4);}\n"
       ;; The routes list. DADS has no list-with-a-trailing-control, which is
       ;; the one shape this page needs and the design system does not ship.
       ".auth-routes{list-style:none;padding:0;"
       "margin:var(--hig-spacing-3) 0 0;display:flex;flex-direction:column;"
       "gap:var(--hig-spacing-2);}\n"
       ".auth-route{display:flex;gap:var(--hig-spacing-3);flex-wrap:wrap;"
       "align-items:center;justify-content:space-between;"
       "border:var(--hig-hairline) solid var(--hig-color-separator);"
       "border-radius:var(--hig-radius-md);padding:var(--hig-spacing-3);}\n"
       ".auth-route__what{display:flex;flex-direction:column;"
       "gap:var(--hig-spacing-1);}\n"
       ".auth-route__label{font-family:var(--hig-font-mono);"
       "font-size:var(--hig-text-footnote-font-size);"
       "line-height:var(--hig-text-footnote-line-height);"
       "color:var(--hig-color-secondary-label);overflow-wrap:anywhere;}\n"))

(def return-to-slot
  "Replaced at request time by the validated `return_to`
  (`itonami.auth.viewer/safe-return-to`). Kept as a slot so the document stays
  build-time generated — the only thing about this page that varies per
  request is where it sends someone afterwards."
  "{{RETURN_TO}}")

(defn- view [id & body]
  (into [:section {:data-view id :data-active "false"}] body))

(defn- sign-in-view []
  (view
   "sign-in"
   (dds/heading 1 "サインイン")
   [:p {:class "auth-mut"}
    "パスキーでサインインします。Email や SSO を連携済みなら、それでも入れます。"]
   [:div {:class "auth-actions"}
    (dds/button "パスキーでサインイン"
                {:type :solid-fill :size "lg" :attrs {:data-act "passkey"}})
    (dds/button "パスキーを作る" {:type :text :href config/enrolment-url})]
   ;; The managers are named here, not left to the browser's own wording. A
   ;; passkey is only as recoverable as the vault holding it, and "パスキーを
   ;; 作る" tells someone nothing about where it lands — which is how a
   ;; device-bound credential gets created by someone who believed otherwise.
   [:p {:class "auth-mut"}
    "鍵は " (str/join " / " config/key-managers)
    " のいずれかに保存してください。登録は itonami.cloud で行います。"]))

(defn- routes-section []
  [:section
   (dds/heading 2 "鍵に繋がっている経路")
   [:p {:id "auth-method-mode" :class "auth-mut"}
    "パスキーが本人の根です。Email や SSO はそこに繋ぐ、復旧経路 兼 別のサインイン方法です。"]
   ;; Filled by `itonami.auth.app` from GET /v1/methods. Present and empty in
   ;; the document rather than created by script, so the shape the script
   ;; writes into is reviewable here.
   [:ul {:id "auth-routes" :class "auth-routes"}]
   [:p {:id "auth-routes-empty" :class "auth-mut" :hidden true}
    "まだ何も繋がっていません。端末を全て失うと入れなくなるので、"
    "予備のパスキーか、下の方法を 1 つ繋いでおいてください。"]
   (dds/heading 3 "繋ぐ")
   [:div {:class "auth-actions" :id "sso-methods"}
    (for [id config/sso-order]
      (dds/button (str (get config/provider-labels id id) " を繋ぐ")
                  {:type :outline :href "#"
                   :attrs {:data-sso id :hidden true}}))]
   [:form {:id "email-form" :class "auth-actions" :hidden true}
    [:label {:for "email-address"} "Email"]
    [:input {:id "email-address" :name "email" :type "email"
             :autocomplete "email" :required true}]
    (dds/button "確認リンクを送る" {:type :outline :attrs {:type "submit"}})]
   [:p {:id "auth-manage-note" :class "auth-mut"}
    "Email や SSO が一致しただけでは DID を作りも統合もしません。"
    "経路の追加と解除はパスキーでサインインしているときだけできます。"]])

(defn- signed-in-view []
  (view
   "signed-in"
   (dds/heading 1 "サインイン済み")
   [:p "いまサインインしている資格情報です。"]
   [:p {:id "auth-identity" :class "auth-did"}]
   [:p {:id "auth-backup" :class "auth-mut"}]
   [:div {:class "auth-actions"}
    ;; This Worker holds no KEK and so cannot enrol (`config/enrolment-url`).
    ;; The link is the whole of the recovery loop that lives here: a route
    ;; gets you back in, and this is where you turn that back into a key.
    (dds/button "予備のパスキーを作る"
                {:type :outline :href config/enrolment-url})
    (dds/button "サインアウト" {:type :text :attrs {:data-act "logout"}})
    (dds/button "すべての端末からサインアウト"
                {:type :text :attrs {:data-act "logout-all"}})]))

(defn- unsupported-view []
  (view
   "unsupported"
   (dds/heading 1 "この端末では使えません")
   [:p "このブラウザはパスキー（WebAuthn）に対応していません。"
    "対応しているブラウザで開き直してください。"]
   ;; No fallback control. Offering one that cannot finish is worse than
   ;; offering none: it moves the failure from a sentence someone can read to
   ;; a dead end they discover after committing.
   [:p {:class "auth-mut"}
    "iOS / iPadOS は Safari 16 以降、macOS は Safari 16 / Chrome 108 以降、"
    "Windows は Chrome / Edge 108 以降で使えます。"]))

(defn render []
  (page/->page
   {:title "サインイン — cloud-itonami"
    :description "パスキーで cloud-itonami のアプリにサインインします。"
    :lang "ja"
    :css dds-css
    :app-css app-css
    :head [[:meta {:name "robots" :content "noindex"}]
           ;; `defer`, not `async`: the script reads the DOM contract above on
           ;; init, and an async script can run before the document it selects
           ;; into exists.
           [:script {:src (str config/mount "/app.js") :defer true}]]}
   [:main {:data-return-to return-to-slot}
    (dds/container
     (sign-in-view)
     (signed-in-view)
     (unsupported-view)
     (routes-section)
     [:p {:id "auth-status" :class "auth-status" :role "status" :aria-live "polite"}])]))
