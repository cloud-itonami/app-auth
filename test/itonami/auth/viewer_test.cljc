(ns itonami.auth.viewer-test
  "The parts most likely to be wrong, checked without a browser, an
  authenticator, a Worker, or a network.

  Every case here is a failure that has actually happened to a sign-in page
  somewhere — an open redirect on a `return_to`, a cookie truncated at its own
  padding, a clone baseline that could be lowered. They are cheap to check and
  expensive to discover in production, which is the whole reason the decisions
  live in `.cljc` and the mechanism does not."
  (:require [clojure.test :refer [deftest is testing]]
            [itonami.auth.config :as config]
            [itonami.auth.viewer :as viewer]))

(deftest cookie-token-reads-our-cookie-only
  (testing "picks ours out of a header carrying several"
    (is (= "abc" (viewer/cookie-token (str "other=1; " config/cookie-name "=abc; third=2")))))

  (testing "a value containing '=' survives"
    ;; base64url padding is the obvious case. Splitting on every '=' truncates
    ;; the token to a prefix that never matches a stored digest — a sign-in
    ;; that succeeds and then does not stick.
    (is (= "aGVsbG8=" (viewer/cookie-token (str config/cookie-name "=aGVsbG8=")))))

  (testing "absent, empty and non-string all read as no session"
    (is (nil? (viewer/cookie-token "other=1")))
    (is (nil? (viewer/cookie-token (str config/cookie-name "="))))
    (is (nil? (viewer/cookie-token nil)))))

(deftest set-cookie-carries-every-attribute-that-matters
  (let [c (viewer/set-cookie "tok" 3600)]
    (is (.contains c (str "Domain=" config/cookie-domain))
        "scoped to the registrable parent, or the app plane cannot read it")
    (is (.contains c "HttpOnly"))
    (is (.contains c "Secure"))
    (is (.contains c "SameSite=Lax"))
    (is (.contains c "Max-Age=3600")))
  (testing "clearing keeps the same Domain and Path"
    ;; A clear written with a different Domain does not delete the cookie; it
    ;; sets a second, empty one and leaves the live session in place.
    (let [c (viewer/clear-cookie)]
      (is (.contains c (str "Domain=" config/cookie-domain)))
      (is (.contains c "Max-Age=0")))))

(deftest safe-return-to-contains-the-redirect
  (testing "accepts what we serve"
    (is (= "/kaisya/" (viewer/safe-return-to "/kaisya/")))
    (is (= "https://itonami.cloud/os/" (viewer/safe-return-to "https://itonami.cloud/os/")))
    (is (= "https://app.itonami.cloud/kaisya"
           (viewer/safe-return-to "https://app.itonami.cloud/kaisya"))))

  (testing "refuses everything else, falling back to the mount"
    (is (= config/mount (viewer/safe-return-to "https://evil.example/")))
    (is (= config/mount (viewer/safe-return-to "https://evil-itonami.cloud/"))
        "a suffix test would admit this one")
    (is (= config/mount (viewer/safe-return-to "//evil.example"))
        "protocol-relative resolves to another origin; starts-with \"/\" admits it")
    (is (= config/mount (viewer/safe-return-to "http://itonami.cloud/")) "plaintext")
    (is (= config/mount (viewer/safe-return-to "javascript:alert(1)")))
    (is (= config/mount (viewer/safe-return-to "")))
    (is (= config/mount (viewer/safe-return-to nil)))))

(deftest credential-record-reads-only-what-a-login-needs
  (let [record {"pubKeyB64" "BASE64" "did" "did:key:z6Mk" "counter" 7
                "backupEligible" true "backupState" false
                ;; The sealed custody fields are present in the real record and
                ;; must not come out of this function: a shape this service
                ;; cannot use is a shape it cannot leak.
                "sealedPrivB64" "…" "wrappedDekB64" "…"}
        read (viewer/credential-record record)]
    (is (= {:public-key-b64 "BASE64" :did "did:key:z6Mk" :counter 7
            :backup-eligible? true :backed-up? false}
           read)))

  (testing "a record without a usable public key is not a credential"
    (is (nil? (viewer/credential-record {"did" "did:key:z6Mk"})))
    (is (nil? (viewer/credential-record {"pubKeyB64" ""})))
    (is (nil? (viewer/credential-record nil))))

  (testing "a missing counter is 0, not nil"
    ;; nil would reach the clone comparison as a non-number and refuse a login
    ;; that is fine.
    (is (= 0 (:counter (viewer/credential-record {"pubKeyB64" "B"}))))))

(deftest baseline-seed-may-rise-and-never-fall
  (testing "the higher of the two stores wins"
    (is (= 9 (viewer/baseline-seed 9 5)) "KV ahead of the object")
    (is (= 9 (viewer/baseline-seed 5 9)) "object ahead of KV"))
  (testing "absent values are zero, not nil"
    (is (= 5 (viewer/baseline-seed nil 5)))
    (is (= 5 (viewer/baseline-seed 5 nil)))
    (is (= 0 (viewer/baseline-seed nil nil))))
  (testing "a stale KV record cannot lower an established baseline"
    ;; If it could, replaying an old record would be a way to disarm clone
    ;; detection: drop the baseline to 0 and every spent count is acceptable
    ;; again.
    (is (= 9 (viewer/baseline-seed 0 9)))))

(deftest viewer-payload-separates-account-from-credential
  (let [v (viewer/viewer {:account-did "did:web:kotobase.net:tenant:u"
                          :active-did "did:key:z6Mk"
                          :credential-id "cred"
                          :backup-eligible? true :backed-up? true
                          :expires-at 123})]
    (is (true? (get v "valid")))
    (is (= "did:web:kotobase.net:tenant:u" (get v "accountDid")))
    (is (= "did:key:z6Mk" (get v "activeDid")))
    (is (true? (get v "backedUp")))
    (testing "no assurance field"
      ;; Nothing here has seen an attestation chain. A field named `assurance`
      ;; would be read as though something had.
      (is (not (contains? v "assurance")))))
  (is (= {"valid" false} viewer/anonymous)))

(deftest route-is-mount-relative
  (is (= "/" (config/route config/mount)))
  (is (= "/" (config/route (str config/mount "/"))) "one address, not two")
  (is (= "/v1/session" (config/route (str config/mount "/v1/session"))))
  (is (nil? (config/route "/kaisya")))
  (testing "a path that merely starts with the same characters is not ours"
    (is (nil? (config/route "/authority")))))

(deftest endpoints-are-built-from-one-mount
  (is (= "/auth/v1/session" (config/endpoint :session)))
  (is (= "/auth/v1/passkey/login/verify" (config/endpoint :login-verify)))
  (testing "every declared path round-trips through route"
    (doseq [[k p] config/paths]
      (is (= p (config/route (config/endpoint k))) (str k)))))
