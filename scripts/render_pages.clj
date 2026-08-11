(ns render-pages
  "Build-time renderer for app.itonami.cloud/auth's one document.

  Hiccup authored in `.cljc` against jp-go-dds, rendered on the JVM, shipped
  as a file the Worker inlines with `shadow.resource/inline`. The design
  system is build-time only and never reaches the Worker bundle — a page that
  renders identically on every request has no reason to pay for a UI library
  in an isolate with a size limit.

    clojure -M:render-pages"
  (:require [clojure.java.io :as io]
            [itonami.auth.sign-in-page :as sign-in]))

(def ^:private outputs
  {"resources/itonami/auth/sign-in.html" #(sign-in/render)})

(defn -main [& _]
  (doseq [[path render] outputs]
    (let [content (render)]
      (io/make-parents path)
      (spit path content)
      (println "wrote" path (count content) "bytes"))))
