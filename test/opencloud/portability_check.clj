(ns opencloud.portability-check
  "Run the deciding namespaces on both runtimes and compare.

    npm run test:portability

  The server runs on Node and its tests run on the JVM. Anything that differs
  between them is a defect the test suite cannot see.")

(require '[kotoba.lang.edn :as edn]
         '[clojure.java.shell :as shell]
         '[clojure.string :as str]
         '[opencloud.portability :as portability])

(def runner "(require '[opencloud.portability :as p]) (prn (p/results))")

(defn- node-results []
  (let [script (java.io.File/createTempFile "portability" ".cljs")]
    (spit script runner)
    (let [{:keys [exit out err]} (shell/sh "nbb" "--classpath" "src:resources:test"
                                           (.getPath script))]
      (.delete script)
      (when-not (zero? exit)
        (println "nbb failed:")
        (println (str/trim (str out err)))
        (System/exit 1))
      (edn/read-string out))))

(defn -main [& _]
  (when-not (zero? (:exit (shell/sh "sh" "-c" "command -v nbb")))
    (println "nbb is not on PATH — the runtime this server runs on cannot be checked")
    (System/exit 1))
  (let [jvm (portability/results)
        node (node-results)
        ids (sort (map str (distinct (concat (keys jvm) (keys node)))))
        differences (for [id ids
                          :let [k (keyword (subs id 1))]
                          :when (not= (get jvm k ::absent) (get node k ::absent))]
                      k)]
    (doseq [k differences]
      (println (str "\ndiffers: " k))
      (println "  jvm  " (pr-str (get jvm k)))
      (println "  node " (pr-str (get node k))))
    (println (format "\n%d/%d cases agree across both runtimes"
                     (- (count ids) (count differences)) (count ids)))
    (when (seq differences) (System/exit 1))))
