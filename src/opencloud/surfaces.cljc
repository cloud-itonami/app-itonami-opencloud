(ns opencloud.surfaces
  "Checking the surface declaration against the server it describes.

  The declaration exists so that `verified against a wire-compatible server`
  means something a reader can look up. That only holds if the file is true,
  and a file about behaviour is exactly the kind that stops being true without
  anything failing.

  So: every operation it declares must be answered, every operation the server
  answers must be declared, and every fidelity claim must name a test that
  exists. The third is the weakest check and the most useful — it stops a
  claim from being added without anything being written to hold it."
  (:require [clojure.set :as set]
            [clojure.string :as str]))

(defn errors
  "What is wrong with the declaration.

  `answered` maps a surface id to the operations that really respond, and
  `exists?` answers whether a test path is present."
  [{:keys [surfaces]} answered exists?]
  (vec
   (remove
    nil?
    (concat
     (let [ids (map :surface/id surfaces)]
       (for [[id n] (frequencies ids) :when (> n 1)]
         {:error :duplicate-surface :surface id}))

     (for [{:surface/keys [id operations fidelity not-emulated]} surfaces]
       (cond
         (empty? operations)
         {:error :surface-without-operations :surface id}

         ;; a surface with no stated absence is a surface claiming to be
         ;; complete, and none of these is
         (empty? not-emulated)
         {:error :surface-without-stated-absences :surface id}

         (empty? fidelity)
         {:error :surface-without-fidelity-claims :surface id}

         :else nil))

     ;; declared and not answered: the client believes it was exercised
     (for [{:surface/keys [id operations]} surfaces
           operation operations
           :let [served (set (get answered id))]
           :when (and (contains? answered id)
                      (not (contains? served operation)))]
       {:error :declared-but-not-answered :surface id :value operation})

     ;; answered and not declared: a client can come to depend on something
     ;; nobody wrote down, and it can disappear without anybody noticing
     (for [[id served] answered
           :let [declared (set (some (fn [{:surface/keys [id* operations]
                                           :as surface}]
                                       (when (= id (:surface/id surface))
                                         operations))
                                     surfaces))]
           operation served
           :when (not (contains? declared operation))]
       {:error :answered-but-not-declared :surface id :value operation})

     (for [{:surface/keys [id fidelity]} surfaces
           {:fidelity/keys [id* test] :as claim} fidelity
           :let [claim-id (:fidelity/id claim)]]
       (cond
         (nil? test)
         {:error :fidelity-claim-without-a-test :surface id :value claim-id}

         (not (exists? test))
         {:error :fidelity-test-does-not-exist :surface id
          :value {:claim claim-id :test test}}

         :else nil))))))

(defn summary [{:keys [surfaces]}]
  {:surface/count (count surfaces)
   :surface/operations (reduce + 0 (map (comp count :surface/operations) surfaces))
   :surface/fidelity-claims (reduce + 0 (map (comp count :surface/fidelity)
                                             surfaces))
   ;; the number worth reading: how much of each real service is deliberately
   ;; absent, because that is what a passing client was not checked against
   :surface/stated-absences (reduce + 0 (map (comp count :surface/not-emulated)
                                             surfaces))})

(defn describe [{:keys [surfaces]}]
  (mapv (fn [{:surface/keys [id summary operations not-emulated]}]
          (str (name id) ": " summary " — " (count operations) " operations, "
               (count not-emulated) " stated absences ("
               (str/join ", " (map (comp name :absent/id) not-emulated)) ")"))
        surfaces))
