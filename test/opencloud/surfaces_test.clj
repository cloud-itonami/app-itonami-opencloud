(ns opencloud.surfaces-test
  (:require [kotoba.lang.edn :as edn]
            [clojure.java.io :as io]
            [kotoba.lang.text :as str]
            [clojure.test :refer [deftest is]]
            [opencloud.advisory :as advisory]
            [opencloud.kubernetes :as kubernetes]
            [opencloud.registry :as registry]
            [opencloud.surfaces :as surfaces]))

(def catalog (edn/read-string (slurp (io/file "resources/surfaces.edn"))))

(defn- exists? [path] (.exists (io/file path)))

;; What really answers, asked of the handlers rather than assumed. Only the
;; surfaces whose handler takes a request without a socket are probed here;
;; the rest are checked by their own suites and are not asserted to be
;; complete, which is why `answered` is partial by design.

(def kubernetes-seed
  (edn/read-string (slurp (io/file "resources/seed/kubernetes.edn"))))

(def registry-seed
  {:base-url "http://registry.test" :service "opencloud" :token "t"
   :page-size 2
   :repositories {"library/ubuntu"
                  {:tags {"latest" "sha256:aa"}
                   :documents {"sha256:aa"
                               {:media-type registry/index-media-type
                                :bytes "{}" :length 2}}}}})

(def advisory-seed
  (edn/read-string (slurp (io/file "resources/seed/advisory.edn"))))

(defn- answers? [response]
  (and response (not= 404 (:status response))))

(def kubernetes-paths
  {;; how a namespace-scoped credential finds out which namespaces it has.
   ;; Probed with the flag on, because it is itself a cluster-scoped read and
   ;; the point of the flag is that a credential may not have it
   :list-namespaces "/api/v1/namespaces"
   :list-pods "/api/v1/pods"
   :list-services "/api/v1/services"
   :list-service-accounts "/api/v1/serviceaccounts"
   :list-secrets "/api/v1/secrets"
   :list-roles "/apis/rbac.authorization.k8s.io/v1/roles"
   :list-cluster-roles "/apis/rbac.authorization.k8s.io/v1/clusterroles"
   :list-role-bindings "/apis/rbac.authorization.k8s.io/v1/rolebindings"
   :list-cluster-role-bindings
   "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"})

(def answered
  {:kubernetes
   (vec (keep (fn [[operation path]]
                (when (answers?
                       (kubernetes/handle
                        {;; the discovery flag on, because the operation is
                         ;; declared and a credential that lacks the
                         ;; ClusterRole for it is a scenario, not an absence
                         :seed (assoc kubernetes-seed :namespace-discovery? true)
                         :method "GET" :target path
                         :headers {"authorization"
                                   (str "Bearer " (:token kubernetes-seed))}}))
                  operation))
              kubernetes-paths))

   :oci-registry
   (vec (keep identity
              [(when (answers? (registry/handle
                                {:seed registry-seed :method "GET"
                                 :target "/v2/"
                                 :headers {"authorization" "Bearer t.library/ubuntu"}}))
                 :api-version-check)
               (when (answers? (registry/handle
                                {:seed registry-seed :method "GET"
                                 :target "/token?scope=repository:library/ubuntu:pull"
                                 :headers {}}))
                 :token)
               (when (answers? (registry/handle
                                {:seed registry-seed :method "GET"
                                 :target "/v2/library/ubuntu/manifests/latest"
                                 :headers {"authorization" "Bearer t.library/ubuntu"
                                           "accept" "*/*"}}))
                 :get-manifest)
               (when (answers? (registry/handle
                                {:seed registry-seed :method "GET"
                                 :target "/v2/library/ubuntu/blobs/sha256:aa"
                                 :headers {"authorization" "Bearer t.library/ubuntu"}}))
                 :get-blob)
               (when (answers? (registry/handle
                                {:seed registry-seed :method "GET"
                                 :target "/v2/library/ubuntu/tags/list"
                                 :headers {"authorization" "Bearer t.library/ubuntu"}}))
                 :list-tags)]))

   :osv
   (vec (keep identity
              [(when (answers? (advisory/handle
                                {:seed advisory-seed :method "POST"
                                 :target "/v1/query"
                                 :parsed-body {"package" {"name" "lodash"}}}))
                 :query)
               (when (answers? (advisory/handle
                                {:seed advisory-seed :method "POST"
                                 :target "/v1/querybatch"
                                 :parsed-body {"queries" []}}))
                 :querybatch)
               (when (answers? (advisory/handle
                                {:seed advisory-seed :method "GET"
                                 :target (str "/v1/vulns/"
                                              (get (first (:records advisory-seed))
                                                   "id"))}))
                 :get-vuln)]))})

(deftest the-declaration-agrees-with-the-server
  ;; `verified against a wire-compatible server` only means something if this
  ;; file is true, and a file about behaviour stops being true without
  ;; anything failing
  (is (= [] (surfaces/errors catalog answered exists?))))

(deftest every-surface-states-what-it-does-not-emulate
  ;; a client never exercises what is absent, so it believes that part works;
  ;; the belief comes from the silence
  (doseq [{:surface/keys [id not-emulated]} (:surfaces catalog)]
    (is (seq not-emulated) id)))

(deftest a-claim-with-no-test-behind-it-is-caught
  (let [inflated (update catalog :surfaces
                         (fn [surfaces]
                           (mapv #(if (= :aws (:surface/id %))
                                    (update % :surface/fidelity conj
                                            {:fidelity/id :retries-are-idempotent})
                                    %)
                                 surfaces)))]
    (is (some #(= :fidelity-claim-without-a-test (:error %))
              (surfaces/errors inflated answered exists?)))))

(deftest a-test-that-does-not-exist-is-caught
  (let [invented (update catalog :surfaces
                         (fn [surfaces]
                           (mapv #(if (= :osv (:surface/id %))
                                    (update % :surface/fidelity conj
                                            {:fidelity/id :x
                                             :fidelity/test "test/nope.clj"})
                                    %)
                                 surfaces)))]
    (is (some #(= :fidelity-test-does-not-exist (:error %))
              (surfaces/errors invented answered exists?)))))

(deftest an-operation-that-is-declared-and-does-not-answer-is-caught
  (let [wishful (update catalog :surfaces
                        (fn [surfaces]
                          (mapv #(if (= :kubernetes (:surface/id %))
                                   (update % :surface/operations conj :watch-pods)
                                   %)
                                surfaces)))]
    ;; the client believes it was exercised
    (is (some #(= :declared-but-not-answered (:error %))
              (surfaces/errors wishful answered exists?)))))

(deftest an-operation-that-answers-and-is-not-declared-is-caught
  (let [quiet (update catalog :surfaces
                      (fn [surfaces]
                        (mapv #(if (= :osv (:surface/id %))
                                 (assoc % :surface/operations [:query :querybatch])
                                 %)
                              surfaces)))]
    ;; a client can come to depend on something nobody wrote down
    (is (some #(and (= :answered-but-not-declared (:error %))
                    (= :get-vuln (:value %)))
              (surfaces/errors quiet answered exists?)))))

(deftest the-summary-counts-what-is-absent-too
  (let [summary (surfaces/summary catalog)]
    (is (= 8 (:surface/count summary)))
    (is (pos? (:surface/operations summary)))
    ;; every surface carries at least one stated absence: a surface claiming
    ;; to be complete is the claim this file exists to stop
    (is (every? #(seq (:surface/not-emulated %)) (:surfaces catalog)))
    ;; the number worth reading: what a passing client was not checked against
    (is (pos? (:surface/stated-absences summary)))
    (is (every? #(str/includes? % "stated absences")
                (surfaces/describe catalog)))))
