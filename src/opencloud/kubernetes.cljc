(ns opencloud.kubernetes
  "Kubernetes API server responses.

  A cluster answers bearer-token JSON like the other providers, but it lists
  differently: every response is a typed List with its own `kind`, and the
  continuation token lives in `metadata.continue` rather than in a field named
  after paging. A client written against a generic REST shape reads the first
  page and calls it the cluster."
  (:require [kotoba.lang.text :as str]
            [opencloud.wire :as wire]))

(defn- json-ok [value]
  {:status 200
   :headers {"content-type" "application/json"}
   :body (wire/json value)})

(defn- unauthorized []
  {:status 401
   :headers {"content-type" "application/json"}
   :body (wire/json {"kind" "Status" "apiVersion" "v1" "status" "Failure"
                     "message" "Unauthorized" "reason" "Unauthorized"
                     "code" 401})})

(defn- forbidden [verb resource]
  {:status 403
   :headers {"content-type" "application/json"}
   :body (wire/json {"kind" "Status" "apiVersion" "v1" "status" "Failure"
                     "reason" "Forbidden"
                     "message" (str "opencloud permits only get, list, and "
                                    "watch; " verb " on " resource
                                    " is refused")
                     "code" 403})})

(defn- forbidden-scope [resource]
  {:status 403
   :headers {"content-type" "application/json"}
   :body (wire/json
          {"kind" "Status" "apiVersion" "v1"
           "status" "Failure"
           "message" (str "pods is forbidden: User \"system:serviceaccount:"
                          "opencloud:scanner\" cannot list resource \""
                          resource "\" in API group \"\" at the cluster scope")
           "reason" "Forbidden"
           "code" 403})})

(defn- not-found [path]
  {:status 404
   :headers {"content-type" "application/json"}
   :body (wire/json {"kind" "Status" "apiVersion" "v1" "status" "Failure"
                     "reason" "NotFound"
                     "message" (str "opencloud does not implement " path)
                     "code" 404})})

(def ^:private collections
  "Path suffix -> the seed key and the List kind the API server returns."
  {"pods" [:pods "PodList"]
   "services" [:services "ServiceList"]
   "serviceaccounts" [:service-accounts "ServiceAccountList"]
   "secrets" [:secrets "SecretList"]
   "roles" [:roles "RoleList"]
   "clusterroles" [:cluster-roles "ClusterRoleList"]
   "rolebindings" [:role-bindings "RoleBindingList"]
   "clusterrolebindings" [:cluster-role-bindings "ClusterRoleBindingList"]})

(defn- listed
  "A typed List with the continuation where the API server really puts it."
  [seed kind rows query]
  (let [{:keys [items next-marker]} (wire/page rows (:page-size seed)
                                               (get query "continue"))]
    (json-ok
     (cond-> {"kind" kind
              "apiVersion" (if (str/starts-with? kind "Cluster") "v1" "v1")
              "metadata" (cond-> {"resourceVersion" "1"}
                           next-marker (assoc "continue" next-marker))}
       true (assoc "items" items)))))

(def cluster-scoped
  "Kinds that only exist cluster-wide. A namespace-scoped credential cannot
  read them at all, and pretending otherwise would let a client believe a
  namespaced scan is a whole-cluster one."
  #{"clusterroles" "clusterrolebindings"})

(defn- namespace-of
  "`/api/v1/namespaces/prod/pods` -> `prod`, or nil for a cluster-wide path."
  [path]
  (second (re-find #"/namespaces/([^/]+)/" (str path))))

(defn- in-namespace [rows namespace*]
  (if (nil? namespace*)
    (vec rows)
    (vec (filter #(= namespace* (get-in % ["metadata" "namespace"])) rows))))

(defn- namespace-list
  "`/api/v1/namespaces`, which is itself a cluster-scoped read.

  This is the shape RBAC really takes: a credential bound to two namespaces,
  plus a ClusterRole that lets it *list namespaces* so it can find out which
  ones. Without the second, a client has to be told — and a client that is
  told is a client whose operator can forget one."
  [seed]
  (let [names (vec (sort (distinct (keep #(get-in % ["metadata" "namespace"])
                                         (mapcat (fn [key*] (get seed key*))
                                                 [:pods :services :secrets
                                                  :service-accounts :roles
                                                  :role-bindings])))))]
    (json-ok {"kind" "NamespaceList"
         "apiVersion" "v1"
         "metadata" {}
         "items" (for [name* names]
                    {"kind" "Namespace"
                     "apiVersion" "v1"
                     "metadata" {"name" name*}
                     "status" {"phase" "Active"}})})))

(defn handle
  [{:keys [seed target headers method]}]
  (let [[path raw-query] (wire/split-target target)
        query (wire/parse-query raw-query)
        token (get headers "authorization")
        suffix (last (str/split path #"/"))
        namespace* (namespace-of path)
        [seed-key kind] (get collections suffix)]
    (cond
      (not (and token (str/starts-with? (str/lower token) "bearer ")))
      (unauthorized)

      (not= (:token seed) (subs token 7))
      (unauthorized)

      ;; the API names its verbs, so refusing a write is exact rather than a
      ;; guess about what the method means
      (not (contains? #{"GET" nil} (or method "GET")))
      (forbidden (str/lower (str method)) suffix)

      ;; how a namespace-scoped credential finds out which namespaces it has.
      ;; Cluster-scoped itself, so a credential without the ClusterRole for it
      ;; is refused here too — and then a client really does have to be told
      (= "/api/v1/namespaces" path)
      (if (:namespace-discovery? seed)
        (namespace-list seed)
        (forbidden-scope "namespaces"))

      (nil? kind) (not-found path)

      ;; a credential bound to namespaces cannot list across the cluster, and
      ;; the API server says so rather than answering with nothing. A client
      ;; that reads this 403 as an empty cluster reports a clean cluster
      (and (:namespaced-only? seed) (nil? namespace*))
      (forbidden-scope suffix)

      ;; and there is no namespaced path to fall back to for these
      (and namespace* (contains? cluster-scoped suffix))
      (not-found path)

      :else (listed seed kind (in-namespace (get seed seed-key) namespace*)
                    query))))
