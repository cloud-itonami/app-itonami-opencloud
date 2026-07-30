(ns opencloud.gcp
  "Google Cloud JSON API responses.

  GCP is bearer-token JSON, but its list responses carry a `kind` discriminator
  and paginate with `nextPageToken` rather than a marker. A client written
  against a generic REST shape misses both."
  (:require [clojure.string :as str]
            [opencloud.wire :as wire]))

(defn- json-ok [value]
  {:status 200
   :headers {"content-type" "application/json"}
   :body (wire/json value)})

(defn- unauthorized []
  {:status 401
   :headers {"content-type" "application/json"}
   :body (wire/json {"error" {"code" 401
                              "message" "Request had invalid authentication credentials."
                              "status" "UNAUTHENTICATED"}})})

(defn throttled
  "What Google says when a project is being read too fast — in two shapes.

  429 `RESOURCE_EXHAUSTED` is the one people expect. The other is **403 with
  `reason: rateLimitExceeded`**, and it is the dangerous one: a 403 reads as
  `this credential may not call this API`, so a client that classifies by
  status records a permanent permission gap and never asks again. The estate
  it reports is smaller than the real one and nothing in the output says a
  retry would have worked. Both shapes come back here, alternating, so a
  client that only handles the obvious one is caught."
  [request-count]
  (if (even? (quot (or request-count 0) 2))
    {:status 429
     :headers {"content-type" "application/json" "retry-after" "1"}
     :body (wire/json
            {"error" {"code" 429
                      "message" (str "Quota exceeded for quota metric "
                                     "'Queries' and limit 'Queries per minute'")
                      "status" "RESOURCE_EXHAUSTED"
                      "errors" [{"message" "Rate Limit Exceeded"
                                 "domain" "usageLimits"
                                 "reason" "rateLimitExceeded"}]}})}
    {:status 403
     :headers {"content-type" "application/json" "retry-after" "1"}
     :body (wire/json
            {"error" {"code" 403
                      "message" "Rate Limit Exceeded"
                      "status" "PERMISSION_DENIED"
                      "errors" [{"message" "Rate Limit Exceeded"
                                 "domain" "usageLimits"
                                 "reason" "rateLimitExceeded"}]}})}))

(defn throttle?
  [{:keys [throttle-every request-count]}]
  (and throttle-every
       (pos? throttle-every)
       (zero? (mod (inc (or request-count 0)) throttle-every))))

(defn- project-of
  "Which project a request is about. Google puts it in three different places
  depending on the API — the compute path, the storage query string, and the
  resource-manager path — which is itself a reason a client scans the wrong
  one without noticing."
  [path query]
  (or (second (re-find #"/compute/v1/projects/([^/]+)" (str path)))
      (second (re-find #"/v1/projects/([^/:]+)" (str path)))
      (get query "project")))

(defn handle
  [{:keys [seed target headers]}]
  (let [[path raw-query] (wire/split-target target)
        query (wire/parse-query raw-query)
        token (get headers "authorization")
        ;; each project answers with its own estate: without this a client
        ;; that scans one project twice, or the wrong one, gets the same
        ;; answer either way
        requested (project-of path query)
        seed (if-let [other (get (:other-projects seed) requested)]
               (merge (select-keys seed [:token :page-size :projects
                                         :other-projects :throttle-every
                                         :request-count])
                      other)
               seed)]
    (cond
      (not (and token (str/starts-with? (str/lower-case token) "bearer ")))
      (unauthorized)

      (not= (:token seed) (subs token 7))
      (unauthorized)

      ;; before anything else: a throttle is not a smaller project
      (throttle? seed)
      (throttled (:request-count seed))

      ;; what this credential can see at all. `projects.list` is how an
      ;; organisation is discovered, and skipping it is how a scan of one
      ;; project comes to be read as a scan of the organisation
      (re-find #"^/v1/projects(\?|$)" path)
      (json-ok
       (let [{:keys [items next-marker]} (wire/page (:projects seed)
                                                    (:page-size seed)
                                                    (get query "pageToken"))]
         (cond-> {}
           next-marker (assoc "nextPageToken" next-marker)
           true (assoc "projects"
                       (for [project items]
                         {"projectId" (:project-id project)
                          "projectNumber" (:project-number project)
                          "name" (:name project)
                          "lifecycleState" (:lifecycle-state project)})))))

      ;; a project this credential cannot see is 403, not an empty project
      (and requested
            (seq (:projects seed))
            (not (contains? (set (map :project-id (:projects seed))) requested)))
      {:status 403
       :headers {"content-type" "application/json"}
       :body (wire/json
              {"error" {"code" 403
                        "message" (str "Required 'compute.instances.list' "
                                       "permission for 'projects/" requested "'")
                        "status" "PERMISSION_DENIED"}})}

      (re-find #"/compute/v1/projects/[^/]+/zones/[^/]+/instances" path)
      (json-ok
       (let [{:keys [items next-marker]} (wire/page (:instances seed)
                                                   (:page-size seed)
                                                   (get query "pageToken"))]
        (cond-> {"kind" "compute#instanceList"
                 "id" (str "projects/" (:project-id seed) "/zones/instances")}
          next-marker (assoc "nextPageToken" next-marker)
          true (assoc
                "items"
                (for [instance items]
                  {"kind" "compute#instance"
                   "id" (:id instance)
                   "name" (:name instance)
                   "status" (:status instance)
                   "machineType" (:machine-type instance)
                   "serviceAccounts"
                   (for [account (:service-accounts instance)]
                     {"email" account
                      "scopes" ["https://www.googleapis.com/auth/cloud-platform"]})
                   "networkInterfaces"
                   [{"network" "global/networks/default"
                     "accessConfigs" (when (:public-ip instance)
                                       [{"type" "ONE_TO_ONE_NAT"
                                         "natIP" (:public-ip instance)}])}]})))))

      (re-find #"/storage/v1/b/[^/]+/iam$" path)
      ;; a bucket name is global in GCS and the path carries no project, so
      ;; the lookup spans every project this credential can see. A server that
      ;; only searched the project the last request happened to name would
      ;; 404 on a bucket it had just listed
      (let [name* (second (re-find #"/storage/v1/b/([^/]+)/iam$" path))
            all-buckets (concat (:buckets seed)
                                (mapcat :buckets (vals (:other-projects seed))))
            bucket (first (filter #(= name* (:name %)) all-buckets))]
        (if bucket
          (json-ok
           {"kind" "storage#policy"
            "version" 1
            "bindings" (for [binding (:bucket-bindings bucket)]
                         {"role" (:role binding) "members" (:members binding)})})
          {:status 404
           :headers {"content-type" "application/json"}
           :body (wire/json {"error" {"code" 404 "message" "Not Found"
                                      "status" "NOT_FOUND"}})}))

      (re-find #"/storage/v1/b(\?|$)" path)
      (json-ok
       (let [{:keys [items next-marker]} (wire/page (:buckets seed)
                                                   (:page-size seed)
                                                   (get query "pageToken"))]
        (cond-> {"kind" "storage#buckets"}
          next-marker (assoc "nextPageToken" next-marker)
          true (assoc
                "items"
                (for [bucket items]
                  {"kind" "storage#bucket"
                   "id" (:name bucket)
                   "name" (:name bucket)
                   "location" (:location bucket)
                   "labels" (or (:labels bucket) {})
                   "iamConfiguration"
                   {"uniformBucketLevelAccess"
                    {"enabled" (boolean (:uniform-access? bucket))}
                    "publicAccessPrevention" (if (:public? bucket)
                                               "inherited" "enforced")}
                   "encryption" (when (:kms-key bucket)
                                  {"defaultKmsKeyName" (:kms-key bucket)})})))))

      (re-find #"/v1/projects/[^/]+:getIamPolicy" path)
      (json-ok
       {"version" 1
        "bindings" (for [binding (:iam-bindings seed)]
                     {"role" (:role binding)
                      "members" (:members binding)})})

      :else
      {:status 404
       :headers {"content-type" "application/json"}
       :body (wire/json
              {"error" {"code" 404
                        "message" (str "opencloud does not implement " path
                                       ". Implemented: compute instances, "
                                       "storage buckets, project IAM policy.")
                        "status" "NOT_FOUND"}})})))
