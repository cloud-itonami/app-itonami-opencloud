(ns opencloud.azure
  "Azure Resource Manager responses.

  ARM is bearer-token JSON with a mandatory `api-version` query parameter, and
  it fails a request that omits it. That is a real client requirement, so this
  server enforces it rather than being forgiving in a way the real service is
  not."
  (:require [clojure.string :as str]
            [opencloud.wire :as wire]))

(defn- unauthorized []
  (wire/json-error 401 "AuthenticationFailed"
                   "Authentication failed. The 'Authorization' header is missing or malformed."))

(defn throttled
  "What ARM says when a subscription is being read too fast.

  429 with `Retry-After`, and the seconds in that header are the only thing
  that says when to come back — the body's code says nothing about timing. A
  client that retries on its own schedule is asking to be throttled again, and
  one that does not retry at all reports a partial subscription."
  []
  {:status 429
   :headers {"content-type" "application/json"
             "retry-after" "1"
             "x-ms-ratelimit-remaining-subscription-reads" "0"}
   :body (wire/json
          {"error" {"code" "TooManyRequests"
                    "message" (str "Number of read requests for subscription "
                                   "exceeded the limit. Please try again later.")}})})

(defn- json-ok [value]
  {:status 200
   :headers {"content-type" "application/json"}
   :body (wire/json value)})

(defn- paged
  "ARM pages with an absolute `nextLink`. It is built from the host the request
  arrived on, never from a configured base: a hardcoded one is correct only
  while the server happens to run where someone assumed it would, and it fails
  by silently producing a gap rather than by saying anything."
  [{:keys [seed host request-path query rows]}]
  (let [{:keys [items next-marker]} (wire/page rows (:page-size seed)
                                               (get query "skipToken"))]
    (cond-> {"value" items}
      next-marker (assoc "nextLink"
                         (str (if (str/starts-with? (str host) "http") "" "http://")
                              host request-path
                              "?api-version=" (get query "api-version")
                              "&skipToken=" next-marker)))))

(defn- resource-id [seed & parts]
  (str "/subscriptions/" (:subscription-id seed) (str/join parts)))

(defn throttle?
  "Deterministic: every nth request to this face is refused."
  [{:keys [throttle-every request-count]}]
  (and throttle-every
       (pos? throttle-every)
       (zero? (mod (inc (or request-count 0)) throttle-every))))

(defn- subscription-of
  "`/subscriptions/<id>/providers/...` — which subscription this request is
  about. ARM puts it in the path, so a client that scans two of them is
  visible in the URL and one that scans one is visible in the absence."
  [path]
  (second (re-find #"^/subscriptions/([^/]+)" (str path))))

(defn handle
  [{:keys [seed target headers]}]
  (let [[path raw-query] (wire/split-target target)
        query (wire/parse-query raw-query)
        host (get headers "host")
        token (get headers "authorization")
        ;; each subscription answers with its own estate. Without this a
        ;; client that scans the wrong one, or only one, gets the same
        ;; answer either way and the difference is invisible
        requested (subscription-of path)
        seed (if-let [other (get (:other-subscriptions seed) requested)]
               (merge (select-keys seed [:token :page-size :tenant-id
                                         :throttle-every :request-count
                                         :subscriptions :other-subscriptions])
                      other)
               seed)
        page (fn [rows] (paged {:seed seed :host host :request-path path
                                :query query :rows rows}))]
    (cond
      (not (and token (str/starts-with? (str/lower-case token) "bearer ")))
      (unauthorized)

      (not= (:token seed) (subs token 7))
      (unauthorized)

      ;; before anything else: a throttle is not a smaller subscription
      (throttle? seed)
      (throttled)

      (str/blank? (get query "api-version"))
      (wire/json-error 400 "MissingApiVersionParameter"
                       "The api-version query parameter (?api-version=) is required for all requests.")

      ;; what this credential can see at all. A scan of the subscription
      ;; somebody named is not a scan of the tenant, and this is the call
      ;; that says how many there were
      (= "/subscriptions" path)
      (json-ok
       (page
        (for [subscription (:subscriptions seed)]
          {"id" (str "/subscriptions/" (:subscription-id subscription))
           "subscriptionId" (:subscription-id subscription)
           "displayName" (:display-name subscription)
           "state" (:state subscription)
           "tenantId" (:tenant-id seed)})))

      ;; a subscription this credential cannot see is 403, not an empty one:
      ;; the difference is `you may not look` against `there is nothing there`
      (and requested
           (seq (:subscriptions seed))
           (not (contains? (set (map :subscription-id (:subscriptions seed)))
                           requested)))
      (wire/json-error 403 "AuthorizationFailed"
                       (str "The client does not have authorization to perform "
                            "action over scope '/subscriptions/" requested
                            "' or the scope is invalid."))

      (str/includes? path "/providers/Microsoft.Compute/virtualMachines")
      (json-ok
       (page
        (for [vm (:virtual-machines seed)]
          {"id" (resource-id seed "/resourceGroups/" (:resource-group vm)
                             "/providers/Microsoft.Compute/virtualMachines/"
                             (:name vm))
           "name" (:name vm)
           "location" (:location vm)
           "tags" (or (:tags vm) {})
           "properties" {"hardwareProfile" {"vmSize" (:size vm)}
                         "provisioningState" "Succeeded"}
           "identity" (when (:identity vm)
                        {"type" "SystemAssigned"
                         "principalId" (:identity vm)})})))

      (str/includes? path "/providers/Microsoft.Storage/storageAccounts")
      (json-ok
       (page
        (for [account (:storage-accounts seed)]
          {"id" (resource-id seed "/resourceGroups/" (:resource-group account)
                             "/providers/Microsoft.Storage/storageAccounts/"
                             (:name account))
           "name" (:name account)
           "location" (:location account)
           "properties" {"allowBlobPublicAccess" (boolean (:public? account))
                         "supportsHttpsTrafficOnly"
                         (boolean (:https-only? account))
                         "encryption" {"services"
                                       {"blob" {"enabled"
                                                (boolean (:encrypted? account))}}}}})))

      (str/includes? path "/providers/Microsoft.Authorization/roleAssignments")
      (json-ok
       (page
        (for [assignment (:role-assignments seed)]
          {"id" (resource-id seed "/providers/Microsoft.Authorization/roleAssignments/"
                             (:id assignment))
           "name" (:id assignment)
           "properties" {"roleDefinitionId" (:role-definition assignment)
                         "principalId" (:principal assignment)
                         "principalType" (:principal-type assignment)
                         "scope" (:scope assignment)}})))

      :else
      (wire/json-error
       404 "ResourceNotFound"
       (str "opencloud does not implement " path
            ". Implemented: virtualMachines, storageAccounts, roleAssignments.")))))
