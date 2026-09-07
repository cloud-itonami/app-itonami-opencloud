(ns opencloud.server
  "HTTP shim. The only part of this repository that touches a socket.

  Requests are verified before they are answered. A server that skips
  signature verification is a fixture, not a verification target: a client
  could sign nothing at all and still pass."
  (:require [opencloud.advisory :as advisory]
            [opencloud.sts :as sts]
            [opencloud.registry :as registry]
            [opencloud.registry-seed :as registry-seed]
            ["node:crypto" :as crypto]
            ["node:fs" :as fs]
            ["node:http" :as http]
            [kotoba.lang.edn :as edn]
            [clojure.string :as str]
            [opencloud.aws :as aws]
            [opencloud.ecr :as ecr]
            [opencloud.azure :as azure]
            [opencloud.gcp :as gcp]
            [opencloud.kubernetes :as kubernetes]
            [opencloud.sigv4-verify :as sigv4]
            [opencloud.wire :as wire]))

(def crypto-fns
  {:sha256-hex (fn [text]
                 (-> (.createHash crypto "sha256")
                     (.update text "utf8")
                     (.digest "hex")))
   :hmac-sha256 (fn [key* message]
                  (let [buffer (if (string? key*)
                                 (js/Buffer.from key* "utf8")
                                 (js/Buffer.from (clj->js (vec key*))))]
                    (vec (js/Array.from
                          (-> (.createHmac crypto "sha256" buffer)
                              (.update message "utf8")
                              (.digest))))))})

(defn- read-seed [path]
  (edn/read-string (.readFileSync fs path "utf8")))

(defn- headers-of [request]
  (into {} (map (fn [[k v]] [(str/lower-case (str k)) (str v)])
                (js->clj (.-headers request)))))

(defn- read-body [request]
  (js/Promise.
   (fn [resolve _]
     (let [chunks (atom "")]
       (.on request "data" #(swap! chunks str %))
       (.on request "end" #(resolve @chunks))))))

(defn- aws-response
  "Verify, then dispatch. `verbose?` echoes the canonical request on a
  mismatch, which is what a client author needs to find their own bug."
  [{:keys [seed verbose? aws-requests session-issued-at
           registry-requests registry-credential-issued-at]}
   {:keys [method target headers body]}]
  (let [[path raw-query] (wire/split-target target)
        query (wire/parse-query raw-query)
        host (get headers "host" "")
        verdict (sigv4/verify {:headers headers
                               :method method
                               :path (wire/percent-decode path)
                               :query query
                               :body-hash ((:sha256-hex crypto-fns)
                                           (or body ""))
                               :accounts (merge (:accounts seed)
                                               (sts/sessions seed))}
                              crypto-fns)]
    (if-not (:verified? verdict)
      (do
        (when (and verbose? (= :signature-mismatch (:reason verdict)))
          (.error js/console
                  (str "signature mismatch\n  expected " (:expected verdict)
                       "\n  provided " (:provided verdict)
                       "\n  canonical request:\n" (:canonical-request verdict))))
        (wire/error {:status (if (= :signature-mismatch (:reason verdict))
                               403 401)
                     :code (:code verdict)
                     :message (:message verdict)
                     :shape (if (str/includes? host "s3") :s3 :query)}))
      (let [principal (get (merge (:accounts seed) (sts/sessions seed))
                           (:access-key-id verdict))]
        ;; a client pointed at a local endpoint cannot put the service in the
        ;; host, but it already named the service in its credential scope, and
        ;; that is signed — so routing on it costs the client nothing
        (cond
          ;; a session past its expiry is renewable, and saying so is what
          ;; lets a client renew instead of failing
          ;; counted since this session was issued, not since the process
          ;; started: a global counter expires a freshly renewed session on
          ;; arrival, which no real service does
          (sts/session-expired? seed principal
                                (- @aws-requests (or @session-issued-at 0)))
          sts/expired-token-error

          ;; STS is its own service, and the credential scope names it
          (or (str/includes? host "sts") (= "sts" (:service verdict)))
          (let [sts-query (merge query (wire/parse-query
                                        body {:plus-is-space true}))]
            (when (= "AssumeRole" (get sts-query "Action"))
              (reset! session-issued-at @aws-requests))
            (sts/handle {:seed seed :query sts-query :principal principal}))

          ;; ECR is signed for its own service name, and it is the only AWS
          ;; face here that is not the query protocol
          (or (str/includes? host "ecr") (= "ecr" (:service verdict))
              (= "api.ecr" (:service verdict)))
          (do
            ;; a minted credential's life starts now
            (when (and registry-credential-issued-at
                       (= "GetAuthorizationToken" (ecr/operation headers)))
              (reset! registry-credential-issued-at @registry-requests))
            (ecr/handle {:seed seed :headers headers :principal principal
                       :encode (fn [text]
                                 (.toString (js/Buffer.from text "utf8")
                                            "base64"))}))

          (or (str/includes? host "s3") (= "s3" (:service verdict)))
          (aws/handle-s3 {:seed (assoc (aws/for-principal seed principal)
                                       :request-count
                                       (swap! aws-requests inc))
                          :host host :path path :query query})
          :else
          (aws/handle-query {:seed (assoc (aws/for-principal seed principal)
                                         :request-count
                                         (swap! aws-requests inc))
                             ;; the region is in the credential scope and the
                             ;; scope is signed, so it is the client's own
                             ;; claim about where it thinks it is looking
                             :region (:region verdict)
                             :query (merge query
                                           (wire/parse-query
                                            body {:plus-is-space true}))
                             :principal principal}))))))

(defn- respond! [response {:keys [status headers body]}]
  (.writeHead response status (clj->js (or headers {})))
  (.end response (or body "")))

(defn handler
  [{:keys [seed azure-seed gcp-seed kubernetes-seed] :as options}]
  (fn [request response]
    (-> (read-body request)
        (.then
         (fn [body]
           (let [headers (headers-of request)
                 host (get headers "host" "")
                 context {:method (.-method request)
                          :target (.-url request)
                          :headers headers
                          :body body}]
             (respond!
              response
              (cond
                ;; the one AWS call that carries no AWS credential, so it is
                ;; routed before anything tries to verify one. A client whose
                ;; AWS layer cannot build an unsigned request never gets here
                (and (str/includes? (str (:body context))
                                    "Action=AssumeRoleWithWebIdentity")
                     (str/blank? (str (get headers "authorization" ""))))
                (do
                  ;; a session's life is counted from the moment it is
                  ;; issued, whichever call issued it. Forgetting this for
                  ;; one of them expires a freshly issued session on arrival
                  ;; and makes a client that renews correctly look broken —
                  ;; which has now happened three times in this server, for
                  ;; STS sessions, registry credentials and this
                  (reset! (:session-issued-at options) @(:aws-requests options))
                  (sts/handle {:seed (:seed options)
                               :query (wire/parse-query (:body context)
                                                        {:plus-is-space true})}))

                (or (str/includes? host "amazonaws.com")
                    (str/starts-with? (str (get headers "authorization" ""))
                                      "AWS4-HMAC-SHA256"))
                (aws-response options context)

                ;; a client aimed at a local endpoint cannot put the
                ;; provider in the host, but the path shape names it in every
                ;; request and costs the client nothing
                (or (str/includes? host "azure.com")
                    (str/starts-with? (:target context) "/subscriptions"))
                (azure/handle
                 (assoc context :seed
                        (assoc azure-seed :request-count
                               (swap! (:azure-requests options) inc))))

                ;; narrow on purpose: GCP's resource manager also lives
                ;; under /v1/, and a prefix match here takes its requests
                (re-find #"^/v1/(query|querybatch|vulns/)" (:target context))
                (advisory/handle
                 (assoc context :seed (assoc (:advisory-seed options)
                                             :request-count
                                             (swap! (:advisory-requests options)
                                                    inc))
                        :parsed-body (when (seq (str (:body context)))
                                       (try (js->clj (js/JSON.parse (:body context)))
                                            (catch :default _ nil)))))

                ;; the registry protocol is entirely under /v2/ plus the
                ;; token endpoint its own challenge points at
                (or (str/starts-with? (:target context) "/v2/")
                    (str/starts-with? (:target context) "/token?")
                    ;; where a redirected blob lands
                    (str/starts-with? (:target context) "/blobstore/"))
                (registry/handle
                 (assoc context :seed
                        (assoc (:registry-seed options)
                               :request-count
                               (swap! (:registry-requests options) inc)
                               :credential-issued-at
                               @(:registry-credential-issued-at options))))

                ;; the API server's paths are unmistakable, which is what
                ;; lets a client aim at a local endpoint without changing
                (re-find #"^/(api|apis)/" (:target context))
                (kubernetes/handle (assoc context :seed kubernetes-seed
                                          :method (:method context)))

                (or (str/includes? host "googleapis.com")
                    (re-find #"^/(compute|storage)/v\d" (:target context))
                    (re-find #"^/v\d+/projects/[^/]+:" (:target context))
                    ;; projects.list: the discovery call, and the only GCP
                    ;; path with nothing after `projects` to route on
                    (re-find #"^/v\d+/projects(\?|$)" (:target context)))
                (gcp/handle
                 (assoc context :seed
                        (assoc gcp-seed :request-count
                               (swap! (:gcp-requests options) inc))))

                ;; a request with no recognisable provider host is a client
                ;; misconfiguration, and saying so beats a confusing 404
                :else
                (wire/json-error
                 400 "UnknownProvider"
                 (str "Host '" host "' does not name a provider this server "
                      "emulates. Point aws at *.amazonaws.com, azure at "
                      "management.azure.com, gcp at *.googleapis.com.")))))))
        (.catch (fn [error]
                  (respond! response
                            (wire/json-error 500 "InternalError"
                                             (str (.-message error)))))))))

(defn -main [& args]
  (let [options (into {} (map (fn [[k v]] [(keyword (str/replace k #"^--" "")) v])
                              (partition 2 args)))
        port (js/parseInt (or (:port options)
                              (aget (.-env js/process) "OPENCLOUD_PORT")
                              "4566")
                          10)
        seed (cond-> (read-seed (or (:aws-seed options) "resources/seed/aws.edn"))
               (:throttle-every options)
               (assoc :throttle-every (js/parseInt (:throttle-every options) 10))
               ;; the customer-side half of the confused-deputy control:
               ;; the trust policy names an ExternalId and a scanner that
               ;; does not send it is refused
               (:require-external-id options)
               (assoc :external-ids
                      (into {} (map (fn [role]
                                      [role (:require-external-id options)]))
                            (:assumable-roles
                             (read-seed (or (:aws-seed options)
                                            "resources/seed/aws.edn")))))
               ;; the OIDC token a workload identity provider writes to
               ;; disk. Fixed here; what matters is that it is checked, so a
               ;; client that caches a rotated one is visible
               (:web-identity-token options)
               (assoc :web-identity-token (:web-identity-token options))
               (:deny-posture options)
               (assoc :posture-denied (:deny-posture options))
               (:inconsistent-every options)
               (assoc :inconsistent-every
                      (js/parseInt (:inconsistent-every options) 10))
               (:session-ttl-requests options)
               (assoc :session-ttl-requests
                      (js/parseInt (:session-ttl-requests options) 10)))
        ;; one flag for every face: a fleet is not throttled by one provider
        ;; at a time, and each provider says so in a different shape
        throttle-every (some-> (:throttle-every options) (js/parseInt 10))
        azure-seed (cond-> (read-seed (or (:azure-seed options)
                                          "resources/seed/azure.edn"))
                     throttle-every (assoc :throttle-every throttle-every))
        gcp-seed (cond-> (read-seed (or (:gcp-seed options)
                                        "resources/seed/gcp.edn"))
                   throttle-every (assoc :throttle-every throttle-every))
        kubernetes-seed (cond-> (read-seed (or (:kubernetes-seed options)
                                               "resources/seed/kubernetes.edn"))
                          (:namespaced-only options)
                          (assoc :namespaced-only? true)
                          ;; a ClusterRole that lets a namespace-scoped
                          ;; credential list namespaces, so it can find out
                          ;; which ones it has instead of being told
                          (:namespace-discovery options)
                          (assoc :namespace-discovery? true))
        advisory-requests (atom 0)
        aws-requests (atom 0)
        azure-requests (atom 0)
        registry-requests (atom 0)
        registry-credential-issued-at (atom 0)
        gcp-requests (atom 0)
        session-issued-at (atom 0)
        registry-seed (assoc (registry-seed/build
                              {:base-url (or (:registry-base-url options)
                                             (str "http://127.0.0.1:" port))})
                             ;; off by default: a client is checked against the
                             ;; plain path first and against this one on
                             ;; purpose
                             :redirect-blobs? (some? (:redirect-blobs options))
                             ;; --registry-basic-auth user:pass turns the
                             ;; whole face into a Basic-auth registry: no
                             ;; token endpoint, credential on every request
                             :basic-auth
                             (some-> (:registry-basic-auth options)
                                     (#(.toString (js/Buffer.from %) "base64")))
                             ;; how many requests a minted credential lasts.
                             ;; Wall-clock expiry cannot be tested without
                             ;; waiting, and a scanner's real failure is not
                             ;; that twelve hours passed — it is that a scan
                             ;; big enough to outlive its token was in the
                             ;; middle of reading layers when it did
                             :credential-ttl-requests
                             (some-> (:registry-ttl-requests options)
                                     (js/parseInt 10))
                             ;; what a client that minted a token at the ECR
                             ;; face will present here
                             :ecr-basic-auth
                             (when (:registry-basic-auth options)
                               (.toString
                                (js/Buffer.from
                                 (str "AWS:opencloud-ecr."
                                      (:account-id
                                       (read-seed (or (:aws-seed options)
                                                      "resources/seed/aws.edn"))))
                                 "utf8")
                                "base64"))
                             ;; the same process, a different host name: real
                             ;; object storage is somewhere else entirely
                             :blob-store-url (str "http://localhost:" port))
        advisory-seed (cond-> (read-seed (or (:advisory-seed options)
                                             "resources/seed/advisory.edn"))
                        (:throttle-every options)
                        (assoc :throttle-every
                               (js/parseInt (:throttle-every options) 10)))
        server (.createServer http (handler {:seed seed
                                             :advisory-seed advisory-seed
                                             :advisory-requests advisory-requests
                                             :aws-requests aws-requests
                                             :azure-requests azure-requests
                                             :registry-requests registry-requests
                                             :registry-credential-issued-at
                                             registry-credential-issued-at
                                             :gcp-requests gcp-requests
                                             :session-issued-at session-issued-at
                                             :registry-seed registry-seed
                                             :azure-seed azure-seed
                                             :gcp-seed gcp-seed
                                             :kubernetes-seed kubernetes-seed
                                             :verbose? (some? (:verbose options))}))]
    (.listen server port
             (fn []
               (.log js/console
                     (str "opencloud listening on " port
                          "\n  aws   account " (:account-id seed)
                          ", key " (first (keys (:accounts seed)))
                          "\n  azure subscription " (:subscription-id azure-seed)
                          "\n  gcp   project " (:project-id gcp-seed)
                          "\n  k8s   cluster " (:cluster kubernetes-seed)
                          "\n  oci   " (str/join ", " (sort (keys (:repositories registry-seed))))
                          "\n  osv   " (count (:records advisory-seed)) " advisories"))))))

(defn main [& args] (apply -main args))
