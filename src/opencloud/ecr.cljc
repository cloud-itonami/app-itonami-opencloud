(ns opencloud.ecr
  "Elastic Container Registry, and the one thing about it that matters here:
  **the credential is minted, not configured.**

  Every other registry this server emulates is handed a username and password.
  ECR is not: a client signs an AWS request with its own role, receives a
  short-lived token, and presents that token to the registry as ordinary Basic
  auth. So a scanner running in AWS — which is most of them — needs a path
  nobody stores a secret for.

  It is also the only AWS API here that is not the query protocol. ECR speaks
  **AWS JSON 1.1 over POST**: the operation is in an `X-Amz-Target` header
  rather than an `Action` parameter, the body is JSON rather than form
  encoding, and the signature covers the body. A client whose AWS layer only
  ever issues signed GETs cannot call it at all, and the way that failure
  presents is `we cannot authenticate to your registry` rather than anything
  about protocols."
  (:require [kotoba.lang.text :as str]
            [opencloud.wire :as wire]))

(def target-prefix "AmazonEC2ContainerRegistry_V20150921.")

(defn- json-error [status code message]
  {:status status
   :headers {"content-type" "application/x-amz-json-1.1"}
   :body (wire/json {"__type" code "message" message})})

(defn operation
  "Which operation a request names. `X-Amz-Target` and nothing else — a client
  that puts the name in the body or the query string is talking to a protocol
  this service does not speak."
  [headers]
  (let [target (str (get headers "x-amz-target"))]
    (when (str/starts-with? target target-prefix)
      (subs target (count target-prefix)))))

(defn authorization-token
  "The token a client presents to the registry, and what it is made of.

  Base64 of `AWS:<password>` — the username is literally `AWS` for every
  account, which is why a client that stores this as a username/password pair
  and reuses it across registries is storing something that only ever works in
  one place, briefly."
  [{:keys [account-id registry-token]} encode]
  (encode (str "AWS:" (or registry-token "opencloud-ecr") "." account-id)))

(defn handle
  [{:keys [seed headers principal encode]}]
  (let [account (or (:account-id principal) (:account-id seed))]
    (case (operation headers)
      "GetAuthorizationToken"
      {:status 200
       :headers {"content-type" "application/x-amz-json-1.1"}
       :body (wire/json
              {"authorizationData"
               [{"authorizationToken"
                 (authorization-token (assoc seed :account-id account) encode)
                 ;; the registry this token opens, named by the service rather
                 ;; than assembled by the client: a client that builds the
                 ;; host itself gets it wrong for every non-default partition
                 "proxyEndpoint" (str "https://" account ".dkr.ecr."
                                      (or (:default-region seed) "us-east-1")
                                      ".amazonaws.com")
                 ;; twelve hours, and the client is expected to notice
                 "expiresAt" "2036-01-01T00:00:00Z"}]})}

      nil
      (json-error 400 "InvalidSignatureException"
                  (str "no X-Amz-Target header: ECR is AWS JSON 1.1 and names "
                       "its operation in a header, not in an Action parameter"))

      (json-error 400 "UnknownOperationException"
                  (str "opencloud does not implement "
                       (operation headers)
                       ". Implemented: GetAuthorizationToken.")))))
