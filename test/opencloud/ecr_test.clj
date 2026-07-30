(ns opencloud.ecr-test
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [opencloud.ecr :as ecr]))

(def seed (edn/read-string (slurp (io/file "resources/seed/aws.edn"))))

(defn- b64 [text]
  (.encodeToString (java.util.Base64/getEncoder) (.getBytes ^String text "UTF-8")))

(defn- ask [headers]
  (ecr/handle {:seed seed :headers headers :encode b64
               :principal (first (vals (:accounts seed)))}))

(deftest the-operation-is-a-header-not-a-parameter
  ;; ECR is AWS JSON 1.1. A client whose AWS layer only knows the query
  ;; protocol sends `Action=GetAuthorizationToken` and gets nothing, and the
  ;; way that presents downstream is a 401 from a registry with no mention of
  ;; AWS anywhere in it
  (is (= 400 (:status (ask {}))))
  (is (str/includes? (:body (ask {})) "X-Amz-Target"))
  (is (= 400 (:status (ask {"x-amz-target"
                            (str ecr/target-prefix "DescribeRepositories")}))))
  (is (= 200 (:status (ask {"x-amz-target"
                            (str ecr/target-prefix "GetAuthorizationToken")})))))

(deftest the-token-is-a-basic-credential-with-a-fixed-username
  (let [body (:body (ask {"x-amz-target"
                          (str ecr/target-prefix "GetAuthorizationToken")}))
        token (second (re-find #"\"authorizationToken\":\"([^\"]+)\"" body))
        decoded (String. (.decode (java.util.Base64/getDecoder) ^String token)
                         "UTF-8")]
    ;; `AWS` for every account: a client that stores this as a username and
    ;; password pair is storing something that works in one place, briefly
    (is (str/starts-with? decoded "AWS:"))
    (is (str/includes? decoded (:account-id seed)))
    ;; and the registry it opens is named by the service, not assembled by
    ;; the client — which gets it wrong for every non-default partition
    (is (str/includes? body "proxyEndpoint"))
    (is (str/includes? body (str (:account-id seed) ".dkr.ecr.")))
    (is (str/includes? body "expiresAt"))))
