(ns opencloud.advisory-test
  (:require [kotoba.lang.edn :as edn]
            [clojure.java.io :as io]
            [kotoba.lang.text :as str]
            [clojure.test :refer [deftest is]]
            [opencloud.advisory :as advisory]))

(def seed (edn/read-string (slurp (io/file "resources/seed/advisory.edn"))))

(defn- post [path body]
  (advisory/handle {:seed seed :method "POST" :target path :parsed-body body}))

(defn- get* [path]
  (advisory/handle {:seed seed :method "GET" :target path}))

(deftest querybatch-answers-with-identifiers-and-not-with-advisories
  (let [response (post "/v1/querybatch"
                       {"queries" [{"package" {"name" "lodash"
                                               "ecosystem" "npm"}
                                    "version" "4.17.19"}]})]
    (is (= 200 (:status response)))
    ;; identifiers and modification times only. A client that reads these as
    ;; advisories holds records that name no package and no version range,
    ;; matches nothing, and reports every host clean
    (is (str/includes? (:body response) "\"id\":\"GHSA-p6mc-m468-83gg\""))
    (is (str/includes? (:body response) "\"modified\""))
    (is (not (str/includes? (:body response) "affected")))
    (is (not (str/includes? (:body response) "ranges"))))
  ;; the real API bounds a batch, and a client that ignores the bound is told
  (is (= 400 (:status (post "/v1/querybatch"
                            {"queries" (repeat 9 {"package" {"name" "x"}})})))))

(deftest query-answers-with-whole-records-and-pages-with-a-token
  (let [first-page (post "/v1/query" {"package" {"name" "lodash"
                                                 "ecosystem" "npm"}
                                      "version" "4.17.19"})
        body (:body first-page)]
    (is (= 200 (:status first-page)))
    (is (str/includes? body "\"affected\""))
    ;; the seed pages one at a time so a client that stops at the first page
    ;; is visible
    (is (str/includes? body "\"next_page_token\":\"1\""))
    (let [second-page (post "/v1/query" {"package" {"name" "lodash"
                                                    "ecosystem" "npm"}
                                         "version" "4.17.19"
                                         "page_token" "1"})]
      (is (not= body (:body second-page)))
      (is (str/includes? (:body second-page) "GHSA-35jh-r3h4-6jhm"))))
  ;; a token this server did not issue is a client that built its own
  (is (thrown? clojure.lang.ExceptionInfo
               (post "/v1/query" {"package" {"name" "lodash"}
                                  "page_token" "cursor-1"}))))

(deftest an-unqualified-ecosystem-reaches-a-qualified-one
  ;; `Debian` is how a client asks without knowing the release; `Debian:11`
  ;; is how the advisory is filed
  (is (str/includes? (:body (post "/v1/query" {"package" {"name" "openssl"
                                                          "ecosystem" "Debian"}}))
                     "DSA-5343-1"))
  (is (str/includes? (:body (post "/v1/query" {"package" {"name" "openssl"
                                                          "ecosystem" "Debian:11"}}))
                     "DSA-5343-1"))
  (is (not (str/includes? (:body (post "/v1/query" {"package" {"name" "openssl"
                                                               "ecosystem" "npm"}}))
                          "DSA-5343-1"))))

(deftest an-identifier-that-does-not-resolve-is-a-404
  (is (= 200 (:status (get* "/v1/vulns/GHSA-p6mc-m468-83gg"))))
  (is (str/includes? (:body (get* "/v1/vulns/GHSA-p6mc-m468-83gg")) "affected"))
  ;; a hole in what the client can know, not an advisory with nothing in it
  (is (= 404 (:status (get* "/v1/vulns/GHSA-does-not-exist"))))
  (is (= 404 (:status (get* "/v1/nonsense")))))

(deftest a-withdrawn-record-is-still-served
  ;; the API does not hide it — deciding what a withdrawal means is the
  ;; client's job, and a server that filtered it would hide the decision
  (is (str/includes? (:body (get* "/v1/vulns/GHSA-withdrawn-example"))
                     "withdrawn")))

(deftest the-advisory-face-does-not-answer-for-another-face
  ;; GCP's resource manager also lives under /v1/, and a prefix match here
  ;; takes its requests — which fails as a routing error rather than as a
  ;; wrong answer only because it is caught
  (is (= 404 (:status (get* "/v1/projects/example:getIamPolicy"))))
  (is (= 404 (:status (get* "/v1/anything-else")))))

(deftest a-throttled-request-is-a-refusal-and-not-an-empty-answer
  (let [throttling (assoc seed :throttle-every 2)
        first-call (advisory/handle {:seed (assoc throttling :request-count 0)
                                     :method "POST" :target "/v1/query"
                                     :parsed-body {"package" {"name" "lodash"}}})
        second-call (advisory/handle {:seed (assoc throttling :request-count 1)
                                      :method "POST" :target "/v1/query"
                                      :parsed-body {"package" {"name" "lodash"}}})]
    (is (= 200 (:status first-call)))
    ;; a client that reads 429 as an answer reports a throttled scan as a
    ;; clean fleet, and no recorded response can show that
    (is (= 429 (:status second-call)))
    (is (= "2" (get-in second-call [:headers "retry-after"])))
    (is (str/includes? (:body second-call) "rate limit exceeded"))
    (is (not (str/includes? (:body second-call) "vulns")))))
