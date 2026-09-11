(ns opencloud.gcp-test
  (:require [kotoba.lang.edn :as edn]
            [clojure.java.io :as io]
            [kotoba.lang.text :as str]
            [clojure.test :refer [deftest is testing]]
            [opencloud.gcp :as gcp]))

(def seed (edn/read-string (slurp (io/file "resources/seed/gcp.edn"))))

(defn- request [path & [overrides]]
  (gcp/handle {:seed (merge seed overrides)
               :target path
               :headers {"host" "compute.googleapis.com"
                         "authorization" (str "Bearer " (:token seed))}}))

(def instances-path
  (str "/compute/v1/projects/" (:project-id seed)
       "/zones/asia-northeast1-a/instances"))

(deftest a-quota-refusal-comes-in-two-shapes
  ;; 429 is the one everybody handles. The other is a 403 whose *body* says
  ;; rate limit — a status that means `you may not` carrying a message that
  ;; means `slow down`. A client that classifies by status alone records a
  ;; permanent permission gap, stops asking, and reports a project smaller
  ;; than the real one, with nothing in the output to say a retry would have
  ;; worked. Both shapes are served so a client meets both.
  (let [shapes (for [n (range 4)]
                 (request instances-path {:throttle-every 1 :request-count n}))
        statuses (set (map :status shapes))]
    (is (= #{429 403} statuses)
        "both refusal shapes must occur, not just the obvious one")
    (doseq [{:keys [status body headers]} shapes]
      (testing (str "shape " status)
        ;; the header is the only thing that knows when the window turns
        ;; over; without it a client retries on a schedule of its own
        ;; invention and is refused again
        (is (= "1" (get headers "retry-after")))
        (is (str/includes? body "\"reason\":\"rateLimitExceeded\"")
            "the reason is what makes a 403 readable as a throttle")
        ;; and it is emphatically not an empty list
        (is (not (str/includes? body "\"items\"")))))))

(deftest a-throttle-is-not-a-smaller-project
  ;; the refusal is decided before the path is looked at: every listing this
  ;; face serves can be throttled, not only the first one a client happens to
  ;; call
  (doseq [path [instances-path
                (str "/storage/v1/b?project=" (:project-id seed))
                (str "/v1/projects/" (:project-id seed) ":getIamPolicy")]]
    (let [{:keys [status]} (request path {:throttle-every 1 :request-count 0})]
      (is (= 429 status) (str path " must be throttleable")))))

(deftest an-untouched-request-still-answers
  (let [{:keys [status body]} (request instances-path {:throttle-every 3
                                                       :request-count 0})]
    (is (= 200 status))
    (is (str/includes? body "compute#instanceList")
        "the list carries its kind discriminator, not a generic REST shape")))

(deftest an-organisation-is-not-a-project
  ;; the credential can see two projects, and the one nobody would name holds
  ;; a bucket bound to allUsers with objectAdmin. A scanner pointed at the
  ;; other returns a clean report that never mentions it.
  (let [listing (:body (request "/v1/projects"))]
    (is (str/includes? listing "opencloud-example"))
    ;; paged like everything else, so a client that reads page one believes
    ;; the organisation is one project
    (is (str/includes? listing "nextPageToken"))
    (is (str/includes? (:body (request "/v1/projects?pageToken=1"))
                       "opencloud-sandbox")))

  ;; the other project really holds different resources
  (let [instances (:body (request (str "/compute/v1/projects/opencloud-sandbox"
                                       "/zones/asia-northeast1-a/instances")))]
    (is (str/includes? instances "sandbox-1"))
    (is (not (str/includes? instances "web-1"))))

  (let [buckets (:body (request "/storage/v1/b?project=opencloud-sandbox"))]
    (is (str/includes? buckets "sandbox-drop"))
    (is (not (str/includes? buckets "payroll-archive"))))

  ;; a bucket name is global and the IAM path carries no project, so the
  ;; policy resolves across every project — a server that searched only the
  ;; last-named project would 404 on a bucket it had just listed
  (let [{:keys [status body]} (request "/storage/v1/b/sandbox-drop/iam")]
    (is (= 200 status))
    (is (str/includes? body "allUsers"))
    (is (str/includes? body "storage.objectAdmin")))

  ;; a project outside what this credential can see is 403, not an empty one
  (is (= 403 (:status (request (str "/compute/v1/projects/somebody-elses"
                                    "/zones/asia-northeast1-a/instances"))))))
