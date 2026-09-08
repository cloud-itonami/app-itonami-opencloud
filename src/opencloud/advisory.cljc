(ns opencloud.advisory
  "The OSV API.

  The shape that catches clients is `querybatch`. It takes many queries at
  once and answers with *identifiers only* — `id` and `modified`, no
  `affected`, no ranges. A client that reads those as advisories gets records
  that name no package and no version range, matches nothing against them, and
  reports every host clean. Nothing in the response says it is a summary; it
  simply is one, and a recorded response of it looks like a complete answer.

  So this serves the real thing: `query` returns whole records and pages with
  an opaque token, `querybatch` returns identifiers and the client has to go
  and fetch each one, `GET /v1/vulns/{id}` serves the record, and an id that
  is not there is a 404 rather than an empty object."
  (:require [kotoba.lang.text :as str]
            [opencloud.wire :as wire]))

(defn- matches?
  "Whether a record affects this package. Deliberately simple — this is a
  server, and what it has to be is consistent, not clever."
  [record {:keys [name ecosystem version]}]
  (some (fn [entry]
          (let [package (get entry "package")
                ecosystem* (get package "ecosystem")]
            (and (= name (get package "name"))
                 (or (str/blank? (str ecosystem))
                     (= ecosystem ecosystem*)
                     ;; `Debian` matches `Debian:11`, the way the real API
                     ;; treats an unqualified ecosystem
                     (str/starts-with? (str ecosystem*) (str ecosystem ":")))
                 (or (str/blank? (str version))
                     (contains? (set (get entry "versions")) version)
                     (seq (get entry "ranges"))))))
        (get record "affected")))

(defn- summary
  "What `querybatch` answers with: the identifier and when it changed."
  [record]
  {"id" (get record "id")
   "modified" (or (get record "modified") "2026-01-01T00:00:00Z")})

(defn handle
  "`parsed-body` is the request body already decoded — the HTTP shim parses,
  this decides, the same arrangement as every other face here."
  [{:keys [seed method target parsed-body]}]
  (let [[path] (str/split (str target) #"\?" 2)
        records (:records seed)
        by-id (into {} (map (juxt #(get % "id") identity)) records)
        parsed parsed-body]
    (cond
      ;; Deterministic throttling: the nth request to this face is refused
      ;; the way the real API refuses one. A client that reads 429 as an
      ;; answer reports a throttled scan as a clean fleet, and nothing about
      ;; a recorded response can show that.
      (and (:throttle-every seed)
           (zero? (mod (inc (or (:request-count seed) 0))
                       (:throttle-every seed))))
      {:status 429
       :headers {"content-type" "application/json"
                 "retry-after" "2"}
       :body (wire/json {"code" 8 "message" "rate limit exceeded"})}

      (and (= "GET" (or method "GET"))
           (re-matches #"/v1/vulns/.+" path))
      (let [id (subs path (count "/v1/vulns/"))]
        (if-let [record (get by-id id)]
          {:status 200
           :headers {"content-type" "application/json"}
           :body (wire/json record)}
          ;; an id the batch named and the server does not have is a gap in
          ;; the client's knowledge, not an advisory with nothing in it
          {:status 404
           :headers {"content-type" "application/json"}
           :body (wire/json {"code" 5 "message" (str id " not found")})}))

      (and (= "POST" method) (= "/v1/query" path))
      (let [{:strs [package version page_token]} (or parsed {})
            wanted {:name (get package "name")
                    :ecosystem (get package "ecosystem")
                    :version version}
            hits (vec (filter #(matches? % wanted) records))
            size (or (:page-size seed) 1)
            offset (if (str/blank? (str page_token))
                     0
                     (let [n (re-matches #"\d+" (str page_token))]
                       (if n
                         #?(:clj (Long/parseLong n) :cljs (js/parseInt n 10))
                         ;; a token this server did not issue is a client
                         ;; that built its own, and it must not be humoured
                         (throw (ex-info "bad page token" {:token page_token})))))
            page (vec (take size (drop offset hits)))
            next-offset (+ offset (count page))]
        {:status 200
         :headers {"content-type" "application/json"}
         :body (wire/json
                (cond-> {"vulns" page}
                  (< next-offset (count hits))
                  (assoc "next_page_token" (str next-offset))))})

      (and (= "POST" method) (= "/v1/querybatch" path))
      (let [queries (get (or parsed {}) "queries" [])]
        (if (> (count queries) (or (:max-batch seed) 1000))
          {:status 400
           :headers {"content-type" "application/json"}
           :body (wire/json {"code" 3
                             "message" (str "too many queries: "
                                            (count queries))})}
          {:status 200
           :headers {"content-type" "application/json"}
           :body (wire/json
                  {"results"
                   (mapv (fn [entry]
                           (let [package (get entry "package")
                                 wanted {:name (get package "name")
                                         :ecosystem (get package "ecosystem")
                                         :version (get entry "version")}]
                             ;; identifiers only. A client that stops here
                             ;; holds records with no affected entries
                             {"vulns" (mapv summary
                                            (filter #(matches? % wanted)
                                                    records))}))
                         queries)})}))

      :else
      {:status 404
       :headers {"content-type" "application/json"}
       :body (wire/json {"code" 5 "message" (str "no such endpoint: " path)})})))
