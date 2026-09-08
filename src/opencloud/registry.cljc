(ns opencloud.registry
  "An OCI Distribution v2 registry.

  A scanner that reads container images has to get through a protocol that
  looks like HTTP and is not quite: the first request is refused with a
  challenge naming where to get a token, the response body for a manifest
  depends on what the client said it accepts, tag listing pages with a `Link`
  header rather than a field in the body, and every blob is addressed by the
  digest of its own bytes.

  Recording responses cannot verify a client against any of that, because a
  recording has already resolved the negotiation. This serves it: the
  challenge is real, the token is checked, `Accept` decides which document
  comes back, and the digests are computed over the exact bytes served — so a
  client that skips verification is not detected here, but a client that
  verifies incorrectly is."
  (:require [kotoba.lang.text :as str]
            [opencloud.wire :as wire]))

(def index-media-type "application/vnd.oci.image.index.v1+json")
(def manifest-media-type "application/vnd.oci.image.manifest.v1+json")
(def config-media-type "application/vnd.oci.image.config.v1+json")
(def layer-media-type "application/vnd.oci.image.layer.v1.tar+gzip")
(def layer-zstd-media-type "application/vnd.oci.image.layer.v1.tar+zstd")

(defn- accepts? [headers media-type]
  (let [accept (str (get headers "accept" ""))]
    (or (str/includes? accept media-type)
        (str/includes? accept "*/*"))))

(defn- bearer-token [headers]
  (let [authorization (str (get headers "authorization" ""))]
    (when (str/starts-with? (str/lower authorization) "bearer ")
      (str/trim (subs authorization 7)))))

(defn- basic-credential [headers]
  (let [authorization (str (get headers "authorization" ""))]
    (when (str/starts-with? (str/lower authorization) "basic ")
      (str/trim (subs authorization 6)))))

(defn challenge
  "The 401 that starts authentication.

  Two registries in one: by default a `Bearer` challenge naming a token
  endpoint, and with `:basic-auth` set, the `Basic` challenge that Harbor,
  Artifactory and GitLab's registry give — no token endpoint at all, and the
  credential goes on **every** request instead of being exchanged once.

  A client that treats the 401 as a fatal authentication error never reaches a
  public image; one that ignores the realm and invents a token URL reaches a
  different registry's; and one that only knows the Bearer flow finds no
  `Bearer realm=` to parse here and has to decide what to do about it. What it
  must not decide is that the image is empty."
  [{:keys [base-url service basic-auth]} scope]
  {:status 401
   :headers {"content-type" "application/json"
             "docker-distribution-api-version" "registry/2.0"
             "www-authenticate"
             (if basic-auth
               (str "Basic realm=\"" service "\"")
               (str "Bearer realm=\"" base-url "/token\",service=\"" service "\""
                    (when scope (str ",scope=\"" scope "\""))))}
   :body (wire/json
          {"errors" [{"code" "UNAUTHORIZED"
                      "message" "authentication required"
                      "detail" nil}]})})

(defn- error [status code message]
  {:status status
   :headers {"content-type" "application/json"
             "docker-distribution-api-version" "registry/2.0"}
   :body (wire/json {"errors" [{"code" code "message" message}]})})

(defn- scope-for [repository] (str "repository:" repository ":pull"))

(defn- token-for [{:keys [token]} repository]
  ;; one token per repository, so a client that reuses the token it got for
  ;; another repository is refused the way a real registry refuses it
  (str token "." repository))

(defn- repository-of
  "`/v2/<name>/manifests/<ref>` where <name> itself contains slashes, so the
  repository is what precedes the last endpoint marker rather than the first
  path segment."
  [target]
  (when-let [[_ path] (re-matches #"/v2/(.+)" target)]
    (when-let [index (->> ["/manifests/" "/blobs/" "/tags/list"]
                          (keep #(str/last-index-of path %))
                          (reduce max -1)
                          (#(when (nat-int? %) %)))]
      (subs path 0 index))))

(defn handle
  "`seed` holds {:base-url :service :token :repositories {name {:tags {tag
  digest} :documents {digest {:media-type :bytes :length}}}}}. Bytes are
  produced by the caller so the digests are over what is really served."
  [{:keys [seed method target headers]}]
  (let [method (or method "GET")
        [path query] (str/split (str target) #"\?" 2)
        parameters (wire/parse-query query)
        ;; with basic auth every request carries the credential itself, so
        ;; `token` is `is this request authenticated` in both modes and the
        ;; rest of the handler does not branch
        ;; a minted credential runs out. The registry cannot say `renew`: it
        ;; answers the same 401 a wrong password gets, because to the registry
        ;; those are the same thing. So a client that treats a mid-scan 401 as
        ;; `bad credential` stops with a partial image, and one that treats it
        ;; as `renew` and cannot renew loops
        ;; counted since the credential was last minted, not since the
        ;; process started. A global counter expires a freshly minted token on
        ;; arrival, which no real registry does — and it makes a client that
        ;; renews correctly look broken, which is the opposite of what this
        ;; is for. (The same mistake was made once already, for STS sessions.)
        expired? (and (:credential-ttl-requests seed)
                      (pos? (:credential-ttl-requests seed))
                      (> (- (or (:request-count seed) 0)
                            (or (:credential-issued-at seed) 0))
                         (:credential-ttl-requests seed)))
        token (if (:basic-auth seed)
                (when (contains? (set (remove nil? [(:basic-auth seed)
                                                    ;; a token minted at the
                                                    ;; ECR face opens this
                                                    ;; registry too: the whole
                                                    ;; point of minting it
                                                    (:ecr-basic-auth seed)]))
                                 (basic-credential headers))
                  (token-for seed (repository-of path)))
                (bearer-token headers))]
    (cond
      (not= "GET" method)
      (error 405 "UNSUPPORTED" (str method " is not supported; this registry "
                                    "is pull-only"))

      ;; the credential this client is holding has run out. Indistinguishable
      ;; from a wrong one, which is the whole difficulty
      (and expired? token (not= "/token" path)
           (not (str/starts-with? path "/blobstore/")))
      (challenge seed nil)

      ;; a Basic-auth registry has no token endpoint. A client that asks for
      ;; one anyway — because it assumed the realm without reading it — gets
      ;; the 404 the real thing gives, not a token
      (and (:basic-auth seed) (= "/token" path))
      (error 404 "NOT_FOUND" (str "this registry authenticates with Basic; "
                                  "there is no token endpoint"))

      ;; the token endpoint is not under /v2/ and carries no bearer of its own
      (= "/token" path)
      (let [scope (get parameters "scope")
            repository (second (re-matches #"repository:(.+):pull"
                                           (str scope)))]
        (if (and repository (contains? (:repositories seed) repository))
          {:status 200
           :headers {"content-type" "application/json"}
           :body (wire/json {"token" (token-for seed repository)
                                    "access_token" (token-for seed repository)
                                    "expires_in" 300})}
          (error 403 "DENIED" (str "no such repository: " scope))))

      ;; where the redirect points. Not under /v2/, and deliberately hostile
      ;; to a credential that was not issued for it
      (str/starts-with? path "/blobstore/")
      (let [after (subs path (count "/blobstore/"))
            index (str/last-index-of after "/")
            repository (when index (subs after 0 index))
            digest (when index (subs after (inc index)))
            blob (get-in seed [:repositories repository :documents digest])]
        (cond
          (seq (str (get headers "authorization")))
          {:status 400
           :headers {"content-type" "application/xml"}
           :body (str "<?xml version=\"1.0\"?><Error><Code>"
                      "InvalidArgument</Code><Message>"
                      "Only one auth mechanism allowed"
                      "</Message></Error>")}

          (nil? blob)
          {:status 404 :headers {"content-type" "application/xml"}
           :body "<?xml version=\"1.0\"?><Error><Code>NoSuchKey</Code></Error>"}

          :else
          {:status 200
           :headers {"content-type" "application/octet-stream"
                     "content-length" (str (:length blob))}
           :body (:bytes blob)}))

      (= "/v2/" path)
      (if token
        {:status 200
         :headers {"content-type" "application/json"
                   "docker-distribution-api-version" "registry/2.0"}
         :body "{}"}
        (challenge seed nil))

      :else
      (let [repository (repository-of path)
            repo (get-in seed [:repositories repository])]
        (cond
          (nil? repo)
          (if token
            (error 404 "NAME_UNKNOWN" (str "repository not known: " repository))
            ;; a real registry challenges before it admits whether a private
            ;; repository exists, and a client has to handle the challenge on
            ;; a path it has never seen
            (challenge seed (scope-for (str repository))))

          (nil? token)
          (challenge seed (scope-for repository))

          (not= token (token-for seed repository))
          (error 401 "UNAUTHORIZED"
                 "the token was not issued for this repository")

          :else
          (let [after (subs path (+ (count "/v2/") (count repository)))]
            (cond
              (= "/tags/list" after)
              (let [tags (vec (sort (keys (:tags repo))))
                    requested (get parameters "n")
                    n (or (when (re-matches #"\d+" (str requested))
                            #?(:clj (Long/parseLong requested)
                               :cljs (js/parseInt requested 10)))
                          (:page-size seed))
                    last* (get parameters "last")
                    remaining (if last*
                                (vec (drop-while #(<= (compare % last*) 0) tags))
                                tags)
                    page (vec (take (or n (count remaining)) remaining))
                    more? (and n (> (count remaining) (count page)))]
                {:status 200
                 :headers (cond-> {"content-type" "application/json"}
                            more?
                            ;; pagination in a header, and the client has to
                            ;; parse the URL out of it rather than build one
                            (assoc "link"
                                   (str "</v2/" repository "/tags/list?n=" n
                                        "&last=" (last page) ">; rel=\"next\"")))
                 :body (wire/json {"name" repository "tags" page})})

              (str/starts-with? after "/manifests/")
              (let [reference (subs after (count "/manifests/"))
                    digest (or (get (:tags repo) reference)
                               (when (contains? (:documents repo) reference)
                                 reference))
                    document (get (:documents repo) digest)]
                (cond
                  (nil? document)
                  (error 404 "MANIFEST_UNKNOWN"
                         (str "manifest unknown: " reference))

                  ;; content negotiation is real: a client that asks only for
                  ;; the image manifest type must not be handed an index it
                  ;; will read as an image with no layers
                  (not (accepts? headers (:media-type document)))
                  (error 404 "MANIFEST_UNKNOWN"
                         (str "manifest unknown: no representation matching "
                              (get headers "accept" "")))

                  :else
                  {:status 200
                   :headers {"content-type" (:media-type document)
                             "docker-content-digest" digest
                             "content-length" (str (:length document))}
                   :body (:bytes document)}))

              (str/starts-with? after "/blobs/")
              (let [digest (subs after (count "/blobs/"))
                    blob (get (:documents repo) digest)]
                (cond
                  (nil? blob)
                  (error 404 "BLOB_UNKNOWN" (str "blob unknown: " digest))

                  ;; Real registries hand the bytes off to object storage. The
                  ;; redirect is the easy half; the trap is that the storage
                  ;; host rejects a request carrying the registry's
                  ;; Authorization header — the credential is for the registry
                  ;; and presenting it elsewhere is both a failure and a leak.
                  ;; A client that forwards headers across a redirect works
                  ;; against a registry that serves blobs directly and fails
                  ;; against every one that does not.
                  (:redirect-blobs? seed)
                  {:status 307
                   ;; a different host, because that is where the trap is: a
                   ;; client that keeps its credential across the hop is
                   ;; presenting the registry's token to somebody else
                   :headers {"location" (str (or (:blob-store-url seed)
                                                 (:base-url seed))
                                             "/blobstore/" repository "/"
                                             digest)
                             "content-length" "0"}
                   :body ""}

                  :else
                  {:status 200
                   :headers {"content-type" (or (:media-type blob)
                                                "application/octet-stream")
                             "docker-content-digest" digest
                             "content-length" (str (:length blob))}
                   :body (:bytes blob)}))

              :else
              (error 404 "UNSUPPORTED" (str "not a registry endpoint: " path)))))))))
