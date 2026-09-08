(ns opencloud.registry-test
  (:require [kotoba.lang.text :as str]
            [clojure.test :refer [deftest is]]
            [opencloud.registry :as registry]))

(def seed
  {:base-url "http://registry.test" :service "opencloud" :token "t"
   :page-size 2
   :repositories
   {"library/ubuntu"
    {:tags {"22.04" "sha256:aa" "latest" "sha256:aa" "jammy" "sha256:aa"
            "rolling" "sha256:aa"}
     :documents {"sha256:aa" {:media-type registry/index-media-type
                              :bytes "{\"index\":true}" :length 14}
                 "sha256:bb" {:media-type registry/manifest-media-type
                              :bytes "{\"manifest\":true}" :length 17}
                 "sha256:cc" {:media-type registry/layer-media-type
                              :bytes "layer" :length 5}}}}})

(def token "t.library/ubuntu")

(defn- get* [target & [{:keys [token accept]}]]
  (registry/handle {:seed seed :method "GET" :target target
                    :headers (cond-> {}
                               token (assoc "authorization" (str "Bearer " token))
                               accept (assoc "accept" accept))}))

(deftest the-challenge-says-where-the-token-comes-from
  (let [refused (get* "/v2/library/ubuntu/manifests/22.04")]
    (is (= 401 (:status refused)))
    ;; the realm is not derivable from the registry host — a mirror answers on
    ;; one host and issues tokens on another — so it has to be stated
    (is (= (str "Bearer realm=\"http://registry.test/token\","
                "service=\"opencloud\",scope=\"repository:library/ubuntu:pull\"")
           (get-in refused [:headers "www-authenticate"])))
    (is (= "registry/2.0"
           (get-in refused [:headers "docker-distribution-api-version"]))))
  ;; a repository nobody has heard of is challenged too: a registry does not
  ;; disclose which private repositories exist before authentication
  (is (= 401 (:status (get* "/v2/acme/secret/manifests/latest"))))
  (is (= 404 (:status (get* "/v2/acme/secret/manifests/latest" {:token token})))))

(deftest a-token-is-scoped-to-the-repository-it-was-issued-for
  (let [issued (registry/handle
                {:seed seed :method "GET"
                 :target "/token?service=opencloud&scope=repository:library/ubuntu:pull"
                 :headers {}})]
    (is (= 200 (:status issued)))
    (is (str/includes? (:body issued) token)))
  (is (= 403 (:status (registry/handle
                       {:seed seed :method "GET"
                        :target "/token?scope=repository:acme/absent:pull"
                        :headers {}}))))
  ;; reusing another repository's token is refused rather than honoured
  (is (= 401 (:status (get* "/v2/library/ubuntu/manifests/22.04"
                            {:token "t.library/alpine" :accept "*/*"})))))

(deftest accept-decides-which-document-comes-back
  (let [ok (get* "/v2/library/ubuntu/manifests/22.04"
                 {:token token :accept registry/index-media-type})]
    (is (= 200 (:status ok)))
    (is (= registry/index-media-type (get-in ok [:headers "content-type"])))
    ;; the digest travels in the header the client verifies against
    (is (= "sha256:aa" (get-in ok [:headers "docker-content-digest"]))))
  ;; a client that asks only for an image manifest must not be handed an
  ;; index, which it would read as an image with no layers and no packages
  (is (= 404 (:status (get* "/v2/library/ubuntu/manifests/22.04"
                            {:token token
                             :accept registry/manifest-media-type}))))
  ;; a manifest is addressable by its digest as well as by its tag
  (is (= 200 (:status (get* "/v2/library/ubuntu/manifests/sha256:bb"
                            {:token token
                             :accept registry/manifest-media-type})))))

(deftest tags-page-through-a-link-header-and-not-through-the-body
  (let [page (get* "/v2/library/ubuntu/tags/list" {:token token})]
    (is (= 200 (:status page)))
    (is (= "{\"name\":\"library/ubuntu\",\"tags\":[\"22.04\",\"jammy\"]}"
           (:body page)))
    ;; the next page is a URL in a header the client has to parse, not a
    ;; marker it can append to what it just fetched
    (is (= "</v2/library/ubuntu/tags/list?n=2&last=jammy>; rel=\"next\""
           (get-in page [:headers "link"]))))
  (let [page-two (get* "/v2/library/ubuntu/tags/list?n=2&last=jammy"
                       {:token token})]
    (is (str/includes? (:body page-two) "\"latest\",\"rolling\""))
    ;; the last page carries no link, which is how the client knows to stop
    (is (nil? (get-in page-two [:headers "link"])))))

(deftest the-registry-is-pull-only-and-says-so
  (is (= 405 (:status (registry/handle
                       {:seed seed :method "DELETE"
                        :target "/v2/library/ubuntu/manifests/22.04"
                        :headers {"authorization" (str "Bearer " token)}}))))
  (is (= 404 (:status (get* "/v2/library/ubuntu/blobs/sha256:missing"
                            {:token token}))))
  (is (= 200 (:status (get* "/v2/library/ubuntu/blobs/sha256:cc"
                            {:token token})))))

(deftest a-repository-name-with-slashes-is-read-to-the-endpoint-marker
  ;; `/v2/<name>/manifests/<ref>` where <name> itself has slashes: taking the
  ;; first segment names the wrong repository and the token never matches
  (is (= 200 (:status (get* "/v2/library/ubuntu/tags/list" {:token token}))))
  (is (= 401 (:status (get* "/v2/library/manifests/22.04"))))
  (is (= "Bearer realm=\"http://registry.test/token\",service=\"opencloud\","
         (subs (get-in (get* "/v2/library/manifests/22.04")
                       [:headers "www-authenticate"])
               0 (count "Bearer realm=\"http://registry.test/token\",service=\"opencloud\",")))))

(deftest a-redirected-blob-refuses-the-registrys-credential
  (let [redirecting (assoc seed :redirect-blobs? true)
        redirect (registry/handle
                  {:seed redirecting :method "GET"
                   :target "/v2/library/ubuntu/blobs/sha256:cc"
                   :headers {"authorization" (str "Bearer " token)}})]
    (is (= 307 (:status redirect)))
    (is (= "http://registry.test/blobstore/library/ubuntu/sha256:cc"
           (get-in redirect [:headers "location"])))

    ;; the storage host rejects a request carrying the registry's token: the
    ;; credential is for the registry, and presenting it elsewhere is both a
    ;; failure and a leak. A client that forwards headers across a redirect
    ;; works against a registry that serves blobs directly and fails against
    ;; every one that does not
    (let [with-token (registry/handle
                      {:seed redirecting :method "GET"
                       :target "/blobstore/library/ubuntu/sha256:cc"
                       :headers {"authorization" (str "Bearer " token)}})]
      (is (= 400 (:status with-token)))
      (is (str/includes? (:body with-token) "Only one auth mechanism allowed")))

    (let [without (registry/handle
                   {:seed redirecting :method "GET"
                    :target "/blobstore/library/ubuntu/sha256:cc"
                    :headers {}})]
      (is (= 200 (:status without)))
      (is (= "layer" (:body without))))

    ;; and an object that is not there is the storage host's 404, not the
    ;; registry's error document
    (is (= 404 (:status (registry/handle
                         {:seed redirecting :method "GET"
                          :target "/blobstore/library/ubuntu/sha256:missing"
                          :headers {}}))))))

(deftest a-basic-auth-registry-has-no-token-endpoint
  ;; Harbor, Artifactory and GitLab's registry authenticate this way. The
  ;; challenge names a different scheme, there is nowhere to exchange the
  ;; credential, and it has to go on every request instead of once.
  (let [basic-seed (assoc seed :basic-auth "c2Nhbm5lcjpzM2NyZXQ=")
        ask (fn [target & [authorization]]
              (registry/handle
               {:seed basic-seed :method "GET" :target target
                :headers (cond-> {"accept" "application/vnd.oci.image.index.v1+json"}
                           authorization (assoc "authorization" authorization))}))
        manifest "/v2/library/ubuntu/manifests/22.04"]

    (let [{:keys [status headers]} (ask manifest)]
      (is (= 401 status))
      (is (str/starts-with? (get headers "www-authenticate") "Basic realm=")
          "the scheme is the whole point; a Bearer challenge here would let a
           token-only client through and prove nothing"))

    ;; and there is no token endpoint to fall back to. A client that assumed
    ;; the realm rather than reading it lands here
    (is (= 404 (:status (ask "/token?scope=repository:library/ubuntu:pull"))))

    (is (= 401 (:status (ask manifest "Basic d3Jvbmc6d3Jvbmc="))))
    ;; a bearer token, even a valid-looking one, is not a Basic credential
    (is (= 401 (:status (ask manifest (str "Bearer " (:token basic-seed)
                                           ".library/ubuntu")))))
    (is (= 200 (:status (ask manifest "Basic c2Nhbm5lcjpzM2NyZXQ="))))

    ;; every path, not only the manifest: a client that authenticates the
    ;; manifest and not the blob reads an image with no layers in it
    (is (= 401 (:status (ask "/v2/library/ubuntu/tags/list"))))
    (is (= 200 (:status (ask "/v2/library/ubuntu/tags/list"
                             "Basic c2Nhbm5lcjpzM2NyZXQ="))))))

(deftest a-minted-credential-runs-out-and-the-refusal-says-nothing
  ;; the registry cannot say `renew`: it answers the same 401 a wrong password
  ;; gets, because to the registry those are the same thing. A client that
  ;; reads a mid-scan 401 as `bad credential` stops with a partial image; one
  ;; that reads it as `renew` and cannot renew loops.
  (let [basic "c2Nhbm5lcjpzM2NyZXQ="
        seed* (assoc seed :basic-auth basic :credential-ttl-requests 3)
        ask (fn [n & [issued-at]]
              (registry/handle
               {:seed (assoc seed* :request-count n
                             :credential-issued-at (or issued-at 0))
                :method "GET"
                :target "/v2/library/ubuntu/manifests/22.04"
                :headers {"accept" "application/vnd.oci.image.index.v1+json"
                          "authorization" (str "Basic " basic)}}))]
    (is (= 200 (:status (ask 3))))
    (is (= 401 (:status (ask 4))))
    ;; and the refusal is the ordinary challenge, indistinguishable from the
    ;; one a wrong credential gets
    (is (str/starts-with? (get (:headers (ask 4)) "www-authenticate") "Basic"))

    ;; counted since the credential was minted, not since the process
    ;; started. Without this a freshly minted token is expired on arrival and
    ;; a client that renews correctly looks broken — the same mistake this
    ;; server made once for STS sessions
    (is (= 200 (:status (ask 100 98))))
    (is (= 401 (:status (ask 100 90))))))

(deftest both-layer-compressions-are-named
  ;; the manifest is where a client finds out which decompressor to use. The
  ;; blob itself is just bytes and its digest checks out either way, which is
  ;; what makes reading it with the wrong one convincing: nothing fails, the
  ;; tar parser simply recognises nothing and the layer contributes no
  ;; packages. (The images themselves are built in registry_seed.cljs and
  ;; exercised end to end by the client's conformance suite.)
  (is (= "application/vnd.oci.image.layer.v1.tar+gzip" registry/layer-media-type))
  (is (= "application/vnd.oci.image.layer.v1.tar+zstd"
         registry/layer-zstd-media-type))
  (is (not= registry/layer-media-type registry/layer-zstd-media-type)))
