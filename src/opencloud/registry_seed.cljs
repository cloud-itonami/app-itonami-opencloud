(ns opencloud.registry-seed
  "Build the registry's blobs at boot and address them by their own digests.

  Nothing here is written down as a digest in a seed file. Every document is
  produced, hashed, and then referred to by that hash — so a client that
  verifies what it downloaded is checking arithmetic rather than agreement,
  and a change to any layer's contents moves every digest above it exactly the
  way it does in a real build."
  (:require ["node:crypto" :as crypto]
            [clojure.string :as str]
            [opencloud.registry :as registry]
            [opencloud.tar :as tar]
            [opencloud.wire :as wire]))

(defn- digest-of [buffer]
  (str "sha256:" (-> (.createHash crypto "sha256") (.update buffer) (.digest "hex"))))

(defn- blob
  "A document plus the digest of its bytes."
  [media-type body]
  (let [buffer (if (string? body) (js/Buffer.from body "utf8") body)]
    {:digest (digest-of buffer)
     :document {:media-type media-type :bytes buffer :length (.-length buffer)}}))

(defn- image
  "One platform's image: layers, a config that lists their diff ids, and the
  manifest that ties them together."
  [{:keys [os architecture variant layers compression]}]
  ;; `compression` is one keyword for every layer, or a vector naming each
  ;; one. Mixed is the case that really happens: a base layer built last year
  ;; with gzip and a top layer rebuilt this week with zstd, in one image
  (let [compression-of (fn [index]
                         (if (vector? compression)
                           (get compression index :gzip)
                           (or compression :gzip)))
        layer-blobs (vec
                     (map-indexed
                      (fn [index entries]
                        (let [zstd? (= :zstd (compression-of index))]
                          (assoc (blob (if zstd?
                                         registry/layer-zstd-media-type
                                         registry/layer-media-type)
                                       (if zstd?
                                         (tar/tar-zstd entries)
                                         (tar/tar-gzip entries)))
                                 :media-type (if zstd?
                                               registry/layer-zstd-media-type
                                               registry/layer-media-type))))
                      layers))
        config (blob registry/config-media-type
                     (wire/json
                      {"architecture" architecture
                       "os" os
                       "config" {"Env" ["PATH=/usr/local/sbin:/usr/local/bin"]}
                       "rootfs" {"type" "layers"
                                 "diff_ids" (mapv :digest layer-blobs)}
                       "history" (mapv (fn [_] {"created_by" "opencloud"})
                                       layer-blobs)}))
        manifest (blob registry/manifest-media-type
                       (wire/json
                        {"schemaVersion" 2
                         "mediaType" registry/manifest-media-type
                         "config" {"mediaType" registry/config-media-type
                                   "digest" (:digest config)
                                   "size" (get-in config [:document :length])}
                         "layers" (mapv (fn [{:keys [digest document media-type]}]
                                          {"mediaType" media-type
                                           "digest" digest
                                           "size" (:length document)})
                                        layer-blobs)}))]
    {:manifest manifest
     :platform (cond-> {"os" os "architecture" architecture}
                 variant (assoc "variant" variant))
     :documents (into {(:digest config) (:document config)
                       (:digest manifest) (:document manifest)}
                      (map (juxt :digest :document))
                      layer-blobs)}))

(def ^:private ubuntu-status
  ;; the file dpkg writes, including the two stanzas a scanner must not count:
  ;; one removed with its configuration left behind, one unpacked but never
  ;; configured
  (str/join
   "\n"
   ["Package: openssl"
    "Status: install ok installed"
    "Priority: optional"
    "Architecture: amd64"
    "Version: 3.0.2-0ubuntu1.6"
    "Description: Secure Sockets Layer toolkit"
    " This package is part of the OpenSSL project."
    " Version: 9.9.9-not-a-version"
    " ."
    " It contains the general-purpose command line binary."
    ""
    "Package: libssl3"
    "Status: install ok installed"
    "Architecture: amd64"
    "Version: 3.0.2-0ubuntu1.6"
    ""
    "Package: curl"
    "Status: install ok installed"
    "Architecture: amd64"
    "Version: 7.81.0-1ubuntu1.15"
    ""
    "Package: libpng16-16"
    "Status: deinstall ok config-files"
    "Architecture: amd64"
    "Version: 1.6.37-3build5"
    ""
    "Package: bash"
    "Status: install ok unpacked"
    "Architecture: amd64"
    "Version: 5.1-6ubuntu1"
    ""]))

(def ^:private alpine-installed
  (str/join
   "\n"
   ["C:Q1eVpkNvL8XqvGtLZM0R4Ct6TXhbA="
    "P:musl"
    "V:1.2.4_pre1-r2"
    "A:x86_64"
    "T:the musl c library"
    ""
    "P:busybox"
    "V:1.36.1-r15"
    "A:x86_64"
    ""
    "P:zlib"
    "V:1.3.1-r0"
    "A:x86_64"
    ""]))

(defn build
  "The registry state served at `base-url`."
  [{:keys [base-url token service] :or {service "opencloud" token "registry"}}]
  (let [ubuntu-amd64
        (image {:os "linux" :architecture "amd64"
                :layers
                [[{:path "etc/os-release"
                   :content (str "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n"
                                 "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n"
                                 "VERSION_ID=\"22.04\"\n")}
                  {:path "var/lib/dpkg/status" :content ubuntu-status}
                  {:path "usr/bin/curl" :content "#!/bin/sh\n"}
                  {:path "usr/share/doc/curl/NEWS" :content "old news\n"}]
                 ;; the second layer removes the binary and empties a
                 ;; directory it inherited: a scanner that unions layers
                 ;; reports what this image no longer has
                 ;; the second layer upgraded openssl, so it wrote the
                 ;; database again: a reader that merges layers in the wrong
                 ;; order reports the base image's version and calls a
                 ;; patched image vulnerable
                 [{:path "var/lib/dpkg/status"
                   :content (str/replace ubuntu-status
                                         "3.0.2-0ubuntu1.6"
                                         "3.0.2-0ubuntu1.15")}
                  {:path "usr/bin/.wh.curl" :content ""}
                  {:path "usr/share/doc/.wh..wh..opq" :content ""}
                  {:path "usr/local/bin/app" :content "#!/bin/sh\napp\n"}
                  ;; a path too long for the ustar name field, so it has to
                  ;; be read out of the prefix field
                  {:path (str "usr/local/share/opencloud/a-very-long-directory-name"
                              "/that-does-not-fit-in-one-hundred-bytes/of-a-ustar"
                              "/header/marker.txt")
                   :content "prefix\n"}]]})
        ubuntu-arm64
        (image {:os "linux" :architecture "arm64" :variant "v8"
                :layers [[{:path "etc/os-release"
                           :content "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n"}
                          {:path "var/lib/dpkg/status"
                           :content (str "Package: openssl\n"
                                         "Status: install ok installed\n"
                                         "Architecture: arm64\n"
                                         "Version: 3.0.13-0ubuntu3\n\n")}]]})
        ;; buildkit attaches provenance to the index with an unknown platform
        attestation (image {:os "unknown" :architecture "unknown"
                            :layers [[{:path "provenance.json"
                                       :content "{\"_type\":\"provenance\"}"}]]})
        index
        (blob registry/index-media-type
              (wire/json
               {"schemaVersion" 2
                "mediaType" registry/index-media-type
                "manifests"
                (mapv (fn [{:keys [manifest platform]}]
                        {"mediaType" registry/manifest-media-type
                         "digest" (:digest manifest)
                         "size" (get-in manifest [:document :length])
                         "platform" platform})
                      [ubuntu-amd64 ubuntu-arm64 attestation])}))
        alpine
        (image {:os "linux" :architecture "amd64"
                :layers
                [[{:path "etc/os-release"
                   :content "ID=alpine\nVERSION_ID=3.19.1\n"}
                  {:path "lib/apk/db/installed" :content alpine-installed}
                  ;; a build stage that was removed in the layer above: its
                  ;; lock file is not this image's software, and a scanner
                  ;; that ignores whiteouts reports it forever
                  {:path "build/package-lock.json"
                   :content (wire/json
                             {"lockfileVersion" 3
                              "packages" {"node_modules/lodash"
                                          {"version" "4.17.11"}}})}]
                 [{:path "srv/app/package-lock.json"
                   :content (wire/json
                             {"lockfileVersion" 3
                              "packages" {"" {"name" "app"}
                                          "node_modules/lodash"
                                          {"version" "4.17.19"}
                                          "node_modules/mocha"
                                          {"version" "10.3.0" "dev" true}}})}
                  ;; the app ships its dependencies, and their own lock files
                  ;; describe a tree the top-level lock already has
                  {:path "srv/app/node_modules/lodash/package-lock.json"
                   :content (wire/json
                             {"lockfileVersion" 3
                              "packages" {"node_modules/evil" {"version" "0.0.1"}}})}
                  {:path "build/.wh.package-lock.json" :content ""}]]})
        ;; a zstd-compressed image. Not exotic: buildkit emits these on
        ;; request and some registries default to them. A scanner that only
        ;; knows gzip fetches the blob, verifies the digest, finds nothing a
        ;; tar parser recognises, and reports an image with fewer packages in
        ;; it than it has — the digest checking out is what makes it
        ;; convincing
        zstd-image
        (image {:os "linux" :architecture "amd64"
                :compression :zstd
                :layers [[{:path "etc/os-release"
                           :content (str "ID=debian\nID_LIKE=debian\n"
                                         "VERSION_ID=\"12\"\n"
                                         "PRETTY_NAME=\"Debian GNU/Linux 12\"\n")}
                          {:path "var/lib/dpkg/status"
                           :content (str "Package: openssl\n"
                                         "Status: install ok installed\n"
                                         "Architecture: amd64\n"
                                         "Version: 3.0.11-1~deb12u2\n\n"
                                         "Package: zlib1g\n"
                                         "Status: install ok installed\n"
                                         "Architecture: amd64\n"
                                         "Version: 1:1.2.13.dfsg-1\n\n")}]]})
        ;; one image, two compressions: a base layer built with gzip and a
        ;; top layer rebuilt with zstd. This is what a rebuild on a newer
        ;; buildkit produces, and it is the case where getting compression
        ;; wrong is worst — the image still reads, just without whatever was
        ;; in the layer nobody could open
        mixed
        (image {:os "linux" :architecture "amd64"
                :compression [:gzip :zstd]
                :layers [[{:path "etc/os-release"
                           :content (str "ID=debian\nVERSION_ID=\"12\"\n")}
                          {:path "var/lib/dpkg/status"
                           :content (str "Package: openssl\n"
                                         "Status: install ok installed\n"
                                         "Architecture: amd64\n"
                                         "Version: 3.0.11-1~deb12u1\n\n")}]
                         ;; the rebuild upgraded openssl and added a package.
                         ;; A reader that cannot open this layer reports the
                         ;; *older* version as installed — a vulnerability
                         ;; that was fixed, reported as present, plus one
                         ;; package that is there and is never mentioned
                         [{:path "var/lib/dpkg/status"
                           :content (str "Package: openssl\n"
                                         "Status: install ok installed\n"
                                         "Architecture: amd64\n"
                                         "Version: 3.0.14-1~deb12u2\n\n"
                                         "Package: curl\n"
                                         "Status: install ok installed\n"
                                         "Architecture: amd64\n"
                                         "Version: 7.88.1-10+deb12u5\n\n")}]]})
        ;; an image whose base layer is served by someone else: its inventory
        ;; can never be complete from this registry alone
        foreign
        (let [layer (blob registry/layer-media-type
                          (tar/tar-gzip [{:path "app" :content "app\n"}]))
              config (blob registry/config-media-type
                           (wire/json {"architecture" "amd64" "os" "linux"
                                       "rootfs" {"type" "layers"
                                                 "diff_ids" [(:digest layer)]}}))
              manifest (blob registry/manifest-media-type
                             (wire/json
                              {"schemaVersion" 2
                               "mediaType" registry/manifest-media-type
                               "config" {"mediaType" registry/config-media-type
                                         "digest" (:digest config)
                                         "size" (get-in config [:document :length])}
                               "layers"
                               [{"mediaType" (str "application/vnd.docker.image"
                                                  ".rootfs.foreign.diff.tar.gzip")
                                 "digest" "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                                 "size" 100
                                 "urls" ["https://example.invalid/base.tar.gz"]}
                                {"mediaType" registry/layer-media-type
                                 "digest" (:digest layer)
                                 "size" (get-in layer [:document :length])}]}))]
          {:manifest manifest
           :documents (into {(:digest config) (:document config)
                             (:digest manifest) (:document manifest)
                             (:digest layer) (:document layer)})})]
    {:base-url base-url
     :service service
     :token token
     :page-size 2
     :repositories
     {"library/ubuntu"
      {:tags {"22.04" (:digest index)
              "latest" (:digest index)
              "jammy" (:digest index)
              "rolling" (:digest index)}
       :documents (merge (:documents ubuntu-amd64)
                         (:documents ubuntu-arm64)
                         (:documents attestation)
                         {(:digest index) (:document index)})}
      "library/alpine"
      {:tags {"3.19" (get-in alpine [:manifest :digest])}
       :documents (:documents alpine)}
      "acme/mixed-compression"
      {:tags {"latest" (get-in mixed [:manifest :digest])}
       :documents (:documents mixed)}
      "acme/zstd"
      {:tags {"latest" (get-in zstd-image [:manifest :digest])}
       :documents (:documents zstd-image)}
      "acme/foreign"
      {:tags {"latest" (get-in foreign [:manifest :digest])}
       :documents (:documents foreign)}}}))
