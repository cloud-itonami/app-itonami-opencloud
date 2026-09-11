(ns opencloud.portability
  "Differential cases for the parts that decide, run on both runtimes.

  This server's tests run on the JVM and the server itself runs on Node. A
  verifier that computes differently on the two is worse than no verifier: it
  accepts whatever a client with the same defect produces, which is exactly
  what happened before this file existed."
  (:require [opencloud.aws :as aws]
            [opencloud.sigv4-verify :as sigv4]
            [opencloud.wire :as wire]
            #?@(:cljs [["node:crypto" :as node-crypto]]))
  #?(:clj (:import [java.security MessageDigest]
                   [javax.crypto Mac]
                   [javax.crypto.spec SecretKeySpec])))

(defn- hmac-sha256 [key* message]
  #?(:clj (let [mac (Mac/getInstance "HmacSHA256")]
            (.init mac (SecretKeySpec. (byte-array (map unchecked-byte key*))
                                       "HmacSHA256"))
            (mapv #(bit-and 0xff %)
                  (.doFinal mac (.getBytes (str message) "UTF-8"))))
     :cljs (let [buffer (if (string? key*)
                          (js/Buffer.from key* "utf8")
                          (js/Buffer.from (clj->js (vec key*))))]
             (vec (js/Array.from
                   (-> (.createHmac node-crypto "sha256" buffer)
                       (.update message "utf8")
                       (.digest)))))))

(defn- sha256-hex [text]
  #?(:clj (apply str
                 (map #(format "%02x" (bit-and 0xff %))
                      (.digest (MessageDigest/getInstance "SHA-256")
                               (.getBytes (str text) "UTF-8"))))
     :cljs (-> (.createHash node-crypto "sha256")
               (.update text "utf8")
               (.digest "hex"))))

(def ^:private crypto {:sha256-hex sha256-hex :hmac-sha256 hmac-sha256})

(def ^:private accounts
  {"AKIDEXAMPLE" {:access-key-id "AKIDEXAMPLE"
                  :secret-access-key "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
                  :account-id "123456789012"}})

(defn- request [signature]
  {:method "GET" :path "/" :query {} :accounts accounts
   :body-hash "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
   :headers {"host" "example.amazonaws.com"
             "x-amz-date" "20150830T123600Z"
             "authorization"
             (str "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/"
                  "service/aws4_request, SignedHeaders=host;x-amz-date, "
                  "Signature=" signature)}})

(def ^:private seed
  {:account-id "123456789012"
   :page-size 1
   :roles [{:name "a" :arn "arn:a" :created "t"
            :trust {"Statement" [{"Effect" "Allow" "Principal" "*"}]}}
           {:name "b" :arn "arn:b" :created "t"}]
   :buckets [{:name "x" :created "t" :region "r" :public? true
              :tags {"sensitive" "true"}
              :policy {"Statement" [{"Effect" "Allow" "Principal" "*"}]}}]
   :instances [{:instance-id "i-1" :state "running" :http-tokens "optional"
                :public-ip "203.0.113.1" :security-groups ["sg-1"]
                :tags {"Name" "n"}}]
   :security-groups [{:group-id "sg-1" :group-name "g"
                      :ingress [{:protocol "tcp" :from 22 :to 22
                                 :cidrs ["0.0.0.0/0"]}]}]
   :users [] :policies {} :databases []})

(defn results []
  {;; the primitive that broke the verifier
   :published-vector-verifies
   (:verified? (sigv4/verify
                (request (str "5fa00fa31553b73ebf1942676e86291e8372ff2a2260"
                              "956d9b8aae1d763fbf31"))
                crypto))
   :wrong-signature-refused
   (select-keys (sigv4/verify (request "deadbeef") crypto)
                [:verified? :reason :expected])
   :signing-key (sigv4/signing-key {:secret-access-key "wJalrXUtnFEMI/K7"
                                    :date "20150830" :region "us-east-1"
                                    :service "service"}
                                   crypto)
   :canonical-request (sigv4/canonical-request
                       {:method "GET" :path "/a b" :query {"k" "v w"}
                        :headers {"host" "h" "x" "  a   b  "}
                        :signed-headers ["host" "x"]
                        :payload-hash "abc"})
   :uri-encode [(sigv4/uri-encode "a b~c/d")
                (sigv4/uri-encode "a/b" {:preserve-slash true})]
   :parse-authorization (sigv4/parse-authorization
                         (get-in (request "sig") [:headers "authorization"]))

   ;; wire formats
   :xml (wire/xml [:R [:A "a & b"] nil [:B] [:C 1]])
   :json (wire/json {"a" [1 true nil "x\"y"] :k 2})
   :encoded-policy (wire/encoded-policy {"Effect" "Allow" "Action" "s3:*"})
   :percent-decode [(wire/percent-decode "a%20b") (wire/percent-decode "a+b")
                    (wire/percent-decode "a+b" {:plus-is-space true})]
   :parse-query (wire/parse-query "Action=ListRoles&a=1&a=2&flag")
   :page [(wire/page [1 2 3 4 5] 2 nil) (wire/page [1 2 3 4 5] 2 "4")]

   ;; responses
   :list-roles (:body (aws/handle-query {:seed seed :query {"Action" "ListRoles"}
                                         :principal {}}))
   :describe-instances (:body (aws/handle-query
                               {:seed seed
                                :query {"Action" "DescribeInstances"}
                                :principal {}}))
   :s3-policy (aws/handle-s3 {:seed seed :host "h" :path "/x"
                              :query {"policy" ""}})
   :s3-missing (aws/handle-s3 {:seed seed :host "h" :path "/x"
                               :query {"encryption" ""}})
   :invalid-action (:status (aws/handle-query {:seed seed
                                               :query {"Action" "Nope"}
                                               :principal {}}))})
