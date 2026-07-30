(ns opencloud.sigv4-verify-test
  "The verifier is checked against the same published AWS test vector the
  clients are, from the other side: a signature the specification says is
  correct must be accepted, and anything else must be refused with a reason."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [opencloud.sigv4-verify :as sigv4])
  (:import [java.security MessageDigest]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]))

(defn hmac-sha256 [key* message]
  (let [mac (Mac/getInstance "HmacSHA256")]
    (.init mac (SecretKeySpec. (byte-array (map unchecked-byte key*)) "HmacSHA256"))
    (mapv #(bit-and 0xff %) (.doFinal mac (.getBytes (str message) "UTF-8")))))

(defn sha256-hex [text]
  (->> (.digest (MessageDigest/getInstance "SHA-256") (.getBytes (str text) "UTF-8"))
       (map #(format "%02x" (bit-and 0xff %)))
       str/join))

(def crypto {:sha256-hex sha256-hex :hmac-sha256 hmac-sha256})

(def accounts
  {"AKIDEXAMPLE" {:access-key-id "AKIDEXAMPLE"
                  :secret-access-key "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
                  :account-id "123456789012"}})

;; aws-sig-v4-test-suite / get-vanilla
(def vanilla-signature
  "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")

(defn request [& [{:keys [signature headers]}]]
  {:method "GET"
   :path "/"
   :query {}
   :body-hash "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
   :accounts accounts
   :headers (merge
             {"host" "example.amazonaws.com"
              "x-amz-date" "20150830T123600Z"
              "x-amz-content-sha256"
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
              "authorization"
              (str "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/"
                   "us-east-1/service/aws4_request, "
                   "SignedHeaders=host;x-amz-date, Signature="
                   (or signature vanilla-signature))}
             headers)})

(deftest the-published-signature-verifies
  ;; the vector signs only host and x-amz-date, so the extra content header
  ;; must not participate
  (let [verdict (sigv4/verify (request) crypto)]
    (is (:verified? verdict) (pr-str verdict))
    (is (= "123456789012" (:account verdict)))
    (is (= "service" (:service verdict)))
    (is (= "us-east-1" (:region verdict)))))

(deftest every-refusal-names-what-failed
  (let [reason #(:reason (sigv4/verify % crypto))]
    (is (= :signature-mismatch (reason (request {:signature "deadbeef"}))))
    (is (= :missing-authorization
           (reason (update (request) :headers dissoc "authorization"))))
    (is (= :missing-date
           (reason (update (request) :headers dissoc "x-amz-date"))))
    (is (= :unparsable-authorization
           (reason (assoc-in (request) [:headers "authorization"]
                             "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/a/b/c/aws4_request"))))
    (is (= :unknown-access-key
           (reason (assoc (request) :accounts {}))))
    (is (= :bad-credential-scope
           (reason (assoc-in (request) [:headers "authorization"]
                             (str "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/x/y/z/"
                                  "nope, SignedHeaders=host, Signature=a")))))
    ;; a signature that does not cover the host lets an attacker replay it
    ;; against another endpoint
    (is (= :host-not-signed
           (reason (assoc-in (request) [:headers "authorization"]
                             (str "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/"
                                  "us-east-1/service/aws4_request, "
                                  "SignedHeaders=x-amz-date, Signature=a")))))))

(deftest a-mismatch-reports-what-the-server-canonicalised
  (let [verdict (sigv4/verify (request {:signature "deadbeef"}) crypto)]
    (is (= vanilla-signature (:expected verdict)))
    (is (str/includes? (:canonical-request verdict) "host:example.amazonaws.com"))
    (is (str/starts-with? (:string-to-sign verdict) "AWS4-HMAC-SHA256\n"))))

(deftest the-signature-covers-the-query-string
  (let [signed (sigv4/verify (assoc (request) :query {"Action" "ListRoles"})
                             crypto)]
    ;; the vector was signed with no query, so adding one must break it
    (is (false? (:verified? signed)))
    (is (= :signature-mismatch (:reason signed)))))
