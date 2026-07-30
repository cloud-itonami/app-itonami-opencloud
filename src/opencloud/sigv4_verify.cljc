(ns opencloud.sigv4-verify
  "Server-side AWS Signature Version 4 verification.

  This is deliberately an independent implementation, not a shared library
  with any client. A signer and a verifier that share their canonicalisation
  agree with each other by construction and prove nothing; two implementations
  written from the specification disagree wherever one of them is wrong, which
  is the entire value of signing against this server.

  SHA-256 and HMAC-SHA256 are injected so the same code verifies on the JVM in
  tests and on Node in the running server."
  (:require [clojure.string :as str]))

(def algorithm "AWS4-HMAC-SHA256")

(def unsigned-payload "UNSIGNED-PAYLOAD")

(defn- hex [bytes]
  (str/join
   (map (fn [b]
          (let [value (bit-and 0xff b)]
            (str (when (< value 16) "0")
                 #?(:clj (Integer/toHexString value)
                    :cljs (.toString value 16)))))
        bytes)))

(def ^:private unreserved
  (set "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"))

(defn uri-encode [text & [{:keys [preserve-slash]}]]
  (str/join
   (map (fn [character]
          (cond
            (contains? unreserved character) (str character)
            (and preserve-slash (= \/ character)) "/"
            :else
            (let [code #?(:clj (int character)
                          :cljs (.charCodeAt (str character) 0))]
              (str "%" (str/upper-case
                        (str (when (< code 16) "0")
                             #?(:clj (Integer/toHexString code)
                                :cljs (.toString code 16))))))))
        (seq text))))

(defn parse-authorization
  "`AWS4-HMAC-SHA256 Credential=…/…, SignedHeaders=…, Signature=…`"
  [header]
  (when (and header (str/starts-with? header algorithm))
    (let [parts (into {}
                      (keep (fn [chunk]
                              (let [[k v] (str/split (str/trim chunk) #"=" 2)]
                                (when (and k v) [(str/lower-case k) v])))
                            (str/split (subs header (count algorithm)) #",")))
          [access-key-id date region service terminator]
          (str/split (get parts "credential" "") #"/")]
      (when (and access-key-id (get parts "signedheaders") (get parts "signature"))
        {:access-key-id access-key-id
         :date date
         :region region
         :service service
         :terminator terminator
         :signed-headers (vec (str/split (get parts "signedheaders") #";"))
         :signature (get parts "signature")}))))

(defn canonical-request
  [{:keys [method path query headers signed-headers payload-hash]}]
  (let [lookup (into {} (map (fn [[k v]] [(str/lower-case (name k)) v]) headers))]
    (str/join
     "\n"
     [(str/upper-case (name method))
      (if (str/blank? path) "/" (uri-encode path {:preserve-slash true}))
      (->> query
           (map (fn [[k v]] [(uri-encode (str k)) (uri-encode (str v))]))
           sort
           (map (fn [[k v]] (str k "=" v)))
           (str/join "&"))
      (str (str/join "\n"
                     (map (fn [name*]
                            (str name* ":"
                                 (str/trim (str/replace
                                            (str (get lookup name* "")) #"\s+" " "))))
                          signed-headers))
           "\n")
      (str/join ";" signed-headers)
      payload-hash])))

(defn- ascii-bytes
  "Code points of an ASCII string.

  Not `(map int text)`: on the JVM a character is a Character and `int` is its
  code point, but in ClojureScript a character is a one-character string and
  `int` coerces it to 0. That difference silently derives the signing key from
  almost-constant bytes — the secret is discarded, every request signs the
  same way, and nothing fails until a real service rejects it."
  [text]
  (mapv (fn [character]
          #?(:clj (int character)
             :cljs (.charCodeAt (str character) 0)))
        (str text)))

(defn signing-key
  [{:keys [secret-access-key date region service]} {:keys [hmac-sha256]}]
  (-> (hmac-sha256 (ascii-bytes (str "AWS4" secret-access-key)) date)
      (hmac-sha256 region)
      (hmac-sha256 service)
      (hmac-sha256 "aws4_request")))

(defn expected-signature
  [request credential crypto]
  (let [canonical (canonical-request request)
        to-sign (str/join "\n" [algorithm
                                (:amz-date request)
                                (str/join "/" [(:date credential)
                                               (:region credential)
                                               (:service credential)
                                               "aws4_request"])
                                ((:sha256-hex crypto) canonical)])]
    {:canonical-request canonical
     :string-to-sign to-sign
     :signature (hex ((:hmac-sha256 crypto)
                      (signing-key (assoc credential
                                          :secret-access-key
                                          (:secret-access-key request))
                                   crypto)
                      to-sign))}))

(defn verify
  "Returns {:verified? true} or a reason. Every rejection names what failed, so
  a client author can tell a clock problem from a canonicalisation problem
  without guessing."
  [{:keys [headers method path query body-hash accounts now-ms clock-skew-ms]
    :or {clock-skew-ms 900000}}
   crypto]
  (let [lookup (into {} (map (fn [[k v]] [(str/lower-case (name k)) v]) headers))
        authorization (get lookup "authorization")
        credential (parse-authorization authorization)
        amz-date (get lookup "x-amz-date")
        account (get accounts (:access-key-id credential))]
    (cond
      (nil? authorization)
      {:verified? false :reason :missing-authorization
       :code "MissingAuthenticationToken"
       :message "Request is missing Authentication Token"}

      (nil? credential)
      {:verified? false :reason :unparsable-authorization
       :code "IncompleteSignature"
       :message "Authorization header requires 'Credential', 'SignedHeaders' and 'Signature'"}

      (not= "aws4_request" (:terminator credential))
      {:verified? false :reason :bad-credential-scope
       :code "IncompleteSignature"
       :message "Credential scope must end with aws4_request"}

      (nil? account)
      {:verified? false :reason :unknown-access-key
       :code "InvalidClientTokenId"
       :message "The security token included in the request is invalid."}

      (str/blank? amz-date)
      {:verified? false :reason :missing-date
       :code "IncompleteSignature"
       :message "x-amz-date is required"}

      (not (some #{"host"} (:signed-headers credential)))
      {:verified? false :reason :host-not-signed
       :code "SignatureDoesNotMatch"
       :message "'host' must be a signed header"}

      :else
      (let [{:keys [signature] :as computed}
            (expected-signature
             {:method method :path path :query query :headers headers
              :signed-headers (:signed-headers credential)
              :payload-hash (or (get lookup "x-amz-content-sha256")
                                body-hash)
              :amz-date amz-date
              :secret-access-key (:secret-access-key account)}
             credential
             crypto)]
        (if (= signature (:signature credential))
          {:verified? true
           :account (:account-id account)
           :access-key-id (:access-key-id credential)
           :region (:region credential)
           :service (:service credential)}
          {:verified? false :reason :signature-mismatch
           :code "SignatureDoesNotMatch"
           :message (str "The request signature we calculated does not match "
                         "the signature you provided. Check your AWS Secret "
                         "Access Key and signing method.")
           :expected signature
           :provided (:signature credential)
           :canonical-request (:canonical-request computed)
           :string-to-sign (:string-to-sign computed)})))))
