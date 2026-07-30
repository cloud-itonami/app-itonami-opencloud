(ns opencloud.sts
  "AssumeRole, and the temporary credentials it issues.

  Cross-account reading is how every real security scanner works: one set of
  credentials, a role in each account, and a session per account. Without it a
  client can only ever look at the account it lives in, and the code path that
  looks at somebody else's has never run.

  Two things about it break clients quietly.

  Temporary credentials carry a session token, and the token is a *signed
  header*: it must be sent, and it must be in `SignedHeaders`. A client that
  keeps the new key and secret and forgets the token signs a request that is
  correct in every other respect and is refused — and the refusal looks like
  bad credentials rather than a missing header.

  And an assume that fails must not fall back. A scanner that quietly uses its
  own credentials when the role is unavailable reports its own account's
  resources under the other account's name: everything is present, nothing is
  missing, and the answer is about the wrong estate."
  (:require [clojure.string :as str]
            [opencloud.wire :as wire]))

(defn- account-of-arn [arn]
  (second (re-find #"^arn:aws:iam::(\d+):role/" (str arn))))

(defn session-credentials
  "Deterministic credentials for a role session.

  Derived rather than random so a test can name them, and distinct per role so
  a client that reuses the caller's key is visible."
  [role-arn session-name]
  ;; keyed on the account rather than on the session name: a client picks its
  ;; own name, and a verifier that could only recognise one name would refuse
  ;; every real session while accepting the one the test happened to use
  (let [account (account-of-arn role-arn)
        suffix (str/upper-case (str/replace (str account) #"[^A-Za-z0-9]" ""))]
    {:access-key-id (str "ASIA" (subs (str suffix "XXXXXXXXXXXXXXXX") 0 16))
     :secret-access-key (str "session-secret-for-" account)
     :session-token (str "FwoGZXIvYXdzE" account "-" session-name)
     :account-id account
     :arn (str "arn:aws:sts::" account ":assumed-role/"
               (last (str/split (str role-arn) #"/")) "/" session-name)}))

(defn- access-denied
  "The refusal, worded exactly as the real service words it.

  This message is the same whether the role is not trusted at all, the
  external ID is missing, or the external ID is wrong. That is not an
  oversight in AWS — telling a caller *which* condition failed would let it
  probe for the external ID, which is the secret the control rests on. It does
  mean a client cannot diagnose this from the response, so it has to say what
  it sent: an operator who can see `no ExternalId was sent` fixes it in a
  minute, and one who sees `AccessDenied` alone opens a ticket with the
  customer."
  [role-arn]
  (wire/error {:status 403 :code "AccessDenied"
               :message (str "User is not authorized to perform: "
                             "sts:AssumeRole on resource: " role-arn)}))

(defn assume-role
  "`AssumeRole`, or the refusal a role that cannot be assumed really gives."
  [{:keys [seed query principal]}]
  (let [role-arn (get query "RoleArn")
        session-name (or (get query "RoleSessionName") "session")
        external-id (get query "ExternalId")
        duration (some-> (get query "DurationSeconds") str parse-long)
        account (account-of-arn role-arn)
        assumable (set (or (:assumable-roles seed) []))
        required-external-id (get (:external-ids seed) role-arn)
        chained? (boolean (:session? principal))]
    (cond
      (str/blank? (str role-arn))
      (wire/error {:status 400 :code "MissingParameter"
                   :message "RoleArn is required"})

      (nil? account)
      (wire/error {:status 400 :code "ValidationError"
                   :message (str "Value '" role-arn "' at 'roleArn' failed to "
                                 "satisfy constraint")})

      ;; a role that is not trusted is refused, and the refusal is what a
      ;; client must not paper over with its own credentials
      (not (contains? assumable role-arn))
      (access-denied role-arn)

      ;; the confused-deputy control. Every third-party scanner that reads a
      ;; customer's account is on the other side of this: the customer's trust
      ;; policy names an ExternalId, and a scanner that does not send it is
      ;; refused with a message that says nothing about why
      (and required-external-id (not= required-external-id external-id))
      (access-denied role-arn)

      ;; a role reachable only from another session. Assuming it means signing
      ;; the second AssumeRole **with the first session's credentials** — the
      ;; same mistake as renewing an expired session by signing with the
      ;; expired session, and it fails the same silent way
      (and (contains? (set (:chained-roles seed)) role-arn) (not chained?))
      (access-denied role-arn)

      ;; AWS caps a chained session at one hour and refuses a longer request
      ;; outright rather than quietly shortening it
      (and chained? duration (> duration 3600))
      (wire/error {:status 400 :code "ValidationError"
                   :message (str "The requested DurationSeconds exceeds the 1 "
                                 "hour session limit for roles assumed by "
                                 "role chaining")})

      :else
      (let [session (session-credentials role-arn session-name)]
        (wire/ok
         (wire/document
          [:AssumeRoleResponse
           [:AssumeRoleResult
            [:Credentials
             [:AccessKeyId (:access-key-id session)]
             [:SecretAccessKey (:secret-access-key session)]
             [:SessionToken (:session-token session)]
             [:Expiration "2036-01-01T00:00:00Z"]]
            [:AssumedRoleUser
             [:Arn (:arn session)]
             [:AssumedRoleId (str "AROA" account ":" session-name)]]]
           [:ResponseMetadata
            [:RequestId "01234567-89ab-cdef-0123-456789abcdef"]]]))))))

(defn assume-role-with-web-identity
  "The one AWS call that carries no AWS credential.

  This is how a scanner on EKS, or in a CI job, authenticates: a workload
  identity provider writes a short-lived OIDC token to a file, and the token
  itself is the credential. **The request is unsigned** — there is nothing to
  sign it with, which is the whole point of eliminating static keys.

  That inverts a client's usual order of operations. Every other AWS call
  needs credentials before it can be made; this one produces them. A client
  whose AWS layer refuses to build a request without an access key cannot make
  it at all, and the way that presents is `no credentials configured` on a
  host that was configured correctly.

  The token is short-lived and the provider rewrites the file. A client that
  reads it once and keeps it for the length of a scan presents an expired
  token when it renews — and `InvalidIdentityToken` is not `ExpiredToken`, so
  a client matching only the latter gives up on a scan that a re-read would
  have finished."
  [{:keys [seed query]}]
  (let [role-arn (get query "RoleArn")
        session-name (or (get query "RoleSessionName") "web-identity")
        token (get query "WebIdentityToken")
        account (account-of-arn role-arn)
        expected (:web-identity-token seed)
        assumable (set (or (:assumable-roles seed) []))]
    (cond
      (str/blank? (str token))
      (wire/error {:status 400 :code "MissingParameter"
                   :message "WebIdentityToken is required"})

      (nil? account)
      (wire/error {:status 400 :code "ValidationError"
                   :message (str "Value '" role-arn "' at 'roleArn' failed to "
                                 "satisfy constraint")})

      ;; a token the provider no longer issues. Its own code, because the
      ;; remedy is `read the file again`, not `renew the session`
      (and expected (not= expected token))
      (wire/error {:status 400 :code "InvalidIdentityToken"
                   :message (str "The ID Token provided is not valid: it was "
                                 "not issued by the trusted provider, or it "
                                 "has been rotated since it was read")})

      (not (contains? assumable role-arn))
      (access-denied role-arn)

      :else
      (let [session (session-credentials role-arn session-name)]
        (wire/ok
         (wire/document
          [:AssumeRoleWithWebIdentityResponse
           [:AssumeRoleWithWebIdentityResult
            [:Credentials
             [:AccessKeyId (:access-key-id session)]
             [:SecretAccessKey (:secret-access-key session)]
             [:SessionToken (:session-token session)]
             [:Expiration "2036-01-01T00:00:00Z"]]
            [:SubjectFromWebIdentityToken "system:serviceaccount:security:scanner"]
            [:AssumedRoleUser
             [:Arn (:arn session)]
             [:AssumedRoleId (str "AROA" account ":" session-name)]]
            [:Provider "arn:aws:iam::123456789012:oidc-provider/opencloud"]]
           [:ResponseMetadata
            [:RequestId "01234567-89ab-cdef-0123-456789abcdef"]]]))))))

(def expired-token-error
  "What a session past its expiry gets.

  `ExpiredToken` and not `InvalidClientTokenId`: the two look alike and mean
  opposite things. One says renew, the other says your credentials are wrong,
  and a client that cannot tell them apart either gives up on a scan that
  would have worked or retries forever on one that never will."
  (wire/error {:status 403 :code "ExpiredToken"
               :message "The security token included in the request is expired"}))

(defn session-expired?
  "Deterministic expiry: a session lasts `:session-ttl-requests` requests.

  Wall-clock expiry cannot be tested without waiting, and a scanner's real
  failure is not that time passed — it is that a scan long enough to outlive
  its session was in the middle of something when it did."
  [{:keys [session-ttl-requests]} principal request-count]
  (and session-ttl-requests
       (:session? principal)
       (> (or request-count 0) session-ttl-requests)))

(defn sessions
  "The credential table an assumed session is verified against, alongside the
  long-lived accounts."
  [seed]
  (into {}
        (map (fn [role-arn]
               (let [session (session-credentials role-arn "opencloud")]
                 [(:access-key-id session)
                  (assoc session :session? true)])))
        (or (:assumable-roles seed) [])))

(defn handle
  "The STS face. Only AssumeRole; the rest is not emulated."
  [{:keys [seed query] :as request}]
  (case (get query "Action")
    "AssumeRole" (assume-role request)
    "AssumeRoleWithWebIdentity" (assume-role-with-web-identity request)
    "GetCallerIdentity"
    (wire/ok (wire/document
              [:GetCallerIdentityResponse
               [:GetCallerIdentityResult
                [:Arn (:arn (:principal request))]
                [:UserId (:user-id (:principal request))]
                [:Account (:account-id (:principal request))]]]))
    (wire/error {:status 400 :code "InvalidAction"
                 :message (str "Could not find operation "
                               (get query "Action") " for version 1")})))
