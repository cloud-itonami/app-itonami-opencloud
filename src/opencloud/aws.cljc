(ns opencloud.aws
  "AWS control-plane responses in the shapes the real services send.

  EC2, IAM, and RDS answer the query protocol: `Action=` plus `Version=` in,
  XML out, with lists wrapped in `<item>` or `<member>` depending on the
  service — a difference clients routinely get wrong and which a JSON reskin
  can never expose. S3 is REST with subresource query keys and its own error
  envelope.

  I/O free: a request map in, a response map out. The HTTP shim is the only
  part that touches a socket."
  (:require [clojure.string :as str]
            [opencloud.wire :as wire]))

;; --- helpers ----------------------------------------------------------------

(defn- tags-xml [tags wrapper key-tag value-tag]
  (when (seq tags)
    (into [wrapper]
          (for [[k v] (sort tags)]
            [:item [key-tag k] [value-tag v]]))))

(defn- member-list [wrapper items]
  (into [wrapper] (map (fn [item] (into [:member] item)) items)))

(defn- item-list [wrapper items]
  (into [wrapper] (map (fn [item] (into [:item] item)) items)))

(defn- truncation [next-marker]
  [[:IsTruncated (if next-marker "true" "false")]
   (when next-marker [:Marker next-marker])])

;; --- STS --------------------------------------------------------------------

(defn get-caller-identity [{:keys [seed principal]}]
  [:GetCallerIdentityResponse
   [:GetCallerIdentityResult
    [:Arn (:arn principal)]
    [:UserId (:user-id principal)]
    [:Account (:account-id seed)]]])

;; --- EC2 --------------------------------------------------------------------

(defn- instance-xml [instance]
  [[:instanceId (:instance-id instance)]
   (when (:image-id instance) [:imageId (:image-id instance)])
   [:instanceState [:code (if (= "running" (:state instance)) 16 80)]
    [:name (:state instance)]]
   (when (:private-ip instance) [:privateIpAddress (:private-ip instance)])
   (when (:public-ip instance) [:ipAddress (:public-ip instance)])
   [:instanceType (:instance-type instance)]
   (when (:subnet instance) [:subnetId (:subnet instance)])
   (when (:vpc instance) [:vpcId (:vpc instance)])
   (when (:instance-profile instance)
     [:iamInstanceProfile [:arn (:instance-profile instance)]
      [:id "AIPAEXAMPLE"]])
   [:metadataOptions [:httpTokens (:http-tokens instance)]]
   [:monitoring [:state "disabled"]]
   (item-list :groupSet (map (fn [group] [[:groupId group]])
                             (:security-groups instance)))
   (tags-xml (:tags instance) :tagSet :key :value)])

(def default-enabled-regions
  "Regions this account may read. Everything else answers the way AWS answers
  for a region that is not enabled, which is an authorization failure and not
  an empty region — a client that reads it as empty reports the estate as
  smaller than it is, and reports it that way for exactly the regions nobody
  is watching."
  #{"ap-northeast-1" "us-east-1" "eu-west-1"})

(defn region-enabled? [seed region]
  (contains? (set (or (:enabled-regions seed) default-enabled-regions))
             (str region)))

(defn region-disabled-error [region]
  (wire/error {:status 401 :code "AuthFailure"
               :message (str "AWS was not able to validate the provided access "
                             "credentials for region " region)}))

(defn in-region
  "Only what lives in this region. A resource attributed to the wrong region
  breaks every rule that reads one, and duplicating a global resource per
  region multiplies the estate by the number of regions."
  [rows region]
  (if (nil? region)
    ;; the caller did not scope the request; filtering on nothing would
    ;; answer with nothing, which is the failure this is here to prevent
    (vec rows)
    (vec (filter #(or (nil? (:region %)) (= region (:region %))) rows))))

(defn describe-instances [{:keys [seed query region]}]
  ;; only this region's instances. A client that asks three regions and gets
  ;; the same answer three times counts every instance three times
  (let [{:keys [items next-marker]} (wire/page (in-region (:instances seed)
                                                          region)
                                               (:page-size seed)
                                               (get query "NextToken"))]
    [:DescribeInstancesResponse
     [:requestId "8f7724cf-496f-496e-8fe3-example"]
     (when next-marker [:nextToken next-marker])
     ;; one reservation per page keeps the nesting real without pretending the
     ;; seed models reservation grouping
     (item-list :reservationSet
                [[[:reservationId "r-0000000000000001"]
                  [:ownerId (:account-id seed)]
                  (item-list :instancesSet (map instance-xml items))]])]))

(defn- permission-xml [permission]
  [[:ipProtocol (:protocol permission)]
   (when (:from permission) [:fromPort (:from permission)])
   (when (:to permission) [:toPort (:to permission)])
   (item-list :ipRanges (map (fn [cidr] [[:cidrIp cidr]]) (:cidrs permission)))
   (item-list :ipv6Ranges (map (fn [cidr] [[:cidrIpv6 cidr]])
                               (:cidrs-v6 permission)))])

(defn describe-security-groups [{:keys [seed]}]
  [:DescribeSecurityGroupsResponse
   (item-list :securityGroupInfo
              (for [group (:security-groups seed)]
                [[:groupId (:group-id group)]
                 [:groupName (:group-name group)]
                 [:vpcId (:vpc group)]
                 (item-list :ipPermissions (map permission-xml
                                                (:ingress group)))]))])

(defn describe-vpcs [{:keys [seed]}]
  [:DescribeVpcsResponse
   (item-list :vpcSet (for [vpc (distinct (keep :vpc (:instances seed)))]
                        [[:vpcId vpc] [:state "available"]]))])

(defn describe-subnets [{:keys [seed]}]
  [:DescribeSubnetsResponse
   (item-list :subnetSet (for [subnet (distinct (keep :subnet
                                                      (:instances seed)))]
                           [[:subnetId subnet] [:state "available"]]))])

(defn describe-volumes [{:keys [seed]}]
  [:DescribeVolumesResponse
   (item-list :volumeSet (for [instance (:instances seed)]
                           [[:volumeId (str "vol-" (subs (:instance-id instance) 2))]
                            [:encrypted "true"]
                            [:status "in-use"]]))])

;; --- RDS --------------------------------------------------------------------

(defn describe-db-instances [{:keys [seed]}]
  [:DescribeDBInstancesResponse
   [:DescribeDBInstancesResult
    (member-list
     :DBInstances
     (for [database (:databases seed)]
       [[:DBInstanceArn (:arn database)]
        [:DBInstanceIdentifier (:identifier database)]
        [:Engine (:engine database)]
        [:EngineVersion (:engine-version database)]
        [:PubliclyAccessible (str (boolean (:public? database)))]
        [:StorageEncrypted (str (boolean (:encrypted? database)))]
        [:MultiAZ (str (boolean (:multi-az? database)))]
        [:BackupRetentionPeriod (:backup-retention database)]
        [:DeletionProtection (str (boolean (:deletion-protection? database)))]
        [:AutoMinorVersionUpgrade "true"]
        (member-list :VpcSecurityGroups
                     (for [group (:security-groups database)]
                       [[:VpcSecurityGroupId group] [:Status "active"]]))
        (when (seq (:tags database))
          (member-list :TagList (for [[k v] (sort (:tags database))]
                                  [[:Key k] [:Value v]])))]))]])

;; --- IAM --------------------------------------------------------------------

(defn- role-xml [role]
  [[:Arn (:arn role)]
   [:RoleName (:name role)]
   [:Path "/"]
   [:CreateDate (:created role)]
   (when (:trust role)
     [:AssumeRolePolicyDocument (wire/encoded-policy (:trust role))])
   (when (seq (:tags role))
     (member-list :Tags (for [[k v] (sort (:tags role))]
                          [[:Key k] [:Value v]])))])

(defn list-roles [{:keys [seed query]}]
  (let [{:keys [items next-marker]} (wire/page (:roles seed) (:page-size seed)
                                               (get query "Marker"))]
    [:ListRolesResponse
     (into [:ListRolesResult]
           (concat (truncation next-marker)
                   [(member-list :Roles (map role-xml items))]))]))

(defn list-users [{:keys [seed query]}]
  (let [{:keys [items next-marker]} (wire/page (:users seed) (:page-size seed)
                                               (get query "Marker"))]
    [:ListUsersResponse
     (into [:ListUsersResult]
           (concat (truncation next-marker)
                   [(member-list
                     :Users
                     (for [user items]
                       [[:Arn (:arn user)]
                        [:UserName (:name user)]
                        [:Path "/"]
                        [:CreateDate (:created user)]]))]))]))

(defn- principal-by-name [seed collection name*]
  (first (filter #(= name* (:name %)) (get seed collection))))

(defn- attached-for [seed query]
  (let [role (principal-by-name seed :roles (get query "RoleName"))
        user (principal-by-name seed :users (get query "UserName"))]
    (:attached-policies (or role user))))

(defn list-attached-policies [{:keys [seed query action]}]
  (let [wrapper (if (= "ListAttachedRolePolicies" action)
                  :ListAttachedRolePoliciesResult
                  :ListAttachedUserPoliciesResult)
        response (if (= "ListAttachedRolePolicies" action)
                   :ListAttachedRolePoliciesResponse
                   :ListAttachedUserPoliciesResponse)]
    [response
     [wrapper
      [:IsTruncated "false"]
      (member-list :AttachedPolicies
                   (for [arn (attached-for seed query)]
                     [[:PolicyArn arn]
                      [:PolicyName (get-in seed [:policies arn :name])]]))]]))

(defn list-inline-policies [{:keys [seed query action]}]
  (let [role? (= "ListRolePolicies" action)
        principal (if role?
                    (principal-by-name seed :roles (get query "RoleName"))
                    (principal-by-name seed :users (get query "UserName")))]
    [(if role? :ListRolePoliciesResponse :ListUserPoliciesResponse)
     [(if role? :ListRolePoliciesResult :ListUserPoliciesResult)
      [:IsTruncated "false"]
      (into [:PolicyNames]
            (for [name* (sort (keys (:inline-policies principal)))]
              [:member name*]))]]))

(defn get-inline-policy [{:keys [seed query action]}]
  (let [role? (= "GetRolePolicy" action)
        principal (if role?
                    (principal-by-name seed :roles (get query "RoleName"))
                    (principal-by-name seed :users (get query "UserName")))
        document (get-in principal [:inline-policies (get query "PolicyName")])]
    (when document
      [(if role? :GetRolePolicyResponse :GetUserPolicyResponse)
       [(if role? :GetRolePolicyResult :GetUserPolicyResult)
        [:PolicyName (get query "PolicyName")]
        (if role?
          [:RoleName (get query "RoleName")]
          [:UserName (get query "UserName")])
        [:PolicyDocument (wire/encoded-policy document)]]])))

(defn get-policy [{:keys [seed query]}]
  (let [arn (get query "PolicyArn")
        policy (get-in seed [:policies arn])]
    (when policy
      [:GetPolicyResponse
       [:GetPolicyResult
        [:Policy
         [:PolicyName (:name policy)]
         [:Arn arn]
         [:DefaultVersionId (:default-version policy)]]]])))

(defn get-policy-version [{:keys [seed query]}]
  (let [arn (get query "PolicyArn")
        policy (get-in seed [:policies arn])
        version (get query "VersionId")
        document (get-in policy [:versions version])]
    (when document
      [:GetPolicyVersionResponse
       [:GetPolicyVersionResult
        [:PolicyVersion
         [:VersionId version]
         [:IsDefaultVersion (str (= version (:default-version policy)))]
         [:Document (wire/encoded-policy document)]
         [:CreateDate "2025-11-02T04:00:00Z"]]]])))

(defn list-access-keys [{:keys [seed query]}]
  (let [user (principal-by-name seed :users (get query "UserName"))]
    [:ListAccessKeysResponse
     [:ListAccessKeysResult
      [:IsTruncated "false"]
      (member-list :AccessKeyMetadata
                   (for [key* (:access-keys user)]
                     [[:UserName (:name user)]
                      [:AccessKeyId (:id key*)]
                      [:Status (:status key*)]
                      [:CreateDate (:created key*)]]))]]))

(defn get-access-key-last-used [{:keys [seed query]}]
  (let [key-id (get query "AccessKeyId")
        entry (first (for [user (:users seed)
                           key* (:access-keys user)
                           :when (= key-id (:id key*))]
                       {:user user :key key*}))]
    (when entry
      [:GetAccessKeyLastUsedResponse
       [:GetAccessKeyLastUsedResult
        [:UserName (get-in entry [:user :name])]
        ;; a key that has never been used carries no date, which is a
        ;; different fact from a key used long ago
        (into [:AccessKeyLastUsed]
              (if-let [last-used (get-in entry [:key :last-used])]
                [[:LastUsedDate last-used] [:ServiceName "s3"]
                 [:Region "ap-northeast-1"]]
                [[:ServiceName "N/A"] [:Region "N/A"]]))]])))

(defn list-mfa-devices [{:keys [seed query]}]
  (let [user (principal-by-name seed :users (get query "UserName"))
        account (:account-id seed)]
    [:ListMFADevicesResponse
     [:ListMFADevicesResult
      [:IsTruncated "false"]
      (if (:mfa? user)
        (member-list :MFADevices
                     [[[:UserName (:name user)]
                       [:SerialNumber (str "arn:aws:iam::" account
                                           ":mfa/" (:name user))]
                       [:EnableDate "2024-01-06T00:00:00Z"]]])
        [:MFADevices])]]))

(defn get-account-summary [{:keys [seed]}]
  [:GetAccountSummaryResponse
   [:GetAccountSummaryResult
    (into [:SummaryMap]
          (for [[k v] [["Users" (count (:users seed))]
                       ["Roles" (count (:roles seed))]
                       ["Policies" (count (:policies seed))]
                       ["AccountMFAEnabled" 1]]]
            [:entry [:key k] [:value v]]))]])

;; --- KMS --------------------------------------------------------------------

(defn- key-by-id [seed key-id]
  (first (filter #(or (= key-id (:key-id %)) (= key-id (:arn %)))
                 (:keys seed))))

(defn list-keys [{:keys [seed]}]
  [:ListKeysResponse
   [:ListKeysResult
    [:Truncated "false"]
    (member-list :Keys (for [k (:keys seed)]
                         [[:KeyId (:key-id k)] [:KeyArn (:arn k)]]))]])

(defn describe-key [{:keys [seed query]}]
  (when-let [k (key-by-id seed (get query "KeyId"))]
    [:DescribeKeyResponse
     [:DescribeKeyResult
      [:KeyMetadata
       [:KeyId (:key-id k)]
       [:Arn (:arn k)]
       [:Description (:description k)]
       [:KeyManager (or (:manager k) "CUSTOMER")]
       [:Enabled (str (not (false? (:enabled? k))))]]]]))

(defn get-key-policy [{:keys [seed query]}]
  (when-let [k (key-by-id seed (get query "KeyId"))]
    ;; KMS hands the document back as a JSON string inside the XML, not as
    ;; nested elements
    [:GetKeyPolicyResponse
     [:GetKeyPolicyResult [:Policy (wire/json (:policy k))]]]))

;; --- dispatch ---------------------------------------------------------------

(def query-actions
  "Every action this server answers, and the service it belongs to. A client
  asking for anything else gets InvalidAction, not an empty success."
  {"GetCallerIdentity" [:sts get-caller-identity]
   "DescribeInstances" [:ec2 describe-instances]
   "DescribeSecurityGroups" [:ec2 describe-security-groups]
   "DescribeVpcs" [:ec2 describe-vpcs]
   "DescribeSubnets" [:ec2 describe-subnets]
   "DescribeVolumes" [:ec2 describe-volumes]
   "DescribeDBInstances" [:rds describe-db-instances]
   "ListKeys" [:kms list-keys]
   "DescribeKey" [:kms describe-key]
   "GetKeyPolicy" [:kms get-key-policy]
   "ListRoles" [:iam list-roles]
   "ListUsers" [:iam list-users]
   "ListAttachedRolePolicies" [:iam list-attached-policies]
   "ListAttachedUserPolicies" [:iam list-attached-policies]
   "ListRolePolicies" [:iam list-inline-policies]
   "ListUserPolicies" [:iam list-inline-policies]
   "GetRolePolicy" [:iam get-inline-policy]
   "GetUserPolicy" [:iam get-inline-policy]
   "GetPolicy" [:iam get-policy]
   "GetPolicyVersion" [:iam get-policy-version]
   "ListAccessKeys" [:iam list-access-keys]
   "GetAccessKeyLastUsed" [:iam get-access-key-last-used]
   "ListMFADevices" [:iam list-mfa-devices]
   "GetAccountSummary" [:iam get-account-summary]})

(defn throttled
  "The refusal a real AWS endpoint gives when it is being asked too often.

  The query protocol answers 400 with a `Throttling` code; S3 answers 503
  `SlowDown`. Neither is an empty result, and a client that reads either as
  one reports a partial inventory as a complete estate — which is the failure
  the whole collection contract exists to prevent and which no recorded
  response can produce."
  [shape]
  (if (= :s3 shape)
    (assoc (wire/error {:status 503 :code "SlowDown"
                        :message "Please reduce your request rate."
                        :shape :s3})
           :headers {"content-type" "text/xml" "retry-after" "1"})
    (assoc (wire/error {:status 400 :code "Throttling"
                        :message "Rate exceeded"})
           :headers {"content-type" "text/xml" "retry-after" "1"})))

(defn stale-read?
  "Is this the read that the replica has not caught up on?

  S3 and IAM are eventually consistent, and the way a scanner meets that is
  not `a resource I just created is missing`. It is: **`ListBuckets` names a
  bucket and the very next `GetBucketPolicy` says the bucket does not exist.**
  Two replicas, two answers, seconds apart, in the middle of a scan that is
  doing nothing unusual.

  What makes it dangerous is that `GetBucketPolicy` already uses 404 to mean
  something ordinary — `NoSuchBucketPolicy`, this bucket has no policy, which
  is a fact a scanner must act on. A client that keys on the status and not on
  the code reads `NoSuchBucket` as `no policy attached`, and a bucket whose
  policy it never saw is filed as one that grants nothing."
  [{:keys [inconsistent-every request-count]}]
  (and inconsistent-every
       (pos? inconsistent-every)
       (zero? (mod (inc (or request-count 0)) inconsistent-every))))

(defn throttle-now?
  "Deterministic: every nth request to this face is refused, so a test can say
  which one."
  [{:keys [throttle-every request-count]}]
  (and throttle-every
       (pos? throttle-every)
       (zero? (mod (inc (or request-count 0)) throttle-every))))

(defn for-principal
  "The estate this credential can see.

  A session assumed into another account answers with that account's
  resources. Without this the fallback bug is invisible: a client that
  silently used its own credentials would get the same answer either way and
  file it under whichever account it meant to read."
  [seed principal]
  (if-let [other (get-in seed [:assumed-accounts (:account-id principal)])]
    (merge seed other {:account-id (:account-id principal)})
    seed))

(defn handle-query
  "One query-protocol request."
  [{:keys [seed query principal region]}]
  (let [action (get query "Action")
        [_ handler] (get query-actions action)]
    (cond
      ;; before anything else: a throttle is not a smaller answer
      (throttle-now? seed) (throttled :query)

      (nil? action)
      (wire/error {:status 400 :code "MissingAction"
                   :message "No action was supplied with this request."})

      (nil? handler)
      (wire/error {:status 400 :code "InvalidAction"
                   :message (str "Could not find operation " action
                                 " for version 1")})

      ;; a region the account cannot read answers the way AWS answers, which
      ;; is an authorization failure and not an empty region
      (and region (not (region-enabled? seed region)))
      (region-disabled-error region)

      :else
      (if-let [form (handler {:seed seed :query query :action action
                              :region region :principal principal})]
        (wire/ok (wire/document form))
        (wire/error {:status 404 :code "NoSuchEntity"
                     :message "The request was rejected because it referenced a resource that does not exist."})))))

;; --- S3 ---------------------------------------------------------------------

(defn- bucket-by-name [seed name*]
  (first (filter #(= name* (:name %)) (:buckets seed))))

(defn handle-s3
  "S3 is REST: the bucket is in the host, and the operation is a subresource
  key in the query string. Its errors use a different envelope from the query
  protocol, and a client that assumes one shape for both breaks here."
  [{:keys [seed host path query]}]
  (let [;; virtual-hosted style puts the bucket in the host; path style puts
        ;; it in the first path segment. Both are real, and a client aimed at
        ;; a local endpoint can only use the second.
        bucket-name (or (second (re-find #"^([^.]+)\.s3[.-]" (str host)))
                        (second (re-find #"^/([^/?]+)" (str path))))
        bucket (when bucket-name (bucket-by-name seed bucket-name))
        s3-error (fn [status code message]
                   (wire/error {:status status :code code :message message
                                :shape :s3}))]
    (cond
      ;; S3 says SlowDown with a different envelope from the query protocol,
      ;; and a client that assumes one shape for both breaks here too
      (throttle-now? seed) (throttled :s3)

      (nil? bucket-name)
      (if (= "/" path)
        (wire/ok (wire/document
                  [:ListAllMyBucketsResult
                   [:Owner [:ID "opencloud"] [:DisplayName "opencloud"]]
                   (into [:Buckets]
                         (for [b (:buckets seed)]
                           [:Bucket [:Name (:name b)]
                            [:CreationDate (:created b)]]))]))
        (s3-error 404 "NoSuchKey" "The specified key does not exist."))

      (nil? bucket)
      (s3-error 404 "NoSuchBucket" "The specified bucket does not exist.")

      ;; the bucket the listing just named, gone from the replica that
      ;; answers the detail. Only the sub-resource reads: the listing stays
      ;; authoritative, which is exactly what makes the pair contradictory
      (and (stale-read? seed) (some #(contains? query %)
                                    ["policyStatus" "policy" "encryption"
                                     "publicAccessBlock" "tagging"]))
      (s3-error 404 "NoSuchBucket" "The specified bucket does not exist.")

      ;; a credential that may list buckets but not read one bucket's posture.
      ;; 403 here is `you may not know`, and a client that substitutes an
      ;; empty PolicyStatus for it has written down `not public` — about the
      ;; one bucket it could not see, which in this seed is a public one
      (and (= (:name bucket) (:posture-denied seed))
           (some #(contains? query %) ["policyStatus" "policy"]))
      (s3-error 403 "AccessDenied" "Access Denied")

      (contains? query "policyStatus")
      (wire/ok (wire/document
                [:PolicyStatus [:IsPublic (str (boolean (:public? bucket)))]]))

      (contains? query "encryption")
      (if-let [algorithm (:encryption bucket)]
        (wire/ok (wire/document
                  [:ServerSideEncryptionConfiguration
                   [:Rule (into [:ApplyServerSideEncryptionByDefault
                                 [:SSEAlgorithm algorithm]]
                                (when-let [key-arn (:kms-key bucket)]
                                  [[:KMSMasterKeyID key-arn]]))]]))
        ;; the real service 404s rather than returning an empty configuration
        (s3-error 404 "ServerSideEncryptionConfigurationNotFoundError"
                  "The server side encryption configuration was not found"))

      (contains? query "publicAccessBlock")
      (if (:public-access-block? bucket)
        (wire/ok (wire/document
                  [:PublicAccessBlockConfiguration
                   [:BlockPublicAcls "true"] [:IgnorePublicAcls "true"]
                   [:BlockPublicPolicy "true"] [:RestrictPublicBuckets "true"]]))
        (s3-error 404 "NoSuchPublicAccessBlockConfiguration"
                  "The public access block configuration was not found"))

      (contains? query "tagging")
      (if (seq (:tags bucket))
        (wire/ok (wire/document
                  [:Tagging (into [:TagSet]
                                  (for [[k v] (sort (:tags bucket))]
                                    [:Tag [:Key k] [:Value v]]))]))
        (s3-error 404 "NoSuchTagSet" "The TagSet does not exist"))

      (contains? query "location")
      (wire/ok (wire/document
                [:LocationConstraint (:region bucket)]))

      (contains? query "policy")
      (if-let [policy (:policy bucket)]
        (wire/ok (wire/json policy) {:content-type "application/json"})
        (s3-error 404 "NoSuchBucketPolicy" "The bucket policy does not exist"))

      :else
      (s3-error 400 "InvalidRequest"
                (str "opencloud does not implement this S3 operation: "
                     (str/join "," (sort (keys query))))))))
