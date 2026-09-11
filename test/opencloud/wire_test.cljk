(ns opencloud.wire-test
  (:require [clojure.test :refer [deftest is]]
            [opencloud.wire :as wire]))

(deftest xml-matches-the-shapes-clients-parse
  (is (= "<R><A>x</A></R>" (wire/xml [:R [:A "x"]])))
  ;; an absent optional element is absent, not empty
  (is (= "<R><A>x</A></R>" (wire/xml [:R [:A "x"] nil])))
  (is (= "<R><A/></R>" (wire/xml [:R [:A]])))
  (is (= "<R>a &amp; b &lt;c&gt;</R>" (wire/xml [:R "a & b <c>"])))
  (is (= "<R><A>1</A><A>2</A></R>" (wire/xml [:R [:A 1] [:A 2]]))))

(deftest percent-decoding-distinguishes-a-plus-from-a-space
  (is (= "a b" (wire/percent-decode "a%20b")))
  ;; in a signed query a plus is a literal plus; only a form body decodes it
  (is (= "a+b" (wire/percent-decode "a+b")))
  (is (= "a b" (wire/percent-decode "a+b" {:plus-is-space true})))
  (is (= "a%zz" (wire/percent-decode "a%zz"))))

(deftest query-parsing-keeps-the-first-value-of-a-repeated-name
  (is (= {"Action" "ListRoles" "Version" "2010-05-08"}
         (wire/parse-query "Action=ListRoles&Version=2010-05-08")))
  (is (= {"a" "1"} (wire/parse-query "a=1&a=2")))
  (is (= {"policy" ""} (wire/parse-query "policy")))
  (is (= {} (wire/parse-query ""))))

(deftest policy-documents-go-out-url-encoded
  (is (= "%7B%22Effect%22%3A%22Allow%22%7D"
         (wire/encoded-policy {"Effect" "Allow"})))
  (is (= "{\"a\":[1,true,null]}" (wire/json {"a" [1 true nil]}))))

(deftest paging-hands-back-a-marker-only-while-more-remain
  (is (= {:items [1 2] :next-marker "2"} (wire/page [1 2 3 4 5] 2 nil)))
  (is (= {:items [3 4] :next-marker "4"} (wire/page [1 2 3 4 5] 2 "2")))
  (is (= {:items [5] :next-marker nil} (wire/page [1 2 3 4 5] 2 "4")))
  (is (= {:items [] :next-marker nil} (wire/page [] 2 nil))))
