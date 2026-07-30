(ns opencloud.wire
  "Wire formats the real cloud control planes actually speak.

  The point of this repository is that a client cannot tell the difference. A
  REST-and-JSON reskin of a cloud API verifies nothing about a client that has
  to sign a query-protocol request and read an XML response — the two disagree
  in exactly the places clients get wrong."
  (:require [clojure.string :as str]))

;; --- percent decoding -------------------------------------------------------

(defn- hex-value [character]
  (let [code #?(:clj (int character) :cljs (.charCodeAt (str character) 0))]
    (cond
      (<= 48 code 57) (- code 48)
      (<= 97 code 102) (+ 10 (- code 97))
      (<= 65 code 70) (+ 10 (- code 65))
      :else nil)))

(defn percent-decode
  "`+` is a space only in a form body; in a path or a signed query it is a
  literal plus. The caller says which, because getting this backwards is a
  classic source of signature mismatches."
  [text & [{:keys [plus-is-space]}]]
  (loop [characters (seq (str text))
         out []]
    (if-let [character (first characters)]
      (cond
        (and plus-is-space (= \+ character))
        (recur (rest characters) (conj out \space))

        (= \% character)
        (let [high (hex-value (second characters))
              low (hex-value (nth characters 2 nil))]
          (if (and high low)
            (recur (drop 3 characters) (conj out (char (+ (* 16 high) low))))
            (recur (rest characters) (conj out character))))

        :else (recur (rest characters) (conj out character)))
      (str/join out))))

(defn parse-query
  "Query string -> {name value}. Repeated names keep the first value, which is
  what the query protocol means by a scalar parameter."
  [query & [options]]
  (reduce
   (fn [acc pair]
     (if (str/blank? pair)
       acc
       (let [index (str/index-of pair "=")
             [k v] (if index
                     [(subs pair 0 index) (subs pair (inc index))]
                     [pair ""])
             name* (percent-decode k options)]
         (if (contains? acc name*)
           acc
           (assoc acc name* (percent-decode v options))))))
   {}
   (str/split (or query "") #"&")))

(defn split-target
  "`/path?query` -> [path query]."
  [target]
  (let [index (str/index-of (or target "/") "?")]
    (if index
      [(subs target 0 index) (subs target (inc index))]
      [(or target "/") ""])))

;; --- XML --------------------------------------------------------------------

(def ^:private escapes
  {\& "&amp;" \< "&lt;" \> "&gt;" \" "&quot;" \' "&apos;"})

(defn escape [text]
  (str/join (map #(get escapes % (str %)) (str text))))

(defn xml
  "Hiccup-shaped EDN -> XML text.

    [:Roles [:member [:Arn \"arn:…\"]]]

  nil children are dropped so an optional element is simply absent, the way
  AWS omits it, rather than present and empty."
  [form]
  (cond
    (nil? form) ""
    (string? form) (escape form)
    (or (number? form) (boolean? form) (keyword? form))
    (escape (if (keyword? form) (name form) (str form)))

    (and (vector? form) (keyword? (first form)))
    (let [[tag & children] form
          body (str/join (map xml (remove nil? children)))]
      (if (str/blank? body)
        (str "<" (name tag) "/>")
        (str "<" (name tag) ">" body "</" (name tag) ">")))

    (sequential? form) (str/join (map xml (remove nil? form)))
    :else (escape (str form))))

(defn document
  "An XML response with the declaration the real services send."
  [form]
  (str "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" (xml form)))

;; --- responses --------------------------------------------------------------

(defn ok [body & [{:keys [content-type headers]}]]
  {:status 200
   :headers (merge {"content-type" (or content-type "text/xml")} headers)
   :body body})

(defn error
  "The error envelope matters as much as the success one: a client that treats
  a 403 as an empty result is exactly the failure this repository exists to
  catch, and it can only be caught if the status and code are real."
  [{:keys [status code message request-id shape]
    :or {request-id "00000000-0000-0000-0000-000000000000"}}]
  {:status status
   :headers {"content-type" "text/xml"
             "x-amzn-requestid" request-id}
   :body (document
          (case (or shape :query)
            :s3 [:Error [:Code code] [:Message message] [:RequestId request-id]]
            [:ErrorResponse
             [:Error [:Type "Sender"] [:Code code] [:Message message]]
             [:RequestId request-id]]))})

(defn json-error [status code message]
  {:status status
   :headers {"content-type" "application/json"}
   :body (str "{\"error\":{\"code\":\"" code "\",\"message\":\"" message "\"}}")})

;; --- JSON -------------------------------------------------------------------

(defn json
  "Minimal writer. IAM hands back policy documents as URL-encoded JSON, so the
  seed can hold readable EDN and still go out on the wire in the real shape."
  [value]
  (cond
    (nil? value) "null"
    (string? value) (str \" (-> value
                                (str/replace "\\" "\\\\")
                                (str/replace "\"" "\\\"")
                                (str/replace "\n" "\\n"))
                         \")
    (keyword? value) (json (name value))
    (boolean? value) (str value)
    (number? value) (str value)
    (map? value) (str "{"
                      (str/join "," (map (fn [[k v]]
                                           (str (json (if (keyword? k) (name k)
                                                          (str k)))
                                                ":" (json v)))
                                         value))
                      "}")
    (sequential? value) (str "[" (str/join "," (map json value)) "]")
    :else (json (str value))))

(def ^:private component-safe
  (set "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"))

(defn percent-encode [text]
  (str/join
   (mapcat
    (fn [character]
      (if (contains? component-safe character)
        [character]
        (let [code #?(:clj (int character) :cljs (.charCodeAt (str character) 0))]
          ;; the seed stays ASCII, which is what IAM documents are
          [(str "%" (str/upper-case
                     (str (when (< code 16) "0")
                          #?(:clj (Integer/toHexString code)
                             :cljs (.toString code 16)))))])))
    (seq (str text)))))

(defn encoded-policy
  "A policy document exactly as IAM returns it: URL-encoded JSON."
  [document]
  (percent-encode (json document)))

;; --- pagination -------------------------------------------------------------

(defn page
  "One page plus the marker for the next, or nil when this is the last."
  [items page-size marker]
  (let [ordered (vec items)
        marker* (str marker)
        _ (when-not (or (str/blank? marker*) (re-matches #"\d+" marker*))
            ;; parseInt reads the leading digits of `1?continue=2` as 1 and
            ;; serves page one forever; a client looping like that must be
            ;; told, not humoured
            (throw (ex-info "pagination marker is not a position"
                            {:type :opencloud/invalid-marker :value marker*})))
        start (if (str/blank? marker*)
                0
                (#?(:clj Integer/parseInt :cljs js/parseInt) marker*))
        size (max 1 (or page-size (count ordered)))
        taken (subvec ordered (min start (count ordered))
                      (min (+ start size) (count ordered)))
        next-start (+ start size)]
    {:items taken
     :next-marker (when (< next-start (count ordered)) (str next-start))}))
