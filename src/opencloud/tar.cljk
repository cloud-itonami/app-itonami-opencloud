(ns opencloud.tar
  "A ustar writer, so the registry serves layers a real tar reader has to
  parse rather than a shape agreed on between this server and one client.

  Every field here is a place clients go wrong: sizes are octal text and not
  numbers, the checksum is computed over the header with its own field blanked
  to spaces, a name longer than 100 bytes has to move into the prefix field,
  and the archive ends with two zero blocks rather than at the last entry. A
  reader that gets any of them wrong reads a plausible-looking wrong file, and
  a package database it half-read is worse than one it could not find."
  (:require ["node:zlib" :as zlib]))

(def block-size 512)

(defn- write-string! [buffer offset text length]
  (let [bytes (js/Buffer.from (str text) "utf8")]
    (when (> (.-length bytes) length)
      (throw (js/Error. (str "tar field overflow: " text))))
    (.copy bytes buffer offset)))

(defn- write-octal!
  "Octal text, zero padded, NUL terminated — `size` is `00000001750` and not
  1000."
  [buffer offset value length]
  (let [text (.toString (js/Number value) 8)
        padded (str (.repeat "0" (max 0 (- length 1 (count text)))) text)]
    (write-string! buffer offset padded (dec length))))

(defn- split-path
  "ustar keeps a path longer than 100 bytes in `prefix` + `name`, split at a
  slash. Truncating instead produces an entry with a name nobody asked for."
  [path]
  (if (<= (.-length (js/Buffer.from path "utf8")) 100)
    ["" path]
    (let [index (.lastIndexOf path "/" 100)]
      (when (or (neg? index) (> (- (count path) index 1) 100))
        (throw (js/Error. (str "path does not fit a ustar header: " path))))
      [(subs path 0 index) (subs path (inc index))])))

(defn- header [{:keys [path size mode type mtime]
                :or {mode 0644 type "0" mtime 0}}]
  (let [buffer (.alloc js/Buffer block-size 0)
        [prefix name*] (split-path path)]
    (write-string! buffer 0 name* 100)
    (write-octal! buffer 100 mode 8)
    (write-octal! buffer 108 0 8)                        ; uid
    (write-octal! buffer 116 0 8)                        ; gid
    (write-octal! buffer 124 size 12)
    (write-octal! buffer 136 mtime 12)
    ;; the checksum field is spaces while the checksum is computed over it
    (.fill buffer 32 148 156)
    (write-string! buffer 156 type 1)
    (write-string! buffer 257 "ustar" 6)
    (write-string! buffer 263 "00" 2)
    (let [sum (reduce + 0 (array-seq buffer))]
      (write-octal! buffer 148 sum 7)
      (.write buffer " " 154 1 "utf8"))
    buffer))

(defn- pad-to-block [buffer]
  (let [remainder (mod (.-length buffer) block-size)]
    (if (zero? remainder)
      buffer
      (js/Buffer.concat #js [buffer (.alloc js/Buffer (- block-size remainder) 0)]))))

(defn tar
  "`entries` is a sequence of {:path :content} for files and {:path :type \"5\"}
  for directories."
  [entries]
  (js/Buffer.concat
   (clj->js
    (concat
     (mapcat (fn [{:keys [path content] :as entry}]
               (let [body (js/Buffer.from (or content "") "utf8")]
                 [(header (assoc entry :size (.-length body)))
                  (pad-to-block body)]))
             entries)
     ;; two zero blocks, which is how a reader knows the archive ended and
     ;; not that the connection did
     [(.alloc js/Buffer (* 2 block-size) 0)]))))

(defn tar-gzip [entries]
  (.gzipSync zlib (tar entries)))

(defn tar-zstd
  "A zstd-compressed layer. Not exotic: buildkit emits these on request and
  some registries default to them. A scanner that only knows gzip fetches the
  blob, verifies the digest, finds nothing a tar parser recognises, and
  reports an image with fewer things in it than it has."
  [entries]
  (.zstdCompressSync zlib (tar entries)))
