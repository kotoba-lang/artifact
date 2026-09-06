(ns content-identity-test
  (:require [clojure.test :refer [deftest is testing]]
            [ipld.core :as ipld]
            [kotoba.artifact.content-identity :as identity]))

(def def-cid "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku")
(def toolchain-cid "bafyreic3f5k3w6yqxg6v3s4h2m5r7dngpmv3zmdp4px7gq6n5l6s2by5de")

(def build
  {:compiler {:name "kotoba" :version "1"}
   :target {:isa :x86-64 :os :linux :abi :sysv}
   :flags #{:checked :fuel}
   :dependencies {:toolchain toolchain-cid}})

(deftest source-cid-addresses-exact-bytes
  (let [a (.getBytes "(def x 1)" "UTF-8")
        b (.getBytes "(def  x 1)" "UTF-8")]
    (is (re-matches #"bafkrei[a-z2-7]{52}" (identity/source-cid a)))
    (is (= "bafkreihvye2l63bnbojfkjbef37e3vkwjw7mm74dfn7eqtykjpizmpejhe"
           (identity/source-cid a)))
    (is (not= (identity/source-cid a) (identity/source-cid b)))))

(deftest build-cid-is-order-independent-and-link-sensitive
  (let [same (array-map :dependencies {:toolchain toolchain-cid}
                        :flags #{:fuel :checked}
                        :target {:abi :sysv :os :linux :isa :x86-64}
                        :compiler {:version "1" :name "kotoba"})
        a (identity/build-block build)
        b (identity/build-block same)]
    (is (= (:cid a) (:cid b)))
    (is (= (:cid a) (ipld/cid (:bytes a))))
    (is (= "bafyreigw3oapqsmogzgnyquyeqbybdturctmnzmmzy7tqmaafxmwyqog7e"
           (:cid a))
        "wire-format golden: change only with an explicit identity version")
    (is (not= (:cid a)
              (identity/build-cid (assoc-in build [:target :isa] :aarch64))))))

(deftest artifact-cid-binds-bytes-descriptor-definition-and-build
  (let [build-cid (identity/build-cid build)
        input {:bytes (byte-array [0x7f 0x45 0x4c 0x46])
               :descriptor {:format :elf64 :entry 'main}
               :definition-cid def-cid
               :build-cid build-cid}
        block (identity/artifact-block input)]
    (is (re-matches #"bafyrei[a-z2-7]{52}" (:cid block)))
    (is (re-matches #"bafkrei[a-z2-7]{52}" (:payload-cid block)))
    (is (not= (:cid block)
              (identity/artifact-cid
               (assoc input :bytes (byte-array [0x7f 0x45 0x4c 0x47])))))
    (is (not= (:cid block)
              (identity/artifact-cid
               (assoc-in input [:descriptor :format] :macho))))))

(deftest identity-envelopes-fail-closed
  (testing "unknown build fields"
    (is (thrown? clojure.lang.ExceptionInfo
                 (identity/build-cid (assoc build :ambient "ignored")))))
  (testing "source and artifact payloads are bytes"
    (is (thrown? clojure.lang.ExceptionInfo (identity/source-cid "source")))
    (is (thrown? clojure.lang.ExceptionInfo
                 (identity/artifact-cid
                  {:bytes "ELF" :descriptor {} :definition-cid def-cid
                   :build-cid (identity/build-cid build)})))))
