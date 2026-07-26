(ns artifact-test
  (:require [clojure.test :refer [deftest is]]
            [kotoba.artifact.core :as artifact]
            [kotoba.artifact.runtime-identity]))

;; Load gate: the split must not break namespace resolution. Each extracted
;; namespace must load standalone from this repo's own dependency closure.
(deftest every-extracted-namespace-loads
  (is (some? (find-ns 'kotoba.artifact.core)) "kotoba.artifact.core must load")
  (is (some? (find-ns 'kotoba.artifact.runtime-identity)) "kotoba.artifact.runtime-identity must load"))

(deftest canonical-seals-ignore-map-and-set-order-and-detect-tampering
  (let [left {:payload {:b 2 :a 1} :effects #{:write :read}}
        right {:effects #{:read :write} :payload (array-map :a 1 :b 2)}
        sealed (artifact/seal left)]
    (is (= (artifact/sha256 left) (artifact/sha256 right)))
    (is (artifact/valid-seal? sealed))
    (is (false? (artifact/valid-seal? (assoc-in sealed [:payload :a] 9))))))
