(ns artifact-test
  (:require [clojure.test :refer [deftest is]]
            [kotoba.artifact.core]
            [kotoba.artifact.runtime-identity]))

;; Load gate: the split must not break namespace resolution. Each extracted
;; namespace must load standalone from this repo's own dependency closure.
(deftest every-extracted-namespace-loads
  (is (some? (find-ns 'kotoba.artifact.core)) "kotoba.artifact.core must load")
  (is (some? (find-ns 'kotoba.artifact.runtime-identity)) "kotoba.artifact.runtime-identity must load"))
