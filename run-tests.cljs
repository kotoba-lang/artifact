;; nbb --classpath "src:test:$(clojure -Spath -M:test)" run-tests.cljs
;;
;; This repository had no ClojureScript runner until 2026-09-08, and its four
;; `.cljc` sources include TWO implementations of `sha256` -- `MessageDigest`
;; on the JVM, `node:crypto` here. Only the first had ever been executed.
;;
;; TWO tests stay `.clj` and are deliberately absent, for DIFFERENT reasons,
;; and the difference is the distinction this file exists to make:
;;
;;   descriptor_table_test  asserts through `java.util.List` interop, which
;;     has no meaning on this host. Genuinely JVM-only. Nothing to fix.
;;
;;   content_identity_test  is portable in principle -- `content_identity.cljc`
;;     is `.cljc` -- but it requires `ipld.core`, which needs the npm package
;;     `@noble/hashes` at runtime, and THIS REPOSITORY DECLARES NO NPM
;;     DEPENDENCIES AT ALL. It has no package.json. It resolves today only when
;;     nbb is started from a directory that happens to have `@noble/hashes` in
;;     an ancestor `node_modules` -- the superproject root does; a fresh clone
;;     of this repository does not.
;;
;;     `kotoba-lang/io-ipld` does not declare it either (its package.json lists
;;     only nbb and shadow-cljs as devDependencies), so this is a gap in the
;;     family and not something to paper over here by pinning a version guessed
;;     from whatever the ambient tree happens to hold. Measured 2026-09-08: the
;;     ambient copy is 2.4.0, and nothing in either repository asks for it.
;;
;;     When `@noble/hashes` is declared somewhere that a clone of this repo can
;;     see, move this file back to `.cljc` and add it to both lists below. Its
;;     content-identity CIDs are the same class of two-implementation risk that
;;     `cross_host_digest_test` covers for `sha256`, and they are still
;;     UNMEASURED on this host.
;;
;; Anything added to `test/` as `.cljc` belongs in BOTH lists below. Being
;; required is not being run.
(ns run-tests
  (:require [cljs.test :as t]
            [artifact-test]
            [cross-host-digest-test]))

(defmethod t/report [:cljs.test/default :end-run-tests] [m]
  (println (str "\nnbb: " (:test m) " tests, " (:pass m) " passed, "
                (:fail m) " failed, " (:error m) " errors"))
  (when (pos? (+ (or (:fail m) 0) (or (:error m) 0)))
    (set! (.-exitCode js/process) 1)))

(t/run-tests 'artifact-test
             'cross-host-digest-test)
