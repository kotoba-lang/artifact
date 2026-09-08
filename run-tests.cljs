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
;;   content_identity_test  requires `ipld.core`, and `ipld.link` CANNOT LOAD
;;     UNDER NBB AT ALL. Measured 2026-09-08 by requiring it directly:
;;
;;       Protocol not found: IEquiv
;;       io-ipld/src/ipld/link.cljc:31
;;
;;     Its `Link` deftype extends `IEquiv` and `IHash` in its `:cljs` branch,
;;     and nbb's SCI-based deftype does not resolve those protocol symbols.
;;     io-ipld's own docstring at that line says the repository runs its
;;     ClojureScript tests under shadow-cljs -- so the branch is exercised
;;     there and has never run here.
;;
;;     That is a finding about io-ipld, not about this repository, and it is
;;     load-bearing: `Link` is the IPLD content-addressing primitive, and the
;;     JVM-free runtime cannot construct one. Content-identity CIDs therefore
;;     remain UNMEASURED on this host -- the same gap
;;     `cross_host_digest_test` closed for `sha256`, still open one layer up.
;;
;;     `@noble/hashes` is declared in package.json regardless: it is a real
;;     dependency of `content_identity.cljc` through `ipld.core`, whether or
;;     not the test can run today.
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
