(ns kotoba.artifact.runtime-identity
  (:require [kotoba.artifact.core :as artifact]
            [kotoba.kir.target :as target]))

(def loader-source-sha256
  "Pinned identity of the reviewed POSIX native loader source.
  Includes string_equal/string_concat and the typed string capability
  callback, which validates pair-backed pointer/length handles and canonical
  UTF-8 before and after the provider boundary.

  Advanced 2026-08-03: checked_string_concat computed `length_a + length_b`
  and tested the sum for `< 0` afterwards. Signed overflow is undefined, so
  that test is one a compiler may assume unreachable and remove; the operands
  come from guest-writable pair cells, which is why the function exists. It
  now rules out overflow before adding, matching the order
  kexe_loader_windows.c's string_concat already used. Receipts naming the
  previous identity no longer verify against this loader -- that is the drift
  detector behaving correctly, not a regression.

  Advanced 2026-08-04: adds checked_string_substring at context offset 136,
  which makes `string-substring` work on any string rather than only on an
  all-ASCII literal (that case still compiles to pure pair arithmetic with no
  host call). It allocates no string-pool bytes -- a substring is a contiguous
  range of its source, so the result is a view -- and mirrors the shared
  oracle kotoba.kir.value/utf8-substring!: bounds 0 <= start <= end <= length,
  then both indices must be code-point boundaries. It validates the source is
  canonical UTF-8 rather than assuming it, because over invalid UTF-8 \"not a
  continuation byte\" would not imply \"code-point boundary\", and a guest can
  hand over any pair cell.

  Advanced 2026-08-04 again: adds checked_string_code_point_at at offset 144,
  the operation that lets a guest WALK a string (its result determines the
  code point's byte width, so one op advances). Same bounds discipline as
  substring except the upper bound is exclusive -- no code point starts at the
  end. Nothing is allocated: the result is a scalar, not a handle.

  Advanced 2026-08-04 a third time: the context ABI moves to VERSION 3, adding
  the vector table at offsets 152-192 (ADR-2608030300). Unlike the two
  advances above this one changes the version field, so receipts and artifacts
  naming the previous identity do not merely fail to verify -- a v2 artifact is
  refused by every checked_* in this loader, deliberately. The bump is
  load-bearing in one direction: a v2 host has no slots at 152-192, so
  v3-compiled code calling them would jump through uninitialised memory.

  A vector value is a one-word handle into a host table, the same width and
  discipline as the pair handle strings, options and results already use, so
  the guest gains no new value representation. Two arenas back it, because a
  table entry and the elements it spans are separately exhaustible.

  The one non-obvious property is in checked_vector_conj: it appends in place
  when the source slice ends at the arena top, and copies otherwise. That is
  safe because every handle carries its own length, so the word past a slice
  belongs to no handle and writing it cannot change what any existing handle
  reads. It is what makes a conj chain -- which is how a vector literal is
  built, the ABI being non-variadic -- linear rather than quadratic.
  checked_vector_assoc has no such case and always copies; checked_vector_drop
  allocates no elements at all, a suffix being contiguous within its source.

  Advanced 2026-08-04 a fourth time: sanitizer-only builds omit RLIMIT_AS so
  AddressSanitizer can own its platform-dependent shadow address space beside
  the ABI v3 vector arena. The first 128 MiB allowance proved insufficient on
  native Linux ARM64. Reviewed production builds retain the 64 MiB limit; the
  exception is enabled only by the sanitizer conformance harness, while the
  guest arenas and all other process limits remain bounded."
  "d2239f7d737a7509911826f09991d431e3401137a68f3831ec2c56ae8abf6d57")

(def windows-loader-source-sha256
  "Pinned identity of the reviewed Windows native loader source.
  Includes the AppContainer denial boundary plus pair-backed string,
  option-i64, and result-i64 typed capability validation.

  Advanced 2026-08-04 alongside the POSIX loader, with the same
  string_substring at offset 136 and the same checks. Note the asymmetry in
  how the two were verified: the POSIX loader was compiled and executed, this
  one was not -- it needs windows.h, and no cross-compiler is installed on the
  machine that made this change. Its offset was checked by reading the struct
  (allow[32] spans 16..48, every later field is a pointer), and its
  _Static_assert will catch the layout on a real Windows build.

  Advanced 2026-08-04 again alongside the POSIX loader, with the same
  string_code_point_at at offset 144. The same verification asymmetry applies:
  compiled and executed for POSIX, read and reasoned about for Windows.

  Advanced 2026-08-04 a third time alongside the POSIX loader: context ABI
  version 3 and the same vector table at offsets 152-192, implemented to
  mirror checked_vector_* line for line including the in-place append. The
  verification asymmetry is unchanged and matters more here than for the
  earlier advances, because this change adds ARITHMETIC (offset/length slice
  bookkeeping) rather than another bounds check over an existing shape: the
  POSIX half was compiled with -Wall -Wextra -Werror and executed against the
  conformance vectors, this half was neither. Its _Static_asserts pin the six
  offsets on a real Windows build, and the vector cells sit after string_pool
  so no earlier offset moves."
  "375d20aaa9009df40ab466da6f8be0142eda9e57b6d086a67eb92f9897e49f2f")

(defn loader-source-for-profile [profile]
  (case (:os profile)
    :windows windows-loader-source-sha256
    (:linux :macos) loader-source-sha256
    nil))

(def ^:private fields
  #{:format :target-profile :loader-source-sha256 :loader-binary-sha256
    :compiler-binary-sha256 :compiler-version-sha256
    :assembler-binary-sha256 :linker-binary-sha256
    :compiler-resource-sha256 :system-header-closure-sha256})

(defn- sha256? [value]
  (and (string? value) (boolean (re-matches #"[0-9a-f]{64}" value))))

(defn validate! [runtime]
  (when-not (and (map? runtime)
                 (= fields (set (keys runtime)))
                 (= :kotoba.native-runtime/v6 (:format runtime))
                 (contains? (set (vals target/profiles)) (:target-profile runtime))
                 (= :native (get-in runtime [:target-profile :execution]))
                 (contains? #{:linux :macos :windows} (get-in runtime [:target-profile :os]))
                 (= (loader-source-for-profile (:target-profile runtime))
                    (:loader-source-sha256 runtime))
                 (sha256? (:loader-binary-sha256 runtime))
                 (sha256? (:compiler-binary-sha256 runtime))
                 (sha256? (:compiler-version-sha256 runtime))
                 (sha256? (:assembler-binary-sha256 runtime))
                 (sha256? (:linker-binary-sha256 runtime))
                 (sha256? (:compiler-resource-sha256 runtime))
                 (sha256? (:system-header-closure-sha256 runtime)))
    (throw (ex-info "native runtime identity rejected"
                    {:phase :runtime-identity})))
  runtime)

(defn identity-sha256 [runtime]
  (artifact/sha256 (validate! runtime)))

(defn validate-measurement! [measurement]
  (when-not (and (map? measurement)
                 (= #{:format :runtime} (set (keys measurement)))
                 (= :kotoba.runtime-measurement/v1 (:format measurement)))
    (throw (ex-info "runtime measurement schema mismatch"
                    {:phase :runtime-identity})))
  (validate! (:runtime measurement))
  measurement)

(defn admit! [runtime trust]
  (let [identity (identity-sha256 runtime)
        trusted (:trusted-runtime-sha256 trust)
        revoked (:revoked-runtime-sha256 trust #{})]
    (when (contains? revoked identity)
      (throw (ex-info "native runtime identity is revoked"
                      {:phase :trust :runtime-sha256 identity})))
    ;; Native execution is never a trust-on-first-use operation. A measured
    ;; runtime must be reviewed and explicitly provisioned before guest entry.
    (when-not (and (set? trusted) (contains? trusted identity))
      (throw (ex-info "native runtime identity is not trusted"
                      {:phase :trust :runtime-sha256 identity})))
    {:runtime-sha256 identity :trusted? true}))
