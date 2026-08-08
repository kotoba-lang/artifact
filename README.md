# artifact

Artifact identity and signing contract — what an emitted artifact IS, independent of who emitted it.

**Tier**: `T0`  **Role**: `contract`

Split out of the overloaded core repos by ADR-2607266000 so that each
responsibility has exactly one owner and the dependency direction is
checkable from outside.

## Owns

- `kotoba.artifact.core (artifact digest/identity)`
- `kotoba.artifact.runtime-identity (immutable execution identity)`
- `kotoba.artifact.descriptor-table (typed-value descriptors an artifact carries)`
- `kotoba.artifact.content-identity (SourceCID, BuildCID, ArtifactCID)`

## Content identity

The four names are deliberately non-interchangeable:

- SourceCID is CIDv1/raw over exact source or module bytes.
- DefCID is owned by `kotoba.kir.identity` and addresses normalized checked
  semantics, including type/effect/capability axes and dependency DefCID links.
- BuildCID is CIDv1/DAG-CBOR over compiler, target, flags, and build links.
- ArtifactCID is CIDv1/DAG-CBOR over a descriptor that links the raw artifact
  bytes, DefCID, and BuildCID.

EDN is the human/reference representation and JSON is an interop projection.
Neither `pr-str` nor JSON serialization is a content-identity encoding. The
existing `kotoba.artifact.core/sha256` remains a legacy integrity seal for
already-published envelope shapes; new semantic/graph identities use the CID
APIs above.

### The descriptor table

A native artifact has no wasm custom section, so the sealed artifact map plays
that role: it carries the typed-value descriptor table, so a loader can be
handed a descriptor rather than the integer `kexe_typed_kind_v1` it is handed
today. That integer is why every capability kit is still `:native-aot :pending`
— `clock-v1`'s request is a variant and its result is a variant of records, and
neither has an integer to be.

Every descriptor byte comes from `kotoba.kir.descriptor/encode-descriptor`, the
same function the wasm custom section calls. There is exactly one encoding of a
descriptor by design (ADR-2608049000): two would look correct on both sides
while disagreeing. What is local here is the *framing* — a version byte, a
descriptor count, a contract region — because the wasm section additionally
carries literals and schemas that a native loader has no use for. The tables
themselves are index-compatible: index N denotes the same type in a wasm custom
section and in a native artifact built from the same KIR.

`:bytes-sha256` pins the encoding the producer ran. `validate!` re-encodes and
compares, so a hand-edited artifact is refused and so is a verifier whose
`encode-descriptor` has drifted from the producer's — the same drift detector
`runtime-identity` applies to the loader source.

This repo defines and validates what is carried. Emitting it from the compiler,
and walking a value against it in the loader, are separate landings. **No
capability kit is qualified by this: all remain `:native-aot :pending`.**

## Does not own

- produce artifacts
- own KIR
- decide policy
- verify (that is kotoba-verifier)

## Depends on

- `kotoba-lang/kotoba-kir`

## Test

```bash
clojure -M:test
```
