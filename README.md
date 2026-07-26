# artifact

Artifact identity and signing contract — what an emitted artifact IS, independent of who emitted it.

**Tier**: `T0`  **Role**: `contract`

Split out of the overloaded core repos by ADR-2607266000 so that each
responsibility has exactly one owner and the dependency direction is
checkable from outside.

## Owns

- `kotoba.artifact.core (artifact digest/identity)`
- `kotoba.artifact.runtime-identity (immutable execution identity)`
- `kotoba.artifact.signing (signed artifact envelopes)`

## Does not own

- produce artifacts
- own KIR
- decide policy

## Depends on

- nothing (contract/leaf tier)

## Test

```bash
clojure -M:test
```
