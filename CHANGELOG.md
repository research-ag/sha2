# Sha2 changelog

## 1.0.0

### Changed

- **Breaking:** `Digest` is now a plain, directly-`stable` record instead of
  a class. The `share()`/`unshare()` conversion methods and the
  `DigestShared` type introduced in `0.1.0` are gone — to persist a digest
  across upgrades, declare it `stable` directly (e.g.
  `stable var digestState : ?Sha256.Digest = null;` in a `persistent actor`).
  See the updated README for a full example.

### Fixed

- README and doc-string examples updated to match the current API: the
  "Stable state across upgrades" example no longer references the removed
  `share`/`unshare`/`DigestShared` API, and every `Iter<Nat8>` example now
  type-checks (an unannotated `[72, 101, ...].vals()` was inferring
  `Iter<Nat>` instead of `Iter<Nat8>`).
- Fixed compiler warnings (`M0244` in several files not covered by the
  `0.1.15` fix, plus an unused `Prim` import).

### Documentation

- Documentation coverage raised to 100% (`mops docs coverage`) by adding
  doc comments to previously-undocumented internal modules.

## [0.1.15] - 2026-05-05

### Changed

- Updated `core` from `2.2.0` to `2.5.0`.
- Updated `bench-helper` from `0.0.2` to `0.0.3`.
- Updated `[requirements] moc` from `1.3.0` to `1.6.0`.

### Fixed

- Fixed compiler warnings (M0244).

## 0.1.14

- Use bench-helper package
- Bump core dependency

## 0.1.13

- Bump moc dependency
- Bump core dependency
- Simplify bench code

## 0.1.12

- Add more code documentation
- Rewrite benchmarks without bench package

## 0.1.11

- Bump bench dependency to 2.0.0
- Remove unused test dependency
- Make internal digest functions private
- Add code documentation for all public functions

## 0.1.10

- Bump dependency to core 2.0.0

## 0.1.9

- Remove heap allocations (garbage) when writing Iter

## 0.1.8

- Improve performance of writing Iter

## 0.1.7

- Switch from base to core

## 0.1.6

- Bump dependencies
- Add [requirements] section

## 0.1.5

- Bugfix in writeBlob/writeArray

Note: fromBlob/fromArray were correct, but calling the low-level writeBlob/writeArray multiple times could cause an error.

## 0.1.4

- Improve performance for short messages by 8%/12%
- Utilise explodeNatX functions from moc 0.14.9

## 0.1.3

- Improve performance by 35-40%
- Utilise Blob random access from moc 0.14.8

## 0.1.2

- Improve performance by 10-12%
- Utilise Blob random access from moc 0.14.8

## 0.1.1

- Introduce mops benchmarks
- Remove comparison to other packages from README
- Bump dependencies

## 0.1.0

- Add share/unshare interface to Digest classes
- Bump base dependency

## 0.0.6

- Bump base and test dependencies
- Add benchmarks

## 0.0.5

- Bump base dependency to 0.11.0

## 0.0.4

Sha256:

- Eliminate the heap allocations that were linear in message size
- Reduce instructions per byte by 4%
- Comes with a per message penalty in instructions of 5%

## 0.0.3

Sha256:

- Reduce instructions per byte by 3%
- Reduce instructions for empty message by 25%
- Reduce heap allocations from 1.5x to 1x the message size

Sha512:

- Reduce instructions per byte by 3%
- Reduce instructions for empty message by 35%
