# Sha2 changelog

## 0.3.0

- **Breaking:** remove `peekSum()` (Sha256, Sha512). To re-read a closed digest use `readSum()`; for an intermediate hash of an open digest use `clone().sum()`.
- Add `close()` and `readSum()` (Sha256, Sha512) — finalize a digest without returning a `Blob`, then read the closed digest idempotently (any number of times)
- Add `closeDouble()` (Sha256) — finalize as a double SHA256 in place without returning a `Blob` (the non-returning counterpart of `sumDouble`); read it with `readSum()`
- Add `Hasher/Sha256` — a single-shot, allocation-free SHA-256 hash engine for short, fixed-length messages (`hashBlob32`, `hashState`, `combineBlob32`, `combineState`, `loadBlob32`, `loadState`, `readSum`). It is the bufferless engine for allocation-free Merkle trees and hash chains: `combineBlob32`/`combineState` combine two 32-byte leaves or two child states in place, `hashState(h, h)` folds for double-SHA, and `loadBlob32`/`loadState` park a precomputed hash into the engine verbatim (no re-hash — the inverse of `readSum`)
- Optimize `close()` with a block-boundary fast path that compresses the all-constant padding block directly for block-aligned messages
- Make `writeBlob()` allocation-free (drop the per-call accessor closures)
- Reduce per-call allocations across the API (use `switch` instead of variant `==`)
- Add `examples/` — allocation-free Bitcoin-style Merkle trees (peak-stack and binary-counter variants; from 32-byte leaves and from raw variable-length transactions) and N-fold hashing, with tests including real-block Merkle-root vectors
- Replace precondition `assert`s with diagnostic trap messages (e.g. "Sha256: write to closed digest", "Hasher: hashBlob32 expects a 32-byte blob, got N bytes"); same trapping behavior, better error messages
- Widen the Sha256 block counter to `Nat64` — removes a silent wrong-hash wraparound for cumulative inputs ≥ 256 GiB per digest (theoretical; costs ~10 instructions per hash)
- Skip the block-processing call for sub-block writes in `writeArray`/`writeVarArray`/`writeAccessor`/`writeReader` (~670 fewer instructions per short write, ~5 fewer per block for accessor/reader on long inputs)

## 0.2.4

- Fix `Sha512.reset()` not clearing the `closed` flag (reusing a digest after `sum()` trapped)
- Optimize `Sha512.reset()`
- Add lifecycle benchmarks for Sha512

## 0.2.3

- Add `Sha256.sumDouble()` for double SHA256 (the Bitcoin hash)
- Optimize `reset()`

## 0.2.2

- Add benchmarks (no user-facing changes)

## 0.2.1

- Add doc strings

## 0.2.0

- Complete rewrite based on static records (no classes)
- Complete rewrite of the API

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
