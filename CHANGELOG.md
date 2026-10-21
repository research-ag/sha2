# Sha2 changelog

## 0.3.1

- Changed:
  - `Hasher` combines (`combineBlob32`, `combineState`, `combineStateBlob32`, `combineBlob32State`) are about 10% cheaper: their padding block, the second compression of the 64-byte message, now uses a precomputed message schedule (all 16 message words of that block are fixed, so the 48 expanded words and the per-round `K + w` sums are inlined constants). The gain applies in programs that also use a `Digest` (in a program using only the `Hasher`, wasm-opt already specialized the padding block) and in builds without wasm-opt. A Bitcoin Merkle root over 6467 txids drops from 169M to 158M instructions with wasm-opt, and from 310M to 285M without.

## 0.3.0

- Added:
  - `Digest.closeDouble()` (Sha256 only): finalize as a double SHA256 in place without returning the hash
  - `Hasher/Sha256`: a reusable, bufferless, allocation-free SHA-256 hash engine for short, fixed-length messages.
    - Single-shot API: `hashBlob32`, `hashState`, `combineBlob32`, `combineState`, `combineStateBlob32`, `combineBlob32State`, `loadBlob32`, `loadState`, `readSum`.
    - Improves Merkle-tree performance by 40%

- Removed (**Breaking**):
  - `Digest.fold()`, `combineLeaves()`, `combineNodes()`: replaced by `Hasher/Sha256` (`hashState`, `combineBlob32`, `combineState`)

- Changed:
  - **Breaking:** stable type of `Sha256.Digest` changes its `buffer.i_block` from Nat32 to Nat64. `Sha512.Digest` is unchanged.
  - **Bugfix:** removes a silent wrong-hash wraparound in Sha256 for cumulative inputs ≥ 256 GiB per digest.
  - Optimized short writes in `Digest.writeArray`/`writeVarArray`/`writeAccessor`/`writeReader`

- Maintenance:
  - Migrate to moc 2.0.0 (minimum moc version stays 1.0.0)
  - Bump `core` to 2.6.2.
  - Diagnostic trap messages (same behavior, better messages)

- Documentation:
  - Allocation-free Merkle-tree examples based on the new `Hasher`s.
    - Two different approaches to manage pool of `Hasher`s: stack and binary counter.
    - Two different inputs: `Blob` leaves and variable-length messages.
    - Merkle mountain ranges (MMRs)
    - Bitcoin-style double-SHA trees
    - Bitcoin-style root computation
    - Coinbase inclusion proof building and verifying

## 0.2.5

- New functions added:
  - `close()`: finalize a digest without returning it
  - `readSum()`: read a closed digest idempotently (any number of times)
  - `fold()` (Sha256 only): fold a finalized digest back in as the next message, for N-fold hashing
  - `combineLeaves()` (Sha256 only): hash two 32-byte `Blob`s in place, without message buffers
  - `combineNodes()` (Sha256 only): hash two 32-byte child digests in place, without message buffer
- Optimizations:
  - `close()`: fast path for block-aligned input
  - `writeBlob()`: allocation-free (dropped the per-call accessor closures)
  - Per-call allocations reduced across the API (using `switch` instead of variant `==`)
- Removed (**Breaking**):
  - `peekSum()`: use `clone().sum()` instead, and `readSum()` for re-reading.
- New examples added:
  - allocation-free Bitcoin-style Merkle tree
  - allocation-free N-fold hashing

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
