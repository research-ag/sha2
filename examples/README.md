# sha2 examples

Worked examples for the allocation-free hashing APIs of [`mo:sha2`](../): the
single-shot `Hasher` (`hashBlob32`, `hashState`, `combineBlob32`, `combineState`,
`loadBlob32`, `loadState`, `readSum`) and the buffered `Digest` (`close`,
`closeDouble`, `readSum`, `sumDouble`).

| file                                         | what it shows                                                                                                                                                                                                                                                                                                                                                                                           |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`Merkle.mo`](./Merkle.mo)                   | An allocation-free Bitcoin-style (double-SHA256) Merkle tree for any leaf count (with Bitcoin's last-node duplication) — an iterative Merkle-mountain-range peak stack over a pool of `log2(n)` `Hasher`s, leaf pairs combined with `combineBlob32` + `hashState` and internal nodes in place with `combineState` + `hashState` (drop the folds for a single-SHA tree), only the root `Blob` allocated. |
| [`BitcoinTxMerkle.mo`](./BitcoinTxMerkle.mo) | The same tree but from RAW (variable-length) transactions: one reused `Digest` absorbs each tx and the `Digest` → `Hasher` bridge turns it into a 32-byte leaf, contrasting the two double-SHA exits — `close` + `hashState` for the leaf that must persist vs `closeDouble` for the one consumed immediately — so a leaf pair costs one scratch `Digest` and zero dedicated leaf hashers.              |
| [`MerkleCounter.mo`](./MerkleCounter.mo)     | The same Merkle root via a BINARY-COUNTER mountain range instead of a peak stack: a height-indexed `[var Hasher]` where the occupied slots are the bits of the leaf count (no `level[]` array), adding a leaf is a binary increment with carry, `loadBlob32` parks each leaf, and risen peaks move into place with O(1) reference SWAPs (one scratch `carry` hasher). Power-of-two leaf counts.         |
| [`NFold.mo`](./NFold.mo)                     | N-fold hashing (`H^N(msg)`) that absorbs the message with a `Digest`, then bridges its state into a `Hasher` (the expert `digest.state` → `hashState` path) to fold the remaining rounds with no intermediate `Blob`; plus a batch variant reusing one of each engine across many messages.                                                                                                             |

Each file's header is a how-to: it spells out exactly what you must do to keep
hashing allocation-free in bulk — reuse a pool of hashers, combine 32-byte leaf
pairs with `combineBlob32` + `hashState`, combine internal nodes in place with
`combineState` + `hashState`, and read the result with `readSum()` only for the
final output.

`test/verify.test.mo` checks both examples against straightforward references;
it runs as part of `mops test`.

> These files live inside the sha2 repo, so they import the source directly
> (`import Hasher "../src/Hasher/Sha256"`). **In your own project**, depend on
> the published package and import it by name instead:
>
> ```motoko
> import Hasher "mo:sha2/Hasher/Sha256";
>
> ```
