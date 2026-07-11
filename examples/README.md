# sha2 examples

Worked examples for the allocation-free hashing APIs of [`mo:sha2`](../): the
single-shot `Hasher` (`hashBlob32`, `hashState`, `combineBlob32`, `combineState`,
`loadBlob32`, `loadState`, `readSum`) and the buffered `Digest` (`close`,
`closeDouble`, `readSum`, `sumDouble`).

The five Merkle examples form a progression — each adds one concept:

| #   | file                                               | what it shows                                                                                                                                                                                                                                                                                                                                                                                                        |
| --- | -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | [`MerkleStack.mo`](./MerkleStack.mo)               | A Merkle tree over 32-byte Blob leaves: single SHA256 per node, any leaf count. Called "stack" because the roots of completed subtrees (the "peaks") live in `Hasher`s operated as a stack: a new leaf pair is pushed on top, and while the top two peaks have equal size they are merged and popped — like carrying in binary addition. Leftover peaks are bagged right to left; only the root `Blob` is allocated. |
| 2   | [`MerkleCounter.mo`](./MerkleCounter.mo)           | The same root via a binary counter instead of a stack — the preferred implementation. The `Hasher`s sit in a height-indexed array, and "is height k occupied?" is simply bit k of the leaf count, so there is no bookkeeping array at all; risen peaks move by O(1) reference swaps. Matches/slightly beats the stack.                                                                                               |
| 3   | [`MerkleCounterState.mo`](./MerkleCounterState.mo) | The counter for leaves that are 32-byte hashes already sitting in `Hasher`s (states) rather than Blobs — e.g. handed over one at a time by another hash computation. Same algorithm as example 2; only the handling of the incoming leaves differs with the leaf type.                                                                                                                                               |
| 4   | [`BitcoinMerkle.mo`](./BitcoinMerkle.mo)           | The Bitcoin tree over txid leaves: example 2's counter with double SHA256 per node and Bitcoin's finalization, which pairs an odd last node with itself instead of bagging. Any count; matches real mainnet block roots.                                                                                                                                                                                             |
| 5   | [`BitcoinTxMerkle.mo`](./BitcoinTxMerkle.mo)       | The same Bitcoin tree from raw (variable-length) transactions: one reused `Digest` absorbs each transaction and the `Digest` → `Hasher` bridge lands each txid directly at its destination — `close` + `hashState` for the first leaf of a pair, `closeDouble` + `combineState` for the second — with no copies.                                                                                                     |
|     | [`NFold.mo`](./NFold.mo)                           | N-fold hashing (`H^N(msg)`) that absorbs the message with a `Digest`, then bridges its state into a `Hasher` (the expert `digest.state` → `hashState` path) to fold the remaining rounds with no intermediate `Blob`; plus a batch variant reusing one of each engine across many messages.                                                                                                                          |

Each file's header is a how-to: it spells out exactly what you must do to keep
hashing allocation-free in bulk — reuse a pool of hashers, combine 32-byte leaf
pairs with `combineBlob32`, combine internal nodes in place with
`combineState`, and read the result with `readSum()` only for the final output.

Examples 1–3 build the generic single-SHA mountain-range root (identical roots
for identical leaf bytes); Examples 4–5 build Bitcoin's double-SHA tree with
its last-node duplication. Neither is RFC 6962, which prepends a
domain-separation byte to each node.

`test/verify.test.mo` checks all examples against straightforward references
(including real mainnet Bitcoin block vectors); it runs as part of `mops test`.

> These files live inside the sha2 repo, so they import the source directly
> (`import Hasher "../src/Hasher/Sha256"`). **In your own project**, depend on
> the published package and import it by name instead:
>
> ```motoko
> import Hasher "mo:sha2/Hasher/Sha256";
>
> ```
