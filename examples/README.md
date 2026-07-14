# sha2 examples

Examples demonstrating the allocation-free hashing APIs of [`mo:sha2`](../): the
single-shot `Hasher` (`hashBlob32`, `hashState`, `combineBlob32`, `combineState`,
`loadBlob32`, `loadState`, `readSum`) and the buffered `Digest` (`close`,
`closeDouble`, `readSum`, `sumDouble`).

We provide multiple examples to build a Merkle tree from an arbitrary number of leaves.
The examples all build an MMR first and then "bag" the MMR peaks to obtain a single root hash.

The examples are designed to produce minimal allocations.
`Hasher`s are used both to hash and to store intermediate hashes.
Generally, `N` `Hasher`s are required for a tree with up to `2^N` leaves, one for each depth-level of the tree.
The counter-based examples use one `Hasher` more: they keep one slot per bit of the leaf count — bit length `N + 1` — including slot 0 for the height-0 peak, which is a raw leaf.
The `Hasher`s store the current peaks at different levels of the MMR.
When two peaks are merged then one `Hasher` holds the new higher peak and the other `Hasher` becomes free again.
The examples assume that the tree depth is known in advance and pre-allocate the required number of `Hasher`s.
It is of course also possible to dynamically allocate more `Hasher`s as needed, but this was not in scope for the examples.
The only allocations made by the code in the examples are the creation of the `Hasher`s plus the final root hash Blob.

The five Merkle examples form a progression — each adds one concept:

| #   | file                                               | what it shows                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| --- | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | [`MerkleStack.mo`](./MerkleStack.mo)               | An MMR over 32-byte Blob leaves. The used `Hasher`s form a stack with the one holding the highest peak at the bottom of the stack and the one holding the lowest peak on the top. A parallel `level[]` array tracks each peak's height. In the end, the peaks left in the stack are bagged top to bottom.                                                                                                                                       |
| 2   | [`MerkleCounter.mo`](./MerkleCounter.mo)           | The same as Example 1 but the `Hasher`s are arranged in an array and addressed by position instead of on a stack. The array index corresponds to the depth-level in the tree. Which `Hasher`s are free and which hold a peak is determined by the bits in the binary representation of the number of leaves. Therefore, the `level[]` array of the previous example is replaced by a single leaf counter. This is the preferred implementation. |
| 3   | [`MerkleCounterState.mo`](./MerkleCounterState.mo) | The same as Example 2 but the incoming leaf values are taken from `Hasher` states instead of from Blobs — as when each leaf was just produced by a hash computation. The point of this example is to demonstrate how to consume such leaves without causing additional allocations; Example 5 adds the hashing step itself.                                                                                                                     |
| 4   | [`BitcoinMerkle.mo`](./BitcoinMerkle.mo)           | The same as Example 2 but for the Bitcoin-specific Merkle tree over txid leaves that are 32-byte Blobs. It differs from Example 2 in that a) double SHA256 is used on each level and b) "bagging" works by pairing peaks with themselves to move them up one level.                                                                                                                                                                             |
| 5   | [`BitcoinTxMerkle.mo`](./BitcoinTxMerkle.mo)       | The combination of Example 4 and 3. This is the Bitcoin-specific Merkle tree over the full (variable-length) transactions as input instead of over already precomputed txids. It uses one `Digest` to absorb the transactions one at a time and a `Digest` → `Hasher` bridge lands each txid directly at its destination. This achieves the Bitcoin Merkle tree without allocations.                                                            |
|     | [`NFold.mo`](./NFold.mo)                           | N-fold hashing (`H^N(msg)`) that absorbs the message with a `Digest`, then bridges its state into a `Hasher` (the expert `digest.state` → `hashState` path) to fold the remaining rounds with no intermediate `Blob`; plus a batch variant reusing one of each engine across many messages.                                                                                                                                                     |

Each file's header is a how-to: it spells out exactly what you must do to keep
hashing allocation-free in bulk — reuse a pool of hashers, combine 32-byte leaf
pairs with `combineBlob32`, combine internal nodes in place with
`combineState`, and read the result with `readSum()` only for the final output.

Examples 1–3 build the generic single-SHA mountain-range root (identical roots
for identical leaf bytes); Examples 4–5 build Bitcoin's double-SHA tree with
its last-node duplication. Neither is RFC 6962, which prepends a
domain-separation byte to each node.

The examples are their own small mops project: the [`mops.toml`](./mops.toml)
in this directory maps the package name `sha2` to `../src/`, so the example
code imports the package exactly as your own project would
(`import Hasher "mo:sha2/Hasher/Sha256"`). To reuse an example, copy the code
unchanged and point `sha2` in your `mops.toml` at the published package
instead.

[`test/verify.mo`](./test/verify.mo) checks all examples against
straightforward references (including real mainnet Bitcoin block vectors).
Run it from this directory with `mops test verify`; CI runs it on every PR.
