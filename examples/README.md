# sha2 examples

Examples demonstrating the allocation-free hashing APIs of [`mo:sha2`](../): the
single-shot `Hasher` (`hashBlob32`, `hashState`, `combineBlob32`, `combineState`,
`loadBlob32`, `loadState`, `readSum`) and the buffered `Digest` (`close`,
`closeDouble`, `readSum`, `sumDouble`).

We provide multiple examples to build a Merkle tree from an arbitrary number of leaves.
The examples all build an MMR first and then "bag" the MMR peaks to obtain a single root hash.

The examples are designed to produce minimal allocations.
`Hasher`s are used both to hash and to store intermediate hashes.
Both algorithms use `log2(n)` `Hasher`s for a tree with `n` leaves, roughly one for each depth-level of the tree; the difference between the two is marginal (the exact formulas are given below the table).
The `Hasher`s store the current peaks at different levels of the MMR.
When two peaks are merged then one `Hasher` holds the new higher peak and the other `Hasher` becomes free again.
The examples assume that the tree depth is known in advance and pre-allocate the required number of `Hasher`s.
It is of course also possible to dynamically allocate more `Hasher`s as needed, but this was not in scope for the examples.
The only allocations made by the code in the examples are the creation of the `Hasher`s plus the final root hash Blob.

The five Merkle examples form a progression — each adds one concept:

| #   | file                                               | what it shows                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| --- | -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | [`MerkleStack.mo`](./MerkleStack.mo)               | An MMR over 32-byte Blob leaves. The used `Hasher`s form a stack with the one holding the highest peak at the bottom of the stack and the one holding the lowest peak on the top. A parallel `level[]` array tracks each peak's height. In the end, the peaks left in the stack are bagged top to bottom into the free `Hasher` just above the stack top. Also usable incrementally: add leaves, bag a root, keep adding, bag again — bagging does not modify the stack.                                                                                       |
| 2   | [`MerkleCounter.mo`](./MerkleCounter.mo)           | The same as Example 1 but the `Hasher`s are arranged in an array and addressed by position instead of on a stack. The array index corresponds to the depth-level in the tree. Which `Hasher`s are free and which hold a peak is determined by the bits in the binary representation of the number of leaves. Therefore, the `level[]` array of the previous example is replaced by a single leaf counter. This is the preferred implementation. Also usable incrementally: add leaves, bag a root, keep adding, bag again — bagging does not modify the peaks. |
| 3   | [`MerkleCounterState.mo`](./MerkleCounterState.mo) | The same as Example 2 but the incoming leaf values are taken from `Hasher` states instead of from Blobs — as when each leaf was just produced by a hash computation. The point of this example is to demonstrate how to consume such leaves without causing additional allocations; Example 5 adds the hashing step itself. Also usable incrementally — the bagging accumulator is the top slot of the array, one level above the highest possible peak (slot 0 holds the parked leaf and cannot serve).                                                       |
| 4   | [`BitcoinMerkle.mo`](./BitcoinMerkle.mo)           | The same as Example 2 but for the Bitcoin-specific Merkle tree over txid leaves that are 32-byte Blobs. It differs from Example 2 in that a) double SHA256 is used on each level and b) "bagging" works by pairing peaks with themselves to move them up one level. Also usable incrementally — like Example 2, the collapse accumulates in the free slot 0 and leaves the peaks intact.                                                                                                                                                                       |
| 5   | [`BitcoinTxMerkle.mo`](./BitcoinTxMerkle.mo)       | The combination of Example 4 and 3. This is the Bitcoin-specific Merkle tree over the full (variable-length) transactions as input instead of over already precomputed txids. It uses one `Digest` to absorb the transactions one at a time and a `Digest` → `Hasher` bridge lands each txid directly at its destination. This achieves the Bitcoin Merkle tree without allocations. Also usable incrementally — like Example 3, the collapse accumulates in the top slot and leaves the peaks intact.                                                         |
|     | [`NFold.mo`](./NFold.mo)                           | N-fold hashing (`H^N(msg)`) that absorbs the message with a `Digest`, then bridges its state into a `Hasher` (the expert `digest.state` → `hashState` path) to fold the remaining rounds with no intermediate `Blob`; plus a batch variant reusing one of each engine across many messages.                                                                                                                                                                                                                                                                    |

Examples 2 and 4 share their MMR-building code via
[`CounterBase.mo`](./CounterBase.mo), and Examples 3 and 5 share theirs via
[`CounterStateBase.mo`](./CounterStateBase.mo); within each pair the examples
differ only in the single- vs double-SHA flag they pass and in the
finalization code — bagging vs the Bitcoin collapse — which lives in the
example files.

The exact pool sizes are:

- Counter: `floor(log2 n) + 1` — the bit length of `n`, one slot per bit of the leaf count.
- Stack: `ceil(log2 n)` — the maximum number of simultaneously live peaks plus one, since the stack never fills its pool.
- State counter (Examples 3 and 5): `ceil(log2 n) + 1` — the peak slots plus the top slot as the bagging accumulator, one level above the highest possible peak.

None of them needs a dedicated accumulator `Hasher` for the bagging — a free
slot always exists where it is needed: the counter's slot 0 is vacant by
construction (the height-0 leaf waits as a pending `Blob`), the stack always
has a free slot just above its top, and the state counters' top slot can only
be occupied at a full power of two — a single peak, which short-circuits
without bagging. The blob-leaf sizes differ only when `n` is an exact power of
two, where the counter uses one `Hasher` more.

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
