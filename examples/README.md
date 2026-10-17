# sha2 examples

Examples demonstrating the allocation-free hashing APIs of [`mo:sha2`](../): the
single-shot `Hasher` (`hashBlob32`, `hashState`, `combineBlob32`, `combineState`,
`combineStateBlob32`, `loadBlob32`, `loadState`, `readSum`) and the buffered
`Digest` (`close`, `closeDouble`, `readSum`, `sumDouble`).

We provide multiple examples to build a Merkle tree from an arbitrary number of leaves.
The examples all build an MMR first and then "bag" the MMR peaks to obtain a single root hash.

The examples are designed to produce minimal allocations.
`Hasher`s are used both to hash and to store intermediate hashes.
The examples organize their `Hasher`s in one of two ways, as a stack of peaks (Examples 1 and 2) or as an array indexed by a binary leaf counter (Examples 3 to 7).
Both use about `log2(n)` `Hasher`s for a tree with `n` leaves, roughly one for each depth-level of the tree; the difference between the two is marginal (the exact formulas are given below the table).
The `Hasher`s store the current peaks at different levels of the MMR.
When two peaks are merged then one `Hasher` holds the new higher peak and the other `Hasher` becomes free again.
The examples assume that the tree depth is known in advance and pre-allocate the required number of `Hasher`s, the _pool_.
It is of course also possible to dynamically allocate more `Hasher`s as needed, but this was not in scope for the examples.
The only allocations made by the code in the examples are the creation of the engines — the `Hasher`s, plus one reused `Digest` in the message-fed examples — and the final root hash Blob (whose readout also builds a temporary 32-byte array).

The seven Merkle examples form a progression — each adds one concept:

| #   | file                                               | what it shows                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | [`MerkleStack.mo`](./MerkleStack.mo)               | An MMR over 32-byte Blob leaves. The `Hasher`s that hold peaks form a stack: the highest peak at the bottom, the lowest on top. A parallel `level[]` array records the height of each peak. A leaf without a partner waits in the `pending : ?Blob` field until the next leaf arrives. To get the root, the peaks are folded from the top of the stack down into the free `Hasher` just above the top ("bagging"); a waiting leaf is folded in first. The pool has `ceil(log2 n)` `Hasher`s for `n` leaves. Also usable incrementally: add leaves, compute a root, keep adding, compute it again. Computing the root (bagging) does not change the stack.                                                                                                                                                                                                                                                                                                                                                                                                              |
| 2   | [`MerkleStackState.mo`](./MerkleStackState.mo)     | The same as Example 1, but it takes real messages as input instead of ready 32-byte leaf Blobs. The tree embeds one reused `Digest` that absorbs each message (of any length), and the leaf, SHA256(msg), is read straight from the digest's state, with no intermediate `Blob`. In Example 1, a leaf without a partner waits in the `pending : ?Blob` field until the next leaf arrives. That isn't possible here, because the leaf exists only in the digest's state, which the next message overwrites. So it is stored in a stack slot instead, as a peak at level 0; a level-0 entry on top of the stack is the waiting leaf, so no `pending` field is needed. This takes one `Hasher` more than Example 1, `ceil(log2 n) + 1`. The extra `Hasher` comes from the waiting leaf having to live in a `Hasher` instead of a `Blob`, not from the stack: Example 4, the message-fed counter, needs the same number. Unlike Example 1, bagging needs no special case for a waiting leaf: it is simply the lowest peak, on top of the stack. Also usable incrementally. |
| 3   | [`MerkleCounter.mo`](./MerkleCounter.mo)           | The same as Example 1, but the `Hasher`s are an array indexed by tree level instead of a stack: slot `k` holds the peak of height `k`, if there is one. Which slots hold a peak follows from the binary representation of the number of leaves: bit `k` of the leaf count is set exactly when there is a peak of height `k`. So a single leaf counter replaces the `level[]` array of Examples 1 and 2. As in Example 1, a leaf without a partner waits as a `pending : ?Blob`, so slot 0 is always free and serves as the accumulator for bagging. The pool has `floor(log2 n) + 1` `Hasher`s, one per bit of `n`. The counter organization is preferred over the stack of Examples 1 and 2; whether Example 3 or 4 fits depends on the input, ready 32-byte leaves or messages to hash. Also usable incrementally: computing the root does not change the peaks.                                                                                                                                                                                                     |
| 4   | [`MerkleCounterState.mo`](./MerkleCounterState.mo) | The same as Example 3, but it takes real messages as input through an embedded `Digest`, as in Example 2. As there, a leaf without a partner cannot wait as a `Blob`; it is copied into slot 0 (`loadState`). Slot 0 is therefore not free for bagging, and the accumulator is the top slot of the array instead, one level above the highest possible peak. The pool is `ceil(log2 n) + 1`, the same as in Example 2. Also usable incrementally.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 5   | [`BitcoinMerkle.mo`](./BitcoinMerkle.mo)           | The same as Example 3, but for Bitcoin's Merkle tree over transaction ids (txids), given as 32-byte Blobs. It differs from Example 3 in two ways: every node is a double SHA256, and instead of bagging, the peaks are combined the way Bitcoin does it — at a level with an odd number of nodes, the last node is paired with itself. As in Example 3, slot 0 serves as the accumulator and the peaks are left unchanged, so the tree is also usable incrementally.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 6   | [`BitcoinTxMerkle.mo`](./BitcoinTxMerkle.mo)       | Examples 5 and 4 combined: Bitcoin's Merkle tree over the raw transactions (of any length) instead of precomputed txids. One `Digest` absorbs each transaction; its state is SHA256(tx), and the second SHA256 of the txid writes the result straight into its slot (`hashState`), so unlike Example 4 the waiting leaf needs no extra copy. No allocations per transaction or node. As in Example 4, the top slot serves as the accumulator; usable incrementally.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 7   | [`BitcoinWitness.mo`](./BitcoinWitness.mo)         | An add-on to Examples 5 and 6, not a tree of its own: it produces and checks the coinbase inclusion proof (the "merkle branch" used by SPV proofs and mining protocols) for a tree built with Example 5 or 6, at any number of transactions. See [Coinbase inclusion proof](#coinbase-inclusion-proof-example-7) below.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|     | [`NFold.mo`](./NFold.mo)                           | N-fold hashing, `H^N(msg)`: a `Digest` absorbs the message, then its state is passed straight to a `Hasher` (`hashState(d.state)`), which runs the remaining rounds with no intermediate `Blob`. A batch variant reuses one `Digest` and one `Hasher` across many messages.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |

Examples 3 and 5 share their MMR-building code via
[`CounterBase.mo`](./CounterBase.mo), and Examples 4 and 6 share theirs
(including the embedded `Digest`) via
[`CounterStateBase.mo`](./CounterStateBase.mo); within each pair the examples
differ only in single vs double SHA256 — which for the digest-fed pair also
decides how a leaf exits the digest: a `loadState` capture vs the free
`hashState` bridge — and in the finalization code — bagging vs the Bitcoin
collapse — which lives in the example files. Both bases can optionally
capture the stable part of the coinbase witness as leaves are added (the
`witness` flag of `new`), consumed by Example 7.

The exact pool sizes are:

- Stack (Example 1): `ceil(log2 n)` — the maximum number of simultaneously live peaks plus one, since the stack never fills its pool.
- State stack (Example 2): `ceil(log2 n) + 1` — the parked leaf occupies a stack slot, and the pool is one larger than the maximal stack height so that the slot above the top stays free for the bagging accumulator.
- Counter (Examples 3 and 5): `floor(log2 n) + 1` — the bit length of `n`, one slot per bit of the leaf count.
- State counter (Examples 4 and 6): `ceil(log2 n) + 1` — the peak slots plus the top slot as the bagging accumulator, one level above the highest possible peak.
- Witness capture (`new(_, true)` on Examples 5 and 6, extraction in Example 7): no additional `Hasher`s — only a pre-sized `[var Blob]` with one slot per level of the stable part of the coinbase proof, each written at its capture moment.

None of them needs a dedicated accumulator `Hasher` for the bagging — a free
slot always exists where it is needed: the stack always has a free slot just
above its top, the state stack sizes its pool one above the maximal stack
height, the counter's slot 0 is vacant by construction (the height-0 leaf
waits as a pending `Blob`), and the state counters' top slot can only be
occupied at a full power of two — a single peak, which short-circuits without
bagging. The blob-leaf sizes (Ex. 1 vs 3) differ only when `n` is an exact power of two,
where the counter uses one `Hasher` more. The digest-fed sizes (Ex. 2 and 4) agree with each other for every `n`, and exceed the blob stack (Ex. 1) by exactly one: a Blob
leaf can wait out of band as a borrowed reference at no slot cost, while a
leaf that exists only as the digest's state — about to be overwritten by the
next message — must be captured into a slot the moment it arrives. The extra
`Hasher` is the parked leaf's residency, not a property of the stack or
counter organization.

Each file's header is a how-to: it spells out exactly what you must do to keep
hashing allocation-free in bulk — reuse a pool of hashers, combine 32-byte leaf
pairs with `combineBlob32`, combine internal nodes in place with
`combineState`, and read the result with `readSum()` only for the final output.

Examples 1–4 build the generic single-SHA mountain-range root — the
message-fed Examples 2 and 4 hash each message first, so their root over the
messages equals Examples 1/3 over the hashed leaves; Examples 5–6 build
Bitcoin's double-SHA tree with its last-node duplication. Neither is RFC 6962, which prepends a
domain-separation byte to each node.

The examples are their own small mops project: the [`mops.toml`](./mops.toml)
in this directory maps the package name `sha2` to `../src/`, so the example
code imports the package exactly as your own project would
(`import Hasher "mo:sha2/Hasher/Sha256"`). To reuse an example, copy the code
unchanged and point `sha2` in your `mops.toml` at the published package
instead.

[`test/verify.mo`](./test/verify.mo) checks all examples against
straightforward references (including real mainnet Bitcoin block vectors), and
[`test/allocation.mo`](./test/allocation.mo) checks that they allocate only
what is stated above. Run them from this directory with `mops test verify` and
`mops test allocation`; CI runs both on every PR.

## Coinbase inclusion proof (Example 7)

The coinbase is the first transaction of a block. Its inclusion proof is the list of sibling hashes along the path from the coinbase to the root, one 32-byte hash per level: at level `k`, the hash of the subtree over transactions `[2^k, 2^(k+1))`.

The trees of Examples 5 and 6 are MMRs that grow transaction by transaction, and a proof can be requested at any point, also while the number of transactions `n` is not a power of two. Then the tree consists of several peaks, and the proof has two parts. Let `2^K` be the largest power of two `≤ n`:

- **Stable part:** the siblings at levels `0` to `K − 1`, all inside the first complete subtree of `2^K` transactions. Each becomes final when its subtree is complete, at `n = 2, 4, 8, …`, and never changes after that.
- **Changing part:** the sibling at level `K`, covering all transactions from `2^K` on. Bitcoin's duplication of the last node folds the remaining peaks into it. It changes with every new transaction, and there is none when `n` is a power of two. When `n` reaches the next power of two, it becomes a new stable entry.

The tree captures the stable part itself while it is built, if it was created with the `witness` flag of `new` set. Each such sibling exists for only one step of the build and is copied into a pre-sized `[var Blob]` at that moment. That costs one small `Blob` per level over the whole build, nothing per leaf, and no extra `Hasher`s.

`BitcoinWitness.mo` contains the rest. `coinbaseWitness` (Example 5 trees) and `coinbaseWitnessTx` (Example 6 trees) return the full proof for the current `n`, computing the changing part from the current peaks. On the receiving side, `verifyTxid` and `verifyTx`, which need no tree, check a coinbase txid or raw coinbase transaction plus its proof against the 32-byte root. A malformed proof returns `false`.
