# sha2 examples

This directory shows what the allocation-free engines of [`mo:sha2`](../) are made for: Merkle trees and iterated hashing without a heap allocation per node.
The examples use the single-shot `Hasher` (`mo:sha2/Hasher/Sha256`) to combine hashes and the buffered `Digest` (`mo:sha2/Sha256`) to hash messages of arbitrary length, and the bridge between the two, which hands a finished digest to a `Hasher` without an intermediate `Blob`.

The examples are their own small mops project.
The [`mops.toml`](./mops.toml) in this directory maps the package name `sha2` to `../src/`, so the example code imports the package exactly as your own project would (`import Hasher "mo:sha2/Hasher/Sha256"`).
To reuse an example, copy the file unchanged into your project and point `sha2` in your `mops.toml` at the published package instead.

## Contents

| #   | File                                               | Input per leaf                                             | Hash per node  | Peaks kept in      | Root               |
| --- | -------------------------------------------------- | ---------------------------------------------------------- | -------------- | ------------------ | ------------------ |
| 1   | [`MerkleStack.mo`](./MerkleStack.mo)               | 32-byte `Blob`                                             | SHA-256        | a stack            | bagging            |
| 2   | [`MerkleStackState.mo`](./MerkleStackState.mo)     | message of any length                                      | SHA-256        | a stack            | bagging            |
| 3   | [`MerkleCounter.mo`](./MerkleCounter.mo)           | 32-byte `Blob`                                             | SHA-256        | a counter          | bagging            |
| 4   | [`MerkleCounterState.mo`](./MerkleCounterState.mo) | message of any length                                      | SHA-256        | a counter          | bagging            |
| 5   | [`BitcoinMerkle.mo`](./BitcoinMerkle.mo)           | 32-byte txid                                               | double SHA-256 | a counter          | Bitcoin's collapse |
| 6   | [`BitcoinTxMerkle.mo`](./BitcoinTxMerkle.mo)       | raw transaction                                            | double SHA-256 | a counter          | Bitcoin's collapse |
| 7   | [`BitcoinWitness.mo`](./BitcoinWitness.mo)         | coinbase inclusion proof for the trees of Examples 5 and 6 |                |                    |                    |
| 8   | [`BitcoinMerkleRight.mo`](./BitcoinMerkleRight.mo) | 32-byte txid, last to first                                | double SHA-256 | a mirrored counter | the one peak left  |
| 9   | [`BitcoinChunks.mo`](./BitcoinChunks.mo)           | chunked verification of a block against its Merkle root    | double SHA-256 | mirrored           | the stored proof   |
|     | [`NFold.mo`](./NFold.mo)                           | N-fold hashing `H^N(msg)`                                  |                |                    |                    |

Examples 3 and 5 share their tree-building code in [`CounterBase.mo`](./CounterBase.mo), Examples 4 and 6 share theirs, including the embedded `Digest`, in [`CounterStateBase.mo`](./CounterStateBase.mo).
Within each pair the examples differ only in single versus double SHA-256 and in how the root is computed, which lives in the example files.
Example 8 has its own tree-building code: it mirrors that of Example 5 and does Bitcoin's duplication while building.
The one-shot roots of Examples 5, 6 and 8 share the test for mutated blocks in [`BitcoinMutation.mo`](./BitcoinMutation.mo).

Examples 1 to 8 form a progression, each adding one concept, and they are explained one by one [below](#the-examples-one-by-one).
Each file's header comment is a how-to: it spells out exactly what to do to keep hashing allocation-free in bulk.

## Concepts

A **Merkle tree** hashes pairs of nodes up to a single root: the leaves are hashes, every inner node is the hash of its two children, and the root commits to all leaves.
Done the obvious way, every inner node produces an intermediate hash `Blob`, so a tree over `n` leaves allocates about `n` `Blob`s.
Every allocation costs instructions, once when it is made and again when the garbage collector runs.

The examples instead build a **Merkle mountain range** (MMR).
Leaves are added one at a time.
Whenever two subtrees of the same height exist they are merged into one, exactly like a carry in binary addition, so at any time the structure holds one complete subtree per set bit of the leaf count `n`.
These subtrees are the **peaks**; there are at most `log2(n) + 1` of them.

The peaks are held in **`Hasher`s**: a `Hasher` is nothing but a 32-byte hash state, so it can store a peak, and its `combineState` operation merges two peaks in place, with no `Blob`.
When two peaks are merged, one `Hasher` holds the new, higher peak and the other becomes free again.
The examples pre-allocate the required number of `Hasher`s, the **pool**, for a tree depth known in advance (the `maxLeaves` argument of `new`); adding a leaf beyond that capacity traps.
Allocating more `Hasher`s on demand would also be possible, but is not in scope for the examples.

The examples organize the pool in one of two ways:

- as a **stack** of peaks with a parallel array of their heights (Examples 1 and 2), or
- as an **array indexed by height**, where slot `k` holds the peak of height `k` if there is one (Examples 3 to 9). Which slots are occupied follows from the bits of the leaf count, so a single counter replaces the height array. This organization is the preferred one.

To obtain a **root** from several peaks the examples fold the peaks into one hash, from the lowest peak to the highest: `acc := SHA256(peak ++ acc)`.
This is called **bagging** the peaks and is the usual MMR finalization.
Bitcoin's Merkle tree instead pairs the last node of a level with itself whenever a level has an odd number of nodes; Examples 5 and 6 reproduce that rule.
In both cases the root computation only reads the peaks, so a tree stays valid afterwards: keep adding leaves and compute the root again at any time.
Example 8 builds Bitcoin's tree from the other end, where that rule is applied while the leaves come in and the root is simply the one peak that is left.

Leaves come in two forms.
A **Blob leaf** is a ready 32-byte hash, as in a Merkle tree over hashes.
A **message leaf** is a message of any length that still has to be hashed; the tree embeds one `Digest` for that, reuses it for every message, and takes the leaf straight out of the digest's state.

The only allocations made by the examples are the creation of the engines (the `Hasher`s, plus one `Digest` in the message-fed examples) and the final root `Blob`, whose readout also builds a temporary 32-byte array.

## Using an example

Every Merkle example has the same shape of API: `new` creates a tree with a capacity, `add` adds one leaf, `root` computes the root over the leaves added so far, and a one-shot function does all three for an array of leaves.
The tree is a static record, so it can be kept in a stable variable.

```motoko
import MerkleCounter "MerkleCounter";

let leaves : [Blob] = [...]; // 32-byte hashes

// One shot
let root : Blob = MerkleCounter.merkleRoot(leaves);

// Incrementally: capacity for 1000 leaves; the root can be taken at any time
let tree = MerkleCounter.new(1000);
tree.add(leaves[0]);
tree.add(leaves[1]);
let root2 : Blob = tree.root();
tree.add(leaves[2]);
let root3 : Blob = tree.root();

```

The Bitcoin examples take an extra `witness` flag that records the sibling hashes needed for the coinbase inclusion proof, see [below](#coinbase-inclusion-proof-example-7):

```motoko
import BitcoinTxMerkle "BitcoinTxMerkle";
import BitcoinWitness "BitcoinWitness";

let txs : [Blob] = [...]; // raw transactions, the coinbase first

let tree = BitcoinTxMerkle.new(txs.size(), true); // true: capture the proof
for (tx in txs.values()) tree.add(tx);
let root : Blob = tree.root();
let proof : [Blob] = tree.coinbaseWitnessTx();

// On the receiving side, without the tree:
assert BitcoinWitness.verifyTx(txs[0], proof, root);

```

## The examples one by one

**Example 1, [`MerkleStack.mo`](./MerkleStack.mo).**
An MMR over 32-byte `Blob` leaves.
The `Hasher`s that hold peaks form a stack: the highest peak at the bottom, the lowest on top, with a parallel `level[]` array recording the height of each peak.
A leaf without a partner waits in the `pending : ?Blob` field until the next leaf arrives; the pair is then fused with `combineBlob32` straight from the two `Blob`s.
To get the root, the peaks are bagged from the top of the stack down into the free `Hasher` just above the top; a waiting leaf is folded in first.
The pool has `ceil(log2 n)` `Hasher`s for `n` leaves.

**Example 2, [`MerkleStackState.mo`](./MerkleStackState.mo).**
The same as Example 1, but it takes messages as input instead of ready 32-byte leaves.
The tree embeds one reused `Digest` that absorbs each message, and the leaf, SHA256(msg), is read straight from the digest's state with no intermediate `Blob`.
A leaf without a partner cannot wait in a `pending` field here, because it exists only in the digest's state, which the next message overwrites.
So it is copied into a stack slot instead (`loadState`), as a peak of height 0; a height-0 entry on top of the stack is the waiting leaf.
This takes one `Hasher` more than Example 1, `ceil(log2 n) + 1`.
Bagging needs no special case for a waiting leaf: it is simply the lowest peak, on top of the stack.

**Example 3, [`MerkleCounter.mo`](./MerkleCounter.mo).**
The same as Example 1, but the `Hasher`s are an array indexed by height instead of a stack: slot `k` holds the peak of height `k`, if there is one.
Bit `k` of the leaf count is set exactly when there is a peak of height `k`, so a single leaf counter replaces the `level[]` array.
As in Example 1, a leaf without a partner waits as a `pending : ?Blob`, so slot 0 is always free and serves as the accumulator for bagging.
The pool has `floor(log2 n) + 1` `Hasher`s, one per bit of `n`.
Whether Example 3 or 4 fits depends on the input: ready 32-byte leaves or messages to hash.

**Example 4, [`MerkleCounterState.mo`](./MerkleCounterState.mo).**
The same as Example 3, but it takes messages as input through an embedded `Digest`, as in Example 2.
As there, a leaf without a partner cannot wait as a `Blob`; it is copied into slot 0 (`loadState`).
Slot 0 is therefore not free for bagging, and the accumulator is the top slot of the array instead, one level above the highest possible peak.
The pool is `ceil(log2 n) + 1`, the same as in Example 2.

**Example 5, [`BitcoinMerkle.mo`](./BitcoinMerkle.mo).**
The same as Example 3, but for Bitcoin's Merkle tree over transaction ids (txids), given as 32-byte `Blob`s.
It differs from Example 3 in two ways: every node is a double SHA-256 (`combineState` followed by `hashState` of the node itself), and instead of bagging, the peaks are combined the way Bitcoin does it: at a level with an odd number of nodes, the last node is paired with itself.
As in Example 3, slot 0 serves as the accumulator and the peaks are left unchanged.
The one-shot `bitcoinMerkleRoot` first tests the list with `mutated` of [`BitcoinMutation.mo`](./BitcoinMutation.mo) and traps on a mutated block (see the [security notes](#security-notes)).

**Example 6, [`BitcoinTxMerkle.mo`](./BitcoinTxMerkle.mo).**
Examples 5 and 4 combined: Bitcoin's Merkle tree over the raw transactions, of any length, instead of precomputed txids.
One `Digest` absorbs each transaction; after `close()` its state is SHA256(tx), and the second SHA-256 of the txid writes the result straight into its slot (`hashState`), so unlike Example 4 the waiting leaf needs no extra copy.
No allocations per transaction or node.
As in Example 4, the top slot serves as the accumulator.

**Example 7, [`BitcoinWitness.mo`](./BitcoinWitness.mo).**
An add-on to Examples 5 and 6, not a tree of its own: it produces and checks the coinbase inclusion proof, the "merkle branch" used by SPV proofs and mining protocols, for a tree built with Example 5 or 6, at any number of transactions.
See [Coinbase inclusion proof](#coinbase-inclusion-proof-example-7).

**Example 8, [`BitcoinMerkleRight.mo`](./BitcoinMerkleRight.mo).**
The same root as Example 5, but with the txids added from the last to the first.
A tree grown from the right is aligned at its right end, which in Bitcoin's tree lies beyond the last leaf: the unused places after it are the gap.
The counter starts at the gap instead of at 0, and adding a leaf is the counter increment of Example 5 in a mirror, with one addition: where the counter claims a peak that is not there, the peak lies in the gap, and the rising node is paired with itself.
That is Bitcoin's duplication, done while building, so `add` cannot be shared with Example 5; in exchange `root` computes nothing, because whenever the counter is a power of two one peak is left and it is the root.
Only the gap must be given to `new`, not the number of leaves.
See [Building from the right](#building-from-the-right-example-8).

**Example 9, [`BitcoinChunks.mo`](./BitcoinChunks.mo).**
Not a tree: a verifier that receives a block's transactions in chunks and checks each chunk against the header's Merkle root, holding only the leaf count and the mirrored peaks of the leaves not yet received.
It uses the mirrored carry of Example 8 to verify instead of to build.
See [Chunked verification](#chunked-verification-example-9).

**[`NFold.mo`](./NFold.mo).**
N-fold hashing, `H^N(msg)`: a `Digest` absorbs the message, then its state is passed straight to a `Hasher` (`hashState(d.state)`), which runs the remaining rounds with no intermediate `Blob`.
A batch variant reuses one `Digest` and one `Hasher` across many messages.

All of Examples 1 to 4 compute the same root for the same leaves; Examples 2 and 4 hash each message first, so their root over the messages equals Examples 1 and 3 over the hashed leaves.
Examples 5, 6 and 8 compute Bitcoin's root, which differs by the double hashing and the duplication rule.
None of them is RFC 6962, which prepends a domain-separation byte to each node.

## Pool sizes

| Examples             | Pool size                 | Why                                                                                               |
| -------------------- | ------------------------- | ------------------------------------------------------------------------------------------------- |
| 1 (stack)            | `ceil(log2 n)`            | the maximum number of simultaneously live peaks plus one; the stack never fills its pool          |
| 2 (state stack)      | `ceil(log2 n) + 1`        | the waiting leaf occupies a stack slot; the pool is one larger so a slot above the top stays free |
| 3, 5 (counter)       | `floor(log2 n) + 1`       | the bit length of `n`: one slot per bit of the leaf count                                         |
| 4, 6 (state counter) | `ceil(log2 n) + 1`        | the peak slots plus the top slot as the accumulator, one level above the highest possible peak    |
| 8 (mirrored counter) | `floor(log2 (g + n)) + 1` | the bit length of the gap plus `n`: one slot per bit of the counter, which starts at the gap `g`  |

None of them needs a dedicated accumulator `Hasher` for computing the root; a free slot always exists where it is needed.
The stack always has a free slot just above its top.
The state stack sizes its pool one above the maximal stack height.
The counter's slot 0 is free by construction, because the height-0 leaf waits as a pending `Blob`.
The state counter's top slot can only be occupied when `n` is a power of two, which means a single peak and no accumulation at all.

The sizes for `Blob` leaves (Examples 1 and 3) differ only when `n` is an exact power of two, where the counter uses one `Hasher` more.
The sizes for message leaves (Examples 2 and 4) agree with each other for every `n`, and exceed the `Blob` stack (Example 1) by exactly one.
A `Blob` leaf can wait out of band as a borrowed reference at no slot cost, while a leaf that exists only as the digest's state, about to be overwritten by the next message, must be captured into a slot the moment it arrives.
The extra `Hasher` is the cost of the waiting leaf, not a property of the stack or counter organization.

Witness capture (`new(_, true)` on Examples 5 and 6) adds no `Hasher`s, only a pre-sized `[var Blob]` with one slot per sibling hash of the coinbase proof.

## Coinbase inclusion proof (Example 7)

The coinbase is the first transaction of a block.
Its inclusion proof, the _merkle branch_, is the sequence of sibling hashes along the path from the coinbase to the root, one 32-byte hash per level: at level `k`, the hash of the subtree over transactions `[2^k, 2^(k+1))`.

- As the tree grows, the normal MMR computation produces these sibling hashes. If the number of transactions `n` is not a power of two, the last one appears only during the root computation, as its intermediate result just before the final step. Normally the hashes are discarded right away, and only the peaks are kept.
- With the `witness` flag of `new` set, the tree keeps them, in a pre-sized `[var Blob]`. That costs one small `Blob` per level over the whole build, nothing per leaf, and no extra `Hasher`s.
- On request, the root computation is run up to that final step to get the last hash, and together they form the proof. When `n` is a power of two, no work is necessary, just as for the root.

`BitcoinWitness.mo` contains the functions for the request.
`coinbaseWitness` (Example 5 trees) and `coinbaseWitnessTx` (Example 6 trees) return the proof for the current `n`.
Neither changes the tree, so it can keep growing.
The root is computed separately, with `root` of Example 5 or 6.
On the receiving side, `verifyTxid` and `verifyTx`, which need no tree, check a coinbase txid or raw coinbase transaction plus its proof against the 32-byte root.
A malformed proof returns `false`.

## Building from the right (Example 8)

Bitcoin's tree over n leaves has room for 2^d leaves, d = `ceil(log2 n)`, and the 2^d − n places after the last leaf are unused: the gap.
A tree grown from the right is aligned at the end of that gap, so the gap is what must be known before the first leaf is added.
The number of leaves need not be: with a gap of 3 the tree may end up with 5 leaves, or 13, or 29.
`gapFor(n)` gives the gap of a Bitcoin tree of n leaves.

`count` is the number of places used so far, the gap included: it starts at the gap and goes up by one with every leaf.
As in Example 5 its bits say where the peaks are, but the peaks that its initial value claims do not exist, so `present` records which of the claimed peaks are really there.
A new node climbs through the trailing 1-bits of `count` and comes to rest at the first 0-bit, and at every 1-bit one of two things happens:

- the claimed peak is present: the node merges with it, node first, `dSHA(node ++ peak)`;
- the claimed peak is not present: it lies in the gap, the node is the last of its level, and it is paired with itself, `dSHA(node ++ node)`.

With a gap of 3 (n = 5), `count` = 011b claims peaks of heights 0 and 1; the first leaf is doubled twice and rests at height 2, and `count` = `present` = 4.
With a gap of 2 (n = 6), the first leaf rests at once (`count` = 3, `present` = 1); the second merges with it, meets the missing peak of height 1 and is doubled, and `count` = `present` = 4.
There is one doubling for every 1-bit of the gap, and all are done when `count` reaches the first power of two above the gap; from then on `present` equals `count` and the build is the plain mirror image of Example 5.

Whenever `count` is a power of two, one peak is left and it is the root, read with no computation; the tree can then keep growing to the left.
That root is Bitcoin's root of the leaves added so far exactly when the gap is less than half of the places; the tree does not keep the gap, so that is for the caller to know.
With a larger gap the tree is deeper than Bitcoin would make it: one leaf and a gap of 3 give the leaf doubled twice, where Bitcoin's root of one transaction is the txid itself.
At other values of `count` there is no root, because the missing leaves are on the left and nothing can stand in for them.

As in Example 5, a leaf is never loaded into a `Hasher` on its own: a leaf that rests at height 0 waits as a `Blob`, and the leaf to its left fuses with it straight from the two `Blob`s.

## Chunked verification (Example 9)

A canister receives the N transactions of a block in chunks and knows only the header's Merkle root.
It wants to reject a bad chunk on arrival, within one message's instruction budget, and to know when the last chunk has arrived.

Let M be the number of leaves uploaded so far, a prefix of the N.
In the tree padded to 2^n leaves, the positions after that prefix, [M, 2^n), are covered by aligned subtrees that do not overlap, each as large as its position allows: the tiles of M.
They are the right siblings of leaf M−1's ancestors, and their hashes are the peaks of an MMR grown from the right, P_M (where a tile is stored or compared, its hash is meant).
Tiles entirely beyond the real leaves are duplicates by Bitcoin's rule and are left out, so P_0 is the root alone and P_N is empty.
The verifier stores M and P_M.
A chunk brings the leaves [M, M′) and the uploader's P_M′; the verifier grows P_M′ leftward through the chunk, prepending the leaves last first with the mirrored carry rule (a left child merges with the tile to its right, or with its own duplicate when there is none; a right child waits as a tile), and the tiles left after leaf M must equal the stored P_M:

    [M, M′) + P_M′ → P_M

Every leaf is absorbed into a compared tile and every compared tile was verified down to the root, so wrong leaves, wrong or missing tiles and a wrong root are all caught.
Neither N nor the depth is a parameter.
Equal siblings are rejected before every merge: a valid block never has them, so proofs must be minimal, the last chunk is recognised by an empty proof (then M′ = N), and the mutated blocks of CVE-2012-2459, a tail of the block uploaded twice, are rejected at the merge of the two copies.
The hashing is one node per leaf, as for building the tree once, with no ripple to the root per chunk, and verification allocates nothing: a pool of log N hashers holds the working tiles.
`proof(txids, m)` is the uploader's side, from all leaves.

All of this takes the uploaded leaves to be transaction ids; what the Merkle root alone cannot tell about that is a separate matter, covered in the [security notes](#security-notes).

## Security notes

- **The bagged root does not commit to the leaf count.** In Examples 1 to 4 the same root arises from the same peak hashes at different heights, and a leaf equal to an inner node value is trivially constructible, since leaves are arbitrary 32-byte values. Verifiers must be given `n` out of band; the peak heights are exactly its bits. RFC 6962 closes this with domain separation (`0x00` before leaf data, `0x01` before node inputs), which these fixed 64-byte combiners do not produce.
- **Bitcoin's duplication rule** (Examples 5 to 9) is the source of CVE-2012-2459: distinct transaction lists can yield the same root, for example `[1,2,3]` and `[1,2,3,3]`, or `[1..6]` and `[1,2,3,4,5,6,5,6]`. Every such list other than the block itself ends with a second copy, complete or cut off, of the subtree right before it on some level k, so its last txid equals the one 2^k places before it. `mutated` in [`BitcoinMutation.mo`](./BitcoinMutation.mo) tests a complete list for that up front, on the txids (or raw transactions) alone: it compares the last txid with the ones 1, 2, 4, 8, ... places before it. That catches every mutation, so among lists of genuine transaction ids with a given root at most one passes (a whole level of inner nodes passed as txids passes too, see the next note), and whatever else it flags repeats a txid, which a valid block never does. At most log2(n) `Blob` comparisons, no hashing, no allocation. The one-shot roots of Examples 5, 6 and 8 run it first and trap on a flagged list, so a caller who submits one gets its call rejected. The incremental API (`new`, `add`, `root`) and the shared tree machinery do not check; run `mutated` over the complete list yourself. Example 9, which never sees the whole list, rejects equal siblings at every merge instead, as Bitcoin Core does.
- **Leaves and inner nodes** (Examples 5 to 9). Bitcoin's tree does not mark leaves apart from inner nodes, and the header commits to neither the depth nor the transaction count. The nodes of any whole level, passed as txids, therefore have the same root as the block: the root's two children as a block of two, the root itself as a block of one. No test on the hashes can tell, so with txids as input the examples prove the list against the root only if the caller knows that the leaves are transaction ids. With raw transactions (Example 6, `verifyChunkTx` of Example 9) every leaf is hashed by the example, and an inner node can only pose as a transaction of exactly 64 bytes, the concatenation of its two children (CVE-2017-12842). Closing this gap is left to the application, and one transaction is enough for it: all leaves sit on one level, so it suffices to take the first one, the coinbase, in full (serialized without witness data) and to check that it hashes to the first txid and is not 64 bytes long. Then it is not an inner node, which fixes the depth of the tree and with it the meaning of every other leaf and of the count.
- **Byte order.** Txids, roots and proofs are in Bitcoin's internal byte order, the raw double-SHA-256 output. Block explorers and RPC display them byte-reversed; reverse the 32 bytes to compare (see the mainnet vectors in `test/verify.mo`).
- **Segwit.** A txid hashes the transaction serialized without witness data. Feeding full segwit bytes to Example 6 yields the wtxid instead.

## Tests

[`test/verify.mo`](./test/verify.mo) checks all examples against straightforward reference implementations, including real mainnet Bitcoin block vectors, and [`test/allocation.mo`](./test/allocation.mo) checks that they allocate only what is stated above.
Run them from this directory:

```bash
mops install
mops test verify
mops test allocation
```

CI runs both on every PR, the allocation test also on the 32-bit heap (moc 1.16.2 with `--legacy-persistence`).
