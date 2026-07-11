# sha2 examples

Worked examples for the allocation-free hashing APIs of [`mo:sha2`](../): the
single-shot `Hasher` (`hashBlob32`, `hashState`, `combineBlob32`, `combineState`,
`loadBlob32`, `loadState`, `readSum`) and the buffered `Digest` (`close`,
`closeDouble`, `readSum`, `sumDouble`).

The five Merkle examples form a progression — each adds one concept:

| #   | file                                               | what it shows                                                                                                                                                                                                                                                                                                                                                               |
| --- | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | [`MerkleStack.mo`](./MerkleStack.mo)               | The PEAK-STACK mountain range over Blob leaves: single SHA256 per node, any leaf count, leftover peaks bagged right to left. A pool of `ceil(log2 n) + 1` `Hasher`s, leaf pairs combined with `combineBlob32`, internal nodes in place with `combineState`, only the root `Blob` allocated.                                                                                 |
| 2   | [`MerkleCounter.mo`](./MerkleCounter.mo)           | The same root via the BINARY-COUNTER mountain range: a height-indexed `[var Hasher]` where the occupied slots are the bits of the leaf count — no `level[]` array, no flags. Height 0 is a pending `?Blob` fused with `combineBlob32` (the "delay" trick — no per-leaf deserialize) and risen peaks move with O(1) reference SWAPs, so it matches/slightly beats the stack. |
| 3   | [`MerkleCounterState.mo`](./MerkleCounterState.mo) | The counter over STATE leaves (32-byte hashes already sitting in `Hasher`s): the HALF-delay — only the first leaf of each pair is captured into slot 0 (`loadState`), its partner is read directly by `combineState`. n/2 copies instead of n, modeling transient leaves handed over one at a time.                                                                         |
| 4   | [`BitcoinMerkle.mo`](./BitcoinMerkle.mo)           | The BITCOIN tree over txid leaves: Example 2's counter with double SHA256 per node (`combine` + `hashState`) and Bitcoin's custom finalization — not bagging, but a COLLAPSE that pairs the odd last node with ITSELF, doubling its way up through empty heights and combining at occupied ones. Any count, matches real mainnet block roots.                               |
| 5   | [`BitcoinTxMerkle.mo`](./BitcoinTxMerkle.mo)       | The same Bitcoin tree from RAW (variable-length) transactions: one reused `Digest` absorbs each tx and the `Digest` → `Hasher` bridge lands each txid with zero copies — `close` + `hashState` produces the first leaf of a pair directly INTO its slot, `closeDouble` finishes the second in place for immediate `combineState` consumption.                               |
|     | [`NFold.mo`](./NFold.mo)                           | N-fold hashing (`H^N(msg)`) that absorbs the message with a `Digest`, then bridges its state into a `Hasher` (the expert `digest.state` → `hashState` path) to fold the remaining rounds with no intermediate `Blob`; plus a batch variant reusing one of each engine across many messages.                                                                                 |

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
