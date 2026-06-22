# sha2 examples

Worked examples for the allocation-free hashing API (`close`, `fold`,
`readSum`, `merkleLeaves`, `merkleMerge`) of [`mo:sha2`](../).

| file                       | what it shows                                                                                                                                                                                                                                      |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`Merkle.mo`](./Merkle.mo) | An allocation-free Bitcoin-style (double-SHA256) Merkle tree — a post-order DFS over a pool of `log2(n)` hashers, leaf pairs combined with `merkleLeaves` + `fold` and internal nodes in place with `merkleMerge`, only the root `Blob` allocated. |
| [`NFold.mo`](./NFold.mo)   | N-fold hashing (`H^N(msg)`) with `close`/`fold`, plus a batch variant that reuses a single hasher across many messages.                                                                                                                            |

Each file's header is a how-to: it spells out exactly what you must do to keep
hashing allocation-free in bulk — reuse a pool of hashers, combine 32-byte leaf
pairs with `merkleLeaves` + `fold`, combine internal nodes in place with
`merkleMerge`, and read the result with `readSum()` only for the final output.

`test/verify.test.mo` checks both examples against straightforward references;
it runs as part of `mops test`.

> These files live inside the sha2 repo, so they import the source directly
> (`import Sha256 "../src/Sha256"`). **In your own project**, depend on the
> published package and import it by name instead:
>
> ```motoko
> import Sha256 "mo:sha2/Sha256";
>
> ```
