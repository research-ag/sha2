# sha2 examples

Worked examples for the allocation-free hashing-chain API (`foldSum`,
`pushSum`) of [`mo:sha2`](../).

| file                       | what it shows                                                                                                                                                                            |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`Merkle.mo`](./Merkle.mo) | An allocation-free Bitcoin-style (double-SHA256) Merkle tree — one reusable hasher per level, digests streamed between hashers with `pushSum`/`foldSum`, only the root `Blob` allocated. |
| [`NFold.mo`](./NFold.mo)   | N-fold hashing (`H^N(msg)`) with `foldSum`, plus a batch variant that reuses a single hasher across many messages.                                                                       |

Each file's header is a how-to: it spells out exactly what you must do to keep
hashing allocation-free in bulk — reuse hashers via `reset()`, feed leaves with
`writeBlob`, move digests between hashers with `pushSum`/`foldSum`, and call the
allocating `sum()` only for the final result.

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
