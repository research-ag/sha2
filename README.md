[![mops](https://oknww-riaaa-aaaam-qaf6a-cai.raw.ic0.app/badge/mops/sha2)](https://mops.one/sha2)
[![documentation](https://oknww-riaaa-aaaam-qaf6a-cai.raw.ic0.app/badge/documentation/sha2)](https://mops.one/sha2/docs)

# SHA2 family

Optimized implementation of all SHA2 functions

## Overview

This package implements all SHA2 functions:

- sha256
- sha224
- sha512
- sha384
- sha512-256
- sha512-224

The API allows to hash the types `Blob`, `[Nat8]`, `[var Nat8]`, `Iter<Nat8>`, and `List<Nat8>`, as well as bytes delivered by an accessor function `Nat -> Nat8` or a reader function `() -> Nat8` (`Text` after UTF-8 encoding, see below).

The API provides a Digest type which accepts the message piecewise until finally computing the hash sum (digest).
This allows hashing very large messages over multiple executions of the canister, even across canister upgrades.

For fixed-length inputs (32-byte values and pairs of them, e.g. Merkle trees) there is additionally a single-shot, allocation-free `Hasher` engine (SHA-256 only) — see the [Hasher section](#5-single-shot-hashing-with-the-hasher-engine) below.

### Links

The package is published on [MOPS](https://mops.one/sha2) and [GitHub](https://github.com/research-ag/sha2).
Please refer to the README on GitHub where it renders properly with formulas and tables.

The API documentation can be found [here](https://mops.one/sha2/docs/lib) on Mops.

For updates, help, questions, feedback and other requests related to this package join us on:

- [OpenChat group](https://oc.app/2zyqk-iqaaa-aaaar-anmra-cai)
- [Twitter](https://twitter.com/mr_research_ag)
- [Dfinity forum](https://forum.dfinity.org/)

## Usage

### Install with mops

You need `mops` installed. In your project directory run:

```bash
mops init
mops add sha2
```

In the Motoko source file import the package as:

```motoko
import Sha256 "mo:sha2/Sha256";
import Sha512 "mo:sha2/Sha512";

```

In your `dfx.json` make sure you have the entry:

```
"defaults": {
    "build": {
      "args": "",
      "packtool": "mops sources"
    }
  },
```

## Examples

### 1. Quick hashing with convenience functions

The simplest way to hash a complete message is using the shortcut functions:

```motoko
import Sha256 "mo:sha2/Sha256";
import Sha512 "mo:sha2/Sha512";

// Hash from Blob
let hash1 : Blob = Sha256.fromBlob(#sha256, "Hello, World!");
let hash2 : Blob = Sha512.fromBlob(#sha512, "Hello, World!");

// Hash from Array
let data : [Nat8] = [72, 101, 108, 108, 111];
let hash3 : Blob = Sha256.fromArray(#sha224, data);

// Hash from VarArray
let varData : [var Nat8] = [var 72, 101, 108, 108, 111];
let hash4 : Blob = Sha512.fromVarArray(#sha384, varData);

// Hash from positional byte accessor function
func getByte(i : Nat) : Nat8 { 0; /* return byte at position i */ };
let accessorLen = 100; // number of bytes to read
let hash5 : Blob = Sha256.fromAccessor(#sha256, getByte, 0, accessorLen);

// Hash from next-byte reader function
var pos = 0;
func nextByte() : Nat8 { pos += 1; 0; /* return next byte */ };
let readerLen = 100; // number of bytes to read
let hash6 : Blob = Sha512.fromReader(#sha512_256, nextByte, readerLen);

// Hash from Iter<Nat8>
let iter = [72, 101, 108, 108, 111].vals();
let hash7 : Blob = Sha256.fromIter(#sha256, iter);

```

To hash a `Text`, UTF-8 encode it into a `Blob` first:

```motoko
// Hash from Text
let text = "Hello, World!";
let hash8 : Blob = Sha256.fromBlob(text.encodeUtf8());

```

To hash from `List<Nat8>` the most efficient way is to use the reader function as follows:

```motoko
// Hash from List<Nat8>
import List "mo:core/List";

let list = List.fromArray<Nat8>([72, 101, 108, 108, 111]);
let hash9 : Blob = Sha512.fromReader(#sha512, list.reader(0), list.size());

```

### 2. Streaming API with Digest engine

For processing data in chunks, create a `Digest` type and write to it incrementally:

```motoko
import Sha256 "mo:sha2/Sha256";

// Create a new digest engine
let digest = Sha256.new();

// Write data in chunks of different types
digest.writeBlob("First chunk ");
digest.writeArray([115, 101, 99, 111, 110, 100]); // "second"
digest.writeBlob(" chunk");

let varData : [var Nat8] = [var 32, 116, 104, 105, 114, 100]; // " third"
digest.writeVarArray(varData);

// Write from positional function
func getChunk(i : Nat) : Nat8 { 0; /* return byte at position i */ };
digest.writeAccessor(getChunk, 0, 10);

// Write from reader function
var index = 0;
func nextChunk() : Nat8 { index += 1; 0; /* return next byte */ };
digest.writeReader(nextChunk, 5);

// Finalize and get the hash
let finalHash : Blob = digest.sum();

// Note: sum() closes the digest for further writes. Attempting to write to it
// or finalize it again will trap. The hash remains readable via readSum(),
// and reset() makes the digest reusable for a new message.

```

The first argument `#sha256` in the `Sha256` module functions and `#sha512` in the `Sha512` is implicit and can be skipped when writing code. For example, `Sha512.new(#sha512)` can be written as `Sha512.new()`.

The finalization can also be split into its two halves: `sum()` is exactly `close()` followed by `readSum()`. `close()` finalizes the digest (writes the padding) without producing a `Blob`; `readSum()` reads the hash of a closed digest — idempotent, callable any number of times. Split them when you want to finalize now but read later, repeatedly, or not at all. A digest can be finalized only ONCE: a second `sum()` or `close()` (in any combination) traps, until `reset()` starts a new computation — to read the hash again, use `readSum()`. `Sha256` additionally offers the double-SHA counterparts `sumDouble()` = `closeDouble()` + `readSum()`, which finalize with a SECOND SHA256 pass — the double hash `SHA256(SHA256(m))` used by Bitcoin — at the cost of a single extra compression block.

### 3. Cloning for intermediate hashes

To get an intermediate hash without consuming the digest, `clone()` it and
finalize the clone — your original keeps accumulating:

```motoko
import Sha256 "mo:sha2/Sha256";
import Debug "mo:core/Debug";

let digest = Sha256.new();

// Hash first chunk
digest.writeBlob("Chunk 1");
let hash1 = digest.clone().sum(); // intermediate hash; `digest` stays open
Debug.print("Hash after chunk 1: " # debug_show (hash1));

// Hash second chunk
digest.writeBlob("Chunk 2");
let hash2 = digest.clone().sum();
Debug.print("Hash after chunk 2: " # debug_show (hash2));

// Hash third chunk
digest.writeBlob("Chunk 3");
let hash3 = digest.clone().sum();
Debug.print("Hash after chunk 3: " # debug_show (hash3));

// Final hash (consumes `digest`)
let finalHash = digest.sum();
Debug.print("Final hash: " # debug_show (finalHash));

```

Each `clone().sum()` allocates a copy of the digest plus the result `Blob`, so
reach for it only when you genuinely need a mid-stream snapshot. If you instead
want to read the hash of an already-finalized digest more than once, use
`readSum()` — it re-reads the closed state without re-finalizing.

### 4. Stable state across upgrades

For hashing very large messages across multiple message executions and even upgrades.
A `Digest` is a static record (no classes, no function fields), so it is a stable type: it can be kept in a stable variable directly and its state survives canister upgrades.

```motoko
import Sha256 "mo:sha2/Sha256";

persistent actor {
  // In a persistent actor all declarations are stable by default, and
  // Digest is a stable type — the digest state survives upgrades.
  let digest = Sha256.new();

  // Write a chunk (can be called many times, across messages and upgrades)
  public func writeChunk(data : Blob) : async () {
    digest.writeBlob(data);
  };

  // Get an intermediate hash without finalizing
  public query func peekHash() : async Blob {
    digest.clone().sum();
  };

  // Finalize and get the hash
  public func finalizeHash() : async Blob {
    digest.sum();
  };

  // Start a new hash computation
  public func restart() : async () {
    digest.reset();
  };
};

```

### 5. Single-shot hashing with the Hasher engine

For fixed-length inputs there is a second, more specialized hash engine, `Hasher` (SHA-256 only):

```motoko
import Hasher "mo:sha2/Hasher/Sha256";

```

A `Digest` is a streaming engine: it has an internal message buffer, accepts any number of writes of any length, and is finalized once.
A `Hasher` has NO buffer: it is nothing but the 256-bit state, and every operation is a complete hash — it overwrites the state with the digest of its fixed-length operands. That makes it:

- allocation-free: the only operation that allocates is `readSum()`, which produces the result `Blob`,
- reusable without `reset()`: every operation starts from the IV, so a finished `Hasher` is immediately ready for the next hash,
- cheaper than a `Digest` for its inputs: no buffer management, no per-write bookkeeping.

The operations (each sets `h := SHA256(...)` in place):

| Function             | Input                    | Meaning                                          |
| -------------------- | ------------------------ | ------------------------------------------------ |
| `hashBlob32(b)`      | one 32-byte `Blob`       | `SHA256(b)`                                      |
| `hashState(src)`     | another `Hasher`'s state | `SHA256(src)` — iterated / double hashing        |
| `combineBlob32(a,b)` | two 32-byte `Blob`s      | `SHA256(a ++ b)` — Merkle leaf pair              |
| `combineState(a,b)`  | two `Hasher`s            | `SHA256(a ++ b)` — Merkle inner node             |
| `loadBlob32(b)`      | a 32-byte hash           | load verbatim, no hashing (inverse of `readSum`) |
| `loadState(src)`     | another `Hasher`         | copy verbatim, no hashing                        |
| `readSum()`          | —                        | read the state as a 32-byte `Blob`               |

In `combineState` the sources may alias the destination (e.g. `h.combineState(h, sibling)`), which is what lets a Merkle node move up the tree in place. Example — the Bitcoin double hash of a 32-byte leaf:

```motoko
import Hasher "mo:sha2/Hasher/Sha256";

let leaf : Blob = "\00\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f\10\11\12\13\14\15\16\17\18\19\1a\1b\1c\1d\1e\1f";
let h = Hasher.new();
h.hashBlob32(leaf); // h = SHA256(leaf)
h.hashState(h); // h = SHA256(SHA256(leaf)), in place
let digest : Blob = h.readSum();

```

Limitations:

- SHA-256 only — no sha224 and no SHA-512 family.
- Inputs are fixed-length only: 32-byte blobs or 256-bit states. For arbitrary-length messages use a `Digest` — or bridge the two: after `d.close()` a sha256 `Digest`'s result can be hashed straight into a `Hasher` with `h.hashState(d.state)` (adds one SHA256), with no intermediate `Blob`.
- The `Hasher` type is a raw `[var Nat16]` of length 16; the type system does not enforce the length. Treat it as opaque and only operate on values created by `Hasher.new()`.

The [`examples/` directory](./examples/README.md) shows the intended use cases: allocation-free Merkle trees in five variants (`MerkleStack.mo`, `MerkleCounter.mo`, `MerkleCounterState.mo`, `BitcoinMerkle.mo`, `BitcoinTxMerkle.mo`) and iterated hashing (`NFold.mo`).

### Build & test

Run:

```bash
git clone git@github.com:research-ag/sha2.git
mops install
mops test
```

## Benchmarks

### Mops benchmark

Run

```bash
mops bench
```

or

```bash
mops bench --replica pocket-ic
```

or look at the [benchmark on mops](https://mops.one/sha2/benchmarks).

### Performance

We measure performance with random input messages (seeded `mo:core/Random`). Measuring with a message of all the same bytes is not a reliable way to measure. It produces significantly different results.

### Memory

The hash engines are designed to not make any heap allocations when consuming the message.
This can be seen in the benchmark results.

By this statement we mean that the heap allocations do not depend linearly on the message length.
There is a constant heap allocation when the hash engine (Digest instance) is created.
There may also be a constant heap allocation every time a writer function (e.g. `writeBlob`, etc.) is called.
But the heap allocation does not increase with the message length.

This is true for the Sha256 and Sha512 engines.
It is also true for all different writer functions `writeBlob, writeArray, writeVarArray, writeReader, writeAccessor, writeIter`.

## Implementation notes

The round loops are unrolled.
This was mainly motivated by reducing the heap allocations but it also reduced the instructions significantly.

## Contributing

### Formatting

To format the code, run:

```bash
npx -y prettier --plugin prettier-plugin-motoko --write '**/*.{mo,json,md}'
```

## Copyright

MR Research AG, 2023-2026

## Authors

Main author: Timo Hanke (timohanke)

## License

Apache-2.0
