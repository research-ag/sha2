[![mops](https://oknww-riaaa-aaaam-qaf6a-cai.raw.ic0.app/badge/mops/sha2)](https://mops.one/sha2)
[![documentation](https://oknww-riaaa-aaaam-qaf6a-cai.raw.ic0.app/badge/documentation/sha2)](https://mops.one/sha2/docs)

# SHA2 family

Optimized implementation of all SHA2 functions for Motoko.

## Overview

This package implements the six hash functions of the SHA2 family.
They come in two groups, each with its own module:

| Module           | Algorithm     | Output   | Block size | Notes                 |
| ---------------- | ------------- | -------- | ---------- | --------------------- |
| `mo:sha2/Sha256` | `#sha256`     | 32 bytes | 64 bytes   | default of the module |
|                  | `#sha224`     | 28 bytes | 64 bytes   |                       |
| `mo:sha2/Sha512` | `#sha512`     | 64 bytes | 128 bytes  | default of the module |
|                  | `#sha384`     | 48 bytes | 128 bytes  |                       |
|                  | `#sha512_256` | 32 bytes | 128 bytes  |                       |
|                  | `#sha512_224` | 28 bytes | 128 bytes  |                       |

The hash of a message is returned as a `Blob` of the output length.
In the standard this value is called the _digest_.
In this package the word `Digest` also names the engine that accumulates a message, see below; the text says _hash_ for the output to keep the two apart.

The implementation is optimized for a low instruction count and makes no heap allocations while hashing.
The two go together: an allocation costs instructions when it is made and again when the garbage collector runs.
The instruction count per block is kept low by unrolled round loops (see [Implementation notes](#implementation-notes)).

There are three ways to hash, from the simplest to the most specialized:

1. **Convenience functions** such as `Sha256.fromBlob` hash a complete message in one call.
2. **The `Digest` engine** accepts a message piecewise through `write…` calls and is finalized once with `sum()`.
   It can hash messages of any length, split over many calls, over many canister messages, and even across canister upgrades, because it is a stable type.
3. **The `Hasher` engine** (SHA-256 only) hashes fixed-length inputs, a single 32-byte value or a pair of them, with no buffer and no allocation.
   It is made for Merkle trees and hash chains.

Messages can be given as `Blob`, `[Nat8]`, `[var Nat8]`, `Iter<Nat8>`, through an accessor function `Nat -> Nat8` or a reader function `() -> Nat8`.
`Text` is hashed after UTF-8 encoding and `List<Nat8>` through its reader; both are shown below.

### Links

The package is published on [MOPS](https://mops.one/sha2) and [GitHub](https://github.com/research-ag/sha2).
Please refer to the README on GitHub where it renders properly with tables.

The API documentation can be found [here](https://mops.one/sha2/docs/lib) on Mops.
Changes between versions are listed in the [CHANGELOG](https://github.com/research-ag/sha2/blob/main/CHANGELOG.md).

For updates, help, questions, feedback and other requests related to this package join us on:

- [OpenChat group](https://oc.app/2zyqk-iqaaa-aaaar-anmra-cai)
- [Twitter](https://twitter.com/mr_research_ag)
- [Dfinity forum](https://forum.dfinity.org/)

## Installation

You need [mops](https://mops.one) installed. In your project directory run:

```bash
mops add sha2
```

(Run `mops init` first if the project has no `mops.toml` yet.)
The package requires `moc` 1.0.0 or later and depends on `mo:core`.

In your Motoko source file import the modules you need:

```motoko
import Sha256 "mo:sha2/Sha256";
import Sha512 "mo:sha2/Sha512";
import Hasher "mo:sha2/Hasher/Sha256";

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

## Usage

### Which API to use

| You want to                                                                | Use                                            |
| -------------------------------------------------------------------------- | ---------------------------------------------- |
| hash a message that is already complete in memory                          | `fromBlob`, `fromArray`, … (section 1)         |
| hash a message that arrives in pieces                                      | a `Digest`: `new`, `write…`, `sum` (section 2) |
| take an intermediate hash and keep writing                                 | `clone()` (section 3)                          |
| hash across canister messages or upgrades                                  | a `Digest` in a stable variable (section 4)    |
| hash 32-byte values or pairs of them with SHA-256 only, e.g. a Merkle tree | a `Hasher` (section 5)                         |
| compute SHA256(SHA256(m)), the Bitcoin hash                                | `sumDouble()` on a `Digest` (section 2)        |

### 1. One-shot hashing with the convenience functions

Each module has one convenience function per input type.
They create a `Digest`, write the message and return the hash.

```motoko
import Sha256 "mo:sha2/Sha256";
import Sha512 "mo:sha2/Sha512";

// Hash a Blob (text literals are Blobs when a Blob is expected)
let hash1 : Blob = Sha256.fromBlob("Hello, World!");
let hash2 : Blob = Sha512.fromBlob("Hello, World!");

// Hash an immutable or mutable array
let data : [Nat8] = [72, 101, 108, 108, 111]; // "Hello"
let hash3 : Blob = Sha256.fromArray(data);
let varData : [var Nat8] = [var 72, 101, 108, 108, 111];
let hash4 : Blob = Sha512.fromVarArray(varData);

// Hash an iterator of bytes; it is consumed to the end
let hash5 : Blob = Sha256.fromIter(data.values());

// Hash through an accessor function: `len` bytes from index `start`
func at(i : Nat) : Nat8 = data[i];
let hash6 : Blob = Sha256.fromAccessor(at, 0, data.size());

// Hash through a reader function: it is called `len` times
var pos = 0;
func next() : Nat8 { let b = data[pos]; pos += 1; b };
let hash7 : Blob = Sha512.fromReader(next, data.size());

```

**Choosing the algorithm.**
Every function of `Sha256` takes the algorithm as an optional first argument, `#sha256` or `#sha224`.
It is a Motoko _implicit_ argument: when it is omitted the module default is used, `#sha256` for `Sha256` and `#sha512` for `Sha512`.
To use another algorithm of the family pass it explicitly:

```motoko
import Sha256 "mo:sha2/Sha256";
import Sha512 "mo:sha2/Sha512";

let a : Blob = Sha256.fromBlob(#sha224, "Hello, World!");
let b : Blob = Sha512.fromBlob(#sha384, "Hello, World!");
let c : Blob = Sha512.fromBlob(#sha512_256, "Hello, World!");
let d : Blob = Sha512.fromBlob(#sha512_224, "Hello, World!");

```

The same applies to `new()` below: `Sha512.new(#sha384)` creates a SHA-384 digest, `Sha512.new()` a SHA-512 one.

**Text.**
There is no function for `Text`; UTF-8 encode it into a `Blob` first:

```motoko
import Sha256 "mo:sha2/Sha256";
import Text "mo:core/Text";

let text = "Hello, World!";
let hash8 : Blob = Sha256.fromBlob(text.encodeUtf8());

```

**List.**
The most efficient way to hash a `List<Nat8>` from `mo:core` is through its reader function:

```motoko
import Sha512 "mo:sha2/Sha512";
import List "mo:core/List";

let list = List.fromArray<Nat8>([72, 101, 108, 108, 111]);
let hash9 : Blob = Sha512.fromReader(list.reader(0), list.size());

```

The convenience functions never trap, except if a user-provided accessor or reader function traps.

### 2. Streaming with the Digest engine

A `Digest` is a hash engine that holds the hash state and a buffer for the partial block.
Create it with `new()`, feed the message with any sequence of `write…` calls, in pieces of any size and of any input type, and finalize it with `sum()`:

```motoko
import Sha256 "mo:sha2/Sha256";

let digest = Sha256.new(); // or Sha256.new(#sha224), Sha512.new(#sha384), ...

digest.writeBlob("First chunk ");
digest.writeArray([115, 101, 99, 111, 110, 100]); // "second"
digest.writeBlob(" chunk");

let varData : [var Nat8] = [var 32, 116, 104, 105, 114, 100]; // " third"
digest.writeVarArray(varData);

let more : [Nat8] = [32, 102, 111, 117, 114, 116, 104]; // " fourth"
digest.writeIter(more.values());
func at(i : Nat) : Nat8 = more[i];
digest.writeAccessor(at, 0, more.size());
var pos = 0;
func next() : Nat8 { let b = more[pos]; pos += 1; b };
digest.writeReader(next, more.size());

let hash : Blob = digest.sum();

```

The result is the same as hashing the concatenation of all pieces in one call.

**Lifecycle.**
A digest is _open_ after `new()` and `reset()`, and _closed_ after it has been finalized.
Finalizing writes the padding and the message length into the state, so it can happen only once per message.
The functions involved are:

| Function        | Effect                                                                                       |
| --------------- | -------------------------------------------------------------------------------------------- |
| `write…()`      | Append to the message. Traps on a closed digest.                                             |
| `sum()`         | Finalize and return the hash. Closes the digest. Traps on a closed digest.                   |
| `close()`       | Finalize without returning anything. Closes the digest. Traps on a closed digest.            |
| `readSum()`     | Return the hash of a closed digest. Can be called any number of times. Traps on an open one. |
| `reset()`       | Start a new message. Works on open and closed digests. Keeps the algorithm.                  |
| `clone()`       | Independent copy with the same state. Traps on a closed digest.                              |
| `sumDouble()`   | `Sha256` only: finalize as SHA256(SHA256(m)), the Bitcoin double hash, and return it.        |
| `closeDouble()` | `Sha256` only: the same without returning the hash; read it with `readSum()`.                |

`sum()` is exactly `close()` followed by `readSum()`, and `sumDouble()` is `closeDouble()` followed by `readSum()`.
Split them when you want to finalize now but read the hash later, repeatedly, or not at all: `close()` and `closeDouble()` allocate nothing, only the readout of the hash does.
The double hash costs one extra compression block over the single one.

Writing to a closed digest, or finalizing it a second time, traps with a message such as `Sha256: write to closed digest`.
To hash another message with the same digest call `reset()` first.

### 3. Intermediate hashes with clone()

To get the hash of the message so far without closing the digest, `clone()` it and finalize the clone.
The original keeps accumulating:

```motoko
import Sha256 "mo:sha2/Sha256";
import Debug "mo:core/Debug";

let digest = Sha256.new();

digest.writeBlob("Chunk 1");
let hash1 = digest.clone().sum(); // hash of "Chunk 1"; `digest` stays open
Debug.print("Hash after chunk 1: " # debug_show (hash1));

digest.writeBlob("Chunk 2");
let hash2 = digest.clone().sum(); // hash of "Chunk 1Chunk 2"
Debug.print("Hash after chunk 2: " # debug_show (hash2));

let finalHash = digest.sum(); // closes `digest`
Debug.print("Final hash: " # debug_show (finalHash));

```

Each `clone().sum()` allocates a copy of the digest plus the result `Blob`, so use it only when you need a mid-stream hash.
To read the hash of an already closed digest more than once use `readSum()` instead.

### 4. Keeping a Digest across messages and upgrades

A `Digest` is a plain record of arrays and numbers, with no class and no function fields.
Such a _static record_ is a stable type in Motoko: it can live in a stable variable, and its state survives canister upgrades.
This is how a very large message can be hashed over many canister messages, or even over upgrades:

```motoko
import Sha256 "mo:sha2/Sha256";

actor {
  // In an actor all declarations are stable by default, and
  // Digest is a stable type: the digest state survives upgrades.
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

With `moc` 1.x declare the actor as `persistent actor` to get the same default; with `moc` 2.0 that keyword is implied.

The stable type of `Sha256.Digest` changed in version 0.3.0 (see the [CHANGELOG](https://github.com/research-ag/sha2/blob/main/CHANGELOG.md)).
A canister that keeps a digest from an earlier version in a stable variable has to migrate it, or reset and recreate it, when upgrading.

### 5. Fixed-length hashing with the Hasher engine

For fixed-length inputs there is a second, more specialized engine, `Hasher`, for SHA-256 only:

```motoko
import Hasher "mo:sha2/Hasher/Sha256";

```

A `Digest` is a streaming engine: it has a message buffer, accepts any number of writes of any length and is finalized once.
A `Hasher` has no buffer.
It is nothing but the 256-bit hash state, and every operation is a complete hash: it overwrites the state with the hash of its fixed-length operands, starting from the standard initial value (IV) of SHA-256 and ending with the padding, which is a constant for a fixed length.
That makes it:

- allocation-free: the only operation that allocates is `readSum()`, which produces the result `Blob`,
- reusable without `reset()`: every operation starts from the IV, so a finished `Hasher` is immediately ready for the next hash,
- cheaper than a `Digest` for its inputs: no buffer management, no per-write bookkeeping.

The operands are 32-byte `Blob`s, or the states of other `Hasher`s, which are also 32-byte hashes.
Each operation sets the state `h` to the SHA-256 of its operands:

| Function                   | Input                              | Meaning                                        |
| -------------------------- | ---------------------------------- | ---------------------------------------------- |
| `hashBlob32(b)`            | one 32-byte `Blob`                 | `h := SHA256(b)`                               |
| `hashState(src)`           | another `Hasher`'s state           | `h := SHA256(src)`, iterated or double hashing |
| `combineBlob32(a, b)`      | two 32-byte `Blob`s                | `h := SHA256(a ++ b)`, a Merkle leaf pair      |
| `combineState(a, b)`       | two `Hasher`s                      | `h := SHA256(a ++ b)`, a Merkle inner node     |
| `combineStateBlob32(s, b)` | a `Hasher` state, a 32-byte `Blob` | `h := SHA256(s ++ b)`, mixed operand order     |
| `combineBlob32State(b, s)` | a 32-byte `Blob`, a `Hasher` state | `h := SHA256(b ++ s)`, mirror of the above     |
| `loadBlob32(b)`            | a 32-byte hash                     | `h := b`, no hashing (inverse of `readSum`)    |
| `loadState(src)`           | another `Hasher`                   | `h := src`, no hashing                         |
| `readSum()`                |                                    | read `h` as a 32-byte `Blob`                   |

Any operand may be the destination itself, e.g. `h.combineState(h, sibling)`.
This is what lets a Merkle node move up the tree in place.
Example, the Bitcoin double hash of a 32-byte leaf:

```motoko
import Hasher "mo:sha2/Hasher/Sha256";

let leaf : Blob = "\00\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f\10\11\12\13\14\15\16\17\18\19\1a\1b\1c\1d\1e\1f";
let h = Hasher.new();
h.hashBlob32(leaf); // h = SHA256(leaf)
h.hashState(h); // h = SHA256(SHA256(leaf)), in place
let hash : Blob = h.readSum();

```

**From a Digest to a Hasher.**
A `Hasher` cannot take an arbitrary-length message, but a `Digest` can, and the two connect without an intermediate `Blob`: the `state` field of a closed `#sha256` digest has the same type as a `Hasher`.
After `d.close()`, `h.hashState(d.state)` computes SHA256(SHA256(message)) and `h.loadState(d.state)` copies SHA256(message) into the hasher as it is.
The hasher cannot check that the digest is closed and is `#sha256`; that is the caller's responsibility.
Pass `d.state` only as a source, never as the hasher that is written to.

**Limitations.**

- SHA-256 only, no `#sha224` and no SHA-512 family.
- Inputs are fixed-length only: 32-byte blobs or 256-bit states. A blob of another length traps with a message such as `Hasher: hashBlob32 expects a 32-byte blob, got 20 bytes`.
- The `Hasher` type is a raw `[var Nat16]` of length 16; the type system does not enforce the length. Treat it as opaque and only operate on values created by `Hasher.new()`.

The [`examples/` directory](https://github.com/research-ag/sha2/tree/main/examples) shows the intended use: allocation-free Merkle trees in seven variants, including Bitcoin's block Merkle tree and the coinbase inclusion proof, and iterated hashing.
See its [README](https://github.com/research-ag/sha2/blob/main/examples/README.md).

### Message length limits

SHA-256 and SHA-224 support the full range of the standard: messages shorter than 2^64 bits.
The SHA-512 family also supports messages shorter than 2^64 bits (2^61 bytes, 2 EiB), while the standard allows up to 2^128 bits.
A longer message would give a wrong hash without trapping.

## Allocation behavior

The hash engines make no heap allocation while consuming the message: the allocation of a hash computation does not grow with the message length.
What does allocate, by the test in `test/allocation.test.mo`:

- `new()` allocates the engine once.
- `Sha256`: `writeBlob`, `close`, `closeDouble` and `reset` allocate nothing. The other `write…` functions allocate a small constant per call (the closures they pass internally, and `writeIter` the option values of the iterator), independent of the length of the piece. `sum`, `sumDouble` and `readSum` allocate the result `Blob`.
- `Hasher`: nothing allocates except `readSum()`, which allocates the result `Blob`.
- `Sha512`: the 64-bit words of the state and the message are boxed by Motoko when they are large, so every call allocates a small, bounded amount; nothing is allocated per block.

The same holds for all input types, so for long messages the input type only affects the instruction count, not the memory.

## Performance

### Benchmarks

Run

```bash
mops bench
```

or look at the [benchmarks on mops](https://mops.one/sha2/benchmarks).
The benchmarks cover every convenience function over message lengths from 0 bytes to 1 MB, the cost of each step of the `Digest` lifecycle, the `Hasher` operations against the equivalent `Digest` calls, and a Merkle build.

For orientation, measured with moc 2.0.0 and wasm-opt on the 0.3.0 code:

| Operation                  |       Sha256 |       Sha512 |
| -------------------------- | -----------: | -----------: |
| `fromBlob`, empty message  |       12,100 |       12,900 |
| `fromBlob`, one block      |       31,000 |       42,000 |
| `fromBlob`, 1 MB           |  201,000,000 |  125,000,000 |
| per byte of a long message |          200 |          120 |
| `new()`                    |        1,500 |        1,400 |
| `reset()`                  |          700 |          700 |
| `close()`                  | 8,500–10,100 | 7,700–13,200 |
| `readSum()`                |        2,300 |        3,700 |

The ranges for `close()` span a message ending on a block boundary (cheaper) and one ending mid-block.
Hashing from an array costs about the same as from a `Blob`.
The accessor, reader and iterator inputs cost 13%, 29% and 63% more per byte for Sha256, because every byte goes through a function call; the figures for Sha512 are similar.

A `Hasher` operation on a reused engine costs 13,100 instructions for a single 32-byte hash and 17,000 to 18,000 for a combine of two 32-byte values, against 15,200 and 26,800 for the same hashes through a reused `Digest`.

### Measuring

We measure with random input messages (seeded `mo:core/Random`).
Measuring with a message of all the same bytes is not reliable: it produces significantly different results.

### Benchmark history

The benchmark history on mops.one shows changed numbers from 0.2.5 to 0.3.0 because the measurement setup changed, not the hashing code.
The published 0.2.5 results were measured with moc 1.10.0 under legacy persistence (32-bit heap, copying GC) and without wasm-opt; the 0.3.0 results with moc 2.0.0 (64-bit heap, incremental GC) and wasm-opt.
Measured with the same setup, the 0.2.5 code and the 0.3.0 code cost the same for hashing with Sha256 and Sha512, for all input types and the whole `Digest` lifecycle (within 0.2%; some short writes are up to 4% faster).

- Instructions: +9% to +35% for Sha256 hashing, −6% to +23% for Sha512 hashing. Creating a digest with `new()` costs about 3× as much: each heap allocation costs about 130 instructions more with the incremental GC.
- Heap: the Heap table now shows what each cell allocates (0.2.5 reported its allocation in the Garbage Collection table). Allocations are about twice as large: words and pointers take 8 bytes on the 64-bit heap, and the incremental GC adds a forwarding pointer to every object.
- The allocation-free Merkle build is 40% faster than in 0.2.5, because it now uses the `Hasher` engine.

## Implementation notes

- The round loops of the compression function are unrolled, for both SHA-256 and SHA-512. This was mainly motivated by reducing the heap allocations but it also reduced the instructions significantly.
- SHA-256 keeps its state and message buffer in 16-bit half-words (`Nat16`), which Motoko never boxes, so hashing allocates nothing. SHA-512 needs 64-bit words, which are boxed when large; that is the bounded per-call allocation noted above.
  - On the 64-bit heap `Nat32` is never boxed either, so the state and the message buffer could be kept in `Nat32` words instead of `Nat16` half-words. We measured this. It saves the joining and splitting of half-words only where a call reads and writes back the state and where bytes pass through the buffer, so the improvement is per call, not per byte: long messages are unaffected. Short messages get up to about 8% fewer instructions, and Merkle-tree hashing with the `Hasher`, which has no buffer, about 3.5% (Blob leaves) to 7% (state leaves). A `Digest` would also be 192 B smaller.
  - We don't make this change because the package also supports the 32-bit heap (moc 1.x with legacy persistence), where large `Nat32` values are boxed. There the state words would allocate, and the package is meant to stay allocation-free on the 32-bit heap as well.
- Whole blocks are compressed directly from the input (`Blob`, arrays, accessor, reader, iterator) without passing through the message buffer. Only the partial block at the start and at the end of a write goes through the buffer.
- `writeBlob` reads the `Blob` directly rather than through an accessor closure, so it allocates nothing.
- When a message ends on a block boundary, the padding block is compressed directly from constants instead of being assembled in the buffer.
- The `Hasher` operations are specialized compressions for 32- and 64-byte messages: the message words come straight from the operands and the padding is constant.

## Correctness

The test suite checks the implementation against reference vectors for every algorithm and every padding length (0 to 128 bytes), chunked writes of every size, the `Digest` lifecycle, the `Hasher` operations against the `Digest`, and the allocation claims above.
The examples are verified against straightforward reference implementations and real Bitcoin mainnet blocks.
Run it with `mops test`, see below.

## Development

Build and test:

```bash
git clone git@github.com:research-ag/sha2.git
cd sha2
mops install
mops test
```

The examples are their own mops project with their own tests; see [examples/README.md](https://github.com/research-ag/sha2/blob/main/examples/README.md).

Benchmarks:

```bash
mops bench
```

Formatting:

```bash
npm install --no-save prettier prettier-plugin-motoko
npx prettier --plugin prettier-plugin-motoko --write '**/*.{mo,json,md}'
```

## Copyright

MR Research AG, 2023-2026

## Authors

Main author: Timo Hanke (timohanke)

## License

Apache-2.0
