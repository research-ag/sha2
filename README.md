[![mops](https://oknww-riaaa-aaaam-qaf6a-cai.raw.ic0.app/badge/mops/sha2)](https://mops.one/sha2)
[![documentation](https://oknww-riaaa-aaaam-qaf6a-cai.raw.ic0.app/badge/documentation/sha2)](https://mops.one/sha2/docs)
# SHA2 family 

Optimized implementation of all SHA2 functions
## Overview

This package implements all SHA2 functions:

* sha256
* sha224
* sha512
* sha384
* sha512-256
* sha512-224

The API allows to hash types `Blob`, `[Nat8]`, `[var Nat8]`, `Iter<Nat8>`, and `List<Nat8>`.

The API provides the usual Digest instance which accepts the message piecewise until finally computing the hash sum (digest).
This allows hashing very large messages over multiple executions of the canister, even across canister upgrades.
### Links

The package is published on [MOPS](https://mops.one/sha2) and [GitHub](https://github.com/research-ag/sha2).
Please refer to the README on GitHub where it renders properly with formulas and tables.

The API documentation can be found [here](https://mops.one/sha2/docs/lib) on Mops.

For updates, help, questions, feedback and other requests related to this package join us on:

* [OpenChat group](https://oc.app/2zyqk-iqaaa-aaaar-anmra-cai)
* [Twitter](https://twitter.com/mr_research_ag)
* [Dfinity forum](https://forum.dfinity.org/)

## Usage
### Install with mops

You need `mops` installed. In your project directory run:
```
mops init
mops add sha2
```

In the Motoko source file import the package as:
```
import Sha256 "mo:sha2/Sha256";
import Sha512 "mo:sha2/Sha512";
```

In you `dfx.json` make sure you have the entry:
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

// Hash from positional function
func getByte(i : Nat) : Nat8 { /* return byte at position i */ };
let hash5 : Blob = Sha256.fromPositional(#sha256, getByte, 100);

// Hash from iterator function
var pos = 0;
func nextByte() : Nat8 { pos += 1; /* return next byte */ };
let hash6 : Blob = Sha512.fromNext(#sha512_256, nextByte, 100);

// Hash from Iter<Nat8>
import Iter "mo:base/Iter";
let iter = Iter.fromArray([72, 101, 108, 108, 111]);
let hash7 : Blob = Sha256.fromIter(#sha256, iter);

// Hash from List<Nat8>
import List "mo:base/List";
let list = List.fromArray<Nat8>([72, 101, 108, 108, 111]);
let hash8 : Blob = Sha512.fromIter(#sha512, List.toIter(list));
```

### 2. Streaming API with Digest engine

For processing data in chunks, create a `Digest` instance and write to it incrementally:

```motoko
import Sha256 "mo:sha2/Sha256";

// Create a new digest engine
let digest = Sha256.new(#sha256);

// Write data in chunks of different types
digest.writeBlob("First chunk ");
digest.writeArray([115, 101, 99, 111, 110, 100]); // "second"
digest.writeBlob(" chunk");

let varData : [var Nat8] = [var 32, 116, 104, 105, 114, 100]; // " third"
digest.writeVarArray(varData);

// Write from positional function
func getChunk(i : Nat) : Nat8 { /* return byte at position i */ };
digest.writePositional(getChunk, 10);

// Write from iterator
var index = 0;
func nextChunk() : Nat8 { index += 1; /* return next byte */ };
digest.writeNext(nextChunk, 5);

// Finalize and get the hash
let finalHash : Blob = digest.sum();

// Note: After calling sum(), the digest is consumed and cannot be reused
// Attempting to write or sum again will trap
```

### 3. Cloning for intermediate hashes

Use `clone()` and `peekSum()` to get intermediate hashes without losing your progress:

```motoko
import Sha256 "mo:sha2/Sha256";
import Debug "mo:base/Debug";

let digest = Sha256.new(#sha256);

// Hash first chunk
digest.writeBlob("Chunk 1");
let hash1 = digest.peekSum(); // Get hash without consuming
Debug.print("Hash after chunk 1: " # debug_show(hash1));

// Hash second chunk
digest.writeBlob("Chunk 2");
let hash2 = digest.peekSum();
Debug.print("Hash after chunk 2: " # debug_show(hash2));

// Hash third chunk
digest.writeBlob("Chunk 3");
let hash3 = digest.peekSum();
Debug.print("Hash after chunk 3: " # debug_show(hash3));

// Final hash
let finalHash = digest.sum();
Debug.print("Final hash: " # debug_show(finalHash));

// Alternative: clone before sum if you want to keep the digest alive
let digest2 = Sha512.new(#sha512);
digest2.writeBlob("Some data");

let clone1 = digest2.clone();
let intermediateHash = clone1.sum(); // Consumes clone1, but digest2 is still usable

digest2.writeBlob("More data");
let finalHash2 = digest2.sum(); // Now digest2 is consumed
```

### 4. Stable state across upgrades

For hashing very large messages across multiple message executions and even upgrades:

```motoko
import Sha256 "mo:sha2/Sha256";

actor {
  // Declare digest as stable
  stable var digestState : ?Sha256.DigestShared = null;

  // Initialize on first call
  public func initDigest() : async () {
    let d = Sha256.new(#sha256);
    digestState := ?d.share();
  };

  // Write a chunk (can be called multiple times across different messages)
  public func writeChunk(data : Blob) : async () {
    switch (digestState) {
      case null { assert false }; // Must call initDigest first
      case (?state) {
        let d = Sha256.unshare(state);
        d.writeBlob(data);
        digestState := ?d.share(); // Save updated state
      };
    };
  };

  // Get intermediate hash without finalizing
  public query func peekHash() : async ?Blob {
    switch (digestState) {
      case null { null };
      case (?state) {
        let d = Sha256.unshare(state);
        ?d.peekSum();
      };
    };
  };

  // Finalize and get the hash
  public func finalizeHash() : async ?Blob {
    switch (digestState) {
      case null { null };
      case (?state) {
        let d = Sha256.unshare(state);
        let hash = d.sum();
        digestState := null; // Clear the consumed digest
        ?hash;
      };
    };
  };

  // Reset to start a new hash
  public func resetDigest() : async () {
    switch (digestState) {
      case null {};
      case (?state) {
        let d = Sha256.unshare(state);
        d.reset();
        digestState := ?d.share();
      };
    };
  };

  // Example: Hash a large file in chunks across multiple calls
  public func hashLargeFile(chunks : [Blob]) : async Blob {
    let d = Sha256.new(#sha256);
    for (chunk in chunks.vals()) {
      d.writeBlob(chunk);
    };
    d.sum();
  };
};
```

### Build & test

Run:
```
git clone git@github.com:research-ag/sha2.git
mops install
mops test
```

## Benchmarks

### Mops benchmark

Run
```
mops bench
```
or
```
mops bench --replica pocket-ic
```
or look at the [benchmark on mops](https://mops.one/sha2/benchmarks).
### Performance

We measure performance with random input messages created by the [Prng package](https://mops.one/prng). Measuring with a message of all the same bytes is not a reliable way to measure. It produces significantly different results.
### Memory

The hash engines are designed to not make any heap allocations when consuming the message.
This can be seen in the benchmark results.

By this statement we mean that the heap allocations do not depend linearly on the message length.
There is a constant heap allocation when the hash engine (Digest instance) is created.
There may also be a constant heap allocation every time the writeX function is called.
But the heap allocation does not increase with the message length.

This is true for the Sha256 and Sha512 engines.
It is also true for all different write functions (type `Blob`, `Array`, `Iter<Nat8>`).
## Implementation notes

The round loops are unrolled.
This was mainly motivated by reducing the heap allocations but it also reduced the instructions significantly.
## Copyright

MR Research AG, 2023-2025
## Authors

Main author: Timo Hanke (timohanke)
## License 

Apache-2.0
