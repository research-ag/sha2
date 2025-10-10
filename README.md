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

The API allows to hash types `Blob`, `[Nat8]` and `Iter<Nat8>`.

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
### Example

```
import Sha256 "mo:sha2/Sha256";
[
Sha256.fromBlob(#sha256,""),
Sha256.fromBlob(#sha224,"")
];
```

```
import Sha512 "mo:sha2/Sha512";
[
Sha512.fromBlob(#sha512,""),
Sha512.fromBlob(#sha384,""),
Sha512.fromBlob(#sha512_224,""),
Sha512.fromBlob(#sha512_256,"")
];
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
