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

### Motivation

### Interface

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

The benchmarking code can be found here: [canister-profiling](https://github.com/research-ag/canister-profiling)

We benchmarked this library's sha256 and sha512 against two other existing implementations,
specifically these branches:

* motoko-sha2 for sha256/512: https://github.com/timohanke/motoko-sha2#v2.0.0
* crypto.mo from aviate labs for sha256 only: https://github.com/skilesare/crypto.mo#main

The benchmark was run with dfx 0.20.1 with cycle optimisation enabled and moc 0.11.3.
### Time

We first measured the instructions for hashing the empty message:

|method|Sha256|Sha512|mo-sha256|mo-sha512|crypto.mo|
|---|---|---|---|---|---|
|empty message|11,723|17,580|285,526|818,633|101,275|
|relative|1.0|1.5|24.3|69.7|8.6|

We then measured a long message of 1,000 blocks and divided by the length.
We provide the value per block where a block is 64 bytes for Sha256 and 128 bytes for Sha512, per byte, and relative to this libary's Sha256:

|method|Sha256|Sha512|mo-sha256|mo-sha512|crypto.mo|
|---|---|---|---|---|---|
|per block|16,821|31,248|48,299|78,677|48,863|
|per byte|263|244|755|615|763|
|relative|1.0|0.93|2.87|2.34|2.90|

Notes:

* All functions except crypto.mo have been measure with hashing type `Blob`. crypto.mo has been measured with hashing type `[Nat8]` because it does not offer type `Blob` directly.
* We measured with random input messages created by the [Prng package](https://mops.one/prng). Measuring with a constant message such that all 0x00 or all 0xff is not a reliable way to measure and produces significantly different results.
### Memory

Hashing also creates garbage.
We measured the garbage created by a message of length 1,000 blocks and divided the result by the length of the message in bytes. 
This tells us how many bytes of garbage are produced for each byte that is hashed.
For Sha256 this value is 0 which means that the garbage has size O(1).
In fact, it is 1,008 bytes regardless of the message length.

|method|Sha256|Sha512|mo-sha256|mo-sha512|crypto.mo|
|---|---|---|---|---|---|
|per byte|0|7.5|8.8|12.5|6.1|

Notes: 

* All functions except crypto.mo have been measure with hashing type `Blob`. crypto.mo has been measured with hashing type `[Nat8]` because it does not offer type `Blob` directly. Converting `Blob` to `[Nat8]` first will increase the value of garbage per byte by 4.
* We can see how the use of Nat64 in Sha512 requires signifantly more heap allocations than the use of Nat32 in Sha256.
* We can conclude that in Motoko it is advisable to use Sha256 over Sha512 despite the slightly higher performance per byte of Sha512.

## Implementation notes

The round loops are unrolled.
This was mainly motivated by reducing the heap allocations but it also reduced the instructions significantly.

## Copyright

MR Research AG, 2023-2024
## Authors

Main author: Timo Hanke (timohanke)
## License 

Apache-2.0

