Optimized of all SHA2 functions

## Overview

This package implements all SHA2 functions:

* sha256
* sha224
* sha512
* sha384
* sha512-256
* sha512-224

The API allows to hash types `Blob`, `[Nat8]` and `Iter<Nat8>`.

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

We need up-to-date versions of `node`, `moc` and `mops` installed.
Suppose `<path-to-moc>` is the path of the `moc` binary of the appropriate version.

Then run:
```
git clone git@github.com:research-ag/sha2.git
mops install
DFX_MOC_PATH=<path-to-moc> mops test
```

## Benchmarks

The benchmarking code can be found here: [canister-profiling](https://github.com/research-ag/canister-profiling)

We benchmarked this library's sha256 and sha512 against two other existing sha256 implementations,
specifically these branches:

* motoko-sha2: https://github.com/timohanke/motoko-sha2#v2.0.0
* crypto.mo from aviate labs: https://github.com/skilesare/crypto.mo#main

### Time

We first measured the instructions for hashing the empty message:

|method|Sha256|Sha512|timohanke|aviate-labs|
|---|---|---|---|---|
|empty message|18,826|31,026|49,3420|98,981|

We then measured a long message of 1,000 blocks and divided by the length.
We provide the value per block where a block is 64 bytes for Sha256 and 128 bytes for Sha512, per byte, and relative to this libary's Sha256:

|method|Sha256|Sha512|timohanke|aviate-labs|
|---|---|---|---|---|
|per block|18,881|34,572|49,352|49,107|
|per byte|295|270|771|767|
|relative|1.0|0.92|2.61|2.60|

### Memory

Hashing also causes heap allocations.

We first measured the instructions for hashing the empty message:

|method|Sha256|Sha512|timohanke|aviate-labs|
|---|---|---|---|---|
|empty message|800|1348|26472|4376|

We then measured a long message of 1,000 blocks and divided the result by the length of the message in bytes. 
This tells us how many bytes are allocated on the heap for each byte that is hashed.
Ideally, this value should be zero.

|method|Sha256|Sha512|timohanke|aviate-labs|
|---|---|---|---|---|
|per byte|1.5|7.9|9|10.1|

## Implementation notes

The round loops are unrolled.
This was mainly motivated by reducing the heap allocations but it also reduced the instructions significantly.

## Copyright

MR Research AG, 2023
## Authors

Main author: Timo Hanke (timohanke)

## License 

Apache-2.0
