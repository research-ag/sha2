import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Random "mo:core/Random";
import Sha256 "../src/Sha256";

// sumDouble(message) must equal the naive double hash: hashing the message,
// then hashing the resulting digest. sumDouble is sha256-only (it folds via
// the sha256-specific fast block). Check message lengths that exercise every
// padding path (empty, sub-block, block-boundary, the 55/56-byte length-field
// edge, and multi-block).
let rng = Random.seed(0xc0ffee);
let lengths = [0, 1, 31, 32, 55, 56, 63, 64, 65, 100, 256];

for (algo in ([#sha256] : [Sha256.Algorithm]).values()) {
  for (len in lengths.values()) {
    let msg = Blob.fromArray(Array.tabulate<Nat8>(len, func(_) = rng.nat8()));

    // Reference: two independent hashing passes.
    let reference = Sha256.fromBlob(algo, Sha256.fromBlob(algo, msg));

    let d = Sha256.new(algo);
    Sha256.writeBlob(d, msg);
    assert (Sha256.sumDouble(d) == reference);
  };
};
