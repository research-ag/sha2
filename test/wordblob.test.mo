import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Random "mo:core/Random";
import Sha256 "../src/Sha256";

// writeWordBlob / fromWordBlob must produce the same hash as the generic
// writeBlob / fromBlob, for any length (even and odd) and both algorithms.
let rng = Random.seed(0x5077);

for (algo in ([#sha256, #sha224] : [Sha256.Algorithm]).values()) {
  // writeWordBlob accepts any length (odd handled via a trailing byte); it only
  // requires starting at a word boundary, which a fresh digest satisfies.
  for (len in ([0, 1, 2, 31, 32, 55, 56, 63, 64, 65, 128, 200] : [Nat]).values()) {
    let msg = Blob.fromArray(Array.tabulate<Nat8>(len, func(_) = rng.nat8()));
    assert (Sha256.fromWordBlob(algo, msg) == Sha256.fromBlob(algo, msg));
  };

  // Two even-length word-aligned chunks then sum == single writeBlob.
  let a = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8()));
  let b = Blob.fromArray(Array.tabulate<Nat8>(40, func(_) = rng.nat8()));
  let d = Sha256.new(algo);
  d.writeWordBlob(a);
  d.writeWordBlob(b);
  let ref = Sha256.new(algo);
  ref.writeBlob(a);
  ref.writeBlob(b);
  assert (d.sum() == ref.sum());
};
