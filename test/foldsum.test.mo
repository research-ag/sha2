import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Random "mo:core/Random";
import Sha256 "../src/Sha256";
import Sha512 "../src/Sha512";

let rng = Random.seed(0xf0d5);
func bytes(n : Nat) : Blob = Blob.fromArray(Array.tabulate<Nat8>(n, func(_) = rng.nat8()));

// --- Sha256 close/fold (sha256 only; fold traps on sha224) ---
for (len in ([0, 1, 32, 55, 56, 64, 100] : [Nat]).values()) {
  let msg = bytes(len);

  // close + fold once + readSum == double hash (== sumDouble).
  let d = Sha256.new();
  d.writeBlob(msg);
  d.close();
  d.fold();
  let double = d.readSum();
  assert (double == Sha256.fromBlob(Sha256.fromBlob(msg)));
  assert (d.readSum() == double); // readSum is idempotent

  let d2 = Sha256.new();
  d2.writeBlob(msg);
  assert (d2.sumDouble() == double);

  // close + fold twice + readSum == triple hash.
  let e = Sha256.new();
  e.writeBlob(msg);
  e.close();
  e.fold();
  e.fold();
  let triple = e.readSum();
  assert (triple == Sha256.fromBlob(Sha256.fromBlob(Sha256.fromBlob(msg))));

  // readSum after sum() returns the same hash.
  let f = Sha256.new();
  f.writeBlob(msg);
  let once = f.sum();
  assert (f.readSum() == once);
};

// Sha512 has close/readSum for symmetry with Sha256, but no fold/combine
// primitives (single-/double-SHA512 Merkle trees aren't supported — see
// Sha512.mo). Check close/readSum for every variant, including lengths that
// straddle the 128-byte block boundary and the extra-padding-block threshold.
for (algo in ([#sha512, #sha384, #sha512_224, #sha512_256] : [Sha512.Algorithm]).values()) {
  for (len in ([0, 1, 100, 111, 112, 128, 200, 256] : [Nat]).values()) {
    let msg = bytes(len);

    // close + readSum == fromBlob, and readSum is idempotent.
    let d = Sha512.new(algo);
    d.writeBlob(msg);
    d.close();
    let once = d.readSum();
    assert (once == Sha512.fromBlob(algo, msg));
    assert (d.readSum() == once);

    // readSum after sum() returns the same hash.
    let e = Sha512.new(algo);
    e.writeBlob(msg);
    let s = e.sum();
    assert (e.readSum() == s);
    assert (s == once);
  };
};
