import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Random "mo:core/Random";
import Sha256 "../src/Sha256";
import Sha512 "../src/Sha512";

let rng = Random.seed(0xf0d5);
func bytes(n : Nat) : Blob = Blob.fromArray(Array.tabulate<Nat8>(n, func(_) = rng.nat8()));

for (algo in ([#sha256, #sha224] : [Sha256.Algorithm]).values()) {
  for (len in ([0, 1, 32, 55, 56, 64, 100] : [Nat]).values()) {
    let msg = bytes(len);

    // foldSum once + sum == double hash (== sumDouble).
    let d = Sha256.new(algo);
    d.writeBlob(msg);
    d.foldSum();
    let double = d.sum();
    assert (double == Sha256.fromBlob(algo, Sha256.fromBlob(algo, msg)));

    let d2 = Sha256.new(algo);
    d2.writeBlob(msg);
    assert (d2.sumDouble() == double);

    // foldSum twice + sum == triple hash.
    let e = Sha256.new(algo);
    e.writeBlob(msg);
    e.foldSum();
    e.foldSum();
    let triple = e.sum();
    assert (triple == Sha256.fromBlob(algo, Sha256.fromBlob(algo, Sha256.fromBlob(algo, msg))));
  };

  // pushSum: writing a digest into a target equals writing those digest bytes.
  let msgL = bytes(20);
  let msgR = bytes(48);
  let dL = Sha256.fromBlob(algo, msgL);
  let dR = Sha256.fromBlob(algo, msgR);

  let ref = Sha256.new(algo);
  ref.writeBlob(dL);
  ref.writeBlob(dR);
  let expected = ref.sum();

  let a = Sha256.new(algo);
  a.writeBlob(msgL);
  let b = Sha256.new(algo);
  b.writeBlob(msgR);
  let parent = Sha256.new(algo);
  a.pushSum(parent);
  b.pushSum(parent);
  assert (parent.sum() == expected);
};

// Same checks for every Sha512 variant, including the sha512-224 tail.
for (algo in ([#sha512, #sha384, #sha512_224, #sha512_256] : [Sha512.Algorithm]).values()) {
  for (len in ([0, 1, 100, 111, 112, 128, 200] : [Nat]).values()) {
    let msg = bytes(len);

    let d = Sha512.new(algo);
    d.writeBlob(msg);
    d.foldSum();
    let double = d.sum();
    assert (double == Sha512.fromBlob(algo, Sha512.fromBlob(algo, msg)));

    let e = Sha512.new(algo);
    e.writeBlob(msg);
    e.foldSum();
    e.foldSum();
    let triple = e.sum();
    assert (triple == Sha512.fromBlob(algo, Sha512.fromBlob(algo, Sha512.fromBlob(algo, msg))));
  };

  // pushSum: a single push equals writing those digest bytes. (Two pushes only
  // for the word-aligned variants; sha512-224 would trap on the second.)
  let msgL = bytes(20);
  let msgR = bytes(48);
  let dL = Sha512.fromBlob(algo, msgL);

  if (algo != #sha512_224) {
    let dR = Sha512.fromBlob(algo, msgR);
    let ref = Sha512.new(algo);
    ref.writeBlob(dL);
    ref.writeBlob(dR);
    let expected = ref.sum();

    let a = Sha512.new(algo);
    a.writeBlob(msgL);
    let b = Sha512.new(algo);
    b.writeBlob(msgR);
    let parent = Sha512.new(algo);
    a.pushSum(parent);
    b.pushSum(parent);
    assert (parent.sum() == expected);
  } else {
    // Single push of a 28-byte digest, then finalize.
    let ref = Sha512.new(algo);
    ref.writeBlob(dL);
    let expected = ref.sum();

    let a = Sha512.new(algo);
    a.writeBlob(msgL);
    let parent = Sha512.new(algo);
    a.pushSum(parent);
    assert (parent.sum() == expected);
  };
};
