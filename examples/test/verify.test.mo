// Verifies the examples produce the same hashes as straightforward references.
import Merkle "../Merkle";
import NFold "../NFold";
import Sha256 "../../src/Sha256";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Random "mo:core/Random";

let rng = Random.seed(0x1234);
func bytes(n : Nat) : Blob = Blob.fromArray(Array.tabulate<Nat8>(n, func(_) = rng.nat8()));

// Naive double-SHA256 Merkle root (materializes every intermediate digest).
func refRoot(leaves : [Blob]) : Blob {
  var level = leaves;
  while (level.size() > 1) {
    level := Array.tabulate<Blob>(
      level.size() / 2,
      func(i) {
        let h = Sha256.new();
        h.writeBlob(level[2 * i]);
        h.writeBlob(level[2 * i + 1]);
        h.sumDouble();
      },
    );
  };
  level[0];
};

for (k in ([0, 1, 2, 3, 4] : [Nat]).values()) {
  let leaves = Array.tabulate<Blob>(2 ** k, func(_) = bytes(32));
  assert (Merkle.bitcoinMerkleRoot(leaves) == refRoot(leaves));
};

// N-fold against manual repeated fromBlob.
let msg = bytes(20);
assert (NFold.nfold(msg, 1) == Sha256.fromBlob(msg));
assert (NFold.nfold(msg, 2) == Sha256.fromBlob(Sha256.fromBlob(msg)));
assert (NFold.nfold(msg, 3) == Sha256.fromBlob(Sha256.fromBlob(Sha256.fromBlob(msg))));

// Batch reuses one hasher but matches the single-message function.
let m0 = bytes(0);
let m100 = bytes(100);
let out = NFold.nfoldBatch([msg, m0, m100], 3);
assert (out[0] == NFold.nfold(msg, 3));
assert (out[1] == NFold.nfold(m0, 3));
assert (out[2] == NFold.nfold(m100, 3));
