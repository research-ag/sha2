// Verifies the examples produce the same hashes as straightforward references.
import Merkle "../Merkle";
import NFold "../NFold";
import Sha256 "../../src/Sha256";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Random "mo:core/Random";

let rng = Random.seed(0x1234);
func bytes(n : Nat) : Blob = Blob.fromArray(Array.tabulate<Nat8>(n, func(_) = rng.nat8()));

// Canonical Bitcoin Merkle root: level by level, duplicating the last node on
// odd counts (materializes every intermediate digest as a Blob).
func refRoot(leaves : [Blob]) : Blob {
  if (leaves.size() == 1) return leaves[0];
  var level = leaves;
  while (level.size() > 1) {
    let m = level.size();
    level := Array.tabulate<Blob>(
      (m + 1) / 2,
      func(i) {
        let right = if (2 * i + 1 < m) level[2 * i + 1] else level[2 * i]; // dup last if odd
        let h = Sha256.new();
        h.writeBlob(level[2 * i]);
        h.writeBlob(right);
        h.sumDouble();
      },
    );
  };
  level[0];
};

// Every leaf count 1..18, plus a few larger and non-power-of-two sizes.
for (n in ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 23, 31, 33, 100] : [Nat]).values()) {
  let leaves = Array.tabulate<Blob>(n, func(_) = bytes(32));
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
