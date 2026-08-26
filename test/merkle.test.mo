import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Blob "mo:core/Blob";
import Random "mo:core/Random";
import Sha256 "../src/Sha256";
import Hasher "../src/Hasher/Sha256";

// Validate that the allocation-free Sha256 Merkle tree (Bitcoin-style double-sha
// via the Hasher combineBlob32/combineState peak stack) produces the same root
// as a naive reference that materializes every intermediate digest as a Blob.

let rng = Random.seed(0x3a3a);

// --- Bitcoin-style double-sha tree over 2^k 32-byte leaves (Sha256) ---
func refRoot256(leaves : [Blob]) : Blob {
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

// Iterative Merkle-mountain-range over a pool of `levels` hashers: push each
// leaf node (combineBlob32 + fold) onto a peak stack and merge in place with
// combineState + fold while the top two peaks share a level.
func mmrRoot256(leaves : [Blob], levels : Nat) : Blob {
  let hasher = Array.tabulate<Hasher.Hasher>(levels, func(_) { Hasher.new() });
  let level = VarArray.repeat<Nat>(0, levels);
  let n = leaves.size();
  var i = 0;
  var p = 0;
  while (p < n) {
    hasher[i].combineBlob32(leaves[p], leaves[p + 1]);
    hasher[i].hashState(hasher[i]);
    level[i] := 1;
    while (i > 0 and level[i - 1] == level[i]) {
      hasher[i - 1].combineState(hasher[i - 1], hasher[i]);
      hasher[i - 1].hashState(hasher[i - 1]); // -> double-SHA
      level[i - 1] += 1;
      i -= 1;
    };
    i += 1;
    p += 2;
  };
  Hasher.readSum(hasher[0]);
};

for (k in ([1, 2, 3, 6] : [Nat]).values()) {
  let count = 2 ** k;
  let leaves = Array.tabulate<Blob>(count, func(_) = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8())));
  assert (mmrRoot256(leaves, k) == refRoot256(leaves));
};
