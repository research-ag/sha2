import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Blob "mo:core/Blob";
import Random "mo:core/Random";
import Sha256 "../src/Sha256";
import Sha512 "../src/Sha512";

// Validate that the allocation-free Merkle trees (Sha256 double-sha via the
// merkleLeaves/merkleMerge peak stack; Sha512 single-sha via the pushSum carry)
// produce the same root as a naive reference that materializes every
// intermediate digest as a Blob.

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

// Iterative Merkle-mountain-range over a pool of `levels` pre-closed hashers:
// push each leaf node (merkleLeaves + fold) onto a peak stack and merge in
// place with merkleMerge while the top two peaks share a level.
func mmrRoot256(leaves : [Blob], levels : Nat) : Blob {
  let hasher = Array.tabulate<Sha256.Digest>(levels, func(_) { let h = Sha256.new(); h.close(); h });
  let level = VarArray.repeat<Nat>(0, levels);
  let n = leaves.size();
  var i = 0;
  var p = 0;
  while (p < n) {
    hasher[i].merkleLeaves(leaves[p], leaves[p + 1]);
    hasher[i].fold();
    level[i] := 1;
    while (i > 0 and level[i - 1] == level[i]) {
      hasher[i - 1].merkleMerge(hasher[i]);
      level[i - 1] += 1;
      i -= 1;
    };
    i += 1;
    p += 2;
  };
  Sha256.readSum(hasher[0]);
};

for (k in ([1, 2, 3, 6] : [Nat]).values()) {
  let count = 2 ** k;
  let leaves = Array.tabulate<Blob>(count, func(_) = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8())));
  assert (mmrRoot256(leaves, k) == refRoot256(leaves));
};

// --- single-sha tree over 2^k 64-byte leaves (Sha512) ---
func refRoot512(leaves : [Blob]) : Blob {
  var level = leaves;
  while (level.size() > 1) {
    level := Array.tabulate<Blob>(
      level.size() / 2,
      func(i) {
        let h = Sha512.new();
        h.writeBlob(level[2 * i]);
        h.writeBlob(level[2 * i + 1]);
        h.sum();
      },
    );
  };
  level[0];
};

func carryRoot512(leaves : [Blob], levels : Nat) : Blob {
  let hashers = Array.tabulate<Sha512.Digest>(levels, func(_) = Sha512.new());
  let pending = VarArray.repeat<Bool>(false, levels);
  var root : Blob = "";
  var i = 0;
  while (i < leaves.size()) {
    hashers[0].writeBlob(leaves[i]);
    hashers[0].writeBlob(leaves[i + 1]);
    var lvl = 0;
    var carrying = true;
    while (carrying) {
      let h = hashers[lvl];
      if (lvl + 1 == levels) { root := h.sum(); h.reset(); carrying := false } else {
        h.pushSum(hashers[lvl + 1]);
        h.reset();
        if (pending[lvl + 1]) { pending[lvl + 1] := false; lvl += 1 } else {
          pending[lvl + 1] := true;
          carrying := false;
        };
      };
    };
    i += 2;
  };
  root;
};

for (k in ([1, 2, 3, 6] : [Nat]).values()) {
  let count = 2 ** k;
  let leaves = Array.tabulate<Blob>(count, func(_) = Blob.fromArray(Array.tabulate<Nat8>(64, func(_) = rng.nat8())));
  assert (carryRoot512(leaves, k) == refRoot512(leaves));
};
