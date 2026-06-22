import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Blob "mo:core/Blob";
import Random "mo:core/Random";
import Sha256 "../src/Sha256";
import Sha512 "../src/Sha512";

// Validate that the allocation-free Merkle trees (Sha256 double-sha via the
// merkleLeaves/merkleMerge DFS; Sha512 single-sha via the pushSum carry)
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

// Post-order DFS over a pool of `levels` pre-closed hashers: leaves combined
// with merkleLeaves, internal nodes with merkleMerge (in place), the right
// child freed back to a free-list after each merge.
func evalDfs256(leaves : [Blob], pool : [Sha256.Digest], freeIx : [var Nat], top : [var Nat], lo : Nat, hi : Nat) : Nat {
  if (hi - lo == 2) {
    top[0] -= 1;
    let i = freeIx[top[0]];
    let h = pool[i];
    h.merkleLeaves(leaves[lo], leaves[lo + 1]);
    h.fold();
    i;
  } else {
    let mid = lo + (hi - lo) / 2;
    let l = evalDfs256(leaves, pool, freeIx, top, lo, mid);
    let r = evalDfs256(leaves, pool, freeIx, top, mid, hi);
    pool[l].merkleMerge(pool[r]);
    freeIx[top[0]] := r;
    top[0] += 1;
    l;
  };
};

func dfsRoot256(leaves : [Blob], levels : Nat) : Blob {
  let pool = Array.tabulate<Sha256.Digest>(levels, func(_) { let h = Sha256.new(); h.close(); h });
  let freeIx = VarArray.tabulate<Nat>(levels, func(i) = i);
  let top = [var levels];
  Sha256.readSum(pool[evalDfs256(leaves, pool, freeIx, top, 0, leaves.size())]);
};

for (k in ([1, 2, 3, 6] : [Nat]).values()) {
  let count = 2 ** k;
  let leaves = Array.tabulate<Blob>(count, func(_) = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8())));
  assert (dfsRoot256(leaves, k) == refRoot256(leaves));
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
