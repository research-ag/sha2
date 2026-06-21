import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha256 "../src/Sha256";

module {
  // Recursive post-order DFS Merkle combine using writeSumPair. Module-level
  // (not a closure) so it captures no mutable state — the free-list lives in
  // `freeIx`/`top` (a 1-cell array), both pre-allocated. Returns the pool index
  // of the hasher holding this subtree's closed double-SHA digest.
  func evalDfs(leaves : [Blob], pool : [Sha256.Digest], freeIx : [var Nat], top : [var Nat], lo : Nat, hi : Nat) : Nat {
    if (hi - lo == 2) {
      top[0] -= 1;
      let i = freeIx[top[0]]; // alloc
      let h = pool[i];
      Sha256.reset(h);
      Sha256.writeBlobPair32(h, leaves[lo], leaves[lo + 1]);
      Sha256.close(h);
      Sha256.fold(h);
      i;
    } else {
      let mid = lo + (hi - lo) / 2;
      let l = evalDfs(leaves, pool, freeIx, top, lo, mid);
      let r = evalDfs(leaves, pool, freeIx, top, mid, hi);
      top[0] -= 1;
      let i = freeIx[top[0]]; // alloc a fresh target (distinct from l, r)
      let h = pool[i];
      Sha256.reset(h);
      Sha256.writeSumPair(h, pool[l], pool[r]);
      Sha256.close(h);
      Sha256.fold(h);
      freeIx[top[0]] := l; // free l
      top[0] += 1;
      freeIx[top[0]] := r; // free r
      top[0] += 1;
      i;
    };
  };

  public func init() : Bench.V1 {
    // Bitcoin-style double-SHA Merkle root over 2^k 32-byte leaves, two ways to
    // combine internal nodes without an intermediate Blob.
    let exps : [Nat] = [8, 10, 12];
    let rows = ["2^8 leaves", "2^10 leaves", "2^12 leaves"];
    let cols = [
      "writeSumPair DFS",
      "pushSum carry",
    ];

    let schema : Bench.Schema = {
      name = "Sha256 Merkle (double-SHA)";
      description = "Bitcoin-style double-SHA Merkle root over 2^k 32-byte leaves, combining internal nodes two ways (leaves fed with writeBlobPair32 in both). 'writeSumPair DFS' evaluates the tree post-order: each node combines its two finished children with writeSumPair (read straight from their state arrays), using a pool of log2(n)+1 hashers managed by a free-list. 'pushSum carry' is the streaming binary-counter carry: one hasher per level (log2(n)), each completed node pushSum'd into the parent's message buffer. Both are allocation-free except the root Blob and produce the identical root. The comparison isolates writeSumPair (reads two child states directly into one block) vs pushSum (writes one child's 16 words into the parent buffer, processed when the buffer fills).";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x6d6b_6c65_6d6b_6c65);
    func b32() : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8()));

    let leavesByRow = Array.tabulate<[Blob]>(
      rows.size(),
      func(ri) = Array.tabulate<Blob>(2 ** exps[ri], func(_) = b32()),
    );
    // DFS scratch: pool of levels+1 hashers + a free-list (indices + top cell).
    let dfsPoolByRow = Array.tabulate<[Sha256.Digest]>(
      rows.size(),
      func(ri) = Array.tabulate<Sha256.Digest>(exps[ri] + 1, func(_) = Sha256.new()),
    );
    let dfsFreeByRow = Array.tabulate<[var Nat]>(
      rows.size(),
      func(ri) = VarArray.tabulate<Nat>(exps[ri] + 1, func(i) = i),
    );
    let dfsTopByRow = Array.tabulate<[var Nat]>(rows.size(), func(ri) = [var exps[ri] + 1]);
    // carry scratch: one hasher per level + a pending flag per level.
    let carryHashersByRow = Array.tabulate<[Sha256.Digest]>(
      rows.size(),
      func(ri) = Array.tabulate<Sha256.Digest>(exps[ri], func(_) = Sha256.new()),
    );
    let carryPendingByRow = Array.tabulate<[var Bool]>(
      rows.size(),
      func(ri) = VarArray.repeat<Bool>(false, exps[ri]),
    );

    func dfsRoot(ri : Nat) : Blob {
      let pool = dfsPoolByRow[ri];
      let freeIx = dfsFreeByRow[ri];
      let top = dfsTopByRow[ri];
      let leaves = leavesByRow[ri];
      var j = 0;
      while (j < pool.size()) { freeIx[j] := j; j += 1 }; // (re)init the free-list
      top[0] := pool.size();
      Sha256.readSum(pool[evalDfs(leaves, pool, freeIx, top, 0, leaves.size())]);
    };

    func carryRoot(ri : Nat) : Blob {
      let hashers = carryHashersByRow[ri];
      let pending = carryPendingByRow[ri];
      let leaves = leavesByRow[ri];
      let levels = exps[ri];
      var p = 0;
      while (p < levels) { pending[p] := false; p += 1 };
      var root : Blob = leaves[0];
      let n = leaves.size();
      var i = 0;
      while (i < n) {
        Sha256.writeBlobPair32(hashers[0], leaves[i], leaves[i + 1]);
        var lvl = 0;
        var carrying = true;
        while (carrying) {
          let h = hashers[lvl];
          Sha256.close(h);
          Sha256.fold(h);
          if (lvl + 1 == levels) {
            root := Sha256.readSum(h);
            Sha256.reset(h);
            carrying := false;
          } else {
            h.pushSum(hashers[lvl + 1]);
            Sha256.reset(h);
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

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      rows.size(),
      func(ri) {
        [
          func() = ignore dfsRoot(ri),
          func() = ignore carryRoot(ri),
        ];
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
