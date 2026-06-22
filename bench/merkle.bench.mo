import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha256 "../src/Sha256";

module {
  // --- Recursive DFS: post-order, hashers tracked by a free-list ---
  // Module-level (not a closure) so the traversal allocates nothing; the
  // free-list lives in `freeIx`/`top`. Returns the pool index of the hasher
  // holding this subtree's closed double-SHA digest.
  func evalDfs(leaves : [Blob], pool : [Sha256.Digest], freeIx : [var Nat], top : [var Nat], lo : Nat, hi : Nat) : Nat {
    if (hi - lo == 2) {
      top[0] -= 1;
      let i = freeIx[top[0]];
      let h = pool[i];
      h.merkleLeaves(leaves[lo], leaves[lo + 1]);
      h.fold();
      i;
    } else {
      let mid = lo + (hi - lo) / 2;
      let l = evalDfs(leaves, pool, freeIx, top, lo, mid);
      let r = evalDfs(leaves, pool, freeIx, top, mid, hi);
      pool[l].merkleMerge(pool[r]);
      freeIx[top[0]] := r;
      top[0] += 1;
      l;
    };
  };

  // --- Iterative: a Merkle-mountain-range peak stack ---
  // `hasher[0 .. i-1]` are the live peaks (left-to-right), `level[j]` is the
  // level of `hasher[j]`, and `i` is the stack height. Each new leaf node is
  // pushed, then while it matches the level of the peak below, they merge in
  // place (merkleMerge writes into the left peak). No recursion, no free-list.
  func iterRoot(leaves : [Blob], hasher : [Sha256.Digest], level : [var Nat]) : Blob {
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

  public func init() : Bench.V1 {
    // Bitcoin-style double-SHA Merkle root over 2^k 32-byte leaves, built two
    // ways with the same merkleLeaves/merkleMerge primitives and log2(n)
    // hashers: a recursive post-order DFS (free-list) vs a non-recursive peak
    // stack (hasher[]/level[]/i). Both allocation-free except the root Blob.
    let exps : [Nat] = [8, 10, 12];
    let rows = ["2^8 leaves", "2^10 leaves", "2^12 leaves"];
    let cols = [
      "DFS (recursive)",
      "iter (stack)",
    ];

    let schema : Bench.Schema = {
      name = "Sha256 Merkle (double-SHA)";
      description = "Bitcoin-style double-SHA Merkle root over 2^k 32-byte leaves, leaf pairs combined with merkleLeaves + fold and internal nodes in place with merkleMerge, in a pool of log2(n) hashers started closed. 'DFS (recursive)' evaluates post-order and tracks free hashers with a free-list (freeIx + top). 'iter (stack)' is the equivalent Merkle-mountain-range loop: push each leaf node onto a peak stack (hasher[]/level[]/i) and merge in place while the new peak matches the level of the one below it — no recursion, no free-list. Both produce the identical root and are allocation-free except the root Blob.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x6d6b_6c65_6d6b_6c65);
    func b32() : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8()));

    let leavesByRow = Array.tabulate<[Blob]>(
      rows.size(),
      func(ri) = Array.tabulate<Blob>(2 ** exps[ri], func(_) = b32()),
    );

    // Recursive DFS scratch: pool + free-list.
    let poolByRow = Array.tabulate<[Sha256.Digest]>(
      rows.size(),
      func(ri) = Array.tabulate<Sha256.Digest>(exps[ri], func(_) { let h = Sha256.new(); Sha256.close(h); h }),
    );
    let freeByRow = Array.tabulate<[var Nat]>(rows.size(), func(ri) = VarArray.tabulate<Nat>(exps[ri], func(i) = i));
    let topByRow = Array.tabulate<[var Nat]>(rows.size(), func(ri) = [var exps[ri]]);

    // Iterative scratch: a hasher pool + a level array (no free-list, no top).
    let hasherByRow = Array.tabulate<[Sha256.Digest]>(
      rows.size(),
      func(ri) = Array.tabulate<Sha256.Digest>(exps[ri], func(_) { let h = Sha256.new(); Sha256.close(h); h }),
    );
    let levelByRow = Array.tabulate<[var Nat]>(rows.size(), func(ri) = VarArray.repeat<Nat>(0, exps[ri]));

    func dfsRoot(ri : Nat) : Blob {
      let pool = poolByRow[ri];
      let freeIx = freeByRow[ri];
      let top = topByRow[ri];
      let leaves = leavesByRow[ri];
      var j = 0;
      while (j < pool.size()) { freeIx[j] := j; j += 1 }; // (re)init the free-list
      top[0] := pool.size();
      Sha256.readSum(pool[evalDfs(leaves, pool, freeIx, top, 0, leaves.size())]);
    };

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      rows.size(),
      func(ri) {
        [
          func() = ignore dfsRoot(ri),
          func() = ignore iterRoot(leavesByRow[ri], hasherByRow[ri], levelByRow[ri]),
        ];
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
