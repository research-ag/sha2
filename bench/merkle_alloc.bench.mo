import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha256 "../src/Sha256";

module {
  // The merkleLeaves/merkleMerge DFS (see merkle.bench.mo).
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

  public func init() : Bench.V1 {
    // Is the DFS itself (recursion + free-list + merkleLeaves/merkleMerge)
    // allocation-free? Run the SAME pool over R Merkle-tree computations per
    // measurement and watch the garbage. 'compute + readSum' produces one root
    // Blob per computation (so its garbage should scale with R); 'compute only'
    // skips readSum, so if the traversal allocates nothing its garbage must stay
    // FLAT as R grows from 1 to 100. A 2^8 tree is used (the allocation behavior
    // is size-independent — see merkle.bench.mo's constant garbage across sizes).
    let reps : [Nat] = [1, 10, 100];
    let rows = ["x1", "x10", "x100"];
    let cols = [
      "compute + readSum",
      "compute only (no readSum)",
    ];

    let schema : Bench.Schema = {
      name = "Sha256 Merkle allocation probe";
      description = "Run R = 1 / 10 / 100 double-SHA Merkle-tree computations (2^8 leaves) per measurement, all on the same reused pool of hashers. 'compute + readSum' reads the root Blob out each time, so its garbage should grow ~linearly with R. 'compute only (no readSum)' runs the full DFS — recursion, free-list, merkleLeaves, merkleMerge, fold — but never calls readSum, so it allocates no Blob; if the traversal itself allocates nothing, its garbage must stay flat as R grows. A flat 'compute only' column is proof that the hasher stack and recursion cause no per-node / per-level / per-computation allocation.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0xa11_0c_a11_0c);
    let n = 256; // 2^8 leaves
    let levels = 8;
    let leaves = Array.tabulate<Blob>(n, func(_) = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8())));
    // One pool, reused across every cell and every repetition.
    let pool = Array.tabulate<Sha256.Digest>(levels, func(_) { let h = Sha256.new(); Sha256.close(h); h });
    let freeIx = VarArray.tabulate<Nat>(levels, func(i) = i);
    let top = [var levels];

    func reinit() {
      var j = 0;
      while (j < levels) { freeIx[j] := j; j += 1 };
      top[0] := levels;
    };
    func computeRoot() : Blob {
      reinit();
      Sha256.readSum(pool[evalDfs(leaves, pool, freeIx, top, 0, n)]);
    };
    func computeTree() {
      reinit();
      ignore evalDfs(leaves, pool, freeIx, top, 0, n);
    };

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      rows.size(),
      func(ri) {
        let r = reps[ri];
        [
          func() { var m = 0; while (m < r) { ignore computeRoot(); m += 1 } },
          func() { var m = 0; while (m < r) { computeTree(); m += 1 } },
        ];
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
