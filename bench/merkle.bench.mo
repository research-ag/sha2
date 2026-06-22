import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha256 "../src/Sha256";

module {
  // Iterative Merkle-mountain-range build. `hasher[0 .. i-1]` is a stack of
  // completed-subtree "peaks", `level[j]` is the level of `hasher[j]`, `i` the
  // stack height. Each leaf pair is pushed as a node, then while the new peak's
  // level matches the peak below it they merge in place. No recursion, no
  // free-list; hashers start closed.
  //
  // combineLeaves/combineNodes are each ONE SHA256 (SHA256(left ++ right)). With
  // `double = true` we fold after each, making every node double-SHA (Bitcoin);
  // with `double = false` we skip the folds, giving a plain single-SHA tree.
  func merkleRoot(leaves : [Blob], hasher : [Sha256.Digest], level : [var Nat], double : Bool) : Blob {
    let n = leaves.size();
    var i = 0;
    var p = 0;
    while (p < n) {
      hasher[i].combineLeaves(leaves[p], leaves[p + 1]);
      if (double) hasher[i].fold();
      level[i] := 1;
      while (i > 0 and level[i - 1] == level[i]) {
        hasher[i - 1].combineNodes(hasher[i]);
        if (double) hasher[i - 1].fold();
        level[i - 1] += 1;
        i -= 1;
      };
      i += 1;
      p += 2;
    };
    Sha256.readSum(hasher[0]);
  };

  public func init() : Bench.V1 {
    // Merkle root over 2^k 32-byte leaves with the same peak-stack harness and
    // log2(n) hashers, two ways: double-SHA (Bitcoin: combine + fold per node)
    // vs single-SHA (combine only). Isolates the cost of the per-node fold.
    let exps : [Nat] = [8, 10, 12];
    let rows = ["2^8 leaves", "2^10 leaves", "2^12 leaves"];
    let cols = [
      "double-SHA (Bitcoin)",
      "single-SHA",
    ];

    let schema : Bench.Schema = {
      name = "Sha256 Merkle";
      description = "Merkle root over 2^k 32-byte leaves built with an iterative Merkle-mountain-range peak stack (hasher[]/level[]/i), log2(n) hashers started closed, no recursion or free-list. combineLeaves and combineNodes each do one SHA256 (SHA256(left ++ right)). 'double-SHA (Bitcoin)' folds after every combine, so each node is SHA256(SHA256(...)) — the Bitcoin tx tree. 'single-SHA' skips the folds, so each node is a plain SHA256(left ++ right) (note: not RFC 6962, which prepends a domain-separation byte). Both allocation-free except the final root Blob.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x6d6b_6c65_6d6b_6c65);
    func b32() : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8()));

    let leavesByRow = Array.tabulate<[Blob]>(
      rows.size(),
      func(ri) = Array.tabulate<Blob>(2 ** exps[ri], func(_) = b32()),
    );
    // A pool of log2(n) hashers, started CLOSED, plus a per-slot level array.
    // Shared by both columns (each call leaves the pool closed and rewrites level).
    let hasherByRow = Array.tabulate<[Sha256.Digest]>(
      rows.size(),
      func(ri) = Array.tabulate<Sha256.Digest>(exps[ri], func(_) { let h = Sha256.new(); Sha256.close(h); h }),
    );
    let levelByRow = Array.tabulate<[var Nat]>(rows.size(), func(ri) = VarArray.repeat<Nat>(0, exps[ri]));

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      rows.size(),
      func(ri) {
        [
          func() = ignore merkleRoot(leavesByRow[ri], hasherByRow[ri], levelByRow[ri], true),
          func() = ignore merkleRoot(leavesByRow[ri], hasherByRow[ri], levelByRow[ri], false),
        ];
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
