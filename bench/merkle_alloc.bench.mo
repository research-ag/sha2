import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Hasher "../src/Hasher/Sha256";

module {
  // Iterative Merkle-mountain-range build (see merkle.bench.mo). Leaves the
  // double-SHA root in hasher[0]; does NOT read it out.
  func build(leaves : [Blob], hasher : [Hasher.Hasher], level : [var Nat]) {
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
  };

  public func init() : Bench.V1 {
    // Is the Merkle build itself (the peak-stack loop, combineBlob32, combineState,
    // hashState) allocation-free? Run the SAME pool over R computations per
    // measurement and watch the garbage. 'build + readSum' produces one root
    // Blob per computation (so its garbage should scale with R); 'build only'
    // skips readSum, so if the loop allocates nothing its garbage must stay FLAT
    // as R grows from 1 to 100. A 2^8 tree is used (the allocation behavior is
    // size-independent — see merkle.bench.mo's constant garbage across sizes).
    let reps : [Nat] = [1, 10, 100];
    let rows = ["x1", "x10", "x100"];
    let cols = [
      "build + readSum",
      "build only (no readSum)",
    ];

    let schema : Bench.Schema = {
      name = "Sha256 Merkle allocation probe";
      description = "Run R = 1 / 10 / 100 double-SHA Merkle-tree builds (2^8 leaves) per measurement, all on the same reused pool of hashers. 'build + readSum' reads the root Blob out each time, so its garbage should grow ~linearly with R. 'build only (no readSum)' runs the full peak-stack loop — combineBlob32, combineState, hashState — but never calls readSum, so it allocates no Blob; if the loop itself allocates nothing, its garbage must stay flat as R grows. A flat 'build only' column is proof that the hasher stack and the loop cause no per-node / per-level / per-computation allocation.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0xa11_0c_a11_0c);
    let n = 256; // 2^8 leaves
    let levels = 8;
    let leaves = Array.tabulate<Blob>(n, func(_) = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8())));
    // One pool, reused across every cell and every repetition.
    let hasher = Array.tabulate<Hasher.Hasher>(levels, func(_) { Hasher.new() });
    let level = VarArray.repeat<Nat>(0, levels);

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      rows.size(),
      func(ri) {
        let r = reps[ri];
        [
          func() {
            var m = 0;
            while (m < r) {
              build(leaves, hasher, level);
              ignore Hasher.readSum(hasher[0]);
              m += 1;
            };
          },
          func() {
            var m = 0;
            while (m < r) { build(leaves, hasher, level); m += 1 };
          },
        ];
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
