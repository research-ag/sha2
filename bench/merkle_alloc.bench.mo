import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Hasher "../src/Hasher/Sha256";
import MerkleBuild "counterBuild";

module {
  public func init() : Bench.V1 {
    // Is the Merkle build itself (the binary-counter loop with the delay
    // trick — combineBlob32, combineState, the pending ?Blob, the swaps)
    // allocation-free? Run the SAME pool over R computations per measurement
    // and watch the garbage. 'build + readSum' produces one root Blob per
    // computation (so its garbage should scale with R); 'build only' skips
    // readSum, so if the loop allocates nothing its garbage must stay FLAT as
    // R grows from 1 to 100. The build code is shared with merkle.bench.mo
    // (bench/counterBuild.mo) and mirrors examples/MerkleCounter.mo.
    let reps : [Nat] = [1, 10, 100];
    let rows = ["x1", "x10", "x100"];
    let cols = [
      "build + readSum",
      "build only (no readSum)",
    ];

    let schema : Bench.Schema = {
      name = "Sha256 Merkle allocation probe";
      description = "Allocation-freeness proof for the binary-counter Merkle build: R = 1/10/100 builds per measurement on one reused pool — the 'build only' garbage column must stay flat as R grows.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0xa11_0c_a11_0c);
    let n = 256; // 2^8 leaves
    let levels = 8;
    let leaves = Array.tabulate<Blob>(n, func(_) = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8())));
    // One pool, reused across every cell and every repetition.
    let hasher = VarArray.tabulate<Hasher.Hasher>(levels + 1, func(_) { Hasher.new() });
    let carryCell = VarArray.tabulate<Hasher.Hasher>(1, func(_) { Hasher.new() });

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      rows.size(),
      func(ri) {
        let r = reps[ri];
        [
          func() {
            var m = 0;
            while (m < r) {
              ignore MerkleBuild.merkleRootBlob(leaves, hasher, carryCell, false);
              m += 1;
            };
          },
          func() {
            var m = 0;
            while (m < r) {
              ignore MerkleBuild.buildBlob(leaves, hasher, carryCell, false);
              m += 1;
            };
          },
        ];
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
