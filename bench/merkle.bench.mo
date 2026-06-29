import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Hasher "../src/Hasher/Sha256";

module {
  // STACK peak-MMR (see examples/Merkle.mo). `hasher[0 .. i-1]` is a stack of
  // completed-subtree "peaks", `level[j]` is the level of `hasher[j]`, `i` the
  // stack height. Each leaf PAIR is combined (combineBlob32) into the free top
  // slot, then merged down while the new peak's level matches the one below it.
  func merkleRootStack(leaves : [Blob], hasher : [Hasher.Hasher], level : [var Nat], double : Bool) : Blob {
    let n = leaves.size();
    var i = 0;
    var p = 0;
    while (p < n) {
      hasher[i].combineBlob32(leaves[p], leaves[p + 1]);
      if (double) hasher[i].hashState(hasher[i]);
      level[i] := 1;
      while (i > 0 and level[i - 1] == level[i]) {
        hasher[i - 1].combineState(hasher[i - 1], hasher[i]);
        if (double) hasher[i - 1].hashState(hasher[i - 1]);
        level[i - 1] += 1;
        i -= 1;
      };
      i += 1;
      p += 2;
    };
    Hasher.readSum(hasher[0]);
  };

  // BINARY-COUNTER MMR (see examples/MerkleCounter.mo). Height-indexed slots:
  // `hasher[k]` is the height-k peak, `occupied[k]` whether it holds one. Each
  // single LEAF is parked (loadBlob32) into a scratch `carry` and carried up the
  // occupied slots (combineState), then dropped into the free slot with an O(1)
  // reference swap. No level[] array. Power-of-two leaf counts.
  func merkleRootCounter(leaves : [Blob], hasher : [var Hasher.Hasher], occupied : [var Bool], carryCell : [var Hasher.Hasher], double : Bool) : Blob {
    let n = leaves.size();
    var l = 0;
    var pow = 1;
    while (pow < n) { pow *= 2; l += 1 };
    var j = 0;
    while (j <= l) { occupied[j] := false; j += 1 };
    var carry = carryCell[0]; // a spare hasher, never aliased with a slot
    for (leaf in leaves.values()) {
      carry.loadBlob32(leaf); // park the leaf hash as a height-0 peak (no re-hash)
      var k = 0;
      while (occupied[k]) {
        carry.combineState(hasher[k], carry); // SHA256(hasher[k] ++ carry)
        if (double) carry.hashState(carry);
        occupied[k] := false;
        k += 1;
      };
      let tmp = hasher[k]; // swap the risen peak into the free slot (O(1))
      hasher[k] := carry;
      carry := tmp;
      occupied[k] := true;
    };
    carryCell[0] := carry; // persist the orphan for the next reuse (no aliasing)
    Hasher.readSum(hasher[l]);
  };

  public func init() : Bench.V1 {
    // Same Bitcoin / single-SHA Merkle root over 2^k 32-byte leaves, built two
    // ways: the STACK peak-MMR (combineBlob32 per pair + level[] bookkeeping)
    // vs the BINARY-COUNTER MMR (loadBlob32 per leaf + carry-and-swap, occupancy
    // = the bits of the leaf count, no level[] array). Both allocation-free.
    let exps : [Nat] = [8, 10, 12];
    let rows = ["2^8 leaves", "2^10 leaves", "2^12 leaves"];
    let cols = [
      "stack 2-SHA",
      "counter 2-SHA",
      "stack 1-SHA",
      "counter 1-SHA",
    ];

    let schema : Bench.Schema = {
      name = "Sha256 Merkle: stack vs counter";
      description = "Merkle root over 2^k 32-byte leaves, two algorithms x two hash modes. STACK is the peak-mountain-range with a parallel level[] array (examples/Merkle.mo): each leaf PAIR is one combineBlob32 into the free top slot, then merge-down. COUNTER is the binary-counter MMR (examples/MerkleCounter.mo): a height-indexed [var Hasher] whose occupied slots are the bits of the leaf count (no level[] array), each single LEAF parked with loadBlob32 and carried up via combineState, risen peaks moved with O(1) reference swaps through one scratch carry hasher. '2-SHA' double-hashes every node (Bitcoin: combine + hashState); '1-SHA' skips the fold. Both do the same number of compressions (n-1 combines), but the counter additionally deserializes EVERY leaf Blob into a state (loadBlob32) before combining it, whereas the stack's pairwise combineBlob32 reads the two leaf Blobs straight into the compression — so the counter runs moderately more instructions (the gap is largest in 1-SHA, where the fold doesn't dilute the per-leaf parking). That parking cost is specific to precomputed Blob leaves; leaves arriving as a Digest state (combined directly) would not pay it. Both are allocation-free except the final root Blob.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x6d6b_6c65_6d6b_6c65);
    func b32() : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8()));

    let leavesByRow = Array.tabulate<[Blob]>(
      rows.size(),
      func(ri) = Array.tabulate<Blob>(2 ** exps[ri], func(_) = b32()),
    );

    // Stack pool: log2(n) hashers + a per-slot level array. Reused across both
    // stack columns (each call overwrites the pool and rewrites level).
    let stackHasherByRow = Array.tabulate<[Hasher.Hasher]>(
      rows.size(),
      func(ri) = Array.tabulate<Hasher.Hasher>(exps[ri], func(_) { Hasher.new() }),
    );
    let stackLevelByRow = Array.tabulate<[var Nat]>(rows.size(), func(ri) = VarArray.repeat<Nat>(0, exps[ri]));

    // Counter pool: log2(n)+1 height slots, an occupied[] flag array, and one
    // spare carry hasher. Reused across both counter columns.
    let counterHasherByRow = Array.tabulate<[var Hasher.Hasher]>(
      rows.size(),
      func(ri) = VarArray.tabulate<Hasher.Hasher>(exps[ri] + 1, func(_) { Hasher.new() }),
    );
    let counterOccByRow = Array.tabulate<[var Bool]>(rows.size(), func(ri) = VarArray.repeat<Bool>(false, exps[ri] + 1));
    let counterCarryByRow = Array.tabulate<[var Hasher.Hasher]>(rows.size(), func(ri) = VarArray.tabulate<Hasher.Hasher>(1, func(_) { Hasher.new() }));

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      rows.size(),
      func(ri) {
        [
          func() = ignore merkleRootStack(leavesByRow[ri], stackHasherByRow[ri], stackLevelByRow[ri], true),
          func() = ignore merkleRootCounter(leavesByRow[ri], counterHasherByRow[ri], counterOccByRow[ri], counterCarryByRow[ri], true),
          func() = ignore merkleRootStack(leavesByRow[ri], stackHasherByRow[ri], stackLevelByRow[ri], false),
          func() = ignore merkleRootCounter(leavesByRow[ri], counterHasherByRow[ri], counterOccByRow[ri], counterCarryByRow[ri], false),
        ];
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
