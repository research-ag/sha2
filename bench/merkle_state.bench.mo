import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Nat32 "mo:core/Nat32";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Hasher "../src/Hasher/Sha256";

module {
  // Same stack-vs-counter comparison as merkle.bench.mo, but the leaves are
  // STATES (each a 32-byte hash already sitting in a Hasher, as if just produced
  // by a Digest) rather than Blobs. The counter copies only EVERY OTHER leaf:
  // when the height-0 slot is empty it parks the incoming leaf with one
  // loadState; when it is occupied the leaf is fed straight into the combine
  // from the input, no copy. So n/2 loadState copies total instead of n.

  // STACK: a pair is combineState over the two leaf states directly (no park).
  func merkleRootStack(leaves : [Hasher.Hasher], hasher : [Hasher.Hasher], level : [var Nat], double : Bool) : Blob {
    let n = leaves.size();
    var i = 0;
    var p = 0;
    while (p < n) {
      hasher[i].combineState(leaves[p], leaves[p + 1]);
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

  // COUNTER: copy only every OTHER leaf. Occupancy is bit k of the leaf count.
  // When bit 0 is clear (height-0 empty) the leaf is parked with one loadState;
  // when bit 0 is set the leaf goes straight into the combine from the input.
  func merkleRootCounter(leaves : [Hasher.Hasher], hasher : [var Hasher.Hasher], carryCell : [var Hasher.Hasher], double : Bool) : Blob {
    let n = leaves.size();
    var l = 0;
    var pow = 1;
    while (pow < n) { pow *= 2; l += 1 };
    var count : Nat32 = 0;
    var carry = carryCell[0];
    for (leaf in leaves.values()) {
      if ((count & 1) == 0) {
        // height-0 empty: park this leaf there (the only copy)
        hasher[0].loadState(leaf);
      } else {
        // height-0 occupied: combine the leaf directly from the input (no copy)
        carry.combineState(hasher[0], leaf);
        if (double) carry.hashState(carry);
        var k : Nat32 = 1;
        while (((count >> k) & 1) == 1) {
          carry.combineState(hasher[Nat32.toNat(k)], carry);
          if (double) carry.hashState(carry);
          k += 1;
        };
        let kk = Nat32.toNat(k);
        let tmp = hasher[kk];
        hasher[kk] := carry;
        carry := tmp;
      };
      count += 1;
    };
    carryCell[0] := carry;
    Hasher.readSum(hasher[l]);
  };

  public func init() : Bench.V1 {
    let exps : [Nat] = [8, 10, 12];
    let rows = ["2^8 leaves", "2^10 leaves", "2^12 leaves"];
    let cols = [
      "stack 2-SHA",
      "counter 2-SHA",
      "stack 1-SHA",
      "counter 1-SHA",
    ];

    let schema : Bench.Schema = {
      name = "Sha256 Merkle: stack vs counter (STATE leaves)";
      description = "Like bench/merkle.bench.mo but over STATE leaves: each leaf is a 32-byte hash already in a Hasher (as if produced by a Digest), not a Blob. STACK combines each pair with combineState reading both leaf states directly. COUNTER now copies only EVERY OTHER leaf: when the height-0 slot is empty it parks the leaf with one loadState; when occupied it feeds the leaf straight into combineState from the input (no copy) and carries up. So it does n/2 loadState copies, not n. Both allocation-free, both do n-1 combines. With the per-leaf copy roughly halved, the counter should track the stack closely — the residual gap being the ~n/2 state copies plus the carry-and-swap bookkeeping.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x57a7e_1eaf5);
    // Leaf STATES: pre-hash random 32-byte blobs into Hashers, read-only inputs
    // reused across measurements (neither algorithm mutates a leaf).
    func leafState() : Hasher.Hasher {
      let h = Hasher.new();
      h.hashBlob32(Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8())));
      h;
    };
    let leavesByRow = Array.tabulate<[Hasher.Hasher]>(
      rows.size(),
      func(ri) = Array.tabulate<Hasher.Hasher>(2 ** exps[ri], func(_) = leafState()),
    );

    let stackHasherByRow = Array.tabulate<[Hasher.Hasher]>(
      rows.size(),
      func(ri) = Array.tabulate<Hasher.Hasher>(exps[ri], func(_) { Hasher.new() }),
    );
    let stackLevelByRow = Array.tabulate<[var Nat]>(rows.size(), func(ri) = VarArray.repeat<Nat>(0, exps[ri]));

    let counterHasherByRow = Array.tabulate<[var Hasher.Hasher]>(
      rows.size(),
      func(ri) = VarArray.tabulate<Hasher.Hasher>(exps[ri] + 1, func(_) { Hasher.new() }),
    );
    let counterCarryByRow = Array.tabulate<[var Hasher.Hasher]>(rows.size(), func(ri) = VarArray.tabulate<Hasher.Hasher>(1, func(_) { Hasher.new() }));

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      rows.size(),
      func(ri) {
        [
          func() = ignore merkleRootStack(leavesByRow[ri], stackHasherByRow[ri], stackLevelByRow[ri], true),
          func() = ignore merkleRootCounter(leavesByRow[ri], counterHasherByRow[ri], counterCarryByRow[ri], true),
          func() = ignore merkleRootStack(leavesByRow[ri], stackHasherByRow[ri], stackLevelByRow[ri], false),
          func() = ignore merkleRootCounter(leavesByRow[ri], counterHasherByRow[ri], counterCarryByRow[ri], false),
        ];
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
