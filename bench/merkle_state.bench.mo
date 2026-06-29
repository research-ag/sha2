import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Hasher "../src/Hasher/Sha256";

module {
  // Same stack-vs-counter comparison as merkle.bench.mo, but the leaves are
  // STATES (each a 32-byte hash already sitting in a Hasher, as if just produced
  // by a Digest) rather than Blobs. This isolates the counter's only real cost:
  // parking each leaf. For Blob leaves that park is loadBlob32 (a byte
  // deserialize, ~3k instructions); for state leaves it is loadState (a 16-word
  // COPY), so the counter's disadvantage should largely vanish.

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

  // COUNTER: park each leaf with loadState (a cheap state copy), then carry-swap.
  func merkleRootCounter(leaves : [Hasher.Hasher], hasher : [var Hasher.Hasher], occupied : [var Bool], carryCell : [var Hasher.Hasher], double : Bool) : Blob {
    let n = leaves.size();
    var l = 0;
    var pow = 1;
    while (pow < n) { pow *= 2; l += 1 };
    var j = 0;
    while (j <= l) { occupied[j] := false; j += 1 };
    var carry = carryCell[0];
    for (leaf in leaves.values()) {
      carry.loadState(leaf); // park the leaf state (16-word copy, not a deserialize)
      var k = 0;
      while (occupied[k]) {
        carry.combineState(hasher[k], carry);
        if (double) carry.hashState(carry);
        occupied[k] := false;
        k += 1;
      };
      let tmp = hasher[k];
      hasher[k] := carry;
      carry := tmp;
      occupied[k] := true;
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
      description = "Like bench/merkle.bench.mo but over STATE leaves: each leaf is a 32-byte hash already in a Hasher (as if produced by a Digest), not a Blob. STACK combines each pair with combineState reading both leaf states directly; COUNTER parks each leaf with loadState (a 16-word copy) then carries up. Both allocation-free, both do n-1 combines. Because loadState is a cheap copy (unlike loadBlob32's byte deserialize on Blob leaves), the counter's parking overhead is small here — so the two algorithms run much closer than in the Blob-leaf benchmark, confirming that the counter's Blob-leaf penalty is the per-leaf deserialize, not the carry-and-swap bookkeeping.";
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
