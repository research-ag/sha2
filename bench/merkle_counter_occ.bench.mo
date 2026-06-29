import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Nat32 "mo:core/Nat32";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Hasher "../src/Hasher/Sha256";

module {
  // Binary-counter MMR (naive loadBlob32 per leaf; see examples/MerkleCounter.mo),
  // isolating ONE variable: how slot occupancy is tracked.

  // (a) An explicit Bool occupied[] array, updated as the carry frees/fills slots.
  func counterOcc(leaves : [Blob], hasher : [var Hasher.Hasher], occupied : [var Bool], carryCell : [var Hasher.Hasher], double : Bool) : Blob {
    let n = leaves.size();
    var l = 0;
    var pow = 1;
    while (pow < n) { pow *= 2; l += 1 };
    var j = 0;
    while (j <= l) { occupied[j] := false; j += 1 };
    var carry = carryCell[0];
    for (leaf in leaves.values()) {
      carry.loadBlob32(leaf);
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

  // (b) No occupied[] array: occupancy is bit k of the running leaf count, tested
  // on the fly. `count += 1` updates all the bits, so no slot flags to maintain.
  func counterBits(leaves : [Blob], hasher : [var Hasher.Hasher], carryCell : [var Hasher.Hasher], double : Bool) : Blob {
    let n = leaves.size();
    var l = 0;
    var pow = 1;
    while (pow < n) { pow *= 2; l += 1 };
    var count : Nat32 = 0;
    var carry = carryCell[0];
    for (leaf in leaves.values()) {
      carry.loadBlob32(leaf);
      var k : Nat32 = 0;
      while (((count >> k) & 1) == 1) {
        carry.combineState(hasher[Nat32.toNat(k)], carry);
        if (double) carry.hashState(carry);
        k += 1;
      };
      let kk = Nat32.toNat(k);
      let tmp = hasher[kk];
      hasher[kk] := carry;
      carry := tmp;
      count += 1;
    };
    carryCell[0] := carry;
    Hasher.readSum(hasher[l]);
  };

  public func init() : Bench.V1 {
    // Counter MMR over 2^k 32-byte leaves: occupancy tracked by an explicit
    // Bool occupied[] array vs computed on the fly from the bits of the leaf
    // count (count += 1 maintains them for free). Both run the same loadBlob32 +
    // carry-and-swap, so the only difference is the occupancy mechanism: one
    // array read/write per probe vs a shift-and-test on a Nat32 count.
    let exps : [Nat] = [8, 10, 12];
    let rows = ["2^8 leaves", "2^10 leaves", "2^12 leaves"];
    let cols = [
      "occupied[] 2-SHA",
      "from n 2-SHA",
      "occupied[] 1-SHA",
      "from n 1-SHA",
    ];

    let schema : Bench.Schema = {
      name = "Sha256 Merkle counter: occupied[] vs count bits";
      description = "Binary-counter MMR (naive: loadBlob32 every leaf, carry-and-swap) over 2^k 32-byte leaves, comparing two ways to know whether height slot k currently holds a peak. 'occupied[]' keeps an explicit Bool array, cleared/set as the carry frees and fills slots. 'from n' keeps no flags: occupancy is bit k of the running leaf count (a Nat32), tested with (count >> k) & 1, and `count += 1` updates every bit for free — so the carry loop neither reads nor writes a flag array. Both do identical hashing (same loadBlob32 + combineState + swaps); the only difference is array reads/writes vs Nat32 shift-and-test, plus a couple of Nat32<->Nat index conversions in the 'from n' version. Allocation-free.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x0ccc_0ccc_0ccc_0ccc);
    func b32() : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8()));
    let leavesByRow = Array.tabulate<[Blob]>(
      rows.size(),
      func(ri) = Array.tabulate<Blob>(2 ** exps[ri], func(_) = b32()),
    );

    // One counter pool (l+1 height slots + a spare carry), shared by both columns
    // since each call is self-contained. occupied[] is used only by column (a).
    let hasherByRow = Array.tabulate<[var Hasher.Hasher]>(
      rows.size(),
      func(ri) = VarArray.tabulate<Hasher.Hasher>(exps[ri] + 1, func(_) { Hasher.new() }),
    );
    let occByRow = Array.tabulate<[var Bool]>(rows.size(), func(ri) = VarArray.repeat<Bool>(false, exps[ri] + 1));
    let carryByRow = Array.tabulate<[var Hasher.Hasher]>(rows.size(), func(ri) = VarArray.tabulate<Hasher.Hasher>(1, func(_) { Hasher.new() }));

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      rows.size(),
      func(ri) {
        [
          func() = ignore counterOcc(leavesByRow[ri], hasherByRow[ri], occByRow[ri], carryByRow[ri], true),
          func() = ignore counterBits(leavesByRow[ri], hasherByRow[ri], carryByRow[ri], true),
          func() = ignore counterOcc(leavesByRow[ri], hasherByRow[ri], occByRow[ri], carryByRow[ri], false),
          func() = ignore counterBits(leavesByRow[ri], hasherByRow[ri], carryByRow[ri], false),
        ];
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
