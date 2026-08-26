/// Shared Merkle build for the benches: the favored BINARY-COUNTER MMR with
/// the delay trick — verbatim the algorithm of examples/MerkleCounter.mo
/// (Blob leaves) and examples/MerkleCounterState.mo (State leaves), minus the
/// bagging finale: the benches use power-of-two counts, where the single peak
/// in the top slot IS the root. The pool is passed in so the benches can
/// reuse it across measurements, and the `double` flag selects single- vs
/// double-SHA nodes.

import Nat32 "mo:core/Nat32";
import Hasher "../src/Hasher/Sha256";

module {
  /// Counter build over 32-byte BLOB leaves — the full delay: one leaf waits
  /// as a pending ?Blob and each pair is fused with combineBlob32 straight
  /// from the input (no per-leaf loadBlob32); heights >= 1 carry as states.
  /// Power-of-two count. Leaves the root in `hasher[l]` and returns `l`
  /// (= log2 n); does NOT read it out.
  public func buildBlob(leaves : [Blob], hasher : [var Hasher.Hasher], carryCell : [var Hasher.Hasher], double : Bool) : Nat {
    let n = leaves.size();
    var l = 0;
    var pow = 1;
    while (pow < n) { pow *= 2; l += 1 };
    var count : Nat32 = 0; // bit 0 = "a leaf is pending", bit k>=1 = slot occupancy
    var carry = carryCell[0];
    var pending : ?Blob = null; // the height-0 peak, held as a Blob (not a slot)
    for (leaf in leaves.values()) {
      switch (pending) {
        case (null) { pending := ?leaf };
        case (?leaf0) {
          pending := null;
          carry.combineBlob32(leaf0, leaf); // fuse the two leaf Blobs (no loadBlob32)
          if (double) carry.hashState(carry);
          var k : Nat32 = 1; // height-1 node; carry up the state slots
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
      };
      count += 1;
    };
    carryCell[0] := carry;
    l;
  };

  /// `buildBlob` plus the root readout — the only allocation.
  public func merkleRootBlob(leaves : [Blob], hasher : [var Hasher.Hasher], carryCell : [var Hasher.Hasher], double : Bool) : Blob {
    let l = buildBlob(leaves, hasher, carryCell, double);
    Hasher.readSum(hasher[l]);
  };

  /// Counter build over STATE leaves (32-byte hashes already in Hashers) —
  /// the half-delay: when height 0 is empty the leaf is parked there with one
  /// loadState; when occupied the leaf is read directly by combineState —
  /// n/2 state copies total. Power-of-two count. Leaves the root in
  /// `hasher[l]` and returns `l`; does NOT read it out.
  public func buildState(leaves : [Hasher.Hasher], hasher : [var Hasher.Hasher], carryCell : [var Hasher.Hasher], double : Bool) : Nat {
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
    l;
  };

  /// `buildState` plus the root readout — the only allocation.
  public func merkleRootState(leaves : [Hasher.Hasher], hasher : [var Hasher.Hasher], carryCell : [var Hasher.Hasher], double : Bool) : Blob {
    let l = buildState(leaves, hasher, carryCell, double);
    Hasher.readSum(hasher[l]);
  };
};
