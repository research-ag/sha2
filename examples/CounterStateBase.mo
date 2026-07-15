/// Shared MMR-building machinery for the counter examples over STATE leaves:
/// `MerkleCounterState.mo` (Example 3) and `BitcoinTxMerkle.mo` (Example 5).
/// The two examples import this base and differ only in how a leaf lands in
/// slot 0 (a `loadState` capture vs the Digest -> Hasher bridge), in the
/// `double` flag they pass, and in their finalization — bagging vs the
/// Bitcoin collapse — which lives in the example files.

import Hasher "mo:sha2/Hasher/Sha256";
import VarArray "mo:core/VarArray";
import Nat32 "mo:core/Nat32";

module {
  /// The MMR state: the height-indexed peak slots (slot 0 = the parked leaf,
  /// the top slot = the finalization accumulator) and the leaf count, whose
  /// bits are the occupancy flags. A static record — it can be declared
  /// `stable`.
  public type Mmr = {
    hasher : [var Hasher.Hasher];
    var count : Nat32;
  };

  /// Create an empty MMR with capacity for at least `maxLeaves` leaves.
  /// Allocates `ceil(log2 maxLeaves) + 1` hashers: one slot per bit of the
  /// count for the peaks (slot k holds the height-k peak that bit k asserts,
  /// slot 0 the parked leaf) plus the top slot as the finalization
  /// accumulator, one level above the highest possible peak.
  public func new(maxLeaves : Nat) : Mmr {
    var l = 0;
    var pow = 1;
    while (pow < maxLeaves) { pow *= 2; l += 1 }; // l = ceil(log2 maxLeaves)
    {
      hasher = VarArray.tabulate<Hasher.Hasher>(l + 1, func(_) { Hasher.new() });
      var count = 0;
    };
  };

  /// Combine the parked leaf in slot 0 with its partner `src` (read directly,
  /// no copy) and carry the node up; `double` selects double SHA256 per node.
  /// The height-1 node is built in place in slot 0, consuming the parked leaf
  /// exactly as bit 0 clears. Does NOT update the count — the caller does.
  /// Traps (on a slot index out of bounds) if the capacity chosen at `new` is
  /// exceeded.
  public func fuseAndCarry(self : Mmr, src : Hasher.Hasher, double : Bool) {
    let hasher = self.hasher;
    hasher[0].combineState(hasher[0], src);
    if (double) hasher[0].hashState(hasher[0]);
    // Carry: the rising node climbs the slots — the height-(k+1) node is
    // built in slot k by merging the peak there with the node from below.
    var k : Nat32 = 1;
    while (((self.count >> k) & 1) == 1) {
      let kk = Nat32.toNat(k);
      hasher[kk].combineState(hasher[kk], hasher[kk - 1]);
      if (double) hasher[kk].hashState(hasher[kk]);
      k += 1;
    };
    // The carry stopped at a clear bit: slot k is free, and the finished
    // height-k node sits one below it — swap it into its slot.
    let kk = Nat32.toNat(k);
    let tmp = hasher[kk];
    hasher[kk] := hasher[kk - 1];
    hasher[kk - 1] := tmp;
  };
};
