/// Shared MMR-building machinery for the counter examples over Blob leaves:
/// `MerkleCounter.mo` (Example 2) and `BitcoinMerkle.mo` (Example 4). The two
/// examples import this base and differ only in the `double` flag they pass
/// (single vs double SHA256 per node) and in their finalization — bagging vs
/// the Bitcoin collapse — which lives in the example files. See their headers
/// for the full story; the mechanics of the counter (occupancy = the bits of
/// the leaf count, the delayed slot-0 write, the rising carry) are described
/// in `MerkleCounter.mo`.

import Hasher "mo:sha2/Hasher/Sha256";
import VarArray "mo:core/VarArray";
import Nat32 "mo:core/Nat32";

module {
  /// The MMR state: the height-indexed peak slots, the leaf count (whose bits
  /// are the occupancy flags) and the pending height-0 leaf. A static record —
  /// it can be declared `stable`.
  public type Mmr = {
    hasher : [var Hasher.Hasher];
    var count : Nat32;
    var pending : ?Blob;
  };

  /// Create an empty MMR with capacity for at least `maxLeaves` leaves.
  /// Allocates `floor(log2 maxLeaves) + 1` hashers — the bit length of
  /// `maxLeaves`: one slot per bit of the count, slot k holding the height-k
  /// peak that bit k asserts. (Slot 0's write is delayed — the height-0 leaf
  /// waits as the pending `Blob` — leaving slot 0 free as the accumulator for
  /// the finalization.)
  public func new(maxLeaves : Nat) : Mmr {
    var l = 0;
    var pow = 1;
    while (pow * 2 <= maxLeaves) { pow *= 2; l += 1 };
    {
      hasher = VarArray.tabulate<Hasher.Hasher>(l + 1, func(_) { Hasher.new() });
      var count = 0;
      var pending = null;
    };
  };

  /// Add one 32-byte leaf to the MMR; `double` selects double SHA256 per
  /// node. Traps (on a slot index out of bounds) if the capacity chosen at
  /// `new` is exceeded.
  public func add(self : Mmr, leaf : Blob, double : Bool) {
    let hasher = self.hasher;
    switch (self.pending) {
      case (null) { self.pending := ?leaf }; // hold this leaf; pair it with the next
      case (?leaf0) {
        self.pending := null;
        // Fuse the pair straight from the two Blobs — no loadBlob32. The
        // height-1 node is built in slot 0, free since bit 0 just cleared.
        hasher[0].combineBlob32(leaf0, leaf);
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
    self.count += 1;
  };
};
