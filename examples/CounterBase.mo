/// Shared MMR-building machinery for the counter examples over Blob leaves:
/// `MerkleCounter.mo` (Example 3) and `BitcoinMerkle.mo` (Example 5). The two
/// examples import this base and differ only in the `double` flag they pass
/// (single vs double SHA256 per node) and in their finalization — bagging vs
/// the Bitcoin collapse — which lives in the example files. See their headers
/// for the full story; the mechanics of the counter (occupancy = the bits of
/// the leaf count, the delayed slot-0 write, the rising carry) are described
/// in `MerkleCounter.mo`.
///
/// Optionally (the `witness` flag of `new`) the base captures the COINBASE
/// WITNESS SPINE — the first leaf's sibling at each level, each of which
/// exists only transiently during a carry — into a pre-sized `[var Blob]`,
/// slot k = level k. See `BitcoinWitness.mo` (Example 7) for the theory, the
/// extraction and the verification.

import Hasher "mo:sha2/Hasher/Sha256";
import Nat32 "mo:core/Nat32";
import VarArray "mo:core/VarArray";

module {
  /// The MMR state: the height-indexed peak slots, the leaf count (whose bits
  /// are the occupancy flags), the pending height-0 leaf and the optional
  /// witness spine (`wit[k]` = the first leaf's sibling at level k, written
  /// exactly when `count` reaches 2^(k+1); "" until then — and provably
  /// never read before its write). A static record — it can be declared
  /// `stable`.
  public type Mmr = {
    hasher : [var Hasher.Hasher];
    var count : Nat32;
    var pending : ?Blob;
    wit : ?[var Blob];
  };

  /// Create an empty MMR with capacity for at least `maxLeaves` leaves.
  /// Allocates `floor(log2 maxLeaves) + 1` hashers — the bit length of
  /// `maxLeaves`: one slot per bit of the count, slot k holding the height-k
  /// peak that bit k asserts. (Slot 0's write is delayed — the height-0 leaf
  /// waits as the pending `Blob` — leaving slot 0 free as the accumulator for
  /// the finalization.) With `witness` the coinbase witness spine is captured
  /// as leaves are added, into `floor(log2 maxLeaves)` pre-allocated Blob
  /// slots — one per level at which a capture can occur (2^(k+1) <=
  /// maxLeaves). Exceeding the capacity traps on the witness array just as
  /// it does on the hasher array.
  public func new(maxLeaves : Nat, witness : Bool) : Mmr {
    var l = 0;
    var pow = 1;
    while (pow * 2 <= maxLeaves) { pow *= 2; l += 1 }; // l = floor(log2 maxLeaves)
    {
      hasher = VarArray.tabulate<Hasher.Hasher>(l + 1, func(_) { Hasher.new() });
      var count = 0;
      var pending = null;
      wit = if (witness) ?VarArray.repeat<Blob>("", l) else null;
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
        // Witness hook 1 — first fuse ever (count == 1): the partner IS the
        // first leaf's sibling at level 0; keep it (a borrowed reference).
        switch (self.wit) {
          case (?w) { if ((self.count >> 1) == 0) w[0] := leaf };
          case (null) {};
        };
        // Fuse the pair straight from the two Blobs — no loadBlob32. The
        // height-1 node is built in slot 0, free since bit 0 just cleared.
        hasher[0].combineBlob32(leaf0, leaf);
        if (double) hasher[0].hashState(hasher[0]);
        // Carry: the rising node climbs the slots — the height-(k+1) node is
        // built in slot k by merging the peak there with the node from below.
        var k : Nat32 = 1;
        while (((self.count >> k) & 1) == 1) {
          let kk = k.toNat();
          // Witness hook 2 — first merge at height k (count == 2^(k+1) - 1):
          // the rising node below covers leaves [2^k, 2^(k+1)) — the first
          // leaf's sibling at level k. It is consumed by the merge on the
          // next line; this is the only moment it exists — copy it out.
          switch (self.wit) {
            case (?w) {
              if ((self.count >> (k + 1)) == 0) w[kk] := hasher[kk - 1].readSum();
            };
            case (null) {};
          };
          hasher[kk].combineState(hasher[kk], hasher[kk - 1]);
          if (double) hasher[kk].hashState(hasher[kk]);
          k += 1;
        };
        // The carry stopped at a clear bit: slot k is free, and the finished
        // height-k node sits one below it — swap it into its slot.
        let kk = k.toNat();
        let tmp = hasher[kk];
        hasher[kk] := hasher[kk - 1];
        hasher[kk - 1] := tmp;
      };
    };
    self.count += 1;
  };
};
