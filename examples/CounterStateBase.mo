/// Shared MMR-building machinery for the counter examples over MESSAGE
/// leaves read from a `Digest`'s state: `MerkleCounterState.mo` (Example 4)
/// and `BitcoinTxMerkle.mo` (Example 6). The two examples import this base —
/// including the one embedded `Digest` that absorbs the messages — and
/// differ only in the `double` flag they pass, which selects single SHA256
/// vs Bitcoin's double SHA256 for the leaf and each node (and thereby how a
/// leaf exits the digest: the free `hashState` bridge vs a `loadState`
/// capture), and in their finalization — bagging vs the Bitcoin collapse —
/// which lives in the example files.
///
/// Optionally (the `witness` flag of `new`) the base captures the COINBASE
/// WITNESS SPINE — the first leaf's sibling at each level, each of which
/// exists only transiently during a carry — into a pre-sized `[var Blob]`,
/// slot k = level k. See `BitcoinWitness.mo` (Example 7) for the theory, the
/// extraction and the verification.

import Hasher "mo:sha2/Hasher/Sha256";
import Nat32 "mo:core/Nat32";
import Sha256 "mo:sha2/Sha256";
import VarArray "mo:core/VarArray";

module {
  /// The MMR state: the height-indexed peak slots (slot 0 = the parked leaf,
  /// the top slot = the finalization accumulator), the leaf count, whose bits
  /// are the occupancy flags, the one reused `Digest` that absorbs the
  /// messages and the optional witness spine (`wit[k]` = the first leaf's
  /// sibling at level k, written exactly when `count` reaches 2^(k+1); ""
  /// until then — and provably never read before its write). A static record
  /// — it can be declared `stable`.
  public type Mmr = {
    hasher : [var Hasher.Hasher];
    var count : Nat32;
    d : Sha256.Digest;
    wit : ?[var Blob];
  };

  /// Create an empty MMR with capacity for at least `maxLeaves` leaves.
  /// Allocates `ceil(log2 maxLeaves) + 1` hashers — one slot per bit of the
  /// count for the peaks (slot k holds the height-k peak that bit k asserts,
  /// slot 0 the parked leaf) plus the top slot as the finalization
  /// accumulator, one level above the highest possible peak — and the one
  /// scratch `Digest`. With `witness` the coinbase witness spine is captured
  /// as leaves are added, into `ceil(log2 maxLeaves)` pre-allocated Blob
  /// slots — one per level at which a capture can occur (2^(k+1) <=
  /// maxLeaves). Exceeding the capacity traps on the witness array just as
  /// it does on the hasher array.
  public func new(maxLeaves : Nat, witness : Bool) : Mmr {
    var l = 0;
    var pow = 1;
    while (pow < maxLeaves) { pow *= 2; l += 1 }; // l = ceil(log2 maxLeaves)
    {
      hasher = VarArray.tabulate<Hasher.Hasher>(l + 1, func(_) { Hasher.new() });
      var count = 0;
      d = Sha256.new();
      wit = if (witness) ?VarArray.repeat<Blob>("", l) else null;
    };
  };

  /// Add one MESSAGE (arbitrary-length `Blob`) to the MMR; its hash — a
  /// single SHA256, or with `double` the double SHA256 (a Bitcoin txid) —
  /// becomes the leaf, read straight from the digest's state; `double` also
  /// selects double SHA256 per node. Traps (on a slot index out of bounds)
  /// if the capacity chosen at `new` is exceeded.
  public func add(self : Mmr, msg : Blob, double : Bool) {
    let d = self.d;
    if (self.count > 0) d.reset();
    d.writeBlob(msg);
    if ((self.count & 1) == 0) {
      // Height 0 empty: the leaf must SURVIVE while its partner is absorbed
      // (the digest gets reset), so it is captured into slot 0.
      d.close(); // d.state := SHA256(msg)
      if (double) {
        // A double-SHA leaf rides its second SHA into the slot for free.
        self.hasher[0].hashState(d.state); // slot0 := SHA256(SHA256(msg))
      } else {
        // A single-SHA leaf has no second SHA to ride: park it with a
        // 32-byte state copy — the only copy, every other leaf.
        self.hasher[0].loadState(d.state); // slot0 := SHA256(msg)
      };
    } else {
      // Height 0 occupied: finish the leaf in the digest, then fuse it with
      // the parked one (read directly, no copy) and carry the node up.
      if (double) d.closeDouble() else d.close(); // d.state := the leaf
      fuseAndCarry(self, d.state, double);
    };
    self.count += 1;
  };

  // Combine the parked leaf in slot 0 with its partner `src` (read directly,
  // no copy) and carry the node up. The height-1 node is built in place in
  // slot 0, consuming the parked leaf exactly as bit 0 clears.
  func fuseAndCarry(self : Mmr, src : Hasher.Hasher, double : Bool) {
    let hasher = self.hasher;
    // Witness hook 1 — first fuse ever (count == 1): `src` is leaf #1, the
    // first leaf's sibling at level 0 — copy it out.
    switch (self.wit) {
      case (?w) { if ((self.count >> 1) == 0) w[0] := src.readSum() };
      case (null) {};
    };
    hasher[0].combineState(hasher[0], src);
    if (double) hasher[0].hashState(hasher[0]);
    // Carry: the rising node climbs the slots — the height-(k+1) node is
    // built in slot k by merging the peak there with the node from below.
    var k : Nat32 = 1;
    while (((self.count >> k) & 1) == 1) {
      let kk = k.toNat();
      // Witness hook 2 — first merge at height k (count == 2^(k+1) - 1): the
      // rising node below covers leaves [2^k, 2^(k+1)) — the first leaf's
      // sibling at level k. It is consumed by the merge on the next line;
      // this is the only moment it exists — copy it out.
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
