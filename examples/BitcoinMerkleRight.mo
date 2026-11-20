/// Example 8: the BITCOIN Merkle root built from the RIGHT — the leaves arrive
/// last to first. The mirror image of `BitcoinMerkle.mo` (Example 5), with
/// one twist that the mirror alone does not give: Bitcoin's duplication of an
/// odd last node now happens DURING the build, as the leaves come in, and no
/// longer in the root computation. In exchange the root needs no accumulation
/// at all: it is a peak, read off as it stands.
///
/// === The gap ===
///
/// A tree grown from the left is aligned at its first leaf, whatever the
/// number of leaves turns out to be. A tree grown from the right is aligned
/// at its right END, and Bitcoin's tree over N leaves does not end at its last
/// leaf: it has room for 2^n leaves, n = ceil(log2 N), and the 2^n - N places
/// after the last leaf are unused. This is the GAP. Bitcoin fills it by
/// pairing the last node of a level with itself wherever a level has an odd
/// number of nodes.
///
/// The gap is all that must be known before the first leaf is added. N need
/// not be: with a gap of 3 the tree may turn out to have 5 leaves (8 places),
/// 13 (16 places), 29, ... `gapFor(n)` gives the gap of a Bitcoin tree of n
/// leaves.
///
/// === The counter starts at the gap ===
///
/// `count` is the number of leaf places used so far, the gap INCLUDED: it
/// starts at the gap and goes up by one with every leaf. As in Example 5 its
/// bits say where the peaks are: bit k set means a peak of height k. But the
/// peaks that the initial value claims do not exist — they are the gap. So a
/// second value, `present`, records which of the claimed peaks are really
/// there.
///
/// Adding a leaf is the counter increment of Example 5 in a mirror. The new
/// node climbs through the trailing 1-bits of `count` and comes to rest at
/// the first 0-bit. At every 1-bit the counter claims a peak to the right:
///
///   - the peak is PRESENT: merge with it, node first, dSHA(node ++ peak);
///   - the peak is NOT present: it lies in the gap, and the node is the last
///     of its level. Bitcoin pairs it with itself: dSHA(node ++ node).
///
/// That is the whole rule. Without a gap (`count` starts at 0) the second case
/// never occurs.
///
/// Example, gap 3 (N = 5): `count` = 3 = 011b claims peaks of heights 0 and 1,
/// neither present. The first leaf climbs through both 1-bits, doubling
/// twice, and rests at height 2: `count` = `present` = 4.
///
/// Example, gap 2 (N = 6): `count` = 2 = 010b claims a peak of height 1. The
/// first leaf rests at once (bit 0 is clear): `count` = 3, `present` = 1. The
/// second leaf merges with the first, then meets the claimed peak of height
/// 1, which is not there, and doubles: `count` = `present` = 4.
///
/// There is one doubling for every 1-bit of the gap, and all of them are done
/// when `count` reaches the first power of two above the gap. From then on
/// `present` equals `count` and the build is the plain mirror image of
/// Example 5.
///
/// === The root ===
///
/// Whenever `count` is a power of two, 2^n, one peak is left: the root of the
/// tree with 2^n places, of which all but the gap hold leaves. It is read off
/// with no computation, and the tree can go on growing to the left: the root
/// then simply waits as a right child.
///
/// That root is BITCOIN'S root of the leaves added so far exactly when the gap
/// is less than half of the places, 2 * gap < `count`. With a larger gap the
/// tree is deeper than Bitcoin would make it: one leaf and a gap of 3 give
/// the leaf doubled twice, where Bitcoin's root of a single transaction is
/// the txid itself. The caller chose the gap and is the one to know; the tree
/// does not keep it. With `gapFor(n)` and n leaves the root is always
/// Bitcoin's.
///
/// At other values of `count` there is no root: the leaves still to come are
/// on the left, and nothing can stand in for them.
///
/// === The delay trick, mirrored ===
///
/// As in Example 5, a leaf is never loaded into a `Hasher` on its own. A leaf
/// that comes to rest at height 0 waits as a borrowed `Blob` (`pending`, bit
/// 0 of `present`); the leaf to its left fuses with it straight from the two
/// Blobs, `combineBlob32(leaf, pending)`, or with itself if bit 0 is claimed
/// by the gap. Slot 0 is therefore always free between leaves, and it is
/// where every rising node starts: the node of height k is built in slot
/// k - 1, and swapped into slot k when it comes to rest.
///
/// The pool is one slot per bit of the largest `count`, as in Example 5:
/// `floor(log2 (gap + maxLeaves)) + 1` hashers.
///
/// === Mutated blocks, byte order ===
///
/// As in Example 5: the one-shot `bitcoinMerkleRootFromRight` runs
/// `BitcoinMutation.mutated` over the list first and traps on a flagged one
/// (CVE-2012-2459), and txids and root are in Bitcoin's internal byte order.
/// See `BitcoinMutation.mo` for the first and the header of `BitcoinMerkle.mo`
/// for the second.
///
/// The incremental API hashes what it is given, but it NOTES one thing: `add`
/// sets the flag `equalSiblings` when it merges two equal siblings. A valid
/// block never has them (that would be a repeated transaction, or a
/// collision), while a mutated block always does: the written-out copy meets
/// its original. A doubling is not a merge and does not set the flag. This is
/// the check Bitcoin Core makes while it builds the tree, and it needs no
/// view of the whole list, which is what a verifier of chunks has to do
/// without.
///
/// === A structure to verify with ===
///
/// The state is a set of peaks plus a counter that says where they sit. So a
/// tree can be STARTED from peaks that someone else supplies, be grown to the
/// left with `add`, and have its peaks compared with others afterwards.
/// `BitcoinChunks.mo` (Example 9) verifies a block chunk by chunk that way,
/// against nothing but its Merkle root.

import Hasher "mo:sha2/Hasher/Sha256";
import Mutation "BitcoinMutation";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import Runtime "mo:core/Runtime";
import VarArray "mo:core/VarArray";

module {
  /// The state of the build: the height-indexed slots, the counter (`count`:
  /// leaf places used, the gap included — its bits claim the peaks), the peaks
  /// that really exist (`present`: bit k for slot k, bit 0 for the pending
  /// leaf), the pending leaf, and whether two equal siblings were ever merged
  /// (`equalSiblings`, never in a valid block). The gap is not kept, it is
  /// only where `count` starts. A static record — it can be declared `stable`.
  public type Mmr = {
    hasher : [var Hasher.Hasher];
    var count : Nat64;
    var present : Nat64;
    var pending : ?Blob;
    var equalSiblings : Bool;
  };

  /// The gap of a Bitcoin tree of `n` leaves (>= 1): the unused places after
  /// its last leaf, `2^ceil(log2 n) - n`.
  public func gapFor(n : Nat) : Nat {
    assert n >= 1;
    var pow = 1;
    while (pow < n) pow *= 2;
    pow - n;
  };

  /// An empty tree that ends `gap` places before the end of its last level,
  /// with capacity for at least `maxLeaves` leaves. Allocates
  /// `floor(log2 (gap + maxLeaves)) + 1` hashers, one slot per bit of the
  /// counter. Exceeding the capacity traps (on a slot index out of bounds).
  public func new(gap : Nat, maxLeaves : Nat) : Mmr {
    var l = 0;
    var pow = 1;
    while (pow * 2 <= gap + maxLeaves) { pow *= 2; l += 1 }; // l = floor(log2 (gap + maxLeaves))
    {
      hasher = VarArray.tabulate<Hasher.Hasher>(l + 1, func(_) { Hasher.new() });
      var count = gap.toNat64(); // the counter starts at the gap
      var present = 0;
      var pending = null;
      var equalSiblings = false;
    };
  };

  /// Add the next leaf, a 32-byte txid in internal byte order. The leaves are
  /// taken from the LAST of the block to the first. Allocation-free. Sets
  /// `equalSiblings` if two equal siblings are merged. Traps (when the leaf is
  /// hashed) if it is not 32 bytes long.
  public func add(self : Mmr, leaf : Blob) {
    let count = self.count; // the places to the right of this leaf
    self.count := count + 1;
    if ((count & 1) == 0) {
      // Bit 0 is clear: the leaf rests at height 0. It waits, as a Blob, for
      // the leaf to its left.
      self.pending := ?leaf;
      self.present |= 1;
      return;
    };
    let hasher = self.hasher;
    // Bit 0 is set: fuse the leaf with the one to its right, straight from
    // the two Blobs — no loadBlob32 — or, if that place lies in the gap, with
    // itself. The height-1 node is built in slot 0.
    switch (self.pending) {
      case (?right) {
        self.pending := null;
        if (leaf == right) self.equalSiblings := true;
        hasher[0].combineBlob32(leaf, right);
      };
      case (null) hasher[0].combineBlob32(leaf, leaf);
    };
    hasher[0].hashState(hasher[0]); // -> double SHA
    var present = self.present & ^1;
    // Carry: the rising node climbs through the 1-bits of the counter — the
    // node of height k sits in slot k - 1, the node of height k + 1 is built
    // in slot k.
    var k : Nat64 = 1;
    while (((count >> k) & 1) == 1) {
      let kk = k.toNat();
      if (((present >> k) & 1) == 1) {
        // The claimed peak is there: merge.
        if (hasher[kk - 1].equalsState(hasher[kk])) self.equalSiblings := true;
        hasher[kk].combineState(hasher[kk - 1], hasher[kk]); // dSHA(node ++ peak)
        present ^= 1 << k;
      } else {
        // The claimed peak lies in the gap: the node is the last of its level,
        // and Bitcoin pairs it with itself.
        hasher[kk].combineState(hasher[kk - 1], hasher[kk - 1]); // dSHA(node ++ node)
      };
      hasher[kk].hashState(hasher[kk]); // -> double SHA
      k += 1;
    };
    // The carry stopped at a clear bit: slot k is free, and the finished
    // height-k node sits one below it — swap it into its slot.
    let kk = k.toNat();
    let tmp = hasher[kk];
    hasher[kk] := hasher[kk - 1];
    hasher[kk - 1] := tmp;
    self.present := present | (1 << k);
  };

  /// Whether a root can be read: at least one leaf has been added and the
  /// places used, the gap included, are a power of two. Exactly then a single
  /// peak is left.
  public func hasRoot(self : Mmr) : Bool {
    self.present == self.count and Nat64.bitcountNonZero(self.count) == 1;
  };

  /// The root of the tree as it stands: the one peak that is left. Nothing is
  /// computed, and the tree is left unchanged — keep adding leaves and read
  /// the next root when `hasRoot` holds again. Allocation-free except the
  /// returned root `Blob`. Traps unless `hasRoot`. It is Bitcoin's root of the
  /// leaves added so far if the gap given to `new` is less than half of
  /// `count`.
  public func root(self : Mmr) : Blob {
    if (not hasRoot(self)) Runtime.trap("BitcoinMerkleRight: no root unless the places used, gap included, are a power of two");
    switch (self.pending) {
      // One leaf and no gap: by Bitcoin's convention the root is the txid
      // itself — still enforce the 32-byte contract that combineBlob32 checks
      // above.
      case (?b) { assert b.size() == 32; b };
      case (null) self.hasher[Nat64.bitcountTrailingZero(self.count).toNat()].readSum();
    };
  };

  /// Bitcoin (double-SHA256) Merkle root over `txids` (each a 32-byte `Blob`,
  /// in internal byte order), for ANY leaf count (>= 1), in one shot, reading
  /// the list from its end. The same root as `BitcoinMerkle.bitcoinMerkleRoot`.
  /// Allocation-free except the returned root `Blob`. Traps if the list is
  /// flagged by `BitcoinMutation.mutated` (CVE-2012-2459), before the tree is
  /// built.
  public func bitcoinMerkleRootFromRight(txids : [Blob]) : Blob {
    let n = txids.size();
    assert n >= 1;
    if (Mutation.mutated(txids)) Runtime.trap("BitcoinMerkleRight: mutated transaction list (CVE-2012-2459)");
    let mmr = new(gapFor(n), n);
    var i = n;
    while (i > 0) {
      i -= 1;
      add(mmr, txids[i]);
    };
    root(mmr);
  };
};
