/// Example 1: an allocation-free Merkle tree over 32-byte Blob leaves — the
/// PEAK-STACK approach. Single SHA256 per node, any leaf count.
///
/// A Merkle tree hashes pairs of nodes up to a single root. Done the obvious
/// way, every internal node produces an intermediate digest `Blob`, so a tree
/// over N leaves allocates ~N `Blob`s. On the IC that garbage adds up fast.
///
/// This example builds the tree with ZERO per-node allocation — the only
/// `Blob` allocated is the root you get back. It uses the single-shot `Hasher`
/// (`mo:sha2/Hasher/Sha256`), whose combine primitives are each a SINGLE SHA256
/// that leaves its result in place:
///
///   * `combineBlob32(h, l0, l1)` — `h := SHA256(l0 ++ l1)` for two 32-byte leaf
///     blobs, straight from the IV.
///   * `combineState(h, a, b)`    — `h := SHA256(a ++ b)` for two finished child
///     hashers, reading their 32-byte states directly with no `Blob`. Either
///     source may be `h` itself, so `combineState(h, h, sib)` makes `h` "move up
///     a level" in place.
///   * `loadBlob32(h, b)`         — parks a 32-byte hash in `h` VERBATIM (no
///     hashing); used once per bagging, for a pending unpaired leaf.
///
/// A `Hasher` IS the 256-bit state: every call overwrites it from the IV, so a
/// finished hasher is immediately reusable — no `reset`, no `close`, no `Blob`
/// for any internal node.
///
/// === The algorithm: a Merkle-mountain-range peak stack ===
///
/// Leaves are added one at a time, pairs are processed together, keeping a
/// STACK of "peaks" — completed subtrees still waiting for a right sibling.
/// `hasher[j]` holds the j-th peak and `level[j]` its tree level; `i` is the
/// stack height.
///
///   1. An arriving leaf without a partner WAITS as a pending `?Blob` (no
///      hashing, no slot). When its partner arrives, the pair is pushed as a
///      node (`combineBlob32`), a level-1 peak.
///   2. While the new peak has the SAME level as the peak below it, merge the
///      two (`combineState` into the lower peak) and pop — exactly like
///      carrying in binary addition.
///   3. To produce a root, BAG the peaks right to left, `acc := SHA256(peak ++
///      acc)`, starting from the pending leaf (if one is waiting) or the last
///      (lowest) peak. The accumulator is `hasher[i]` — the first FREE slot
///      above the stack top, which always exists: a pair is only ever pushed
///      at index popcount(p) with p even, so the stack never fills its pool.
///      This is the typical mountain-range finalization — no node is ever
///      duplicated (contrast the Bitcoin collapse in `BitcoinMerkle.mo`).
///
/// Because bagging only READS the stack (it writes the free slot above it),
/// the MMR remains valid afterwards: keep adding leaves and bag again for an
/// updated root any time. The module exposes this as an incremental API —
/// `new` (fixed capacity), `add` and `root` — alongside the one-shot
/// convenience `merkleRoot`.
///
/// A tree of N leaves needs ceil(log2 N) hashers. No recursion, no free-list.
///
/// === Security note: the root does not commit to the leaf count ===
///
/// Bagging ignores peak heights, so the same root arises from different leaf
/// counts: peaks [A@2, B@1] (n = 6) and [A@2, B@0] (n = 5) both bag to
/// SHA256(A ++ B). And a leaf EQUAL to an internal node value is trivially
/// constructible — leaves are arbitrary 32-byte values, so anyone can submit
/// SHA256(l5 ++ l6) as a leaf; no hash collision is needed. Verifiers must
/// therefore be given n out of band (the peak heights are exactly the bits of
/// n). This is NOT RFC 6962, which closes the leaf/node confusion with domain
/// separation (`0x00` before leaf data, `0x01` before node inputs — a 65-byte
/// node preimage these fixed 64-byte combiners can't produce). For a
/// double-SHA (Bitcoin) tree see `BitcoinMerkle.mo`.
///
/// === What YOU must do to stay allocation-free ===
///
///   1. Allocate the hashers ONCE, up front. Never `Hasher.new()` per node.
///   2. Leaves must be 32-byte blobs (Merkle leaves are hashes, so this is the
///      normal case).
///   3. Read the output with `readSum()` exactly once, per root — that is
///      the only allocation.

import Hasher "mo:sha2/Hasher/Sha256";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";

module {
  /// The MMR state: the peak stack (`hasher[0 .. i-1]` with `level[]` the
  /// tree level of each peak) and the pending unpaired leaf. A static record —
  /// it can be declared `stable`.
  public type Mmr = {
    hasher : [Hasher.Hasher];
    level : [var Nat];
    var i : Nat; // stack height
    var pending : ?Blob;
  };

  /// Create an empty MMR with capacity for at least `maxLeaves` leaves.
  /// Allocates `ceil(log2 maxLeaves)` hashers: a pair is pushed at index
  /// popcount(p) with p (the consumed leaf count) even, and an even p < 2^L
  /// has at most L-1 set bits — so the pool also always has a free slot left
  /// for the bagging.
  public func new(maxLeaves : Nat) : Mmr {
    var cap = 0;
    var m = 1;
    while (m < maxLeaves) { m *= 2; cap += 1 }; // cap = ceil(log2 maxLeaves)
    {
      hasher = Array.tabulate<Hasher.Hasher>(cap, func(_) { Hasher.new() });
      level = VarArray.repeat<Nat>(0, cap);
      var i = 0;
      var pending = null;
    };
  };

  /// Add one 32-byte leaf to the MMR. Traps (on a stack index out of bounds)
  /// if the capacity chosen at `new` is exceeded.
  public func add(self : Mmr, leaf : Blob) {
    switch (self.pending) {
      case (null) { self.pending := ?leaf }; // hold this leaf; pair it with the next
      case (?leaf0) {
        self.pending := null;
        let hasher = self.hasher;
        let level = self.level;
        var i = self.i;
        // Push the pair as a level-1 node, fused straight from the two Blobs.
        hasher[i].combineBlob32(leaf0, leaf); // SHA256(l0 ++ l1)
        level[i] := 1;
        // Carry: while the top peak matches the level of the one below it, merge.
        while (i > 0 and level[i - 1] == level[i]) {
          hasher[i - 1].combineState(hasher[i - 1], hasher[i]); // lower := SHA256(lower ++ top)
          level[i - 1] += 1; // it rose a level
          i -= 1; // pop the top
        };
        self.i := i + 1;
      };
    };
  };

  /// The Merkle root over the leaves added so far (>= 1): bag the peaks right
  /// to left, `acc := SHA256(peak ++ acc)`, with `hasher[i]` — the first free
  /// slot above the stack top — as the accumulator. The stack itself is only
  /// READ, so the MMR remains valid and one can keep adding leaves and bag
  /// again for an updated root. Allocation-free except the returned root
  /// `Blob`.
  public func root(self : Mmr) : Blob {
    let hasher = self.hasher;
    let i = self.i;
    // Roots that involve no bagging at all:
    switch (self.pending) {
      case (?b) {
        // A lone leaf is its own root — enforce the same 32-byte leaf
        // contract that combineBlob32 checks on the multi-leaf path.
        if (i == 0) { assert b.size() == 32; return b };
      };
      case (null) {
        assert i >= 1; // at least one leaf must have been added
        // A single peak is the root outright — leave it untouched.
        if (i == 1) return Hasher.readSum(hasher[0]);
      };
    };
    // The stack is never full (see `new`), so hasher[i] is free — the
    // bagging accumulator.
    let acc = hasher[i];
    var j = i;
    switch (self.pending) {
      case (?b) {
        // The pending leaf is the lowest component: park it in the
        // accumulator (the only loadBlob32) and fold the peaks onto it.
        acc.loadBlob32(b);
      };
      case (null) {
        // Fuse the two lowest peaks straight into the accumulator, then fold.
        acc.combineState(hasher[i - 2], hasher[i - 1]);
        j := i - 2;
      };
    };
    while (j > 0) {
      j -= 1;
      acc.combineState(hasher[j], acc);
    };
    // readSum is the one and only allocation.
    Hasher.readSum(acc);
  };

  /// Single-SHA256 Merkle root of `leaves`, for ANY leaf count (>= 1), in one
  /// shot. Each leaf must be 32 bytes. Allocates nothing per node — only the
  /// returned root `Blob`.
  public func merkleRoot(leaves : [Blob]) : Blob {
    assert leaves.size() >= 1;
    let mmr = new(leaves.size());
    for (leaf in leaves.values()) {
      mmr.add(leaf);
    };
    mmr.root();
  };
};
