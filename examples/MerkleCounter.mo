/// Example 3: the same Merkle root as `MerkleStack.mo`, built via the
/// BINARY-COUNTER mountain range. Blob leaves, single SHA256 per node, any
/// leaf count. Allocation-free.
///
/// Instead of a packed STACK of peaks plus a parallel `level[]` array, this
/// keeps a SPARSE array indexed by HEIGHT: `hasher[k]` holds the height-`k`
/// peak, or is unused. Adding a leaf is binary increment with carry — a binary
/// counter, where a "carry" is a `combineState`. The occupied slots ARE the
/// binary representation of the leaf count, so there is no `level[]` array and
/// no occupancy flags: "is height k occupied?" is bit k of the running count,
/// `(count >> k) & 1`, and `count += 1` maintains every bit for free.
///
/// === Height 0 is written lazily (the "delay" trick) ===
///
/// The height-0 peak is a raw leaf, and deserializing every leaf into slot 0
/// (`loadBlob32`) would be wasteful. So writing it is DELAYED: the leaf waits
/// as a pending `?Blob` (bit 0 of the count: set iff a leaf is waiting). When
/// its partner arrives, the pair is fused straight from the two Blobs with
/// `combineBlob32` — no `loadBlob32`, exactly like the stack's leaf step. Only
/// if a leaf is still pending at the END is it actually written into slot 0
/// (one `loadBlob32`), for the bagging to pick up like any other peak. The
/// delay changes nothing conceptually — slot 0 is the height-0 slot — it just
/// avoids n/2 deserializations, making the counter as fast as the stack (a
/// touch faster, since `occupied = count's bits` beats the stack's `level[]`
/// updates).
///
/// === The two state tricks ===
///
///   * Hashers are MOVED by reference: the array is a `[var Hasher]`, so a
///     risen peak reaches its slot with an O(1) SWAP, never a state copy. The
///     rising node climbs the array: the height-(k+1) node is built in slot k
///     (merging the peak there with the node from slot k-1), and one final
///     swap drops it into its own slot.
///   * `combineBlob32` fuses a leaf pair; `combineState` merges two peaks. Both
///     leave the result in place with no intermediate `Blob`.
///
/// === Finalization: bag the peaks, without touching them ===
///
/// For a power-of-two count the counter ends with a single peak — the root.
/// Otherwise one peak per set bit of the count remains; BAG them bottom-up:
/// `acc := SHA256(peak_k ++ acc)` for each occupied height `k` ascending, `acc`
/// starting as the lowest component (the pending leaf, if one is waiting).
/// Slot 0 — free, thanks to the delay trick — serves as the accumulator, so
/// bagging only READS the peaks: the MMR remains valid afterwards, and one
/// could keep adding leaves and bag again for an updated root each time.
/// Same typical mountain-range finalization as `MerkleStack.mo` — identical
/// roots for identical leaves. (Bitcoin's duplicate-and-collapse variant is
/// shown in `BitcoinMerkle.mo`.)
///
/// Accordingly, the module exposes the MMR as an incremental API — `new`
/// (fixed capacity), `add` and `root` — alongside the one-shot convenience
/// `merkleRoot`: add leaves, bag a root, keep adding, bag again.
///
/// SECURITY NOTE: the bagged root does not commit to the leaf count — the
/// same root arises from the same peak hashes at different heights, and a
/// leaf equal to an internal node value is trivially constructible (leaves
/// are arbitrary 32-byte values). Verifiers must be given n out of band (the
/// peak heights are exactly its bits). This is not RFC 6962 — see the full
/// note in `MerkleStack.mo`.

import Hasher "mo:sha2/Hasher/Sha256";
import Base "CounterBase";
import Nat32 "mo:core/Nat32";

module {
  /// The MMR state — see `CounterBase.mo`, which holds the building machinery
  /// shared with `BitcoinMerkle.mo`. A static record — it can be declared
  /// `stable`.
  public type Mmr = Base.Mmr;

  /// Create an empty MMR with capacity for at least `maxLeaves` leaves
  /// (`floor(log2 maxLeaves) + 1` hashers — see `CounterBase.mo`).
  public func new(maxLeaves : Nat) : Mmr = Base.new(maxLeaves, false);

  /// Add one 32-byte leaf to the MMR (single SHA256 per node). Traps (on a
  /// slot index out of bounds) if the capacity chosen at `new` is exceeded.
  public func add(self : Mmr, leaf : Blob) = Base.add(self, leaf, false);

  /// The Merkle root over the leaves added so far (>= 1): bag the peaks
  /// bottom-up, acc := SHA256(hasher[k] ++ acc) for each occupied height k
  /// ascending. Slot 0 — free, since the height-0 peak is the pending Blob —
  /// serves as the accumulator, so NO peak slot is written: the MMR remains
  /// valid, and one can keep adding leaves and bag again for an updated root.
  /// Allocation-free except the returned root `Blob`.
  public func root(self : Mmr) : Blob {
    let hasher = self.hasher;
    let count = self.count;
    assert count >= 1;
    let l = hasher.size() - 1 : Nat;
    let acc = hasher[0];
    var k : Nat32 = 1;
    switch (self.pending) {
      case (?b) {
        // count == 1: the lone leaf is its own root — enforce the same 32-byte
        // leaf contract that combineBlob32 checks on the multi-leaf path.
        if (count == 1) { assert b.size() == 32; return b };
        // Perform the delayed write of the height-0 peak — into the accumulator.
        acc.loadBlob32(b); // the only loadBlob32: once, per bagging
      };
      case (null) {
        // A single peak is the root outright — leave it untouched.
        while (((count >> k) & 1) == 0) { k += 1 };
        if (Nat32.bitcountNonZero(count) == 1) {
          return hasher[k.toNat()].readSum();
        };
        // Fuse the two lowest peaks straight into the accumulator.
        let k0 = k.toNat();
        k += 1;
        while (((count >> k) & 1) == 0) { k += 1 };
        acc.combineState(hasher[k.toNat()], hasher[k0]);
        k += 1;
      };
    };
    while (k.toNat() <= l) {
      if (((count >> k) & 1) == 1) {
        acc.combineState(hasher[k.toNat()], acc);
      };
      k += 1;
    };
    acc.readSum();
  };

  /// Single-SHA256 Merkle root over `leaves` (each a 32-byte `Blob`), for ANY
  /// leaf count (>= 1), in one shot. Equals `MerkleStack.merkleRoot` on the
  /// same leaves. Allocation-free except the returned root `Blob`.
  public func merkleRoot(leaves : [Blob]) : Blob {
    assert leaves.size() >= 1;
    let mmr = new(leaves.size());
    for (leaf in leaves.values()) {
      mmr.add(leaf);
    };
    mmr.root();
  };
};
