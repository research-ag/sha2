/// Example 4: the binary-counter Merkle root of `MerkleCounter.mo`, but over
/// STATE leaves. Single SHA256 per node, any leaf count. Allocation-free.
///
/// Here each leaf is a 32-byte hash already sitting in a `Hasher` — e.g. read
/// back from storage with `loadBlob32`, or just produced by a hash computation
/// — rather than a `Blob`. The counter mechanics are identical to
/// `MerkleCounter.mo` (height-indexed slots, occupancy = the bits of the leaf
/// count, carry-and-swap); only the height-0 handling differs.
///
/// === Half-delay: copy only every OTHER leaf ===
///
/// The full delay trick of `MerkleCounter.mo` holds the pending leaf as a
/// `?Blob` reference and fuses the pair with `combineBlob32`. With state
/// leaves there is no combine-two-blobs shortcut — but there is `combineState`,
/// which reads BOTH sources directly. So only the FIRST leaf of each pair needs
/// to be captured (parked into slot 0 with one `loadState` — a 32-byte state
/// copy); its partner is fed straight from the input into
/// `combineState(hasher[0], leaf)`, no copy. n/2 copies instead of n.
///
/// The park models leaves that are TRANSIENT — handed to you one at a time by a
/// producer that reuses its engine, so the first of a pair must be captured
/// before the next arrives. If your leaves sit in a persistent array anyway,
/// you could hold a reference instead and skip even that copy; and if they
/// stream out of a `Digest`, the bridge can produce each leaf directly INTO
/// slot 0 (`hashState`), making the capture free — see `BitcoinTxMerkle.mo`.
///
/// === Finalization: bag the peaks, without touching them ===
///
/// Bag the peaks bottom-up exactly as in `MerkleCounter.mo`; bit 0 of the count
/// now refers to the parked leaf in slot 0. Since slot 0 is a real peak slot
/// here, the bagging accumulator is instead the TOP slot of the array — one
/// above the highest possible peak, which is exactly where the bagged root
/// conceptually lives. It is always free when bagging actually happens: its
/// bit can only be set when the count is the full power of two, i.e. a single
/// peak, which short-circuits without an accumulator. Bagging therefore only
/// READS the peaks: the MMR remains valid, and one can keep adding leaves and
/// bag again — the module exposes this as an incremental API (`new`, `add`,
/// `root`) alongside the one-shot convenience `merkleRoot`.
///
/// Identical roots to `MerkleStack.mo`/`MerkleCounter.mo` for leaves holding
/// the same 32 bytes — including the security caveat: the bagged root does not
/// commit to the leaf count; verifiers must be given n out of band (see the
/// note in `MerkleStack.mo`).

import Hasher "mo:sha2/Hasher/Sha256";
import Base "CounterStateBase";
import Nat32 "mo:core/Nat32";

module {
  /// The MMR state — see `CounterStateBase.mo`, which holds the building
  /// machinery shared with `BitcoinTxMerkle.mo`. A static record — it can be
  /// declared `stable`.
  public type Mmr = Base.Mmr;

  /// Create an empty MMR with capacity for at least `maxLeaves` leaves
  /// (`ceil(log2 maxLeaves) + 1` hashers — see `CounterStateBase.mo`).
  public let new = Base.new;

  /// Add one leaf — the 32-byte STATE of a `Hasher`, read-only — to the MMR
  /// (single SHA256 per node). Traps (on a slot index out of bounds) if the
  /// capacity chosen at `new` is exceeded.
  public func add(self : Mmr, leaf : Hasher.Hasher) {
    if ((self.count & 1) == 0) {
      // Height 0 empty: capture this leaf in slot 0 (the only copy, every
      // other leaf).
      self.hasher[0].loadState(leaf);
    } else {
      // Height 0 occupied: fuse the parked leaf with this one, read directly
      // from the input (no copy), and carry the node up.
      Base.fuseAndCarry(self, leaf, false);
    };
    self.count += 1;
  };

  /// The Merkle root over the leaves added so far (>= 1): bag the peaks
  /// bottom-up, acc := SHA256(hasher[k] ++ acc) for each occupied height k
  /// ascending, with the TOP slot as the accumulator. No peak slot is
  /// written, so the MMR remains valid — keep adding leaves and bag again for
  /// an updated root. Allocation-free except the returned root `Blob`.
  public func root(self : Mmr) : Blob {
    let hasher = self.hasher;
    let count = self.count;
    assert count >= 1;
    // A single component (a lone parked leaf, or one peak) is the root
    // outright — leave it untouched.
    var k : Nat32 = 0;
    while (((count >> k) & 1) == 0) { k += 1 };
    if (Nat32.bitcountNonZero(count) == 1) {
      return Hasher.readSum(hasher[Nat32.toNat(k)]);
    };
    // The top slot is free — its bit could only be set at the full power of
    // two, a single peak, handled above. Fuse the two lowest peaks straight
    // into it, then fold the remaining peaks on.
    let top = hasher.size() - 1 : Nat;
    let acc = hasher[top];
    let k0 = Nat32.toNat(k);
    k += 1;
    while (((count >> k) & 1) == 0) { k += 1 };
    acc.combineState(hasher[Nat32.toNat(k)], hasher[k0]);
    k += 1;
    while (Nat32.toNat(k) < top) {
      if (((count >> k) & 1) == 1) {
        acc.combineState(hasher[Nat32.toNat(k)], acc);
      };
      k += 1;
    };
    Hasher.readSum(acc);
  };

  /// Single-SHA256 Merkle root over `leaves`, each the 32-byte STATE of a
  /// `Hasher`, for ANY leaf count (>= 1), in one shot. The leaves are
  /// read-only. Equals `MerkleStack.merkleRoot`/`MerkleCounter.merkleRoot` on
  /// the same 32-byte leaf values. Allocation-free except the returned root
  /// `Blob`.
  public func merkleRoot(leaves : [Hasher.Hasher]) : Blob {
    assert leaves.size() >= 1;
    let mmr = new(leaves.size());
    for (leaf in leaves.values()) {
      mmr.add(leaf);
    };
    mmr.root();
  };
};
