/// Example 4: the binary-counter Merkle root of `MerkleCounter.mo`, but over
/// real MESSAGES: each leaf is SHA256(msg), produced by ONE reused `Digest`
/// and read straight from its state. Single SHA256 per node, any leaf count.
/// Allocation-free.
///
/// === Two engines, two roles ===
///
///   * ONE `Digest` (embedded in the MMR, `reset` between messages) absorbs
///     each variable-length message — only it has a message buffer, so only
///     it can take arbitrary-length input.
///   * The binary counter of `MerkleCounter.mo` holds the peaks and combines
///     them with `combineState`: occupancy = the bits of the leaf count,
///     risen peaks swapped by reference.
///
/// === The Digest -> MMR bridge: copy only every OTHER leaf ===
///
/// After `d.close()` the digest's STATE is the leaf, SHA256(msg) — no `Blob`
/// is ever materialized. The two leaves of a pair exit the digest
/// differently:
///
///   * The FIRST must SURVIVE while its partner is absorbed (the digest gets
///     reset), and `MerkleCounter.mo`'s trick of holding it out of band as a
///     pending `?Blob` would allocate. So it is parked into slot 0 with one
///     `loadState` — a 32-byte state copy, the only copy, every other leaf.
///   * The SECOND is consumed IMMEDIATELY: `combineState` fuses the parked
///     leaf with `d.state` read directly, no copy.
///
/// (With DOUBLE-SHA leaves even the parking copy disappears: the second SHA
/// application can transport the leaf into its slot, `hashState(d.state)` —
/// see `BitcoinTxMerkle.mo`, the Bitcoin version of this example. A
/// single-SHA leaf has no second SHA to ride, so it is parked by
/// `loadState`.)
///
/// The counter mechanics are otherwise identical to `MerkleCounter.mo`:
/// height-indexed slots, occupancy = the bits of the leaf count,
/// carry-and-swap.
///
/// === Finalization: bag the peaks, without touching them ===
///
/// Bag the peaks bottom-up exactly as in `MerkleCounter.mo`; bit 0 of the
/// count now refers to the parked leaf in slot 0. Since slot 0 is a real peak
/// slot here, the bagging accumulator is instead the TOP slot of the array —
/// one above the highest possible peak, which is exactly where the bagged
/// root conceptually lives. It is always free when bagging actually happens:
/// its bit can only be set when the count is the full power of two, i.e. a
/// single peak, which short-circuits without an accumulator. Bagging
/// therefore only READS the peaks: the MMR remains valid, and one can keep
/// adding messages and bag again — the module exposes this as an incremental
/// API (`new`, `add`, `root`) alongside the one-shot convenience
/// `merkleRoot`.
///
/// The root equals `MerkleStack.mo`/`MerkleCounter.mo` over the HASHED
/// leaves, [SHA256(msg)] — and the security caveat carries over: the bagged
/// root does not commit to the leaf count; verifiers must be given n out of
/// band (see the note in `MerkleStack.mo`).

import Hasher "mo:sha2/Hasher/Sha256";
import Base "CounterStateBase";
import Nat32 "mo:core/Nat32";

module {
  /// The MMR state — see `CounterStateBase.mo`, which holds the building
  /// machinery and the embedded `Digest`, shared with `BitcoinTxMerkle.mo`.
  /// A static record — it can be declared `stable`.
  public type Mmr = Base.Mmr;

  /// Create an empty MMR with capacity for at least `maxLeaves` leaves
  /// (`ceil(log2 maxLeaves) + 1` hashers plus the one scratch `Digest` — see
  /// `CounterStateBase.mo`).
  public func new(maxLeaves : Nat) : Mmr = Base.new(maxLeaves, false);

  /// Add one MESSAGE (arbitrary-length `Blob`) to the MMR; its single SHA256
  /// becomes the leaf, read straight from the digest's state (single SHA256
  /// per node as well). Traps (on a slot index out of bounds) if the capacity
  /// chosen at `new` is exceeded.
  public func add(self : Mmr, msg : Blob) = Base.add(self, msg, false);

  /// The Merkle root over the messages added so far (>= 1): bag the peaks
  /// bottom-up, acc := SHA256(hasher[k] ++ acc) for each occupied height k
  /// ascending, with the TOP slot as the accumulator. No peak slot is
  /// written, so the MMR remains valid — keep adding messages and bag again
  /// for an updated root. Allocation-free except the returned root `Blob`.
  public func root(self : Mmr) : Blob {
    let hasher = self.hasher;
    let count = self.count;
    assert count >= 1;
    // A single component (a lone parked leaf, or one peak) is the root
    // outright — leave it untouched.
    var k : Nat32 = 0;
    while (((count >> k) & 1) == 0) { k += 1 };
    if (Nat32.bitcountNonZero(count) == 1) {
      return hasher[k.toNat()].readSum();
    };
    // The top slot is free — its bit could only be set at the full power of
    // two, a single peak, handled above. Fuse the two lowest peaks straight
    // into it, then fold the remaining peaks on.
    let top = hasher.size() - 1 : Nat;
    let acc = hasher[top];
    let k0 = k.toNat();
    k += 1;
    while (((count >> k) & 1) == 0) { k += 1 };
    acc.combineState(hasher[k.toNat()], hasher[k0]);
    k += 1;
    while (k.toNat() < top) {
      if (((count >> k) & 1) == 1) {
        acc.combineState(hasher[k.toNat()], acc);
      };
      k += 1;
    };
    acc.readSum();
  };

  /// Single-SHA256 Merkle root over the messages `msgs` (each an
  /// arbitrary-length `Blob`), for ANY count (>= 1), in one shot; each leaf
  /// is SHA256(msg). Equals `MerkleStack.merkleRoot`/`MerkleCounter.merkleRoot`
  /// over the hashed leaves. Allocation-free except the returned root `Blob`.
  public func merkleRoot(msgs : [Blob]) : Blob {
    assert msgs.size() >= 1;
    let mmr = new(msgs.size());
    for (msg in msgs.values()) {
      mmr.add(msg);
    };
    mmr.root();
  };
};
