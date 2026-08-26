/// Example 2: the peak-stack Merkle root of `MerkleStack.mo`, but over real
/// MESSAGES: each leaf is SHA256(msg), produced by ONE reused `Digest` and
/// read straight from its state. Single SHA256 per node, any leaf count.
/// Allocation-free.
///
/// Example 1 takes ready 32-byte leaves; here a leaf must first be COMPUTED
/// from an arbitrary-length message. Only the buffered `Digest` can absorb
/// such input, so the MMR embeds one, reused (`reset`) per message; after
/// `d.close()` the digest's STATE is the leaf — no `Blob` is ever
/// materialized. The stack mechanics are identical to `MerkleStack.mo`; only
/// the height-0 handling differs, and that difference costs exactly one pool
/// slot.
///
/// === The parked leaf is a REAL stack element ===
///
/// `MerkleStack.mo` holds the unpaired leaf out of band, as a pending `?Blob`
/// — a borrowed reference, costing no `Hasher`. That is not possible here:
/// the leaf exists only as the digest's state, which the NEXT message
/// overwrites, and exporting it as a `Blob` would allocate — the very thing
/// being avoided. So the first leaf of each pair is captured (`loadState`, a
/// 32-byte state copy — the only copy, every other leaf) onto the stack as a
/// LEVEL-0 peak; its partner is then fused into that slot in place with
/// `combineState`, reading `d.state` directly, no copy. (With DOUBLE-SHA
/// leaves even that capture copy disappears — see `BitcoinTxMerkle.mo`.)
///
/// With the parked leaf on the stack, no `pending` field and no parity
/// counter is needed: a level-0 top IS the parked leaf. (Completed peaks have
/// level >= 1 and levels strictly decrease going up the stack, so "is a leaf
/// waiting?" is simply `level[i - 1] == 0`.)
///
/// === Pool size: ceil(log2 n) + 1 — the +1 is the parked leaf ===
///
/// At rest the stack holds one component per set bit of the leaf count — now
/// INCLUDING the height-0 one — up to ceil(log2 n) of them, and the
/// non-destructive bagging still wants a free slot above the top. In
/// `MerkleStack.mo` that free slot was guaranteed precisely because the
/// pending leaf stayed out of band; here it must be paid for: the pool is one
/// larger, `ceil(log2 n) + 1` hashers — exactly one more than the blob-leaf
/// stack for EVERY n, and exactly the size of the digest-fed counter
/// (`MerkleCounterState.mo`). The organization (stack vs counter) does not
/// decide the pool size; where the leaf lives (a digest's state vs a `Blob`)
/// does.
///
/// === Finalization: bagging without special cases ===
///
/// Bag the peaks top to bottom into the free slot above the stack top,
/// `acc := SHA256(peak ++ acc)`, exactly as in `MerkleStack.mo` — except that
/// no pending-leaf case exists: the parked leaf, if any, is simply the lowest
/// component, already sitting on top of the stack. The stack is only READ, so
/// the MMR remains valid afterwards: keep adding messages and bag again for
/// an updated root any time. The module exposes this as an incremental API —
/// `new` (fixed capacity), `add` and `root` — alongside the one-shot
/// convenience `merkleRoot`.
///
/// The root equals `MerkleStack.mo`/`MerkleCounter.mo` over the HASHED
/// leaves, [SHA256(msg)] — and the security caveat carries over: the bagged
/// root does not commit to the leaf count; verifiers must be given n out of
/// band (see the note in `MerkleStack.mo`).

import Hasher "mo:sha2/Hasher/Sha256";
import Sha256 "mo:sha2/Sha256";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";

module {
  /// The MMR state: the peak stack (`hasher[0 .. i-1]` with `level[]` the
  /// tree level of each peak; a level-0 top is the parked leaf) and the one
  /// reused `Digest` that absorbs the messages. A static record — it can be
  /// declared `stable`.
  public type Mmr = {
    hasher : [Hasher.Hasher];
    level : [var Nat];
    var i : Nat; // stack height
    d : Sha256.Digest;
  };

  /// Create an empty MMR with capacity for at least `maxLeaves` leaves.
  /// Allocates `ceil(log2 maxLeaves) + 1` hashers — unlike `MerkleStack.mo`,
  /// the parked leaf occupies a stack slot, so the stack holds up to
  /// `ceil(log2 maxLeaves)` components (one per set bit of the leaf count)
  /// and the +1 keeps the slot above the top free for the bagging
  /// accumulator — and the one scratch `Digest`.
  public func new(maxLeaves : Nat) : Mmr {
    var cap = 0;
    var m = 1;
    while (m < maxLeaves) { m *= 2; cap += 1 }; // cap = ceil(log2 maxLeaves)
    {
      hasher = Array.tabulate<Hasher.Hasher>(cap + 1, func(_) { Hasher.new() });
      level = VarArray.repeat<Nat>(0, cap + 1);
      var i = 0;
      d = Sha256.new();
    };
  };

  /// Add one MESSAGE (arbitrary-length `Blob`) to the MMR; its single SHA256
  /// becomes the leaf, read straight from the digest's state (single SHA256
  /// per node as well). Traps (on a stack index out of bounds) if the
  /// capacity chosen at `new` is exceeded.
  public func add(self : Mmr, msg : Blob) {
    let d = self.d;
    if (self.i > 0) d.reset(); // the stack is never empty after the first add
    d.writeBlob(msg);
    d.close(); // d.state := SHA256(msg) — the leaf, no Blob materialized
    let hasher = self.hasher;
    let level = self.level;
    var i = self.i;
    if (i == 0 or level[i - 1] > 0) {
      // No leaf is parked: capture this one on top of the stack as a level-0
      // peak (the only copy, every other leaf) — the digest is about to be
      // reused for its partner.
      hasher[i].loadState(d.state);
      level[i] := 0;
      self.i := i + 1;
      return;
    };
    // The top peak is the parked partner: fuse the pair in place, reading
    // this leaf directly from the digest's state (no copy) — the top rises
    // to level 1.
    i -= 1;
    hasher[i].combineState(hasher[i], d.state);
    level[i] := 1;
    // Carry: while the top peak matches the level of the one below it, merge.
    while (i > 0 and level[i - 1] == level[i]) {
      hasher[i - 1].combineState(hasher[i - 1], hasher[i]); // lower := SHA256(lower ++ top)
      level[i - 1] += 1; // it rose a level
      i -= 1; // pop the top
    };
    self.i := i + 1;
  };

  /// The Merkle root over the messages added so far (>= 1): bag the peaks
  /// right to left, `acc := SHA256(peak ++ acc)`, with `hasher[i]` — the free
  /// slot above the stack top — as the accumulator. The parked leaf, if any,
  /// needs no special case: it is the lowest component, on top of the stack.
  /// The stack itself is only READ, so the MMR remains valid and one can keep
  /// adding messages and bag again for an updated root. Allocation-free
  /// except the returned root `Blob`.
  public func root(self : Mmr) : Blob {
    let hasher = self.hasher;
    let i = self.i;
    assert i >= 1; // at least one message must have been added
    // A single component — one peak, or just the parked leaf — is the root
    // outright; leave it untouched.
    if (i == 1) return hasher[0].readSum();
    // The pool is one larger than the maximal stack height (see `new`), so
    // hasher[i] is free — the bagging accumulator. Fuse the two lowest
    // components straight into it, then fold the remaining peaks on.
    let acc = hasher[i];
    acc.combineState(hasher[i - 2], hasher[i - 1]);
    var j = i - 2;
    while (j > 0) {
      j -= 1;
      acc.combineState(hasher[j], acc);
    };
    // readSum is the one and only allocation.
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
