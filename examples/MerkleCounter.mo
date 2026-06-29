/// Example: a Merkle root via the BINARY-COUNTER mountain range, allocation-free.
///
/// Same Bitcoin double-SHA256 tree as `Merkle.mo`, built with different (and
/// arguably simpler) bookkeeping. Instead of a packed STACK of peaks plus a
/// parallel `level[]` array, this keeps a SPARSE array indexed by HEIGHT:
/// `hasher[k]` holds the height-`k` peak, or is unused. Adding a leaf is binary
/// increment with carry — a binary counter, where a "carry" is a `combineState`.
/// The occupied slots ARE the binary representation of the leaf count, so there
/// is no `level[]` array and no occupancy flags: "is height k occupied?" is bit
/// k of the running count, `(count >> k) & 1`, and `count += 1` maintains every
/// bit for free.
///
/// === Height 0 is a pending Blob (the "delay") ===
///
/// The one wrinkle: a height-0 peak is a raw leaf, and deserializing every leaf
/// into a Hasher (`loadBlob32`) is wasteful. So height 0 is NOT a hasher slot —
/// it is a pending `?Blob` (bit 0 of the count: set iff a leaf is waiting). When
/// its partner arrives, the pair is fused straight from the two Blobs with
/// `combineBlob32` — no `loadBlob32`, exactly like `Merkle.mo`'s leaf step — and
/// the resulting height-1 node carries up the *state* slots (heights >= 1). This
/// makes the counter as fast as the stack (a touch faster, since `occupied =
/// count's bits` + reference swaps beat the stack's `level[]` updates).
///
/// === The two state tricks ===
///
///   * Hashers are MOVED by reference: the array is a `[var Hasher]`, so a risen
///     peak is dropped into its new slot with an O(1) SWAP, never a state copy.
///     One scratch `carry` hasher rides the carry up and is swapped into place.
///   * `combineBlob32` fuses a leaf pair; `combineState` merges two peaks. Both
///     leave the result in place with no intermediate `Blob`.
///
/// For clarity this handles a POWER-OF-TWO leaf count — the clean case, where
/// the counter ends with a single peak (the root) and no leftover-peak collapse
/// is needed. Bitcoin's odd-count duplication/collapse is shown in `Merkle.mo`;
/// for power-of-two inputs the two algorithms produce identical roots.

import Hasher "../src/Hasher/Sha256";
import VarArray "mo:core/VarArray";
import Nat32 "mo:core/Nat32";

module {
  /// Bitcoin (double-SHA256) Merkle root over `leaves` (each a 32-byte `Blob`),
  /// where the leaf count is a power of two (>= 1). Allocation-free except the
  /// returned root `Blob`. Traps if the count is not a power of two.
  public func merkleRoot(leaves : [Blob]) : Blob {
    let n = leaves.size();
    assert n >= 1;
    // Height L with 2^L == n (the `assert` also rejects non-powers-of-two).
    var l = 0;
    var pow = 1;
    while (pow < n) { pow *= 2; l += 1 };
    assert pow == n;

    // hasher[1..l]: height-indexed peak slots (slot 0 unused — height 0 is the
    // pending Blob). carry: one scratch hasher that rides each carry up. count:
    // leaves added so far — bit k answers "is hasher[k] occupied?" (bit 0 is
    // "is a leaf pending?", tracked by `pending`).
    let hasher = VarArray.tabulate<Hasher.Hasher>(l + 1, func(_) { Hasher.new() });
    var carry = Hasher.new();
    var count : Nat32 = 0;
    var pending : ?Blob = null; // the height-0 peak, held as a Blob

    for (leaf in leaves.values()) {
      switch (pending) {
        case (null) { pending := ?leaf }; // hold this leaf; pair it with the next
        case (?leaf0) {
          pending := null;
          // Fuse the pair straight from the two Blobs — no loadBlob32.
          carry.combineBlob32(leaf0, leaf);
          carry.hashState(carry); // -> double-SHA (drop for a single-SHA tree)
          // carry is now a height-1 node; carry it up through occupied slots.
          var k : Nat32 = 1;
          while (((count >> k) & 1) == 1) {
            carry.combineState(hasher[Nat32.toNat(k)], carry);
            carry.hashState(carry);
            k += 1;
          };
          let kk = Nat32.toNat(k);
          let tmp = hasher[kk];
          hasher[kk] := carry;
          carry := tmp;
        };
      };
      count += 1;
    };

    // A lone leaf (n == 1) is its own root; otherwise the single peak is at l.
    switch (pending) {
      case (?b) b;
      case (null) Hasher.readSum(hasher[l]);
    };
  };
};
