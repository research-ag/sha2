/// Example: a Merkle root via the BINARY-COUNTER mountain range, allocation-free.
///
/// Same Bitcoin double-SHA256 tree as `Merkle.mo`, built with different (and
/// arguably simpler) bookkeeping. Instead of a packed STACK of peaks plus a
/// parallel `level[]` array, this keeps a SPARSE array indexed by HEIGHT:
/// `hasher[k]` holds the height-`k` peak, or is unused. Adding a leaf is binary
/// increment with carry — exactly a binary counter, where a "carry" is a
/// `combineState`. The occupied slots ARE the binary representation of the leaf
/// count, so there is no `level[]` array and no occupancy flags at all: "is
/// height k occupied?" is just bit k of the running count, `(count >> k) & 1`,
/// and `count += 1` updates every bit for free.
///
/// Two tricks keep it copy-free:
///
///   * `loadBlob32` parks each leaf hash as a height-0 peak — a verbatim COPY
///     into the engine, NOT a re-hash (the leaf is already a hash). For leaves
///     computed from raw data, swap in `loadState(carry, digest.state)` (single
///     SHA) or the `hashState` bridge (double SHA); the loop is otherwise the
///     same.
///   * Hashers are MOVED by reference: the array is a `[var Hasher]`, so a risen
///     peak is dropped into its new slot with an O(1) SWAP, never a state copy.
///     One scratch `carry` hasher rides the carry up and is swapped into place.
///
/// For clarity this handles a POWER-OF-TWO leaf count — the clean case, where
/// the counter ends with a single peak (the root) and no leftover-peak collapse
/// is needed. Bitcoin's odd-count duplication/collapse is shown in `Merkle.mo`;
/// for power-of-two inputs the two algorithms produce identical roots.
///
/// Speed note: parking every leaf with `loadBlob32` deserializes each leaf Blob,
/// which the stack's pairwise `combineBlob32` avoids — so over precomputed Blob
/// leaves this clear version runs ~20-30% more instructions than `Merkle.mo`
/// (see `bench/merkle.bench.mo`). The fix is to hold the height-0 leaf as a
/// pending `Blob` and fuse each pair with `combineBlob32` (no `loadBlob32`); that
/// matches the stack. State leaves (`loadState`) don't have the deserialize, so
/// the gap there is small. The counter's draw is the layout (no `level[]`,
/// occupancy = the count's bits, persistence/append), not raw leaf throughput.

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

    // hasher[0..l]: height-indexed peak slots. carry: one scratch hasher that
    // rides each carry up the heights. count: leaves added so far — bit k of it
    // answers "does hasher[k] hold a peak?", so no occupancy flags are needed.
    let hasher = VarArray.tabulate<Hasher.Hasher>(l + 1, func(_) { Hasher.new() });
    var carry = Hasher.new();
    var count : Nat32 = 0;

    for (leaf in leaves.values()) {
      carry.loadBlob32(leaf); // park the leaf hash as a height-0 peak (no re-hash)
      var k : Nat32 = 0;
      while (((count >> k) & 1) == 1) {
        // Bit k is set: height k is occupied. Merge it with the rising carry.
        carry.combineState(hasher[Nat32.toNat(k)], carry); // SHA256(hasher[k] ++ carry)
        carry.hashState(carry); // -> double-SHA (drop for a single-SHA tree)
        k += 1;
      };
      // Drop the risen peak into the now-free slot k with an O(1) reference swap.
      let kk = Nat32.toNat(k);
      let tmp = hasher[kk];
      hasher[kk] := carry;
      carry := tmp;
      count += 1; // increment flips bits 0..k-1 to 0 and bit k to 1 — the new occupancy
    };

    // A power-of-two count leaves exactly one peak — the root, at height l.
    hasher[l].readSum();
  };
};
