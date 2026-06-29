/// Example: a Merkle root via the BINARY-COUNTER mountain range, allocation-free.
///
/// Same Bitcoin double-SHA256 tree as `Merkle.mo`, built with different (and
/// arguably simpler) bookkeeping. Instead of a packed STACK of peaks plus a
/// parallel `level[]` array, this keeps a SPARSE array indexed by HEIGHT:
/// `hasher[k]` holds the height-`k` peak, or is unused. Adding a leaf is binary
/// increment with carry — exactly a binary counter, where a "carry" is a
/// `combineState`. The occupied slots are the binary representation of the leaf
/// count, so there is no `level[]` array (an `occupied[]` flag array just makes
/// the carry loop readable).
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

import Hasher "../src/Hasher/Sha256";
import VarArray "mo:core/VarArray";

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

    // hasher[0..l]: height-indexed peak slots. occupied[k]: does hasher[k] hold
    // a peak? carry: one scratch hasher that rides each carry up the heights.
    let hasher = VarArray.tabulate<Hasher.Hasher>(l + 1, func(_) { Hasher.new() });
    let occupied = VarArray.repeat<Bool>(false, l + 1);
    var carry = Hasher.new();

    for (leaf in leaves.values()) {
      carry.loadBlob32(leaf); // park the leaf hash as a height-0 peak (no re-hash)
      var k = 0;
      while (occupied[k]) {
        // Carry up: merge the height-k peak with the rising carry, one level up.
        carry.combineState(hasher[k], carry); // SHA256(hasher[k] ++ carry)
        carry.hashState(carry); // -> double-SHA (drop for a single-SHA tree)
        occupied[k] := false;
        k += 1;
      };
      // Drop the risen peak into the now-free slot k with an O(1) reference swap.
      let tmp = hasher[k];
      hasher[k] := carry;
      carry := tmp;
      occupied[k] := true;
    };

    // A power-of-two count leaves exactly one peak — the root, at height l.
    hasher[l].readSum();
  };
};
