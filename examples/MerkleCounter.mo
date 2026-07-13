/// Example 2: the same Merkle root as `MerkleStack.mo`, built via the
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
/// === Height 0 is a pending Blob (the "delay" trick) ===
///
/// A height-0 peak is a raw leaf, and deserializing every leaf into a Hasher
/// (`loadBlob32`) would be wasteful. So height 0 is NOT a hasher slot — it is a
/// pending `?Blob` (bit 0 of the count: set iff a leaf is waiting). When its
/// partner arrives, the pair is fused straight from the two Blobs with
/// `combineBlob32` — no `loadBlob32`, exactly like the stack's leaf step — and
/// the resulting height-1 node carries up the *state* slots (heights >= 1).
/// This makes the counter as fast as the stack (a touch faster, since
/// `occupied = count's bits` + reference swaps beat the stack's `level[]`
/// updates).
///
/// === The two state tricks ===
///
///   * Hashers are MOVED by reference: the array is a `[var Hasher]`, so a risen
///     peak is dropped into its new slot with an O(1) SWAP, never a state copy.
///     One scratch `carry` hasher rides the carry up and is swapped into place.
///   * `combineBlob32` fuses a leaf pair; `combineState` merges two peaks. Both
///     leave the result in place with no intermediate `Blob`.
///
/// === Finalization: bag the peaks ===
///
/// For a power-of-two count the counter ends with a single peak — the root.
/// Otherwise one peak per set bit of the count remains; BAG them bottom-up:
/// `acc := SHA256(peak_k ++ acc)` for each occupied height `k` ascending, `acc`
/// starting as the lowest peak (the pending leaf, if one is waiting). Same
/// typical mountain-range finalization as `MerkleStack.mo` — identical roots
/// for identical leaves. (Bitcoin's duplicate-and-collapse variant is shown in
/// `BitcoinMerkle.mo`.)
///
/// SECURITY NOTE: the bagged root does not commit to the leaf count — the
/// same root arises from the same peak hashes at different heights, and a
/// leaf equal to an internal node value is trivially constructible (leaves
/// are arbitrary 32-byte values). Verifiers must be given n out of band (the
/// peak heights are exactly its bits). This is not RFC 6962 — see the full
/// note in `MerkleStack.mo`.

import Hasher "mo:sha2/Hasher/Sha256";
import VarArray "mo:core/VarArray";
import Nat32 "mo:core/Nat32";

module {
  /// Single-SHA256 Merkle root over `leaves` (each a 32-byte `Blob`), for ANY
  /// leaf count (>= 1). Equals `MerkleStack.merkleRoot` on the same leaves.
  /// Allocation-free except the returned root `Blob`.
  public func merkleRoot(leaves : [Blob]) : Blob {
    let n = leaves.size();
    assert n >= 1;
    // Height L = ceil(log2 n); slots 1..L can hold peaks.
    var l = 0;
    var pow = 1;
    while (pow < n) { pow *= 2; l += 1 };

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
          // carry is now a height-1 node; carry it up through occupied slots.
          var k : Nat32 = 1;
          while (((count >> k) & 1) == 1) {
            carry.combineState(hasher[Nat32.toNat(k)], carry);
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

    // Bag the peaks bottom-up: acc := SHA256(hasher[k] ++ acc) for each
    // occupied height k ascending. acc starts as the lowest peak — the pending
    // leaf (parked once, into the scratch) if bit 0 is set, else the lowest
    // occupied slot (taken by reference, no copy).
    var k : Nat32 = 1;
    var acc = carry;
    switch (pending) {
      case (?b) {
        // n == 1: the lone leaf is its own root — enforce the same 32-byte
        // leaf contract that combineBlob32 checks on the multi-leaf path.
        if (n == 1) { assert b.size() == 32; return b };
        carry.loadBlob32(b); // the only loadBlob32: once, at the finale
      };
      case (null) {
        while (((count >> k) & 1) == 0) { k += 1 };
        acc := hasher[Nat32.toNat(k)];
        k += 1;
      };
    };
    while (Nat32.toNat(k) <= l) {
      if (((count >> k) & 1) == 1) {
        acc.combineState(hasher[Nat32.toNat(k)], acc);
      };
      k += 1;
    };
    Hasher.readSum(acc);
  };
};
