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
    // Height L = floor(log2 n) — the highest set bit the leaf count can reach,
    // i.e. the highest possible peak height. l + 1 is the bit length of n: one
    // slot per bit of the count, slot k holding the height-k peak that bit k
    // asserts. (Slot 0's write is delayed — see the header.)
    var l = 0;
    var pow = 1;
    while (pow * 2 <= n) { pow *= 2; l += 1 };

    let hasher = VarArray.tabulate<Hasher.Hasher>(l + 1, func(_) { Hasher.new() });
    var count : Nat32 = 0; // bit k answers "is hasher[k] occupied?"
    var pending : ?Blob = null; // the height-0 peak, its slot-0 write delayed

    for (leaf in leaves.values()) {
      switch (pending) {
        case (null) { pending := ?leaf }; // hold this leaf; pair it with the next
        case (?leaf0) {
          pending := null;
          // Fuse the pair straight from the two Blobs — no loadBlob32. The
          // height-1 node is built in slot 0, free since bit 0 just cleared.
          hasher[0].combineBlob32(leaf0, leaf);
          // Carry: the rising node climbs the slots — the height-(k+1) node is
          // built in slot k by merging the peak there with the node from below.
          var k : Nat32 = 1;
          while (((count >> k) & 1) == 1) {
            let kk = Nat32.toNat(k);
            hasher[kk].combineState(hasher[kk], hasher[kk - 1]);
            k += 1;
          };
          // The carry stopped at a clear bit: slot k is free, and the finished
          // height-k node sits one below it — swap it into its slot.
          let kk = Nat32.toNat(k);
          let tmp = hasher[kk];
          hasher[kk] := hasher[kk - 1];
          hasher[kk - 1] := tmp;
        };
      };
      count += 1;
    };

    // Perform the delayed write: a still-pending leaf is the height-0 peak —
    // put it into slot 0 (the only loadBlob32), for the bagging to pick up
    // like any other peak.
    switch (pending) {
      case (?b) {
        // n == 1: the lone leaf is its own root — enforce the same 32-byte
        // leaf contract that combineBlob32 checks on the multi-leaf path.
        if (n == 1) { assert b.size() == 32; return b };
        hasher[0].loadBlob32(b);
      };
      case (null) {};
    };

    // Bag the peaks bottom-up: acc := SHA256(hasher[k] ++ acc) for each
    // occupied height k ascending, acc starting as the lowest peak (taken by
    // reference, no copy).
    var k : Nat32 = 0;
    while (((count >> k) & 1) == 0) { k += 1 };
    let acc = hasher[Nat32.toNat(k)];
    k += 1;
    while (Nat32.toNat(k) <= l) {
      if (((count >> k) & 1) == 1) {
        acc.combineState(hasher[Nat32.toNat(k)], acc);
      };
      k += 1;
    };
    Hasher.readSum(acc);
  };
};
