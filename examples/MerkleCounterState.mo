/// Example 3: the binary-counter Merkle root of `MerkleCounter.mo`, but over
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
/// === Finalization ===
///
/// Bag the peaks bottom-up exactly as in `MerkleCounter.mo`; bit 0 of the count
/// now refers to the parked leaf in slot 0. Identical roots to
/// `MerkleStack.mo`/`MerkleCounter.mo` for leaves holding the same 32 bytes —
/// including the security caveat: the bagged root does not commit to the leaf
/// count; verifiers must be given n out of band (see the note in
/// `MerkleStack.mo`).

import Hasher "../src/Hasher/Sha256";
import VarArray "mo:core/VarArray";
import Nat32 "mo:core/Nat32";

module {
  /// Single-SHA256 Merkle root over `leaves`, each the 32-byte STATE of a
  /// `Hasher`, for ANY leaf count (>= 1). The leaves are read-only. Equals
  /// `MerkleStack.merkleRoot`/`MerkleCounter.merkleRoot` on the same 32-byte
  /// leaf values. Allocation-free except the returned root `Blob`.
  public func merkleRoot(leaves : [Hasher.Hasher]) : Blob {
    let n = leaves.size();
    assert n >= 1;
    // Height L = ceil(log2 n); slots 0..L can hold peaks (slot 0 = parked leaf).
    var l = 0;
    var pow = 1;
    while (pow < n) { pow *= 2; l += 1 };

    let hasher = VarArray.tabulate<Hasher.Hasher>(l + 1, func(_) { Hasher.new() });
    var carry = Hasher.new();
    var count : Nat32 = 0;

    for (leaf in leaves.values()) {
      if ((count & 1) == 0) {
        // Height 0 empty: capture this leaf there (the only copy, every other leaf).
        hasher[0].loadState(leaf);
      } else {
        // Height 0 occupied: combine the leaf directly from the input (no copy).
        carry.combineState(hasher[0], leaf);
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
      count += 1;
    };

    // Bag the peaks bottom-up: acc := SHA256(hasher[k] ++ acc) for each
    // occupied height k ascending, acc starting as the lowest peak (bit 0 =
    // the parked odd leaf). All by reference — no copies.
    var k : Nat32 = 0;
    while (((count >> k) & 1) == 0) { k += 1 };
    var acc = hasher[Nat32.toNat(k)];
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
