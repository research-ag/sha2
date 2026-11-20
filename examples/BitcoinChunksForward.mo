/// Example 10: CHUNKED verification of a Bitcoin block's transactions against
/// the block header's Merkle root — the same task as `BitcoinChunks.mo`
/// (Example 9), done the FORWARD way: a tree is grown from the left as the
/// chunks arrive, and each chunk is checked by closing that tree with the
/// uploader's proof and comparing with the root. One self-contained file: it
/// imports no other example.
///
/// === The tree ===
///
/// The binary counter of Example 5 (`BitcoinMerkle.mo`): slot k holds the
/// peak of height k, and the 1-bits of the leaf count say which slots are
/// occupied. A new leaf climbs through the trailing 1-bits of the count,
/// merging with the peak it finds at each, `dSHA(peak ++ node)`, and comes to
/// rest at the first 0-bit.
///
/// Unlike Example 5, every leaf is loaded into a `Hasher` when it is added
/// (`loadBlob32`), and from there on it is a node like any other. Example 5
/// lets a leaf without a partner wait as a `Blob` and fuses two leaves
/// straight from their Blobs, which is about 1.7% cheaper for this verifier
/// but needs a case of its own for the waiting leaf in `add`, in closing the
/// tree, in the checks for equal siblings and in undoing a chunk. Here the
/// rising node lives in a spare hasher, the last of the pool; where it comes
/// to rest, the hasher that was in that slot becomes the spare.
///
/// === The check ===
///
/// A chunk brings the next leaves and the uploader's proof for the leaves that
/// are still to come: the peaks to the right of the chunk's last leaf, lowest
/// first. The proofs are those of Example 9, and `BitcoinChunkProof.mo`
/// computes them for both. The verifier then
///
///   1. adds the leaves of the chunk to its tree,
///   2. closes the tree: it computes the root from its own peaks on the left
///      and the proof's peaks on the right,
///   3. compares that with the block's root,
///   4. and keeps the grown tree if they are equal.
///
/// Every chunk is thus checked against the root itself. The proof is used
/// once and not stored; an empty proof says that the chunk is the last one.
///
/// === Closing the tree ===
///
/// This is the root computation of Example 5 with one more case. Start from
/// the lowest peak and go up. At every height the node in hand meets
///
///   - a peak of the tree on its LEFT, if the leaf count has a 1-bit there,
///   - else the next peak of the proof on its RIGHT,
///   - else nothing: it is the last node of its level, in the gap after the
///     last leaf, and Bitcoin pairs it with itself.
///
/// The node in hand lives in the spare hasher, so the peaks of the tree are
/// only read and the tree goes on growing afterwards. The peaks of the proof
/// are combined straight from their Blobs (`combineStateBlob32`), without
/// being loaded anywhere.
///
/// === Equal siblings ===
///
/// A valid block never has two sibling subtrees that hash alike (that would
/// be a repeated transaction, which consensus forbids, or a collision). The
/// verifier rejects a chunk on any such pair, in the three places where two
/// siblings are combined:
///
///   1. in `add`, where two nodes of the tree are merged,
///   2. in closing, where the node in hand meets a peak of the tree,
///   3. in closing, where it meets a peak of the proof.
///
/// Nothing valid is rejected, and it buys what it buys in Example 9: a proof
/// may not contain a peak that Bitcoin's rule would duplicate, so proofs are
/// minimal and the LAST chunk is recognised by an EMPTY proof; and a mutated
/// block — a tail of the block uploaded twice, CVE-2012-2459 — is rejected
/// where the copy meets its original.
///
/// Fewer checks would do for these two purposes. A mutated block has its
/// equal pair on the right edge of the finished tree, and a peak that
/// Bitcoin's rule would duplicate is always among the highest of a proof. So
/// it would be enough to check
///
///   - (1) for the last leaf of the last chunk only, the one that comes with
///     an empty proof,
///   - (2) only when closing with an empty proof,
///   - (3) only for the highest peak of the proof.
///
/// The checks at all other merges reject a block that repeats a transaction
/// elsewhere, which no other list shares its root with. They are kept: they
/// cost little, and checking every pair of siblings is what Bitcoin Core does.
///
/// === A rejected chunk ===
///
/// The leaves are added to the tree before the check can fail. To leave the
/// verifier unchanged by a bad chunk, the peaks are copied aside first and
/// copied back on failure (a handful of 32-byte states per chunk). A canister
/// that TRAPS on a bad chunk needs no such copy: the trap rolls the call's
/// changes back.
///
/// === What this does NOT establish ===
///
/// As in Example 9: that the leaves are transaction ids and not the nodes of
/// a whole level of the tree. See there, and the security notes of the README.
///
/// === Cost ===
///
/// One node is hashed per leaf, as for building the tree once, plus one per
/// level for closing the tree, per chunk. That last part is what Example 9
/// does not pay, so for many small chunks Example 9 is the cheaper one.
/// Verification allocates nothing. Txids, proofs and the root are in
/// Bitcoin's INTERNAL byte order.

import Hasher "mo:sha2/Hasher/Sha256";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import VarArray "mo:core/VarArray";

module {
  /// The verifier's state. A static record; it can be declared `stable`.
  public type Verifier = {
    /// The block's Merkle root.
    root : Blob;
    /// The tree over the leaves accepted so far: slot k is the peak of height
    /// k, the last slot is the spare.
    hasher : [var Hasher.Hasher];
    /// Room to copy the peaks aside while a chunk is being checked.
    backup : [var Hasher.Hasher];
    /// The number of leaves accepted so far; its 1-bits are the peaks.
    var count : Nat64;
    /// Whether the last chunk has been accepted.
    var done : Bool;
  };

  /// A verifier for the block with Merkle root `root` (32 bytes, internal byte
  /// order), for blocks of at most 2^maxDepth transactions. Allocates
  /// `2 * maxDepth + 3` hashers: the slots 0 to maxDepth, the spare, and room
  /// to copy the slots aside.
  public func new(root : Blob, maxDepth : Nat) : Verifier {
    assert root.size() == 32 and maxDepth <= 62;
    {
      root;
      hasher = VarArray.tabulate<Hasher.Hasher>(maxDepth + 2, func(_) { Hasher.new() });
      backup = VarArray.tabulate<Hasher.Hasher>(maxDepth + 1, func(_) { Hasher.new() });
      var count = 0;
      var done = false;
    };
  };

  /// Whether the upload is complete: the last accepted chunk came with an
  /// empty proof, so no leaf can follow, and `count` is N, the block's
  /// transaction count. (That the leaves are transaction ids is taken for
  /// granted here, as in Example 9.)
  public func complete(self : Verifier) : Bool = self.done;

  func wellFormed(hashes : [Blob]) : Bool {
    var i = 0;
    while (i < hashes.size()) {
      if (hashes[i].size() != 32) return false;
      i += 1;
    };
    true;
  };

  // Add a leaf to the tree. False if two equal siblings would be merged, or
  // if the tree has no room for the leaf. The tree is then left half-updated;
  // the caller restores it.
  func add(self : Verifier, leaf : Blob) : Bool {
    let hasher = self.hasher;
    let spare = hasher.size() - 1 : Nat;
    let node = hasher[spare]; // the rising node
    node.loadBlob32(leaf);
    let count = self.count;
    // Carry: the node climbs through the trailing 1-bits of the count.
    var k : Nat64 = 0;
    while (((count >> k) & 1) == 1) {
      let peak = hasher[k.toNat()];
      if (peak.equalsState(node)) return false; // equal siblings (1)
      node.combineState(peak, node); // dSHA(peak ++ node)
      node.hashState(node); // -> double SHA
      k += 1;
    };
    // The node rests in slot k, and the hasher that was there is the spare.
    let kk = k.toNat();
    if (kk >= spare) return false; // more leaves than the tree has room for
    hasher[spare] := hasher[kk];
    hasher[kk] := node;
    self.count := count + 1;
    true;
  };

  // Close the tree with `proof`, the peaks to the right of its last leaf, and
  // compare with the root. Works in the spare hasher and only reads the
  // peaks. False on equal siblings, on a tree deeper than the capacity, and
  // on a different root.
  func closes(self : Verifier, proof : [Blob]) : Bool {
    let hasher = self.hasher;
    let count = self.count;
    let maxDepth = (hasher.size() - 2 : Nat).toNat64();
    let acc = hasher[hasher.size() - 1]; // the node in hand
    var i = 0; // the next peak of the proof
    // The lowest peak is a left child: its right sibling is the first peak of
    // the proof, or, if there is none, the peak itself.
    var k = Nat64.bitcountTrailingZero(count);
    let lowest = hasher[k.toNat()];
    if (i < proof.size()) {
      if (lowest.equalsBlob32(proof[i])) return false; // equal siblings (3)
      acc.combineStateBlob32(lowest, proof[i]);
      i += 1;
    } else {
      if (Nat64.bitcountNonZero(count) == 1) return lowest.equalsBlob32(self.root); // a single peak is the root
      acc.combineState(lowest, lowest);
    };
    acc.hashState(acc); // -> double SHA
    k += 1;
    // Upward: a peak of the tree on the left, else a peak of the proof on the
    // right, else, in the gap, the node itself.
    while ((count >> k) > 0 or i < proof.size()) {
      if (k >= maxDepth) return false;
      if (((count >> k) & 1) == 1) {
        let peak = hasher[k.toNat()];
        if (peak.equalsState(acc)) return false; // equal siblings (2)
        acc.combineState(peak, acc); // dSHA(peak ++ acc)
      } else if (i < proof.size()) {
        if (acc.equalsBlob32(proof[i])) return false; // equal siblings (3)
        acc.combineStateBlob32(acc, proof[i]); // dSHA(acc ++ peak)
        i += 1;
      } else {
        acc.combineState(acc, acc); // dSHA(acc ++ acc)
      };
      acc.hashState(acc); // -> double SHA
      k += 1;
    };
    k <= maxDepth and acc.equalsBlob32(self.root);
  };

  // Copy the peaks that a tree of `count` leaves holds from one pool to the
  // other: the slots at the 1-bits of the count.
  func copyPeaks(from : [var Hasher.Hasher], to : [var Hasher.Hasher], count : Nat64) {
    var bits = count;
    while (bits != 0) {
      let k = Nat64.bitcountTrailingZero(bits).toNat();
      to[k].loadState(from[k]);
      bits &= bits - 1; // on to the next peak
    };
  };

  /// Verify the next chunk of txids (32 bytes each, internal byte order) with
  /// the uploader's proof `next` for the leaves after the chunk (see
  /// `BitcoinChunkProof.mo`), and accept it if it checks out: `true` and the
  /// verifier advances; otherwise `false` and the verifier is unchanged. An
  /// empty `next` claims that the chunk is the last one. Allocation-free.
  public func verifyChunk(self : Verifier, txids : [Blob], next : [Blob]) : Bool {
    if (self.done or txids.size() == 0 or not wellFormed(txids) or not wellFormed(next)) return false;
    // To be able to undo: the peaks and the count.
    let count = self.count;
    copyPeaks(self.hasher, self.backup, count);
    // 1. Add the chunk.
    var ok = true;
    var j = 0;
    label adding while (j < txids.size()) {
      if (not self.add(txids[j])) {
        ok := false;
        break adding;
      };
      j += 1;
    };
    // 2. and 3. Close the tree with the proof and compare with the root.
    if (ok and self.closes(next)) {
      // 4. Keep the grown tree.
      self.done := next.size() == 0;
      return true;
    };
    copyPeaks(self.backup, self.hasher, count);
    self.count := count;
    false;
  };
};
