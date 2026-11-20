/// Example 11: CHUNKED verification of a Bitcoin block's transactions against
/// the block header's Merkle root, the FORWARD way — `BitcoinChunksForward.mo`
/// (Example 10) once more, as one self-contained file and WITHOUT the pending
/// leaf of Example 5. It imports no other example: the tree it needs is
/// written out here.
///
/// === What is different from Example 10 ===
///
/// Example 10 keeps the tree of Example 5, in which a leaf without a partner
/// waits as a `Blob` and two leaves are fused straight from their Blobs. Here
/// every leaf is loaded into a `Hasher` when it is added (`loadBlob32`), and
/// from there on it is a node like any other:
///
///   - `add` is one loop from height 0 up, with one check for equal siblings;
///   - closing the tree starts from the lowest peak in every case, where
///     Example 10 has a second start for the pending leaf;
///   - there are three kinds of check for equal siblings instead of four: the
///     last leaf meeting the first peak of the proof is no longer a case of
///     its own;
///   - undoing a rejected chunk has only peaks and a count to restore.
///
/// It costs one more `Hasher` and more instructions per leaf: loading two
/// leaves costs more than combining two hasher states saves over combining
/// two Blobs.
///
/// === The tree ===
///
/// The binary counter of Example 5: slot k holds the peak of height k, and the
/// 1-bits of the leaf count say which slots are occupied, bit 0 included. A
/// new leaf is loaded into a spare hasher, the last of the pool, and climbs
/// through the trailing 1-bits of the count, merging with the peak it finds at
/// each, `dSHA(peak ++ node)`. Where it comes to rest, the hasher that was in
/// that slot becomes the spare.
///
/// === The check ===
///
/// As in Example 10. A chunk brings the next leaves and the uploader's proof
/// for the leaves still to come, the peaks to the right of the chunk's last
/// leaf, lowest first (`BitcoinChunkProof.mo` computes them). The verifier
///
///   1. adds the leaves of the chunk to its tree,
///   2. closes the tree: starting from the lowest peak and going up, the node
///      in hand meets a peak of the tree on its LEFT where the leaf count has
///      a 1-bit, else the next peak of the proof on its RIGHT, else nothing —
///      then it is the last node of its level, and Bitcoin pairs it with
///      itself,
///   3. compares the result with the block's root,
///   4. and keeps the grown tree if they are equal.
///
/// Closing works in the spare hasher and only reads the peaks, so the tree
/// goes on growing afterwards. The proof's peaks are combined straight from
/// their Blobs. An empty proof says that the chunk is the last one.
///
/// === Equal siblings ===
///
/// A valid block never has two sibling subtrees that hash alike. The verifier
/// rejects a chunk on any such pair, in the three places where two siblings
/// are combined:
///
///   1. in `add`, where two nodes of the tree are merged,
///   2. in closing, where the node in hand meets a peak of the tree,
///   3. in closing, where it meets a peak of the proof.
///
/// That makes proofs minimal, lets the last chunk be recognised by its empty
/// proof, and rejects mutated blocks (CVE-2012-2459). See Example 10 for the
/// reasons, and for which of these checks could be left out.
///
/// === A rejected chunk, and what is not established ===
///
/// As in Example 10: the peaks are copied aside before a chunk is added and
/// copied back if it is rejected, which a canister that traps on a bad chunk
/// can do without; and the check does not establish that the leaves are
/// transaction ids rather than the nodes of a whole level (see Example 9 and
/// the security notes of the README).
///
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
