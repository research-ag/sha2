/// Example 9: CHUNKED verification of a Bitcoin block's transactions against
/// the block header's Merkle root, chunk by chunk, with no chunk trusted and
/// nothing kept but a few hashes. Built on the tree of `BitcoinMerkleRight.mo`
/// (Example 8), which is grown from the right.
///
/// === The problem ===
///
/// A canister receives the N transaction ids of a block in chunks and knows
/// only the Merkle root from the block header. It wants to reject a bad chunk
/// when it arrives — not to find out at the end that the root does not match
/// — and it wants to know when the last chunk has arrived.
///
/// === A proof is a set of peaks ===
///
/// Build the tree of the block from the right, as Example 8 does, and stop
/// when the leaves M .. N - 1 are in. What is left in the tree is a set of
/// peaks: together they stand for everything to the right of the first M
/// leaves. Call that set P_M, the PROOF for M, lowest peak first.
///
///   - P_0 is the root alone: every leaf is in, and one peak is left.
///   - P_N is empty: no leaf is in.
///
/// (Seen from the tree, the peaks of P_M are the right siblings of the
/// ancestors of leaf M - 1, as far as they contain real leaves.)
///
/// Computing the proofs is the uploader's side: see `BitcoinChunkProof.mo`,
/// which Example 10 shares.
///
/// === The check ===
///
/// The verifier stores M, the number of leaves accepted so far, and P_M;
/// initially 0 and the root. A chunk brings the leaves M .. M' - 1 and the
/// uploader's P_M'. The verifier then
///
///   1. starts a tree from P_M': it puts the peaks into their slots,
///   2. adds the leaves of the chunk to it, last to first, as Example 8 does,
///   3. compares the peaks that are left with the stored P_M,
///   4. and if they are equal, stores M' and P_M' in place of M and P_M.
///
///   P_M' + leaves M .. M' - 1  ->  P_M
///
/// Every leaf of the chunk ends up inside a peak that is compared, and every
/// stored peak was itself compared, chunk by chunk, back to the root. So a
/// wrong leaf, a wrong or missing peak and a wrong root are all caught.
///
/// === Where the peaks go ===
///
/// A proof is a list of hashes; the height of each follows from M' alone.
/// Walk to the right from position M': the first peak starts at M' and is as
/// large as that position allows (2^k places, k the number of trailing zeros
/// of M'), the next one starts where it ends, and so on, each larger than the
/// one before. A peak of 2^k places goes into slot k.
///
/// The tree of Example 8 also needs its counter, the number of leaf places to
/// the right of the leaves it holds, and for that the size of the tree.
/// Neither N nor the depth is given to the verifier, and it does not need the
/// true size, only one that is large enough for the chunk at hand: the
/// smallest power of two that has room for the M' leaves and for the peaks of
/// the proof, 2^n. The counter is then 2^n - M'. Where it claims a peak that
/// the proof does not have, that peak lies in the gap after the last leaf,
/// and Example 8 doubles there.
///
/// A tree that is in truth larger makes no difference to the chunk: only the
/// leaf at position 0 ever climbs to the top, and when that leaf is in the
/// chunk this n is the true depth — either the highest peak of the proof is
/// the root's right child, or the whole block is in the chunk.
///
/// === Completeness and mutation ===
///
/// Example 8 notes when two EQUAL siblings are merged (`mergedEqualSiblings`),
/// and the verifier rejects the chunk then. In a valid block two sibling
/// subtrees never hash alike (that would be a repeated transaction, which
/// consensus forbids, or a collision), so nothing valid is rejected, and it
/// buys two things:
///
///   - A proof may not contain a peak that Bitcoin's rule would duplicate, so
///     proofs are minimal, and the LAST chunk is recognised by an EMPTY P_M'.
///     Then M' = N.
///   - A mutated block — a tail of the block uploaded twice, CVE-2012-2459 —
///     is rejected where the copy meets its original, which is how Bitcoin
///     Core detects it too.
///
/// === What this does NOT establish: that the leaves are transactions ===
///
/// Bitcoin's tree does not mark leaves apart from inner nodes, and the header
/// commits to neither the depth nor the transaction count. So the nodes of
/// any whole level, uploaded as "txids", verify just as well as a shorter
/// block: the root's two children as a block of two, the root itself as a
/// block of one. No check on the hashes can tell. `verifyChunk` therefore
/// proves "these leaves, in this order and no others, hash to the root", and
/// the caller must know from elsewhere that they are transaction ids.
///
/// (A caller that computes the txids from raw transactions itself narrows
/// this: an inner node can then only pose as a transaction in the form of a
/// 64-byte one, the concatenation of its two children, CVE-2017-12842.)
///
/// Closing this gap is LEFT TO THE APPLICATION. One transaction is enough:
/// take the first one, the coinbase, in full (its serialization without
/// witness data), check that it hashes to the first txid and that it is NOT
/// 64 bytes long. A leaf at position 0 that is a real transaction fixes the
/// depth of the tree, and with it the level of every other leaf.
///
/// === Cost ===
///
/// One node is hashed per leaf, as for building the tree once: nothing ripples
/// to the root per chunk. `verifyChunk` allocates nothing — the hashers are
/// allocated once by `new`, the leaves and the proof's peaks are loaded into
/// them, and the uploader's proof is kept by reference.
///
/// Like Example 8, this example takes txids, 32-byte `Blob`s, not raw
/// transactions. Txids, proofs and the root are in Bitcoin's INTERNAL byte
/// order.

import Hasher "mo:sha2/Hasher/Sha256";
import Right "BitcoinMerkleRight";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";

module {
  /// The verifier's state between chunks. A static record; it can be declared
  /// `stable`.
  public type Verifier = {
    /// Leaves accepted so far (M).
    var count : Nat64;
    /// P_M, lowest peak first: `[root]` before the first chunk, `[]` once the
    /// block is complete.
    var proof : [Blob];
    /// The working tree of Example 8, started afresh from the uploader's
    /// proof for every chunk; its hashers are allocated once.
    tree : Right.Mmr;
  };

  /// A verifier for the block with Merkle root `root` (32 bytes, internal byte
  /// order), for blocks of at most 2^maxDepth transactions. Allocates
  /// `maxDepth + 2` hashers.
  public func new(root : Blob, maxDepth : Nat) : Verifier {
    assert root.size() == 32 and maxDepth <= 62;
    {
      var count = 0;
      var proof = [root];
      tree = Right.new(0, 2 ** maxDepth);
    };
  };

  /// Whether the upload is complete: the last accepted chunk came with an
  /// empty proof, so no leaf can follow, and `count` is N, the block's
  /// transaction count. (That the leaves are transaction ids is taken for
  /// granted here: see "What this does NOT establish" above.)
  public func complete(self : Verifier) : Bool = self.count > 0 and self.proof.size() == 0;

  func wellFormed(hashes : [Blob]) : Bool {
    var i = 0;
    while (i < hashes.size()) {
      if (hashes[i].size() != 32) return false;
      i += 1;
    };
    true;
  };

  // Start `tree` from the peaks `proof` of the leaves from position `m` on.
  // False if that takes a deeper tree than there are hashers for.
  func start(tree : Right.Mmr, m : Nat64, proof : [Blob]) : Bool {
    let maxDepth = (tree.hasher.size() - 2 : Nat).toNat64();
    var present : Nat64 = 0;
    var x = m; // where the next peak starts
    var i = 0;
    while (i < proof.size()) {
      let k = Nat64.bitcountTrailingZero(x); // it is as large as its position allows
      if (k >= maxDepth) return false;
      tree.hasher[k.toNat()].loadBlob32(proof[i]);
      present |= 1 << k;
      x += 1 << k;
      i += 1;
    };
    // The tree: the smallest power of two of places that holds the m leaves
    // and these peaks, which end at x.
    let depth = 64 - Nat64.bitcountLeadingZero(x - 1); // ceil(log2 x)
    if (depth > maxDepth) return false;
    tree.count := (1 << depth) - m;
    tree.present := present;
    tree.mergedEqualSiblings := false;
    true;
  };

  // Whether the peaks of `tree`, lowest first, are exactly `proof`.
  func hasPeaks(tree : Right.Mmr, proof : [Blob]) : Bool {
    var bits = tree.present;
    var i = 0;
    while (bits != 0) {
      if (i >= proof.size()) return false;
      let k = Nat64.bitcountTrailingZero(bits);
      if (not tree.hasher[k.toNat()].equalsBlob32(proof[i])) return false;
      bits &= bits - 1; // on to the next peak
      i += 1;
    };
    i == proof.size();
  };

  /// Verify the next chunk of txids (32 bytes each, internal byte order) with
  /// the uploader's proof `next` for the leaves after the chunk (see
  /// `BitcoinChunkProof.mo`),
  /// and accept it if it checks out: `true` and the verifier advances;
  /// otherwise `false` and the verifier is unchanged. An empty `next` claims
  /// that the chunk is the last one. Allocation-free.
  public func verifyChunk(self : Verifier, txids : [Blob], next : [Blob]) : Bool {
    if (complete(self) or txids.size() == 0 or not wellFormed(txids) or not wellFormed(next)) return false;
    let tree = self.tree;
    let m2 = self.count + txids.size().toNat64();
    // 1. Start a tree from the uploader's peaks.
    if (not start(tree, m2, next)) return false;
    // 2. Add the chunk to it, last leaf first.
    var j = txids.size();
    while (j > 0) {
      j -= 1;
      tree.add(txids[j]);
    };
    // Equal siblings never occur in a valid block: a peak that should have
    // been left out of the proof, or a mutated block (CVE-2012-2459).
    if (tree.mergedEqualSiblings) return false;
    // 3. The peaks that are left must be the stored proof.
    if (not hasPeaks(tree, self.proof)) return false;
    // 4. Advance.
    self.count := m2;
    self.proof := next;
    true;
  };
};
