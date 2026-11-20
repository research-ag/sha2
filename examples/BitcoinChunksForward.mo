/// Example 10: CHUNKED verification of a Bitcoin block's transactions against
/// the block header's Merkle root — the same task as `BitcoinChunks.mo`
/// (Example 9), done the FORWARD way: the tree of `BitcoinMerkle.mo` (Example
/// 5) is grown from the left as the chunks arrive, and each chunk is checked
/// by closing that tree with the uploader's proof and comparing with the root.
///
/// === The check ===
///
/// The verifier keeps the tree of Example 5 over the leaves accepted so far:
/// a few peaks, as many as the leaf count has 1-bits. A chunk brings the next
/// leaves and the uploader's proof for the leaves that are still to come: the
/// peaks to the right of the chunk's last leaf, lowest first (see Example 9,
/// "A proof is a set of peaks" — the proofs are the same). The verifier then
///
///   1. adds the leaves of the chunk to its tree, as Example 5 does,
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
/// As in Example 5 the node in hand lives in slot 0, which is free, so the
/// peaks of the tree are only read and the tree goes on growing afterwards.
/// The peaks of the proof are combined straight from their Blobs
/// (`combineStateBlob32`), without being loaded anywhere.
///
/// === Equal siblings ===
///
/// A valid block never has two sibling subtrees that hash alike (that would
/// be a repeated transaction, which consensus forbids, or a collision). The
/// verifier rejects a chunk on any such pair, in all four places where two
/// siblings are combined:
///
///   1. in `add`, where two nodes of the tree are merged,
///   2. in closing, where the node in hand meets a peak of the tree,
///   3. in closing, where it meets a peak of the proof,
///   4. in closing, where the last leaf itself meets the first peak of the
///      proof.
///
/// Nothing valid is rejected, and it buys what it buys in Example 9: a proof
/// may not contain a peak that Bitcoin's rule would duplicate, so proofs are
/// minimal and the LAST chunk is recognised by an EMPTY proof; and a mutated
/// block — a tail of the block uploaded twice, CVE-2012-2459 — is rejected
/// where the copy meets its original. The shared tree code of Example 5
/// (`CounterBase.mo`) has no such check, so this example has its own `add`.
///
/// Fewer checks would do for these two purposes. A mutated block has its
/// equal pair on the right edge of the finished tree, and a peak that
/// Bitcoin's rule would duplicate is always among the highest of a proof. So
/// it would be enough to check
///
///   - (1) for the last leaf of the last chunk only, the one that comes with
///     an empty proof,
///   - (2) only when closing with an empty proof,
///   - (3) and (4) only for the highest peak of the proof.
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
/// level for closing the tree, per chunk. Verification allocates nothing.
/// Txids, proofs and the root are in Bitcoin's INTERNAL byte order.

import Hasher "mo:sha2/Hasher/Sha256";
import Sha256 "mo:sha2/Sha256";
import BitcoinMerkle "BitcoinMerkle";
import Array "mo:core/Array";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import VarArray "mo:core/VarArray";

module {
  /// The verifier's state. A static record; it can be declared `stable`.
  public type Verifier = {
    /// The block's Merkle root.
    root : Blob;
    /// The tree of Example 5 over the leaves accepted so far; `mmr.count` is
    /// their number.
    mmr : BitcoinMerkle.Mmr;
    /// Room to copy the peaks aside while a chunk is being checked.
    backup : [var Hasher.Hasher];
    /// Whether the last chunk has been accepted.
    var done : Bool;
  };

  /// A verifier for the block with Merkle root `root` (32 bytes, internal byte
  /// order), for blocks of at most 2^maxDepth transactions. Allocates
  /// `2 * (maxDepth + 1)` hashers.
  public func new(root : Blob, maxDepth : Nat) : Verifier {
    assert root.size() == 32 and maxDepth <= 62;
    let mmr = BitcoinMerkle.new(2 ** maxDepth, false);
    {
      root;
      mmr;
      backup = VarArray.tabulate<Hasher.Hasher>(mmr.hasher.size(), func(_) { Hasher.new() });
      var done = false;
    };
  };

  /// Whether the upload is complete: the last accepted chunk came with an
  /// empty proof, so no leaf can follow, and `mmr.count` is N, the block's
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

  // `add` of Example 5 (`CounterBase.add` with double SHA256), with the check
  // for equal siblings: false if two equal siblings would be merged, or if
  // the capacity is exceeded. The tree is then left half-updated; the caller
  // restores it.
  func addChecked(self : BitcoinMerkle.Mmr, leaf : Blob) : Bool {
    let hasher = self.hasher;
    switch (self.pending) {
      case (null) { self.pending := ?leaf }; // hold this leaf; pair it with the next
      case (?leaf0) {
        self.pending := null;
        if (leaf0 == leaf) return false; // equal siblings (1)
        hasher[0].combineBlob32(leaf0, leaf);
        hasher[0].hashState(hasher[0]);
        var k : Nat64 = 1;
        while (((self.count >> k) & 1) == 1) {
          let kk = k.toNat();
          if (hasher[kk].equalsState(hasher[kk - 1])) return false; // equal siblings (1)
          hasher[kk].combineState(hasher[kk], hasher[kk - 1]);
          hasher[kk].hashState(hasher[kk]);
          k += 1;
        };
        let kk = k.toNat();
        if (kk >= hasher.size()) return false; // more leaves than the tree has room for
        let tmp = hasher[kk];
        hasher[kk] := hasher[kk - 1];
        hasher[kk - 1] := tmp;
      };
    };
    self.count += 1;
    true;
  };

  // Close the tree with `proof`, the peaks to the right of its last leaf, and
  // compare with `root`. Only reads the peaks of the tree: slot 0 holds the
  // node in hand. False on equal siblings, on a tree deeper than the capacity,
  // and on a different root.
  func closes(mmr : BitcoinMerkle.Mmr, proof : [Blob], root : Blob) : Bool {
    let hasher = mmr.hasher;
    let count = mmr.count;
    let maxDepth = (hasher.size() - 1 : Nat).toNat64();
    let acc = hasher[0];
    var i = 0; // the next peak of the proof
    var k : Nat64 = 1; // the height of the node in hand
    switch (mmr.pending) {
      case (?leaf) {
        // The last leaf is a left child: its right sibling is the first peak
        // of the proof, or, if there is none, the leaf itself.
        if (i < proof.size()) {
          if (leaf == proof[i]) return false; // equal siblings (4)
          acc.combineBlob32(leaf, proof[i]);
          i += 1;
        } else {
          if (count == 1) return leaf == root; // a block of one: the txid is the root
          acc.combineBlob32(leaf, leaf);
        };
      };
      case (null) {
        // The lowest peak is a left child, likewise.
        k := Nat64.bitcountTrailingZero(count);
        let lowest = hasher[k.toNat()];
        if (i < proof.size()) {
          if (lowest.equalsBlob32(proof[i])) return false; // equal siblings (3)
          acc.combineStateBlob32(lowest, proof[i]);
          i += 1;
        } else {
          if (Nat64.bitcountNonZero(count) == 1) return lowest.equalsBlob32(root); // a single peak is the root
          acc.combineState(lowest, lowest);
        };
        k += 1;
      };
    };
    acc.hashState(acc); // -> double SHA
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
    k <= maxDepth and acc.equalsBlob32(root);
  };

  // Copy the peaks that a tree of `count` leaves holds from one pool to the
  // other: the slots at the 1-bits of the count above bit 0.
  func copyPeaks(from : [var Hasher.Hasher], to : [var Hasher.Hasher], count : Nat64) {
    var bits = count & ^1;
    while (bits != 0) {
      let k = Nat64.bitcountTrailingZero(bits).toNat();
      to[k].loadState(from[k]);
      bits &= bits - 1; // on to the next peak
    };
  };

  /// Verify the next chunk of txids (32 bytes each, internal byte order) with
  /// the uploader's proof `next` for the leaves after the chunk (see `proof`),
  /// and accept it if it checks out: `true` and the verifier advances;
  /// otherwise `false` and the verifier is unchanged. An empty `next` claims
  /// that the chunk is the last one. Allocation-free.
  public func verifyChunk(self : Verifier, txids : [Blob], next : [Blob]) : Bool {
    if (self.done or txids.size() == 0 or not wellFormed(txids) or not wellFormed(next)) return false;
    let mmr = self.mmr;
    // To be able to undo: the peaks, the count and the pending leaf.
    let count = mmr.count;
    let pending = mmr.pending;
    copyPeaks(mmr.hasher, self.backup, count);
    // 1. Add the chunk.
    var ok = true;
    var j = 0;
    label adding while (j < txids.size()) {
      if (not mmr.addChecked(txids[j])) {
        ok := false;
        break adding;
      };
      j += 1;
    };
    // 2. and 3. Close the tree with the proof and compare with the root.
    if (ok and closes(mmr, next, self.root)) {
      // 4. Keep the grown tree.
      self.done := next.size() == 0;
      return true;
    };
    copyPeaks(self.backup, mmr.hasher, count);
    mmr.count := count;
    mmr.pending := pending;
    false;
  };

  // ---------------------------------------------------------------------------
  // The prover (off-chain, from all leaves)
  // ---------------------------------------------------------------------------

  // Bitcoin's level arrays: level 0 the txids, each next level the double
  // SHA256 of pairs, the last node of an odd level paired with itself.
  func levels(txids : [Blob]) : [[Blob]] {
    var all : [[Blob]] = [txids];
    var level = txids;
    while (level.size() > 1) {
      let len = level.size();
      let next = Array.tabulate<Blob>(
        (len + 1) / 2,
        func(i) {
          let d = Sha256.new();
          d.writeBlob(level[2 * i]);
          d.writeBlob(level[if (2 * i + 1 < len) 2 * i + 1 else len - 1]);
          d.sumDouble();
        },
      );
      all := all.concat([next]);
      level := next;
    };
    all;
  };

  /// The proof for the first `m` leaves of the block `txids` (0 <= m <= n):
  /// the peaks to the right of leaf m - 1, lowest first — the right siblings
  /// of its ancestors that contain real transactions. The root alone for
  /// m = 0, empty for m = n. What the uploader sends with the chunk that ends
  /// at m. The same proofs as in Example 9.
  public func proof(txids : [Blob], m : Nat) : [Blob] {
    let n = txids.size();
    assert n >= 1 and m <= n;
    let lv = levels(txids);
    if (m == 0) return lv[lv.size() - 1];
    var peaks : [Blob] = [];
    var k = 0;
    while (k + 1 < lv.size()) {
      let idx = (m - 1 : Nat) / (2 ** k);
      if (idx % 2 == 0) {
        if ((idx + 1) * (2 ** k) >= n) return peaks; // this and all higher siblings are duplicates
        peaks := peaks.concat([lv[k][idx + 1]]);
      };
      k += 1;
    };
    peaks;
  };
};
