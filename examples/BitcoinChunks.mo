/// Example 8: CHUNKED verification of a Bitcoin block's transactions against
/// the block header's Merkle root, chunk by chunk, with no chunk trusted and
/// without ever holding the tree. Allocation-free verification.
///
/// === The setting ===
///
/// A canister receives the N transactions (or txids) of a block in chunks and
/// knows only the header's Merkle root. It wants to reject a bad chunk on
/// arrival, within one message's instruction budget, rather than discover at
/// the end that the root does not match — and it wants to know when the last
/// chunk has arrived.
///
/// === Mirrored peaks: the right-hand MMR ===
///
/// The Bitcoin tree over N leaves is padded to a depth n. For a prefix of M
/// leaves, consider the aligned subtrees that tile the REST, [M, 2^n), walking
/// right from M: their sizes grow, they are the 1-bits of 2^n - M, and they are
/// the right siblings of leaf M - 1's ancestors. Their hashes are the peaks of
/// an MMR grown from the RIGHT instead of the left — call it P_M. Subtrees that
/// lie entirely beyond the real leaves are, by Bitcoin's rule, duplicates of
/// the node to their left and are left out, so P_M holds only the tiles that
/// contain real leaves; P_0 is the root alone, P_N is empty.
///
/// === The check: close the gap from both sides ===
///
/// The verifier stores M and P_M (at most log N hashes; initially 0 and the
/// root). A chunk brings the leaves [M, M') and the uploader's P_M'. The
/// verifier grows P_M' leftward through the chunk, prepending the leaves
/// M' - 1, ..., M with the mirrored carry rule: a block at level k whose
/// position has bit k clear is a LEFT child and merges with its right sibling,
/// `dSHA(block ++ sibling)`, where the sibling is the tile of P_M' at that
/// level, or — if there is none — the block's own duplicate; a block whose
/// position has bit k set is a RIGHT child and waits as a tile for a left
/// sibling that lies further left. After leaf M the tiles are P_M again and
/// must equal the stored ones. Then M' and P_M' replace M and P_M.
///
///   [M, M') + P_M'  ->  P_M
///
/// Every leaf of the chunk is absorbed into a compared tile and every
/// compared tile was itself verified down to the root, so a wrong leaf, a
/// wrong or missing tile, and a wrong root are all caught. The check needs
/// neither N nor the depth: alignment is a property of the position alone. The forward MMR of
/// Examples 5-6 is never built; the state between chunks is M and P_M.
///
/// === Completeness and mutation ===
///
/// Before each merge the verifier rejects EQUAL siblings. In a valid block two
/// sibling subtrees never hash alike (that would be a duplicated transaction,
/// which consensus forbids, or a collision), so the check never rejects a
/// valid block, and it buys two things: a proof may not contain the tiles
/// that Bitcoin's rule would duplicate (so proofs are minimal, and the LAST
/// chunk is recognised by an EMPTY P_M', after which the number of uploaded
/// leaves is M'), and a
/// mutated block — a tail of the block uploaded twice, CVE-2012-2459 — is
/// rejected at the merge of the two copies, which Bitcoin Core detects the
/// same way.
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
/// With raw transactions (`verifyChunkTx`) every leaf is hashed here, and an
/// inner node can only pose as a transaction in the form of a 64-byte one,
/// the concatenation of its two children (CVE-2017-12842).
///
/// Closing this gap is LEFT TO THE APPLICATION, and one transaction is enough
/// for it. All leaves of the tree sit on one level, so it suffices to show
/// that a single leaf is a transaction: take the first one, the coinbase, in
/// full (its serialization without witness data), check that it hashes to the
/// first txid and that it is NOT 64 bytes long. Then it is not an inner node,
/// which fixes the depth of the tree and with it the meaning of every other
/// leaf and of `count`.
///
/// === Cost ===
///
/// One double-SHA node per leaf plus at most one duplicate per level per
/// chunk: the same hashing as building the tree once, with no per-chunk
/// ripple to the root. The verifier allocates nothing per chunk: a pool of
/// log N hashers holds the working tiles, the tiles of P_M' are loaded into
/// it, the merges use `combineState`, the comparisons `equalsState` and
/// `equalsBlob32`, and P_M' is kept by reference.
///
/// Proofs are produced off-chain by whoever has all leaves (`proof`,
/// `proofTx`): the tiles are nodes of the tree, read off its level arrays.
///
/// Caveats as in `BitcoinMerkle.mo`: txids and the root are in Bitcoin's
/// INTERNAL byte order; for raw transactions the txid hashes the serialization
/// WITHOUT witness data.

import Array "mo:core/Array";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import VarArray "mo:core/VarArray";
import Hasher "mo:sha2/Hasher/Sha256";
import Sha256 "mo:sha2/Sha256";

module {
  /// The verifier's state between chunks. A static record; it can be declared
  /// `stable`.
  public type Verifier = {
    /// Leaves accepted so far (M).
    var count : Nat64;
    /// P_M: the right-hand MMR of the rest, lowest tile first; `[root]` before
    /// the first chunk, `[]` once the block is complete.
    var proof : [Blob];
    /// Working tiles, slot k = level k, plus one spare that carries the rising
    /// block; allocated once.
    pool : [var Hasher.Hasher];
    /// For raw transactions: txid = SHA256(SHA256(tx)).
    d : Sha256.Digest;
  };

  /// A verifier for the block with Merkle root `root` (32 bytes, internal byte
  /// order), for blocks of at most 2^maxDepth transactions. Allocates the
  /// pool of `maxDepth + 2` hashers and one digest.
  public func new(root : Blob, maxDepth : Nat) : Verifier {
    assert root.size() == 32;
    {
      var count = 0;
      var proof = [root];
      pool = VarArray.tabulate<Hasher.Hasher>(maxDepth + 2, func(_) { Hasher.new() });
      d = Sha256.new();
    };
  };

  /// Whether the upload is complete: the last accepted chunk came with an
  /// empty proof, so no leaf can follow. Then `count` is the number of leaves
  /// uploaded. It is the block's transaction count only if the leaves are
  /// transaction ids and not the nodes of a whole level, which is for the
  /// application to check (see "What this does NOT establish" above).
  public func complete(self : Verifier) : Bool = self.count > 0 and self.proof.size() == 0;

  func wellFormed(tiles : [Blob]) : Bool {
    var i = 0;
    while (i < tiles.size()) {
      if (tiles[i].size() != 32) return false;
      i += 1;
    };
    true;
  };

  // The check [M, M') + next -> P_M. `raw` says whether the chunk holds raw
  // transactions (to be hashed into txids) or txids. On success the verifier
  // advances to M' and `next`; on failure it is unchanged.
  func verify(self : Verifier, chunk : [Blob], raw : Bool, next : [Blob]) : Bool {
    if (complete(self) or chunk.size() == 0 or not wellFormed(next)) return false;
    if (not raw and not wellFormed(chunk)) return false;
    let pool = self.pool;
    let levels = pool.size() - 1 : Nat; // slots 0 .. levels-1 hold tiles, slot `levels` is the spare
    let m = self.count;
    let m2 = m + chunk.size().toNat64();

    // Load the tiles of `next`, the right-hand MMR of [M', 2^n): the first
    // starts at M' and has the size of its alignment, each next one starts
    // where the previous ended.
    var present : Nat64 = 0; // bit k: a tile is held at level k
    var x = m2;
    var i = 0;
    while (i < next.size()) {
      let k = Nat64.bitcountTrailingZero(x);
      if (k.toNat() >= levels) return false;
      pool[k.toNat()].loadBlob32(next[i]);
      present |= 1 << k;
      x +%= 1 << k;
      i += 1;
    };

    // Prepend the chunk's leaves, last first. The rising block lives in the
    // spare slot `pool[levels]`; when it comes to rest as a tile, the slots are
    // swapped so that the spare slot always holds a free hasher.
    var j = chunk.size();
    while (j > 0) {
      j -= 1;
      let pos = m + j.toNat64();
      let carry = pool[levels];
      if (raw) {
        let d = self.d;
        d.reset();
        d.writeBlob(chunk[j]);
        d.closeDouble(); // d.state = txid
        carry.loadState(d.state);
      } else {
        carry.loadBlob32(chunk[j]);
      };
      var k : Nat64 = 0;
      label climb loop {
        if (pos == 0 and present == 0) {
          // The first chunk's last leaf has absorbed everything to its right:
          // the carry is the node over [0, 2^k), and at the depth of the tree
          // it is the root, the stored P_0.
          if (carry.equalsBlob32(self.proof[0])) {
            self.count := m2;
            self.proof := next;
            return true;
          };
        };
        if (k.toNat() >= levels) return false;
        if (((pos >> k) & 1) == 1) {
          // A right child: it waits, as the tile at this level, for its left
          // sibling (further left in the chunk, or in the prefix).
          let tmp = pool[k.toNat()];
          pool[k.toNat()] := carry;
          pool[levels] := tmp;
          present |= 1 << k;
          break climb;
        };
        // A left child: merge with the right sibling — the tile at this level,
        // or Bitcoin's duplicate of the block itself where no tile exists.
        if (((present >> k) & 1) == 1) {
          let sibling = pool[k.toNat()];
          // Equal siblings never occur in a valid block: this is a tile that
          // should have been left out, or a mutated block (CVE-2012-2459).
          if (carry.equalsState(sibling)) return false;
          carry.combineState(carry, sibling);
          present &= ^(1 << k);
        } else {
          carry.combineState(carry, carry);
        };
        carry.hashState(carry);
        k += 1;
      };
    };

    // M > 0 (the first chunk returned above): the tiles now present, lowest
    // first, must be the stored P_M.
    var k = 0;
    i := 0;
    while (k < levels) {
      if (((present >> k.toNat64()) & 1) == 1) {
        if (i >= self.proof.size() or not pool[k].equalsBlob32(self.proof[i])) return false;
        i += 1;
      };
      k += 1;
    };
    if (i != self.proof.size()) return false;
    self.count := m2;
    self.proof := next;
    true;
  };

  /// Verify the next chunk of txids (32 bytes each, internal byte order) with
  /// the uploader's proof `next` for the leaves after the chunk (see `proof`),
  /// and accept it if it checks out: `true` and the verifier advances;
  /// otherwise `false` and the verifier is unchanged. An empty `next` claims
  /// that the chunk is the last one. Allocation-free.
  public func verifyChunk(self : Verifier, txids : [Blob], next : [Blob]) : Bool = verify(self, txids, false, next);

  /// The same for a chunk of raw transactions (any length each): the txid of
  /// each is computed through the verifier's digest, with no allocation.
  public func verifyChunkTx(self : Verifier, txs : [Blob], next : [Blob]) : Bool = verify(self, txs, true, next);

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

  /// P_m for the block `txids`: the right-hand MMR of the leaves after the
  /// first `m` (1 <= m <= n), lowest tile first — the right siblings of leaf
  /// m - 1's ancestors that contain real transactions. Empty for m = n. What
  /// the uploader sends with the chunk that ends at m.
  public func proof(txids : [Blob], m : Nat) : [Blob] {
    let n = txids.size();
    assert 1 <= m and m <= n;
    let lv = levels(txids);
    var tiles : [Blob] = [];
    var k = 0;
    while (k + 1 < lv.size()) {
      let idx = (m - 1 : Nat) / (2 ** k);
      if (idx % 2 == 0) {
        if ((idx + 1) * (2 ** k) >= n) return tiles; // this and all higher siblings are duplicates
        tiles := tiles.concat([lv[k][idx + 1]]);
      };
      k += 1;
    };
    tiles;
  };

  /// The txid of a raw transaction (serialized without witness data).
  public func txid(tx : Blob) : Blob {
    let d = Sha256.new();
    d.writeBlob(tx);
    d.sumDouble();
  };

  /// `proof` for a block given as raw transactions.
  public func proofTx(txs : [Blob], m : Nat) : [Blob] = proof(txs.map<Blob, Blob>(txid), m);
};
