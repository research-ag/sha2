/// Example 7: the COINBASE INCLUSION PROOF — the "merkle branch" of SPV
/// proofs and mining protocols (Stratum) — for the Bitcoin trees of Examples
/// 5 and 6. The capture happens inside the shared bases (the `witness` flag
/// of `new`); this file holds the theory, the extraction and the receiver-
/// side verification.
///
/// A Bitcoin inclusion proof for the coinbase (the FIRST transaction) is the
/// sibling hash at every level of the tree: node (level k, index 1) for
/// k = 0 .. height-1, lowest first. Verification is a plain left-fold,
///
///   h := txid0;  for (sib in witness) h := dSHA(h ++ sib);  h == root
///
/// — the path node is always the LEFT input, because index 0 is even at
/// every level, and for the same reason the duplication rule never fires ON
/// the path (the siblings may internally be duplicated nodes; the verifier
/// does not care).
///
/// === Why the hashes are captured DURING building ===
///
/// The counter keeps only ~log n peaks, and SHA256 is one-way — a peak
/// cannot be reopened into its children. Let K = floor(log2 n).
///
///   * The hashes at levels 0 .. K-1: the node over txs [2^k, 2^(k+1)) is
///     produced by the normal MMR computation and exists in the machine for
///     exactly ONE carry step — it is the rising node of the FIRST merge at
///     height k, consumed by that very merge. Normally it is discarded then.
///     With the `witness` flag, two O(1) hooks in the bases copy it out in
///     that moment, into a pre-sized `[var Blob]` (slot k = level k, matching
///     the pre-allocated hasher pool): the level-0 sibling is the partner of
///     the first fuse (`count >> 1 == 0`), and the level-k sibling is the
///     rising node when the carry runs at an all-ones count
///     (`count >> (k+1) == 0`, i.e. count = 2^(k+1) - 1). Cost: at most
///     floor(log2 n) small Blob allocations over the WHOLE build — not per
///     leaf — and no extra `Hasher`s; the Blobs ARE the proof entries,
///     produced once, final on capture (the subtree over [2^k, 2^(k+1))
///     never changes again), and shared into every proof.
///   * The last hash (level K, none when n is a power of two): the sibling
///     of the highest peak covers all transactions from 2^K on. It depends
///     on all later transactions, so it cannot be captured early — and need
///     not be: it appears during the root computation, as the accumulator
///     just before the final step that combines it with the highest peak.
///     The extraction functions below run the root computation up to that
///     step (~2 log n compressions).
///
/// The extraction only READS the peaks (the collapse accumulates in the free
/// slot, exactly as the corresponding `root()`), so the MMR remains valid:
/// keep adding, take root and witness any time.
///
/// The capture hooks are finalization-agnostic — the single-SHA trees of
/// Examples 3 and 4 could capture the same hashes — but extraction is
/// finalization-specific, and only the Bitcoin variants are provided here.
///
/// Caveats as in `BitcoinMerkle.mo`: txids, root and witness are in
/// Bitcoin's INTERNAL byte order, and duplication is CVE-2012-2459 territory
/// — callers must reject blocks with duplicate txids in the vulnerable
/// position.

import Hasher "mo:sha2/Hasher/Sha256";
import Sha256 "mo:sha2/Sha256";
import CounterBase "CounterBase";
import CounterStateBase "CounterStateBase";
import Array "mo:core/Array";
import Nat64 "mo:core/Nat64";
import Runtime "mo:core/Runtime";
// VarArray is needed for dot notation on the witness array (w.sliceToArray).
import VarArray "mo:core/VarArray";

module {
  // The root computation of the components BELOW the highest peak, continuing
  // on `acc` (already holding the doubled lowest component, risen to level
  // `k`) up to level `kTop`, i.e. up to the step before the final one: `acc`
  // then holds the last hash of the proof. Returns the captured hashes ++ the
  // last hash.
  func assemble(
    w : [var Blob],
    hasher : [var Hasher.Hasher],
    count : Nat64,
    acc : Hasher.Hasher,
    kStart : Nat64,
    kTop : Nat,
  ) : [Blob] {
    var k = kStart;
    while (k.toNat() < kTop) {
      if (((count >> k) & 1) == 1) {
        acc.combineState(hasher[k.toNat()], acc); // dSHA(peak ++ acc)
      } else {
        acc.combineState(acc, acc); // duplicate: dSHA(acc ++ acc)
      };
      acc.hashState(acc); // -> double SHA
      k += 1;
    };
    Array.tabulate<Blob>(
      kTop + 1,
      func(i) = if (i < kTop) w[i] else acc.readSum(),
    );
  };

  /// The coinbase inclusion proof for a txid tree of Example 5
  /// (`BitcoinMerkle.new(_, true)`), over the txids added so far (>= 1):
  /// the sibling at each level, lowest first — `ceil(log2 count)` hashes.
  /// Empty for a single txid (it IS the root). Traps if the tree was built
  /// without witness capture. Allocates only the returned array, the closure
  /// that builds it, and the Blob of the last hash — the other entries share
  /// the captured Blobs. Leaves the MMR unchanged: keep adding, take the
  /// proof again.
  public func coinbaseWitness(self : CounterBase.Mmr) : [Blob] {
    let ?w = self.wit else Runtime.trap("BitcoinWitness: tree built without witness capture");
    let hasher = self.hasher;
    let count = self.count;
    assert count >= 1;
    if (count == 1) return []; // the lone txid is its own root
    let kTop = (63 - Nat64.bitcountLeadingZero(count)).toNat(); // floor(log2 count), the highest peak's height
    let acc = hasher[0]; // free: the height-0 leaf is the pending Blob
    var k : Nat64 = 1;
    switch (self.pending) {
      case (?b) {
        // The pending txid is the lowest component — Bitcoin's odd node at
        // level 0: load it and pair it with itself.
        acc.loadBlob32(b);
        acc.combineState(acc, acc);
      };
      case (null) {
        while (((count >> k) & 1) == 0) { k += 1 };
        // A single peak: every hash of the proof was captured during the
        // build.
        if (Nat64.bitcountNonZero(count) == 1) return w.sliceToArray(0, kTop);
        // The lowest peak doubles — its level's node count is odd.
        let k0 = k.toNat();
        acc.combineState(hasher[k0], hasher[k0]);
        k += 1;
      };
    };
    acc.hashState(acc); // -> double SHA
    assemble(w, hasher, count, acc, k, kTop);
  };

  /// The coinbase inclusion proof for a raw-transaction tree of Example 6
  /// (`BitcoinTxMerkle.new(_, true)`), over the transactions added so far
  /// (>= 1). Same output as `coinbaseWitness` for the same leaves; only the
  /// accumulator differs (the TOP slot — slot 0 holds the parked txid).
  public func coinbaseWitnessTx(self : CounterStateBase.Mmr) : [Blob] {
    let ?w = self.wit else Runtime.trap("BitcoinWitness: tree built without witness capture");
    let hasher = self.hasher;
    let count = self.count;
    assert count >= 1;
    // A single component — the lone txid (count == 1) or one peak: every hash
    // of the proof was captured during the build (none for a lone txid, which
    // is its own root).
    var k = Nat64.bitcountTrailingZero(count);
    let kTop = (63 - Nat64.bitcountLeadingZero(count)).toNat(); // floor(log2 count)
    if (Nat64.bitcountNonZero(count) == 1) return w.sliceToArray(0, kTop);
    let acc = hasher[hasher.size() - 1]; // the top slot — free below a full power of two
    // The lowest component doubles — its level's node count is odd.
    let k0 = k.toNat();
    acc.combineState(hasher[k0], hasher[k0]);
    acc.hashState(acc); // -> double SHA
    k += 1;
    assemble(w, hasher, count, acc, k, kTop);
  };

  // The verifier's fold: raise the path node in `h` through the witness,
  // h := dSHA(h ++ sib) — always the LEFT input, no duplication rule on the
  // coinbase path — and read the resulting root. The mixed combine reads each
  // sibling `Blob` directly; no staging copy, no scratch hasher.
  func foldUp(h : Hasher.Hasher, witness : [Blob]) : Blob {
    for (sib in witness.values()) {
      h.combineStateBlob32(h, sib);
      h.hashState(h); // -> double SHA
    };
    h.readSum();
  };

  // Every witness element must be a 32-byte hash, or `foldUp` would trap.
  func wellFormed(witness : [Blob]) : Bool = witness.all(func(sib : Blob) : Bool = sib.size() == 32);

  /// The RECEIVER side: verify a coinbase inclusion proof against the one
  /// 32-byte `root` the receiver holds, given the coinbase's `txid0` and the
  /// `witness` sent by the supplier. An empty witness asserts a
  /// single-transaction block: the txid must BE the root. Stateless — needs
  /// no `Mmr`; allocates one hasher and the folded root. A malformed proof (a
  /// `txid0` or witness element that is not 32 bytes) returns `false`.
  public func verifyTxid(txid0 : Blob, witness : [Blob], root : Blob) : Bool {
    if (txid0.size() != 32 or not wellFormed(witness)) return false;
    let h = Hasher.new();
    h.loadBlob32(txid0);
    foldUp(h, witness) == root;
  };

  /// The same, but from the RAW coinbase transaction: the receiver computes
  /// the txid itself — the realistic SPV/mining check, since the coinbase's
  /// CONTENT (height, payout, commitments) is what the proof is about. A
  /// witness element that is not 32 bytes returns `false`; `tx0` may have any
  /// length.
  public func verifyTx(tx0 : Blob, witness : [Blob], root : Blob) : Bool {
    if (not wellFormed(witness)) return false;
    let d = Sha256.new();
    d.writeBlob(tx0);
    d.close();
    let h = Hasher.new();
    h.hashState(d.state); // txid = SHA256(SHA256(tx0)), bridged, no Blob
    foldUp(h, witness) == root;
  };
};
