/// Example 5: the BITCOIN Merkle root over txid leaves — the binary counter
/// of `MerkleCounter.mo` with double SHA256 and Bitcoin's collapse. Any leaf
/// count. Allocation-free.
///
/// Bitcoin's block Merkle tree differs from the generic tree in two ways:
///
///   1. Every node is a DOUBLE SHA256: `SHA256(SHA256(left ++ right))`. Each
///      combine is followed by `hashState(h, h)`, which re-hashes the node's
///      own digest in place — one extra compression block, still no `Blob`.
///   2. Odd nodes are DUPLICATED: whenever a tree level has an odd number of
///      nodes, the last one is paired with ITSELF. So the finalization is not
///      the typical bagging of `MerkleStack.mo`/`MerkleCounter.mo` — it is a
///      COLLAPSE that doubles its way up (see below).
///
/// === Step 1: build the mountain range (as in Example 3) ===
///
/// Identical to `MerkleCounter.mo` except for the double-SHA: leaf pairs fuse
/// with `combineBlob32` + `hashState` (height 0 is the pending `?Blob` — the
/// delay trick), carries merge with `combineState` + `hashState`, occupancy is
/// the bits of the leaf count, risen peaks swap by reference.
///
/// === Step 2: collapse, Bitcoin style ===
///
/// The peaks are finalized by walking the BITS of the leaf count from the
/// lowest set bit upward, with an accumulator `acc` rising one level per bit:
///
///   * `acc` starts as the LOWEST component — the pending leaf, or the peak at
///     the lowest set bit — and is doubled once: `acc := dSHA(acc ++ acc)`.
///     (Its level's node count `n >> k` is odd, so Bitcoin duplicates it.)
///   * Each higher bit: SET — a peak waits at this height, pair with it:
///     `acc := dSHA(hasher[k] ++ acc)`; CLEAR — no peak, the level's node
///     count is odd again, pair `acc` with itself: `acc := dSHA(acc ++ acc)`.
///
/// After the highest set bit one node — the root — remains. This reproduces
/// Bitcoin's per-level duplication exactly, without ever materializing a
/// level. (Above the lowest set bit, a level's node count is `(n >> k) + 1`
/// — the +1 is the dangling tail `acc` — so odd exactly when bit k is clear.)
///
/// The accumulator `acc` is slot 0 — free, thanks to the delay trick — so the
/// collapse only READS the peaks: the MMR remains valid afterwards, and one
/// can keep adding leaves and collapse again. The module exposes this as an
/// incremental API (`new`, `add`, `root`) alongside the one-shot convenience
/// `bitcoinMerkleRoot`.
///
/// Note how close this is to the typical bagging of `MerkleCounter.mo`: same
/// walk over the bits, same combine at every set bit. The Bitcoin collapse is
/// BAGGING PLUS SELF-PAIRING ON THE GAPS — bagging is height-agnostic and
/// simply skips clear bits, while Bitcoin materializes every level, so the
/// accumulator must climb one level per bit and can only cross a peakless
/// level by pairing with itself (plus once at the start, on its own level).
/// The extra cost is one dSHA per clear bit — bagging spends one compression
/// per SET bit of n, the collapse one per bit position up to the highest.
///
/// === Caveats (byte order, CVE) ===
///
///   * BYTE ORDER: txids and the returned root are in Bitcoin's INTERNAL byte
///     order (the raw double-SHA256 output). Block explorers and RPC display
///     them byte-REVERSED — reverse the 32 bytes to compare (see the mainnet
///     vectors in `test/verify.test.mo`).
///   * Duplicating the last node is the source of Bitcoin's CVE-2012-2459 (two
///     distinct leaf lists can yield the same root); callers must reject blocks
///     with duplicate txids in that position.
///
/// For raw (variable-length) transactions instead of ready txids, see
/// `BitcoinTxMerkle.mo`, which adds the `Digest` -> `Hasher` bridge in front of
/// the same tree.

import Hasher "mo:sha2/Hasher/Sha256";
import Base "CounterBase";
import Nat32 "mo:core/Nat32";

module {
  /// The MMR state — see `CounterBase.mo`, which holds the building machinery
  /// shared with `MerkleCounter.mo`. A static record — it can be declared
  /// `stable`.
  public type Mmr = Base.Mmr;

  /// Create an empty MMR with capacity for at least `maxLeaves` txid leaves
  /// (`floor(log2 maxLeaves) + 1` hashers — see `CounterBase.mo`). With
  /// `witness` the coinbase witness spine is captured as txids are added —
  /// extraction and verification live in `BitcoinWitness.mo` (Example 7).
  public func new(maxLeaves : Nat, witness : Bool) : Mmr = Base.new(maxLeaves, witness);

  /// Add one 32-byte txid leaf to the MMR (double SHA256 per node). Traps (on
  /// a slot index out of bounds) if the capacity chosen at `new` is exceeded.
  public func add(self : Mmr, leaf : Blob) = Base.add(self, leaf, true);

  /// The Bitcoin Merkle root over the txids added so far (>= 1): the collapse,
  /// walking the bits of the count from the lowest set bit upward, with slot 0
  /// — free, since the height-0 peak is the pending Blob — as the accumulator.
  /// No peak slot is written, so the MMR remains valid — keep adding leaves
  /// and collapse again for an updated root. Allocation-free except the
  /// returned root `Blob`.
  public func root(self : Mmr) : Blob {
    let hasher = self.hasher;
    let count = self.count;
    assert count >= 1;
    let acc = hasher[0];
    var k : Nat32 = 1;
    switch (self.pending) {
      case (?b) {
        // count == 1: by Bitcoin's convention the root is the txid itself —
        // still enforce the 32-byte contract that combineBlob32 checks above.
        if (count == 1) { assert b.size() == 32; return b };
        // Perform the delayed write of the height-0 peak — into the
        // accumulator — and pair it with itself: it is Bitcoin's odd last
        // node at level 0.
        acc.loadBlob32(b);
        acc.combineState(acc, acc);
      };
      case (null) {
        // A single peak (power-of-two count) is the root outright — leave it
        // untouched.
        while (((count >> k) & 1) == 0) { k += 1 };
        if (Nat32.bitcountNonZero(count) == 1) {
          return hasher[k.toNat()].readSum();
        };
        // The lowest peak doubles — into the accumulator: its level's node
        // count n >> k is odd, so Bitcoin pairs it with itself.
        let k0 = k.toNat();
        acc.combineState(hasher[k0], hasher[k0]);
        k += 1;
      };
    };
    acc.hashState(acc); // -> double SHA (completes the doubling)
    // Walk the remaining bits: set — pair acc with the waiting peak; clear —
    // the level's node count is odd again, pair acc with itself.
    while ((count >> k) > 0) {
      if (((count >> k) & 1) == 1) {
        acc.combineState(hasher[k.toNat()], acc); // dSHA(peak ++ acc)
      } else {
        acc.combineState(acc, acc); // duplicate: dSHA(acc ++ acc)
      };
      acc.hashState(acc); // -> double SHA
      k += 1;
    };
    acc.readSum();
  };

  /// Bitcoin (double-SHA256) Merkle root over `txids` (each a 32-byte `Blob`,
  /// in internal byte order), for ANY leaf count (>= 1), in one shot.
  /// Allocation-free except the returned root `Blob`.
  public func bitcoinMerkleRoot(txids : [Blob]) : Blob {
    assert txids.size() >= 1;
    let mmr = new(txids.size(), false);
    for (leaf in txids.values()) {
      mmr.add(leaf);
    };
    mmr.root();
  };
};
