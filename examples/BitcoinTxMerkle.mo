/// Example 6: the Bitcoin Merkle root of `BitcoinMerkle.mo`, but from RAW
/// (variable-length) transactions instead of ready txid Blobs. Any count.
/// Allocation-free.
///
/// A txid is the double SHA256 of the raw transaction bytes. `BitcoinMerkle.mo`
/// takes those 32-byte txids as given; this example adds the front half —
/// turning raw transactions into leaves — and is where the `Digest` -> `Hasher`
/// bridge pays off.
///
/// === Two engines, two roles ===
///
///   * ONE `Digest` (reused, `reset` between transactions) absorbs each
///     variable-length transaction — only it has a message buffer, so only it
///     can take an arbitrary-length input.
///   * The binary counter of `BitcoinMerkle.mo` holds the peaks and combines
///     them with `combineState` + `hashState`, occupancy = the bits of the
///     leaf count, risen peaks swapped by reference.
///
/// === The leaf pair: two lifetimes, two exits ===
///
/// With raw transactions the pending height-0 leaf cannot be a `?Blob` — the
/// txid exists only as the digest's STATE, and materializing it would allocate.
/// Instead the counter's slot 0 holds it (as in `MerkleCounterState.mo`), and
/// the two leaves of a pair take different exits out of the `Digest`:
///
///   * The FIRST leaf must SURVIVE while the second is computed, so the bridge
///     produces it directly INTO slot 0 — `close()` leaves SHA256(tx) in the
///     digest, and `hashState` applies the second SHA while writing the txid
///     straight to its destination (capture for free, no `loadState` copy):
///         d.close();  hasher[0].hashState(d.state)   // slot0 = SHA256(SHA256(tx))
///   * The SECOND leaf is consumed IMMEDIATELY by `combineState`, so it can
///     stay in the digest's own state — `closeDouble()` finishes the txid in
///     place:
///         d.closeDouble()                            // d.state = txid
///         hasher[0].combineState(hasher[0], d.state) // SHA256(txid0 ++ txid1)
///
/// Both are `close()` + one more SHA256 block — identical work — they just land
/// the txid in different places. A leaf pair costs ONE scratch `Digest` and
/// ZERO dedicated leaf hashers, with no state copies at all. (These mechanics
/// live in `CounterStateBase.mo`, selected by the `double` flag.)
///
/// === Finalization: collapse, without touching the peaks ===
///
/// The Bitcoin collapse of `BitcoinMerkle.mo` — walk the bits of the count
/// from the lowest set bit upward: the lowest component doubles once, then a
/// SET bit pairs the accumulator with the waiting peak and a CLEAR bit pairs
/// it with itself. Bit 0 is the parked txid in slot 0, so a lone final
/// transaction is paired with itself from there, with no special case. The
/// accumulator is the TOP slot of the array — one above the highest possible
/// peak, always free when a collapse actually happens (its bit could only be
/// set at a full power of two, i.e. a single peak, which short-circuits). The
/// collapse therefore only READS the peaks: the MMR remains valid, and one
/// can keep adding transactions and collapse again — the module exposes this
/// as an incremental API (`new`, `add`, `root`) alongside the one-shot
/// convenience `bitcoinTxMerkleRoot`.
///
/// === Caveats (byte order, segwit, CVE) ===
///
///   * BYTE ORDER: txids and the returned root are in Bitcoin's INTERNAL byte
///     order; explorers display them byte-REVERSED (see the mainnet vectors in
///     `test/verify.test.mo`).
///   * SEGWIT: a txid hashes the transaction serialized WITHOUT witness data.
///     Feeding full segwit bytes (marker/flag and witnesses) yields the wtxid
///     instead. Pre-segwit and stripped serializations are fine as-is.
///   * Last-node duplication is the source of CVE-2012-2459; callers must
///     reject blocks with duplicate txids in that position.

import Hasher "mo:sha2/Hasher/Sha256";
import Base "CounterStateBase";
import Nat32 "mo:core/Nat32";

module {
  /// The MMR state — see `CounterStateBase.mo`, which holds the building
  /// machinery and the embedded `Digest` that absorbs the raw transactions,
  /// shared with `MerkleCounterState.mo`. A static record — it can be
  /// declared `stable`.
  public type Mmr = Base.Mmr;

  /// Create an empty MMR with capacity for at least `maxTxs` transactions
  /// (`ceil(log2 maxTxs) + 1` hashers plus the one scratch `Digest` — see
  /// `CounterStateBase.mo`). With `witness` the coinbase witness spine is
  /// captured as transactions are added — extraction and verification live
  /// in `BitcoinWitness.mo` (Example 7).
  public func new(maxTxs : Nat, witness : Bool) : Mmr = Base.new(maxTxs, witness);

  /// Add one RAW (arbitrary-length) transaction to the MMR; its txid — the
  /// double SHA256 of the bytes — becomes the leaf, produced through the
  /// Digest -> Hasher bridge with no intermediate `Blob`. Traps (on a slot
  /// index out of bounds) if the capacity chosen at `new` is exceeded.
  public func add(self : Mmr, tx : Blob) = Base.add(self, tx, true);

  /// The Bitcoin Merkle root over the transactions added so far (>= 1): the
  /// collapse of `BitcoinMerkle.mo`, with the TOP slot as the accumulator. No
  /// peak slot is written, so the MMR remains valid — keep adding
  /// transactions and collapse again for an updated root. Allocation-free
  /// except the returned root `Blob`.
  public func root(self : Mmr) : Blob {
    let hasher = self.hasher;
    let count = self.count;
    assert count >= 1;
    // A single component is the root outright: the lone txid (count == 1,
    // slot 0) or one peak (power-of-two count) — leave it untouched.
    var k = Nat32.bitcountTrailingZero(count);
    if (Nat32.bitcountNonZero(count) == 1) {
      return hasher[k.toNat()].readSum();
    };
    // The top slot is free — its bit could only be set at the full power of
    // two, a single peak, handled above. It is the accumulator.
    let acc = hasher[hasher.size() - 1];
    // acc = the lowest component, doubled once — its level's node count is
    // odd, so Bitcoin pairs it with itself.
    let k0 = k.toNat();
    acc.combineState(hasher[k0], hasher[k0]);
    acc.hashState(acc); // -> double SHA
    k += 1;
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

  /// Bitcoin Merkle root over the RAW transactions `txs` (each an
  /// arbitrary-length `Blob`), for ANY count (>= 1), in one shot. Equals
  /// `BitcoinMerkle.bitcoinMerkleRoot` over the transactions' txids.
  /// Allocates nothing per transaction or node — only the returned root `Blob`.
  public func bitcoinTxMerkleRoot(txs : [Blob]) : Blob {
    assert txs.size() >= 1;
    let mmr = new(txs.size(), false);
    for (tx in txs.values()) {
      mmr.add(tx);
    };
    mmr.root();
  };
};
