/// Example 5: the Bitcoin Merkle root of `BitcoinMerkle.mo`, but from RAW
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
/// Instead the counter's slot 0 holds it (the half-delay of
/// `MerkleCounterState.mo`), and the two leaves of a pair take different exits
/// out of the `Digest`:
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
///         carry.combineState(hasher[0], d.state)     // SHA256(txid0 ++ txid1)
///
/// Both are `close()` + one more SHA256 block — identical work — they just land
/// the txid in different places. A leaf pair costs ONE scratch `Digest` and
/// ZERO dedicated leaf hashers, with no state copies at all.
///
/// === Finalization ===
///
/// The Bitcoin collapse of `BitcoinMerkle.mo` — walk the bits of the count
/// from the lowest set bit upward: the lowest component doubles once, then a
/// SET bit pairs the accumulator with the waiting peak and a CLEAR bit pairs
/// it with itself. Bit 0 is the parked txid in slot 0, so a lone final
/// transaction is paired with itself from there, with no special case.
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

import Sha256 "mo:sha2/Sha256";
import Hasher "mo:sha2/Hasher/Sha256";
import VarArray "mo:core/VarArray";
import Nat32 "mo:core/Nat32";

module {
  /// Bitcoin Merkle root over the RAW transactions `txs` (each an
  /// arbitrary-length `Blob`), for ANY count (>= 1). Equals
  /// `BitcoinMerkle.bitcoinMerkleRoot` over the transactions' txids.
  /// Allocates nothing per transaction or node — only the returned root `Blob`.
  public func bitcoinTxMerkleRoot(txs : [Blob]) : Blob {
    let n = txs.size();
    assert n >= 1;
    // Height L = ceil(log2 n); slots 0..L can hold peaks (slot 0 = parked txid).
    var l = 0;
    var pow = 1;
    while (pow < n) { pow *= 2; l += 1 };

    let hasher = VarArray.tabulate<Hasher.Hasher>(l + 1, func(_) { Hasher.new() });
    var carry = Hasher.new();
    var count : Nat32 = 0;
    // One scratch Digest absorbs every transaction (reset between them).
    let d = Sha256.new();

    // Step 1: the binary counter, leaves produced through the bridge.
    for (tx in txs.values()) {
      if (count > 0) d.reset();
      d.writeBlob(tx);
      if ((count & 1) == 0) {
        // Height 0 empty: produce the txid directly INTO slot 0 (free capture).
        d.close();
        hasher[0].hashState(d.state); // slot0 := SHA256(SHA256(tx)) = txid
      } else {
        // Height 0 occupied: finish the txid in the digest and consume it.
        d.closeDouble(); // d.state := txid
        carry.combineState(hasher[0], d.state);
        carry.hashState(carry); // -> double SHA
        var k : Nat32 = 1;
        while (((count >> k) & 1) == 1) {
          carry.combineState(hasher[Nat32.toNat(k)], carry);
          carry.hashState(carry); // -> double SHA
          k += 1;
        };
        let kk = Nat32.toNat(k);
        let tmp = hasher[kk];
        hasher[kk] := carry;
        carry := tmp;
      };
      count += 1;
    };

    // Step 2: the Bitcoin collapse (see BitcoinMerkle.mo), walking the bits of
    // the count from the lowest set bit upward. Every component — including a
    // parked odd txid, which is simply the bit-0 peak in slot 0 — lives in a
    // hasher slot, so no case distinction is needed at all.

    // A single component is the root outright: the lone txid (n == 1, slot 0)
    // or one peak (power-of-two count).
    var k = Nat32.bitcountTrailingZero(count);
    if (Nat32.bitcountNonZero(count) == 1) return Hasher.readSum(hasher[Nat32.toNat(k)]);

    // acc = the lowest component, doubled once — its level's node count is
    // odd, so Bitcoin pairs it with itself.
    var acc = hasher[Nat32.toNat(k)]; // by reference, no copy
    acc.combineState(acc, acc);
    acc.hashState(acc); // -> double SHA
    k += 1;
    // Walk the remaining bits: set — pair acc with the waiting peak; clear —
    // the level's node count is odd again, pair acc with itself.
    while ((count >> k) > 0) {
      if (((count >> k) & 1) == 1) {
        acc.combineState(hasher[Nat32.toNat(k)], acc); // dSHA(peak ++ acc)
      } else {
        acc.combineState(acc, acc); // duplicate: dSHA(acc ++ acc)
      };
      acc.hashState(acc); // -> double SHA
      k += 1;
    };
    Hasher.readSum(acc);
  };
};
