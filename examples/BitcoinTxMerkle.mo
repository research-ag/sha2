/// Example: a Bitcoin transaction Merkle root from RAW transactions, allocation-free.
///
/// A Bitcoin block commits to its transactions through a Merkle root over their
/// TXIDs. A txid is the DOUBLE SHA256 of the raw transaction bytes, and each
/// internal node is the double SHA256 of its two children concatenated (with the
/// last node duplicated on odd counts). `Merkle.mo` builds the tree itself from
/// 32-byte leaves; this example adds the front half — turning variable-length
/// raw transactions into those leaves — and is where the `Digest` -> `Hasher`
/// bridge really pays off.
///
/// === Two engines, two roles ===
///
///   * ONE `Digest` (reused) absorbs each variable-length transaction — only it
///     has a message buffer, so only it can take an arbitrary-length input.
///   * The `Hasher` peak stack holds the 32-byte leaves/peaks and combines them
///     with `combineState`, allocating no `Blob` per node (see `Merkle.mo` for
///     the peak-stack mechanics, which are identical here).
///
/// === The leaf pair: two lifetimes, two exits ===
///
/// Each txid is one double SHA256, but the two leaves of a pair have different
/// LIFETIMES, so each uses the cheaper way out of the `Digest`:
///
///   * The FIRST leaf must SURVIVE while the second is computed, so it is hashed
///     into a `Hasher` (the peak slot) via the bridge — `close()` leaves
///     SHA256(tx0) in the digest, and `hashState` reads it straight out while
///     applying the second SHA:
///         d.close();  peak.hashState(d.state)   // peak = SHA256(SHA256(tx0))
///   * The SECOND leaf is consumed IMMEDIATELY by `combineState`, so it can stay
///     in the digest's own state — `closeDouble()` finishes the txid in place:
///         d.closeDouble()                       // d.state = SHA256(SHA256(tx1))
///         peak.combineState(peak, d.state)      // SHA256(txid0 ++ txid1)
///
/// Both are `close()` + one more SHA256 block — identical work — they just land
/// the txid in different places. Because the second leaf never needs to persist,
/// a leaf pair costs ONE scratch `Digest` and ZERO dedicated leaf hashers: the
/// first txid goes straight into the peak slot, the second straight into the
/// combine.
///
/// Allocation-free except the returned root `Blob`. Like `Merkle.mo` this is the
/// Bitcoin tree (plain concatenation + last-node duplication), NOT RFC 6962.
///
/// === Byte order and segwit caveats ===
///
///   * BYTE ORDER: txids and the returned root are in Bitcoin's INTERNAL byte
///     order (the raw double-SHA256 output). Block explorers and RPC interfaces
///     DISPLAY txids and merkle roots byte-REVERSED, so to compare against a
///     displayed hex string, reverse the 32 bytes (see the mainnet test vectors
///     in `test/verify.test.mo`).
///   * SEGWIT: a txid is the double SHA256 of the transaction serialized
///     WITHOUT witness data. Feeding full segwit bytes (with marker/flag and
///     witnesses) yields the wtxid instead. Pre-segwit and stripped
///     serializations are fine as-is.

// In your own application, depend on the sha2 package and import it by name:
//   import Sha256 "mo:sha2/Sha256";
//   import Hasher "mo:sha2/Hasher/Sha256";
// These files live inside the sha2 repo, so they import the source directly.
import Sha256 "../src/Sha256";
import Hasher "../src/Hasher/Sha256";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";

module {
  /// Bitcoin Merkle root over the RAW transactions `txs` (each an
  /// arbitrary-length `Blob`), for any count >= 1. Allocates nothing per
  /// transaction or node — only the returned root `Blob`.
  public func bitcoinTxMerkleRoot(txs : [Blob]) : Blob {
    let n = txs.size();
    assert n >= 1;

    // One scratch Digest absorbs every transaction (reset between them).
    let d = Sha256.new();

    // A single transaction: the root is its txid = double SHA256(tx).
    if (n == 1) {
      d.writeBlob(txs[0]);
      return d.sumDouble();
    };

    // Peak stack of Hashers (see Merkle.mo). ceil(log2 n) + 2 slots is enough.
    var cap = 0;
    var m = 1;
    while (m < n) { m *= 2; cap += 1 };
    cap += 2;
    let hasher = Array.tabulate<Hasher.Hasher>(cap, func(_) { Hasher.new() });
    let level = VarArray.repeat<Nat>(0, cap);

    var i = 0; // stack height
    var p = 0; // next transaction
    while (p < n) {
      // --- Leaf pair -> a level-1 node in hasher[i] ---
      // First leaf: bridge its txid into the peak slot (it must persist).
      d.reset();
      d.writeBlob(txs[p]);
      d.close();
      hasher[i].hashState(d.state); // hasher[i] = txid_p
      if (p + 1 < n) {
        // Second leaf: its txid lives only for the combine, so leave it in
        // d.state and feed it straight in.
        d.reset();
        d.writeBlob(txs[p + 1]);
        d.closeDouble(); // d.state = txid_{p+1}
        hasher[i].combineState(hasher[i], d.state); // SHA256(txid_p ++ txid_{p+1})
      } else {
        // Odd leaf out: Bitcoin duplicates the last txid (hash it with itself).
        hasher[i].combineState(hasher[i], hasher[i]);
      };
      hasher[i].hashState(hasher[i]); // -> double-SHA node
      level[i] := 1;

      // --- Carry: merge equal-level peaks (see Merkle.mo) ---
      while (i > 0 and level[i - 1] == level[i]) {
        hasher[i - 1].combineState(hasher[i - 1], hasher[i]);
        hasher[i - 1].hashState(hasher[i - 1]);
        level[i - 1] += 1;
        i -= 1;
      };
      i += 1;
      p += 2;
    };

    // --- Collapse leftover peaks Bitcoin-style (see Merkle.mo) ---
    while (i > 1) {
      hasher[i - 1].combineState(hasher[i - 1], hasher[i - 1]);
      hasher[i - 1].hashState(hasher[i - 1]);
      level[i - 1] += 1;
      while (i > 1 and level[i - 2] == level[i - 1]) {
        hasher[i - 2].combineState(hasher[i - 2], hasher[i - 1]);
        hasher[i - 2].hashState(hasher[i - 2]);
        level[i - 2] += 1;
        i -= 1;
      };
    };

    // readSum is the one and only allocation.
    hasher[0].readSum();
  };
};
