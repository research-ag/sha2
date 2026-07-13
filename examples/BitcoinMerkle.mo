/// Example 4: the BITCOIN Merkle root over txid leaves — the binary counter
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
/// === Step 1: build the mountain range (as in Example 2) ===
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
import VarArray "mo:core/VarArray";
import Nat32 "mo:core/Nat32";

module {
  /// Bitcoin (double-SHA256) Merkle root over `txids` (each a 32-byte `Blob`,
  /// in internal byte order), for ANY leaf count (>= 1). Allocation-free
  /// except the returned root `Blob`.
  public func bitcoinMerkleRoot(txids : [Blob]) : Blob {
    let n = txids.size();
    assert n >= 1;
    // Height L = floor(log2 n) — the highest set bit the leaf count can reach,
    // i.e. the highest possible peak height. Slots 1..L hold peaks; slot 0 is
    // allocated only so that slot index = height (height 0 is the pending Blob).
    var l = 0;
    var pow = 1;
    while (pow * 2 <= n) { pow *= 2; l += 1 };

    let hasher = VarArray.tabulate<Hasher.Hasher>(l + 1, func(_) { Hasher.new() });
    var carry = Hasher.new();
    var count : Nat32 = 0;
    var pending : ?Blob = null; // the height-0 peak, held as a Blob

    // Step 1: the binary counter of MerkleCounter.mo, with double-SHA nodes.
    for (leaf in txids.values()) {
      switch (pending) {
        case (null) { pending := ?leaf };
        case (?leaf0) {
          pending := null;
          carry.combineBlob32(leaf0, leaf);
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
      };
      count += 1;
    };

    // Step 2: the Bitcoin collapse, walking the bits of the count from the
    // lowest set bit upward.

    // A single component is the root outright: the pending leaf (n == 1) or
    // one peak (power-of-two count).
    if (Nat32.bitcountNonZero(count) == 1) {
      switch (pending) {
        case (?b) {
          // n == 1: by Bitcoin's convention the root is the txid itself — still
          // enforce the 32-byte contract that combineBlob32 checks above.
          assert b.size() == 32;
          return b;
        };
        case (null) {
          return Hasher.readSum(hasher[Nat32.toNat(Nat32.bitcountTrailingZero(count))]);
        };
      };
    };

    // acc = the lowest component, doubled once — its level's node count is
    // odd, so Bitcoin pairs it with itself. (The pending leaf is the odd last
    // node at level 0; a lowest peak at height k is the odd last of the
    // n >> k nodes at its level.)
    var k = Nat32.bitcountTrailingZero(count);
    var acc = carry;
    switch (pending) {
      case (?b) { carry.combineBlob32(b, b) }; // k == 0
      case (null) {
        acc := hasher[Nat32.toNat(k)]; // by reference, no copy
        acc.combineState(acc, acc);
      };
    };
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
