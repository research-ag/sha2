/// Example 1: an allocation-free Merkle tree over 32-byte Blob leaves — the
/// PEAK-STACK approach. Single SHA256 per node, any leaf count.
///
/// A Merkle tree hashes pairs of nodes up to a single root. Done the obvious
/// way, every internal node produces an intermediate digest `Blob`, so a tree
/// over N leaves allocates ~N `Blob`s. On the IC that garbage adds up fast.
///
/// This example builds the tree with ZERO per-node allocation — the only
/// `Blob` allocated is the root you get back. It uses the single-shot `Hasher`
/// (`mo:sha2/Hasher/Sha256`), whose combine primitives are each a SINGLE SHA256
/// that leaves its result in place:
///
///   * `combineBlob32(h, l0, l1)` — `h := SHA256(l0 ++ l1)` for two 32-byte leaf
///     blobs, straight from the IV.
///   * `combineState(h, a, b)`    — `h := SHA256(a ++ b)` for two finished child
///     hashers, reading their 32-byte states directly with no `Blob`. Either
///     source may be `h` itself, so `combineState(h, h, sib)` makes `h` "move up
///     a level" in place.
///   * `loadBlob32(h, b)`         — parks a 32-byte hash in `h` VERBATIM (no
///     hashing); used once, for an unpaired final leaf.
///
/// A `Hasher` IS the 256-bit state: every call overwrites it from the IV, so a
/// finished hasher is immediately reusable — no `reset`, no `close`, no `Blob`
/// for any internal node.
///
/// === The algorithm: a Merkle-mountain-range peak stack ===
///
/// Walk the leaves left to right, two at a time, keeping a STACK of "peaks" —
/// completed subtrees still waiting for a right sibling. `hasher[j]` holds the
/// j-th peak and `level[j]` its tree level; `i` is the stack height.
///
///   1. Push each leaf pair as a node (`combineBlob32`), a level-1 peak.
///   2. While the new peak has the SAME level as the peak below it, merge the
///      two (`combineState` into the lower peak) and pop — exactly like
///      carrying in binary addition.
///   3. An unpaired FINAL leaf is parked verbatim (`loadBlob32`) as a level-0
///      peak.
///   4. At the end, a power-of-two tree has one peak (the root). Otherwise the
///      stack holds one peak per set bit of N, at strictly decreasing levels;
///      BAG them right to left: `acc := SHA256(peak ++ acc)`, starting from the
///      last (lowest) peak. This is the typical mountain-range finalization —
///      no node is ever duplicated (contrast the Bitcoin collapse in
///      `BitcoinMerkle.mo`).
///
/// A tree of N leaves needs only ceil(log2 N) + 1 hashers. No recursion, no
/// free-list.
///
/// === Security note: the root does not commit to the leaf count ===
///
/// Bagging ignores peak heights, so the same root arises from different leaf
/// counts: peaks [A@2, B@1] (n = 6) and [A@2, B@0] (n = 5) both bag to
/// SHA256(A ++ B). And a leaf EQUAL to an internal node value is trivially
/// constructible — leaves are arbitrary 32-byte values, so anyone can submit
/// SHA256(l5 ++ l6) as a leaf; no hash collision is needed. Verifiers must
/// therefore be given n out of band (the peak heights are exactly the bits of
/// n). This is NOT RFC 6962, which closes the leaf/node confusion with domain
/// separation (`0x00` before leaf data, `0x01` before node inputs — a 65-byte
/// node preimage these fixed 64-byte combiners can't produce). For a
/// double-SHA (Bitcoin) tree see `BitcoinMerkle.mo`.
///
/// === What YOU must do to stay allocation-free ===
///
///   1. Allocate the hashers ONCE, up front. Never `Hasher.new()` per node.
///   2. Leaves must be 32-byte blobs (Merkle leaves are hashes, so this is the
///      normal case).
///   3. Read the output with `readSum()` exactly once, for the root — that is
///      the only allocation.

// In your own application, depend on the sha2 package and import it by name:
//   import Hasher "mo:sha2/Hasher/Sha256";
// These files live inside the sha2 repo, so they import the source directly.
import Hasher "../src/Hasher/Sha256";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";

module {
  /// Single-SHA256 Merkle root of `leaves`, for ANY leaf count (>= 1). Each
  /// leaf must be 32 bytes. Leftover peaks are bagged right to left (no
  /// duplication). Allocates nothing per node — only the returned root `Blob`.
  public func merkleRoot(leaves : [Blob]) : Blob {
    let n = leaves.size();
    assert n >= 1;

    // A single leaf is its own root — still enforce the 32-byte leaf contract
    // that combineBlob32 checks below.
    if (n == 1) {
      assert leaves[0].size() == 32;
      return leaves[0];
    };

    // A pool of hashers; `hasher[0 .. i-1]` is the peak stack and `level[j]` the
    // level of `hasher[j]`. One peak per set bit of n, plus slack for the
    // just-pushed pair: `ceil(log2 n) + 1` slots is always enough.
    var cap = 0;
    var m = 1;
    while (m < n) { m *= 2; cap += 1 }; // cap = ceil(log2 n)
    cap += 1;
    let hasher = Array.tabulate<Hasher.Hasher>(cap, func(_) { Hasher.new() });
    let level = VarArray.repeat<Nat>(0, cap);

    var i = 0; // stack height
    var p = 0; // next leaf
    while (p + 1 < n) {
      // Push a leaf pair as a level-1 node.
      hasher[i].combineBlob32(leaves[p], leaves[p + 1]); // SHA256(l0 ++ l1)
      level[i] := 1;
      // Carry: while the top peak matches the level of the one below it, merge.
      while (i > 0 and level[i - 1] == level[i]) {
        hasher[i - 1].combineState(hasher[i - 1], hasher[i]); // lower := SHA256(lower ++ top)
        level[i - 1] += 1; // it rose a level
        i -= 1; // pop the top
      };
      i += 1;
      p += 2;
    };
    // An unpaired final leaf becomes a level-0 peak, parked verbatim.
    if (p < n) {
      hasher[i].loadBlob32(leaves[p]);
      level[i] := 0;
      i += 1;
    };

    // Bag the leftover peaks right to left: acc := SHA256(peak ++ acc), acc
    // starting as the last (lowest) peak. Runs entirely in the stack slots.
    while (i > 1) {
      hasher[i - 2].combineState(hasher[i - 2], hasher[i - 1]);
      i -= 1;
    };

    // readSum is the one and only allocation.
    hasher[0].readSum();
  };
};
