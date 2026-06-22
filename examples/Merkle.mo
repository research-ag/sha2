/// Example: an allocation-free Merkle tree with `mo:sha2`.
///
/// A Merkle tree hashes pairs of nodes up to a single root. Done the obvious
/// way, every internal node produces an intermediate digest `Blob`, so a tree
/// over N leaves allocates ~N `Blob`s. On the IC that garbage adds up fast.
///
/// This example builds the same tree with ZERO per-node allocation — the only
/// `Blob` allocated is the root you get back. It uses two combine primitives,
/// each of which is a SINGLE SHA256 that leaves its result in place:
///
///   * `combineLeaves(h, l0, l1)` — `h := SHA256(l0 ++ l1)` for two 32-byte leaf
///     blobs, straight from the IV.
///   * `combineNodes(a, b)`       — `a := SHA256(a ++ b)` for two finished child
///     digests, in place; `b` is consumed. `a` "moves up a level."
///
/// Both REQUIRE a closed hasher and leave it closed, so a finished hasher is
/// immediately reusable — no `reset` anywhere, no `Blob` for any internal node.
///
/// === Single-SHA vs double-SHA trees ===
///
/// `combineLeaves`/`combineNodes` are one SHA256 per node, each computing
/// `SHA256(left ++ right)` — a plain single-SHA Merkle tree. For a Bitcoin-style
/// DOUBLE-SHA tree, call `fold(h)` after each combine — `fold` re-hashes the
/// node's own digest, so `combine… + fold` = `SHA256(SHA256(…))`. This example
/// does the double-SHA Bitcoin tree; for the plain single-SHA tree, delete the
/// two `fold` lines.
///
/// Note: this is NOT RFC 6962. That tree prepends a domain-separation byte
/// (`0x00` to leaf data, `0x01` to internal nodes), so an internal node hashes
/// 65 bytes — `SHA256(0x01 || left || right)` — which these fixed 64-byte
/// combiners can't produce.
///
/// === The algorithm: a Merkle-mountain-range peak stack ===
///
/// Walk the leaves left to right, two at a time, keeping a STACK of "peaks" —
/// completed subtrees still waiting for a right sibling. `hasher[j]` holds the
/// j-th peak and `level[j]` its tree level; `i` is the stack height.
///
///   1. Push each leaf pair as a node (`combineLeaves` + `fold`), a level-1 peak.
///      An unpaired final leaf is paired with itself (Bitcoin's duplication).
///   2. While the new peak has the SAME level as the peak below it, merge the
///      two (`combineNodes` + `fold` into the lower peak) and pop — exactly like
///      carrying in binary addition.
///   3. At the end, a power-of-two tree has one peak (the root). Otherwise
///      several peaks remain at decreasing levels; collapse them Bitcoin-style
///      by duplicating the lowest peak (`combineNodes` with itself, raising it a
///      level) and carrying, until one peak is left.
///
/// A tree of N leaves needs only ⌈log2 N⌉ hashers. No recursion, no free-list.
///
/// === What YOU must do to stay allocation-free ===
///
///   1. Allocate the hashers ONCE, up front, and `close()` them so they start
///      in the closed state the combine primitives require. Never `Sha256.new()`
///      per node.
///   2. Leaves must be 32-byte blobs (Merkle leaves are hashes, so this is the
///      normal case).
///   3. Read the output with `readSum()` exactly once, for the root — that is
///      the only allocation.

// In your own application, depend on the sha2 package and import it by name:
//   import Sha256 "mo:sha2/Sha256";
// These files live inside the sha2 repo, so they import the source directly.
import Sha256 "../src/Sha256";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";

module {
  /// Bitcoin-style (double-SHA256) Merkle root of `leaves`, for ANY leaf count
  /// (>= 1). Each leaf must be 32 bytes. Allocates nothing per node — only the
  /// returned root `Blob`.
  ///
  /// Bitcoin's rule for non-power-of-two trees: whenever a level has an odd
  /// number of nodes, the LAST node is duplicated (hashed with itself). The peak
  /// stack handles this in two places — an unpaired final leaf is paired with
  /// itself, and at the end any lone leftover peak is duplicated and carried up.
  public func bitcoinMerkleRoot(leaves : [Blob]) : Blob {
    let n = leaves.size();
    assert n >= 1;

    // A single leaf: by the Bitcoin convention the root is the leaf itself.
    if (n == 1) return leaves[0];

    // A pool of hashers, started CLOSED (combineLeaves/combineNodes both require
    // a closed hasher). `hasher[0 .. i-1]` is the peak stack and `level[j]` the
    // level of `hasher[j]`. `ceil(log2 n) + 2` slots is always enough (the peak
    // stack plus the collapse, which can push the root one extra level).
    var cap = 0;
    var m = 1;
    while (m < n) { m *= 2; cap += 1 }; // cap = ceil(log2 n)
    cap += 2;
    let hasher = Array.tabulate<Sha256.Digest>(cap, func(_) { let h = Sha256.new(); h.close(); h });
    let level = VarArray.repeat<Nat>(0, cap);

    var i = 0; // stack height
    var p = 0; // next leaf
    while (p < n) {
      // Push a leaf node. An unpaired final leaf is duplicated (Bitcoin's rule).
      // The `fold` makes the node double-SHA; drop it for a single-SHA tree.
      let right = if (p + 1 < n) leaves[p + 1] else leaves[p];
      hasher[i].combineLeaves(leaves[p], right); // SHA256(l0 ++ l1)
      hasher[i].fold(); // -> double-SHA
      level[i] := 1;
      // Carry: while the top peak matches the level of the one below it, merge.
      while (i > 0 and level[i - 1] == level[i]) {
        hasher[i - 1].combineNodes(hasher[i]); // lower := SHA256(lower ++ top)
        hasher[i - 1].fold(); // -> double-SHA (drop for single-SHA)
        level[i - 1] += 1; // it rose a level
        i -= 1; // pop the top
      };
      i += 1;
      p += 2;
    };

    // Collapse leftover peaks. A power-of-two tree already has one peak; for
    // any other count the stack holds several peaks at strictly decreasing
    // levels. Bitcoin duplicates the lone node at each odd level, which here is:
    // duplicate the lowest peak (combine it with itself, raising it a level) and
    // carry, repeating until a single peak — the root — remains.
    while (i > 1) {
      hasher[i - 1].combineNodes(hasher[i - 1]); // duplicate: SHA256(peak ++ peak)
      hasher[i - 1].fold(); // -> double-SHA (drop for single-SHA)
      level[i - 1] += 1;
      while (i > 1 and level[i - 2] == level[i - 1]) {
        hasher[i - 2].combineNodes(hasher[i - 1]);
        hasher[i - 2].fold();
        level[i - 2] += 1;
        i -= 1;
      };
    };

    // readSum is the one and only allocation.
    Sha256.readSum(hasher[0]);
  };

  // --- Variations you can make in your own tree ---
  //
  // * Plain single-SHA tree: delete the `fold` lines — every node is then one
  //   `SHA256(left ++ right)`. (Not RFC 6962 — see the header. And note the
  //   last-node duplication above is specifically Bitcoin's rule; other trees
  //   handle odd levels differently.)
  //
  // * Caveat: duplicating the last node is the source of Bitcoin's CVE-2012-2459
  //   (two distinct leaf lists can yield the same root); callers must reject
  //   blocks with duplicate txids in that position.
};
