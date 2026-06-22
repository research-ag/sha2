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
/// `combineLeaves`/`combineNodes` are one SHA256 per node. That is exactly an
/// RFC-6962-style single-SHA tree. For a Bitcoin-style DOUBLE-SHA tree, call
/// `fold(h)` after each combine — `fold` re-hashes the node's own digest, so
/// `combine… + fold` = `SHA256(SHA256(…))`. This example does the double-SHA
/// Bitcoin tree; to get a single-SHA tree, just delete the two `fold` lines.
///
/// === The algorithm: a Merkle-mountain-range peak stack ===
///
/// Walk the leaves left to right, two at a time, keeping a STACK of "peaks" —
/// completed subtrees still waiting for a right sibling. `hasher[j]` holds the
/// j-th peak and `level[j]` its tree level; `i` is the stack height.
///
///   1. Push each leaf pair as a node (`combineLeaves` + `fold`), a level-1 peak.
///   2. While the new peak has the SAME level as the peak below it, merge the
///      two (`combineNodes` + `fold` into the lower peak) and pop — exactly like
///      carrying in binary addition.
///
/// A balanced tree of N leaves needs only ⌈log2 N⌉ hashers, and the single
/// remaining peak at the end is the root. No recursion, no free-list.
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
  /// Bitcoin-style (double-SHA256) Merkle root of `leaves`.
  /// `leaves.size()` must be a power of two and at least 1, and each leaf must
  /// be 32 bytes. Allocates nothing per node — only the returned root `Blob`.
  public func bitcoinMerkleRoot(leaves : [Blob]) : Blob {
    let n = leaves.size();
    assert n >= 1;

    // Number of internal levels = log2(n).
    var levels = 0;
    var m = n;
    while (m > 1) { m /= 2; levels += 1 };
    assert (2 ** levels == n); // power-of-two requirement

    // A single leaf: by the Bitcoin convention the root is the leaf itself
    // (leaves are already hashes), so there is nothing to combine.
    if (levels == 0) return leaves[0];

    // A pool of `levels` hashers, started CLOSED (combineLeaves/combineNodes both
    // require a closed hasher). `hasher[0 .. i-1]` is the peak stack and
    // `level[j]` the level of `hasher[j]`.
    let hasher = Array.tabulate<Sha256.Digest>(levels, func(_) { let h = Sha256.new(); h.close(); h });
    let level = VarArray.repeat<Nat>(0, levels);

    var i = 0; // stack height
    var p = 0; // next leaf
    while (p < n) {
      // Push a leaf node. The `fold` makes it double-SHA; drop it for single-SHA.
      hasher[i].combineLeaves(leaves[p], leaves[p + 1]); // SHA256(l0 ++ l1)
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

    // For a power-of-two tree the stack collapses to a single peak: the root.
    // readSum is the one and only allocation.
    Sha256.readSum(hasher[0]);
  };

  // --- Variations you can make in your own tree ---
  //
  // * Single-SHA tree (e.g. RFC 6962): delete the two `fold` lines — every node
  //   is then one SHA256 of `left ++ right`.
  //
  // * Odd number of children at a level (Bitcoin duplicates the last node):
  //   combine the unpaired node with itself. The code above requires a
  //   power-of-two leaf count to keep the example focused.
};
