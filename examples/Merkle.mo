/// Example: an allocation-free Bitcoin-style Merkle tree with `mo:sha2`.
///
/// A Merkle tree hashes pairs of nodes up to a single root. Done the obvious
/// way, every internal node produces an intermediate digest `Blob`, so a tree
/// over N leaves allocates ~N `Blob`s. On the IC that garbage adds up fast.
///
/// This example builds the same tree with ZERO per-node allocation — the only
/// `Blob` allocated is the root you get back. It uses two combine primitives:
///
///   * `merkleLeaves(h, l0, l1)` — hash two 32-byte leaf blobs into `h` as
///     `SHA256(l0 ++ l1)`, straight from the IV, in one self-contained call (no
///     `reset`/`close`). Follow with `fold(h)` for the double SHA256 Bitcoin
///     uses.
///   * `merkleMerge(a, b)`       — combine two finished child digests in place:
///     `a` becomes the double SHA256 of `a ++ b` and `b` is consumed. `a`
///     "moves up a level."
///
/// Both REQUIRE a closed hasher and leave it closed, so a finished hasher is
/// immediately reusable — there is no `reset` anywhere in the hot path, and no
/// `Blob` is produced for any internal node.
///
/// === The algorithm: a Merkle-mountain-range peak stack ===
///
/// Walk the leaves left to right, two at a time, keeping a STACK of "peaks" —
/// completed subtrees that are still waiting for a right sibling. `hasher[j]`
/// holds the j-th peak and `level[j]` its tree level; `i` is the stack height.
///
///   1. Push each leaf pair as a node: `merkleLeaves` + `fold` into `hasher[i]`,
///      a level-1 node.
///   2. While the new peak has the SAME level as the peak below it, merge the
///      two (`merkleMerge` writes into the lower one, which rises a level) and
///      pop — exactly like carrying in binary addition.
///
/// A balanced tree of N leaves needs only ⌈log2 N⌉ hashers, and the single
/// remaining peak at the end is the root. No recursion, no free-list.
///
/// === What YOU must do to stay allocation-free ===
///
///   1. Allocate the hashers ONCE, up front, and `close()` them so they start
///      in the closed state the combine primitives require. Never call
///      `Sha256.new()` per node.
///   2. Leaves must be 32-byte blobs (Merkle leaves are hashes, so this is the
///      normal case). Combine leaf pairs with `merkleLeaves` + `fold`.
///   3. Combine internal nodes with `merkleMerge` and read the output with
///      `readSum()` exactly once, for the root — that is the only allocation.

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

    // A pool of `levels` hashers, started CLOSED (merkleLeaves/merkleMerge both
    // require a closed hasher). `hasher[0 .. i-1]` is the peak stack and
    // `level[j]` the level of `hasher[j]`.
    let hasher = Array.tabulate<Sha256.Digest>(levels, func(_) { let h = Sha256.new(); h.close(); h });
    let level = VarArray.repeat<Nat>(0, levels);

    var i = 0; // stack height
    var p = 0; // next leaf
    while (p < n) {
      // Push a leaf node: SHA256(l0 ++ l1) then fold -> double-SHA, a level-1 peak.
      hasher[i].merkleLeaves(leaves[p], leaves[p + 1]);
      hasher[i].fold();
      level[i] := 1;
      // Carry: while the top peak matches the level of the one below it, merge.
      while (i > 0 and level[i - 1] == level[i]) {
        hasher[i - 1].merkleMerge(hasher[i]); // lower peak := double-SHA(lower ++ top)
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
  // * Odd number of children at a level (Bitcoin duplicates the last node):
  //   combine the unpaired node with itself. The code above requires a
  //   power-of-two leaf count to keep the example focused.
  //
  // * Single-SHA tree (e.g. RFC 6962): `merkleMerge`/`merkleLeaves`+`fold` are
  //   double-SHA. For a single SHA per node, use `merkleLeaves(h, l0, l1)` then
  //   `readSum(h)` at the leaves; internal nodes would need a single-SHA combine
  //   (not provided here).
};
