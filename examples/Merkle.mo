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
/// === What YOU must do to stay allocation-free ===
///
///   1. Allocate the hashers ONCE, up front, and `close()` them so they start
///      in the closed state the combine primitives require. Reuse them via a
///      free-list; never call `Sha256.new()` per node.
///   2. Leaves must be 32-byte blobs (Merkle leaves are hashes, so this is the
///      normal case). Combine leaf pairs with `merkleLeaves` + `fold`.
///   3. Combine internal nodes with `merkleMerge` and read the output with
///      `readSum()` exactly once, for the root — that is the only allocation.
///
/// === Memory: O(log N) hashers ===
///
/// Evaluate the tree post-order (depth first): finish the left subtree (hold
/// its result in a hasher), finish the right subtree (hold its result), then
/// `merkleMerge` them — the merge writes into the left child and frees the
/// right. A balanced tree of N leaves needs only ⌈log2 N⌉ hashers, tracked by a
/// small free-list (`freeIx` + `top`).

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
    // require a closed hasher) and reused via a free-list: `freeIx[0 .. top-1]`
    // hold the indices of the currently-free hashers. `levels` = log2(n) is
    // enough for the whole post-order traversal.
    let pool = Array.tabulate<Sha256.Digest>(levels, func(_) { let h = Sha256.new(); h.close(); h });
    let freeIx = VarArray.tabulate<Nat>(levels, func(i) = i);
    let top = [var levels];

    // The root ends up in the hasher returned by the top-level eval. readSum is
    // the single allocation (the root Blob).
    Sha256.readSum(pool[eval(leaves, pool, freeIx, top, 0, n)]);
  };

  // Evaluate the subtree over `leaves[lo .. hi)` (a power-of-two count >= 2) and
  // return the pool index of the hasher holding its closed double-SHA digest.
  // Defined at module level (not a closure) so the traversal allocates nothing.
  func eval(leaves : [Blob], pool : [Sha256.Digest], freeIx : [var Nat], top : [var Nat], lo : Nat, hi : Nat) : Nat {
    if (hi - lo == 2) {
      // leaf pair -> one double-SHA leaf node
      top[0] -= 1;
      let i = freeIx[top[0]]; // take a free (closed) hasher
      let h = pool[i];
      h.merkleLeaves(leaves[lo], leaves[lo + 1]); // inner SHA256(l0 ++ l1)
      h.fold(); // outer SHA256 -> double-SHA
      i;
    } else {
      let mid = lo + (hi - lo) / 2;
      let l = eval(leaves, pool, freeIx, top, lo, mid); // left subtree (held)
      let r = eval(leaves, pool, freeIx, top, mid, hi); // right subtree (held)
      pool[l].merkleMerge(pool[r]); // l := double-SHA(l ++ r); r consumed
      freeIx[top[0]] := r; // free r
      top[0] += 1;
      l;
    };
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
