/// Example: an allocation-free Bitcoin-style Merkle tree with `mo:sha2`.
///
/// A Merkle tree hashes pairs of nodes up to a single root. Done the obvious
/// way, every internal node produces an intermediate digest `Blob`, so a tree
/// over N leaves allocates ~N `Blob`s. On the IC that garbage adds up fast.
///
/// This example builds the same tree with ZERO per-node allocation — the only
/// `Blob` allocated is the root you get back. It uses three tools from sha2:
///
///   * `pushSum(target)` — finalize a hasher and write its digest straight into
///     another hasher's message buffer, with no intermediate `Blob`.
///   * `foldSum()`        — finalize a hasher and fold its digest back in as the
///     next message. Doing this before the final hash turns a single SHA256
///     into a double SHA256 — the hash Bitcoin uses. (Omit it for a single-SHA
///     tree; see `singleShaCombine` note below.)
///   * `reset()`          — rewind a hasher so it can be reused for the next pair.
///
/// === What YOU must do to stay allocation-free in bulk ===
///
///   1. Allocate the hashers ONCE, up front, and `reset()` them between uses.
///      Never call `Sha256.new()` per node — that is the main source of garbage.
///   2. Feed leaf bytes with `writeBlob`. It is allocation-free as long as the
///      hasher is at a 2-byte word boundary, which holds whenever you have
///      written an even number of bytes so far. Merkle leaves are typically
///      32-byte hashes (even), so this is automatic. An odd-length leaf still
///      hashes correctly but costs one tiny allocation for its trailing byte.
///   3. Move digests between hashers with `pushSum` / `foldSum`, never `sum()`.
///      `sum()` allocates the output `Blob`; call it exactly once, for the root.
///
/// === Memory: O(log N), not O(N) ===
///
/// We keep just ONE hasher per tree level alive at a time (⌈log2 N⌉ of them),
/// feed the leaves left-to-right, and carry each completed pair upward — exactly
/// like incrementing a binary counter. A `pending` flag per level records
/// whether a left child is waiting there for its right sibling.

// In your own application, depend on the sha2 package and import it by name:
//   import Sha256 "mo:sha2/Sha256";
// These files live inside the sha2 repo, so they import the source directly.
import Sha256 "../src/Sha256";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";

module {
  /// Bitcoin-style (double-SHA256) Merkle root of `leaves`.
  /// `leaves.size()` must be a power of two and at least 1.
  /// Allocates nothing per node — only the returned root `Blob`.
  public func bitcoinMerkleRoot(leaves : [Blob]) : Blob {
    let n = leaves.size();
    assert n >= 1;

    // Number of levels above the leaves = log2(n).
    var levels = 0;
    var m = n;
    while (m > 1) { m /= 2; levels += 1 };
    assert (2 ** levels == n); // power-of-two requirement

    // A single leaf: by the Bitcoin convention the root is the leaf itself
    // (leaves are already hashes), so there is nothing to combine.
    if (levels == 0) return leaves[0];

    // One reusable hasher per level, allocated ONCE. hashers[k] combines two
    // level-k nodes into a single level-(k+1) node.
    let hashers = Array.tabulate<Sha256.Digest>(levels, func(_) = Sha256.new());
    // pending[k] : a left child is sitting in hashers[k] awaiting its sibling.
    let pending = VarArray.repeat<Bool>(false, levels);

    var root : Blob = leaves[0]; // overwritten by the final combine
    var i = 0;
    while (i < n) {
      // Write a leaf pair into the level-0 hasher. Allocation-free: the leaves
      // are word-aligned, so writeBlob takes its closure-free path.
      hashers[0].writeBlob(leaves[i]);
      hashers[0].writeBlob(leaves[i + 1]);

      // Carry the freshly completed pair up the tree.
      var lvl = 0;
      var carrying = true;
      while (carrying) {
        let h = hashers[lvl];
        h.foldSum(); // inner SHA256 (this is what makes the combine a double-SHA)
        if (lvl + 1 == levels) {
          // We are at the top: read the root out. THE one allocation.
          root := h.sum(); // outer SHA256 -> root Blob
          h.reset();
          carrying := false;
        } else {
          h.pushSum(hashers[lvl + 1]); // outer SHA256, straight into the parent
          h.reset(); // reuse this level's hasher for its next pair
          if (pending[lvl + 1]) {
            pending[lvl + 1] := false;
            lvl += 1; // parent now has both children -> keep carrying upward
          } else {
            pending[lvl + 1] := true;
            carrying := false; // parent waits for its right sibling
          };
        };
      };
      i += 2;
    };
    root;
  };

  // --- Variations you can make in your own tree ---
  //
  // * Single-SHA tree (e.g. RFC 6962 uses a domain-separated single SHA256):
  //   drop the `h.foldSum()` line, and use `h.sum()` (not double) for the root.
  //   The combine then becomes one SHA256 of `left ++ right`.
  //
  // * Odd number of children at a level (Bitcoin duplicates the last node):
  //   when a level ends with an unpaired left child still `pending`, feed that
  //   child to itself (write it twice) and combine, before moving up. The code
  //   above requires a power-of-two leaf count to keep the example focused.
  //
  // * Sha512 trees: identical structure with `mo:sha2/Sha512`. Note Sha512 is
  //   not fully allocation-free (its 64-bit state boxes on the 32-bit IC wasm),
  //   but the same reuse pattern still avoids the per-node intermediate Blobs.
};
