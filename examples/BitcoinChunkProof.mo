/// The PROVER for the chunked verification of `BitcoinChunks.mo`,
/// `BitcoinChunksForward.mo` and `BitcoinChunksForwardPlain.mo` (Examples 9
/// to 11): the uploader's side, run off-chain over the whole block. All three
/// verifiers take the same proofs.
///
/// A proof is a set of peaks. Build the block's tree from the right, as
/// `BitcoinMerkleRight.mo` (Example 8) does, and stop when the leaves from m
/// on are in: the peaks that are left are the proof for m, lowest first. They
/// stand for everything to the right of the first m leaves, and seen from the
/// finished tree they are the right siblings of leaf m - 1's ancestors, as
/// far as they contain real leaves.
///
///   - The proof for 0 is the root alone: every leaf is in.
///   - The proof for N is empty: no leaf is in.
///
/// With a chunk that ends at leaf m the uploader sends the proof for m, so
/// with the last chunk an empty one.

import Hasher "mo:sha2/Hasher/Sha256";
import Right "BitcoinMerkleRight";
import Array "mo:core/Array";
import Nat64 "mo:core/Nat64";

module {
  /// The peaks of a tree of Example 8, lowest first.
  public func peaks(tree : Right.Mmr) : [Blob] {
    var bits = tree.present;
    Array.tabulate<Blob>(
      Nat64.bitcountNonZero(bits).toNat(),
      func(_) {
        let k = Nat64.bitcountTrailingZero(bits);
        bits &= bits - 1; // on to the next peak
        tree.hasher[k.toNat()].readSum();
      },
    );
  };

  /// The proof for the first `m` leaves of the block `txids` (0 <= m <= n):
  /// the peaks of the block's tree built from the right down to leaf m. The
  /// root alone for m = 0, empty for m = n.
  ///
  /// An uploader who needs the proofs for several chunk boundaries builds the
  /// tree once, from the last leaf to the first, and takes `peaks` at each
  /// boundary on the way.
  public func proof(txids : [Blob], m : Nat) : [Blob] {
    let n = txids.size();
    assert n >= 1 and m <= n;
    let tree = Right.new(Right.gapFor(n), n);
    var i = n;
    while (i > m) {
      i -= 1;
      tree.add(txids[i]);
    };
    peaks(tree);
  };
};
