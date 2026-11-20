/// The test for MUTATED Bitcoin blocks (CVE-2012-2459), used by the one-shot
/// roots of `BitcoinMerkle.mo`, `BitcoinTxMerkle.mo` and
/// `BitcoinMerkleRight.mo` (Examples 5, 6 and 8). It looks at the transaction
/// list alone and needs no tree and no hashing.
///
/// === The problem ===
///
/// Bitcoin pairs the last node of a level with itself when the level has an
/// odd number of nodes. So two distinct txid lists can have the same Merkle
/// root: `[1,2,3]` and `[1,2,3,3]`, `[1..6]` and `[1,2,3,4,5,6,5,6]`,
/// `[1..5]` and `[1,2,3,4,5,5,5]`. A root alone therefore does not pin down
/// the transaction list. Every such list other than the block itself writes
/// out what the rule would have duplicated: it ENDS with a second copy,
/// complete or cut off, of the subtree right before it, on some level k. Each
/// txid of the copy equals the one 2^k places before it, and so does the
/// LAST txid of the list.
///
/// === The test ===
///
/// `mutated` compares the last txid with the txids 1, 2, 4, 8, ... places
/// before it. That catches every mutation (one place back is not enough, as
/// the second example shows), so among lists of GENUINE transaction ids with
/// a given root at most one passes (a whole level of inner nodes passed off
/// as txids passes too: see "What this does NOT establish" in
/// `BitcoinChunks.mo`). A list that is flagged without being a mutation still
/// repeats a txid, which a valid block never does, so nothing valid is
/// rejected. The test costs at most log2(n) `Blob` comparisons and allocates
/// nothing. (It is not a search for repeated txids in general, which is left
/// to block validation, and it flags fewer lists than Bitcoin Core's check,
/// which compares all sibling hashes while building the tree.)
///
/// It needs the COMPLETE list. A block that arrives in chunks is checked
/// differently, at every merge: see `BitcoinChunks.mo`.

module {
  /// Whether `leaves` may be a MUTATED list (CVE-2012-2459): true if the
  /// last leaf equals the one 1, 2, 4, 8, ... places before it. That holds for
  /// every list that shares its root with another one by writing out a
  /// duplicated tail (it ends with a copy of the 2^k leaves before it, or with
  /// the beginning of one), and otherwise only for lists that repeat a leaf,
  /// which a valid block never does. Works on txids and on raw transactions
  /// alike (equal transactions, equal txids). Allocation-free; at most
  /// log2(n) `Blob` comparisons.
  public func mutated(leaves : [Blob]) : Bool {
    let n = leaves.size();
    // Fewer comparisons would do: only the 2^k at the 1-bits of n - 1 (a copy
    // can only have been written out on a level where this list ends in a
    // right-hand subtree), and of those not the highest (the top level always
    // has the root's two children, in the block as in this list). The other
    // comparisons cost little and do no harm: a match there is a repeated
    // leaf all the same.
    var back = 1; // 2^k
    while (back < n) {
      if (leaves[n - 1 - back] == leaves[n - 1]) return true;
      back *= 2;
    };
    false;
  };
};
