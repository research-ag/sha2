// @testmode wasi
// Verifies the examples produce the same hashes as straightforward references.
import MerkleStack "../MerkleStack";
import MerkleStackState "../MerkleStackState";
import MerkleCounter "../MerkleCounter";
import MerkleCounterState "../MerkleCounterState";
import BitcoinMerkle "../BitcoinMerkle";
import BitcoinMutation "../BitcoinMutation";
import BitcoinTxMerkle "../BitcoinTxMerkle";
import BitcoinWitness "../BitcoinWitness";
import BitcoinMerkleRight "../BitcoinMerkleRight";
import NFold "../NFold";
import BitcoinChunks "../BitcoinChunks";
import Sha256 "mo:sha2/Sha256";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";
import Seiran128 "mo:prng/Seiran128";

// prng instead of core/Random: the latter contains async code, which does not
// compile in testmode wasi (needed for speed).
let rng = Seiran128.new(0x1234);
func bytes(n : Nat) : Blob = Array.tabulate<Nat8>(n, func(_) = (rng.next() & 0xff).toNat8()).toBlob();

let ns : [Nat] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 23, 31, 33, 100];

// --- Reference A: generic single-SHA mountain-range root (Examples 1-4) ---
// Split the leaves into maximal power-of-two chunks left to right (the binary
// decomposition of n), root each perfect subtree recursively, then bag the
// peaks right to left: acc := SHA256(peak ++ acc). Materializes every node.
func refPerfect(leaves : [Blob], from : Nat, size : Nat) : Blob {
  if (size == 1) return leaves[from];
  let h = Sha256.new();
  h.writeBlob(refPerfect(leaves, from, size / 2));
  h.writeBlob(refPerfect(leaves, from + size / 2, size / 2));
  h.sum();
};
func refBagged(leaves : [Blob]) : Blob {
  let n = leaves.size();
  let peaks = List.empty<Blob>();
  var size = 1;
  while (size * 2 <= n) size *= 2;
  var from = 0;
  while (from < n) {
    while (size > (n - from : Nat)) size /= 2;
    peaks.add(refPerfect(leaves, from, size));
    from += size;
  };
  var i = peaks.size() - 1 : Nat;
  var acc = peaks.at(i);
  while (i > 0) {
    i -= 1;
    let h = Sha256.new();
    h.writeBlob(peaks.at(i));
    h.writeBlob(acc);
    acc := h.sum();
  };
  acc;
};

// --- Reference B: canonical Bitcoin Merkle root (Examples 5-6) ---
// Level by level, duplicating the last node on odd counts, double SHA256 per
// node (materializes every intermediate digest as a Blob).
func refBitcoin(leaves : [Blob]) : Blob {
  if (leaves.size() == 1) return leaves[0];
  var level = leaves;
  while (level.size() > 1) {
    let m = level.size();
    level := Array.tabulate<Blob>(
      (m + 1) / 2,
      func(i) {
        let right = if (2 * i + 1 < m) level[2 * i + 1] else level[2 * i]; // dup last if odd
        let h = Sha256.new();
        h.writeBlob(level[2 * i]);
        h.writeBlob(right);
        h.sumDouble();
      },
    );
  };
  level[0];
};

// --- Examples 1 and 3: stack and counter over 32-byte Blob leaves equal
// ref A ---
for (n in ns.values()) {
  let leaves = Array.tabulate<Blob>(n, func(_) = bytes(32));
  let expected = refBagged(leaves);
  assert (MerkleStack.merkleRoot(leaves) == expected);
  assert (MerkleCounter.merkleRoot(leaves) == expected);
};

// --- Examples 2 and 4: message-fed — one Digest absorbs each message and
// the MMR reads the leaf, SHA256(msg), straight from its state. Roots must
// equal ref A over the hashed leaves. ---
for (n in ns.values()) {
  // Messages of assorted lengths, several crossing the 64-byte block
  // boundary, so the Digest absorb path is exercised for each leaf.
  let msgs = Array.tabulate<Blob>(n, func(j) = bytes(8 + (j * 53) % 250));
  let expected = refBagged(msgs.map<Blob, Blob>(func(m) = Sha256.fromBlob(m)));
  assert (MerkleStackState.merkleRoot(msgs) == expected);
  assert (MerkleCounterState.merkleRoot(msgs) == expected);
};

// --- Incremental use (stack and both counters): bagging must not destroy the
// MMR. Bag mid-way, keep adding leaves, bag again; all roots must match the
// reference over the corresponding leaf prefix. The first bag hits the even
// (fuse-two-lowest-peaks) path, the second the odd (pending/parked leaf) path.
do {
  let leaves = Array.tabulate<Blob>(23, func(_) = bytes(32));
  // Messages for the message-fed MMRs (Examples 2 and 4); their tree leaves
  // are the messages' hashes.
  let msgs = Array.tabulate<Blob>(23, func(j) = bytes(8 + (j * 53) % 250));
  let msgLeaves = msgs.map<Blob, Blob>(func(m) = Sha256.fromBlob(m));
  let stack = MerkleStack.new(23);
  let stackState = MerkleStackState.new(23);
  let counter = MerkleCounter.new(23);
  let counterState = MerkleCounterState.new(23);
  let bitcoin = BitcoinMerkle.new(23, false);
  // MerkleCounter.Mmr/BitcoinMerkle.Mmr and MerkleCounterState.Mmr/
  // BitcoinTxMerkle.Mmr are structurally identical pairs, so dot notation on
  // them is ambiguous (M0224) — qualify those calls.
  var i = 0;
  while (i < 12) {
    stack.add(leaves[i]);
    stackState.add(msgs[i]);
    MerkleCounter.add(counter, leaves[i]);
    MerkleCounterState.add(counterState, msgs[i]);
    BitcoinMerkle.add(bitcoin, leaves[i]);
    i += 1;
  };
  let prefix12 = Array.tabulate<Blob>(12, func(j) = leaves[j]);
  let ref12 = refBagged(prefix12);
  let msgRef12 = refBagged(Array.tabulate<Blob>(12, func(j) = msgLeaves[j]));
  assert (stack.root() == ref12);
  assert (stackState.root() == msgRef12);
  assert (MerkleCounter.root(counter) == ref12);
  assert (MerkleCounterState.root(counterState) == msgRef12);
  assert (BitcoinMerkle.root(bitcoin) == refBitcoin(prefix12));
  while (i < 23) {
    stack.add(leaves[i]);
    stackState.add(msgs[i]);
    MerkleCounter.add(counter, leaves[i]);
    MerkleCounterState.add(counterState, msgs[i]);
    BitcoinMerkle.add(bitcoin, leaves[i]);
    i += 1;
  };
  let ref23 = refBagged(leaves);
  assert (stack.root() == ref23);
  assert (stackState.root() == refBagged(msgLeaves));
  assert (MerkleCounter.root(counter) == ref23);
  assert (MerkleCounterState.root(counterState) == refBagged(msgLeaves));
  assert (BitcoinMerkle.root(bitcoin) == refBitcoin(leaves));
};

// --- Example 5 equals ref B on every leaf count ---
for (n in ns.values()) {
  let leaves = Array.tabulate<Blob>(n, func(_) = bytes(32));
  assert (BitcoinMerkle.bitcoinMerkleRoot(leaves) == refBitcoin(leaves));
};

// --- Real mainnet Bitcoin block Merkle roots ---
// Bitcoin hashes the tree over INTERNAL (little-endian) byte order, so each leaf
// below is a block's txid with its display-hex bytes reversed, and the expected
// value is the published merkle root reversed. (Pulled from blockstream.info and
// re-verified; the display-order hex is in the comments.)
do {
  // block 170, 2 transactions; merkle root 7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff
  // tx0 b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082
  let b170t0 : Blob = Array.toBlob([130, 80, 28, 17, 120, 250, 11, 34, 44, 31, 61, 71, 78, 199, 38, 184, 50, 1, 63, 10, 83, 43, 68, 187, 98, 12, 206, 134, 36, 165, 254, 177]);
  // tx1 f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
  let b170t1 : Blob = Array.toBlob([22, 158, 30, 131, 233, 48, 133, 51, 145, 188, 111, 53, 246, 5, 198, 117, 76, 254, 173, 87, 207, 131, 135, 99, 157, 59, 64, 150, 197, 79, 24, 244]);
  let b170root : Blob = Array.toBlob([255, 16, 76, 203, 5, 66, 26, 185, 62, 99, 248, 195, 206, 92, 44, 46, 157, 187, 55, 222, 39, 100, 179, 163, 23, 92, 129, 102, 86, 44, 172, 125]);
  assert (BitcoinMerkle.bitcoinMerkleRoot([b170t0, b170t1]) == b170root);
  assert (BitcoinMerkleRight.bitcoinMerkleRootFromRight([b170t0, b170t1]) == b170root);

  // block 586, 3 transactions (odd -> exercises last-node duplication);
  // merkle root 197b3d968ce463aa5da7d8eeba8af35eba80ded4e4fe6808e6cc0dd1c069594d
  // tx0 d45724bacd1480b0c94d363ebf59f844fb54e60cdfda0cd38ef67154e9d0bc43
  let b586t0 : Blob = Array.toBlob([67, 188, 208, 233, 84, 113, 246, 142, 211, 12, 218, 223, 12, 230, 84, 251, 68, 248, 89, 191, 62, 54, 77, 201, 176, 128, 20, 205, 186, 36, 87, 212]);
  // tx1 4d6edbeb62735d45ff1565385a8b0045f066055c9425e21540ea7a8060f08bf2
  let b586t1 : Blob = Array.toBlob([242, 139, 240, 96, 128, 122, 234, 64, 21, 226, 37, 148, 92, 5, 102, 240, 69, 0, 139, 90, 56, 101, 21, 255, 69, 93, 115, 98, 235, 219, 110, 77]);
  // tx2 6bf363548b08aa8761e278be802a2d84b8e40daefe8150f9af7dd7b65a0de49f
  let b586t2 : Blob = Array.toBlob([159, 228, 13, 90, 182, 215, 125, 175, 249, 80, 129, 254, 174, 13, 228, 184, 132, 45, 42, 128, 190, 120, 226, 97, 135, 170, 8, 139, 84, 99, 243, 107]);
  let b586root : Blob = Array.toBlob([77, 89, 105, 192, 209, 13, 204, 230, 8, 104, 254, 228, 212, 222, 128, 186, 94, 243, 138, 186, 238, 216, 167, 93, 170, 99, 228, 140, 150, 61, 123, 25]);
  assert (BitcoinMerkle.bitcoinMerkleRoot([b586t0, b586t1, b586t2]) == b586root);
  assert (BitcoinMerkleRight.bitcoinMerkleRootFromRight([b586t0, b586t1, b586t2]) == b586root);
};

// --- Example 6: root over RAW (variable-length) transactions must equal the
// vector-tested BitcoinMerkle fed the same transactions' txids (txid = double
// SHA256 of the raw bytes). This exercises the Digest -> Hasher bridge, close +
// hashState-into-slot and closeDouble against the naive double hash,
// transitively tying the raw-tx root to the mainnet block vectors above.
for (count in ([1, 2, 3, 4, 5, 8, 9, 16, 17, 30] : [Nat]).values()) {
  // Raw transactions of assorted lengths, several crossing the 64-byte block
  // boundary, so the Digest absorb path is exercised for each leaf.
  let txs = Array.tabulate<Blob>(count, func(j) = bytes(8 + (j * 53) % 250));
  let txids = txs.map<Blob, Blob>(func(tx) = Sha256.fromBlob(Sha256.fromBlob(tx)));
  assert (BitcoinTxMerkle.bitcoinTxMerkleRoot(txs) == BitcoinMerkle.bitcoinMerkleRoot(txids));
};

// --- Incremental use of the raw-tx tree: collapse mid-way, keep adding
// transactions, collapse again; both roots must match the vector-tested
// BitcoinMerkle over the corresponding txid prefix.
do {
  let txs = Array.tabulate<Blob>(23, func(j) = bytes(8 + (j * 53) % 250));
  let txids = txs.map<Blob, Blob>(func(tx) = Sha256.fromBlob(Sha256.fromBlob(tx)));
  // BitcoinTxMerkle.Mmr is structurally identical to MerkleCounterState.Mmr
  // (both are CounterStateBase.Mmr) — qualify to avoid M0224.
  let mmr = BitcoinTxMerkle.new(23, false);
  var i = 0;
  while (i < 12) { BitcoinTxMerkle.add(mmr, txs[i]); i += 1 };
  assert (BitcoinTxMerkle.root(mmr) == BitcoinMerkle.bitcoinMerkleRoot(Array.tabulate<Blob>(12, func(j) = txids[j])));
  while (i < 23) { BitcoinTxMerkle.add(mmr, txs[i]); i += 1 };
  assert (BitcoinTxMerkle.root(mmr) == BitcoinMerkle.bitcoinMerkleRoot(txids));
};

// --- Example 7: coinbase witness. The verifier's left-fold from the
// coinbase txid through the witness must reproduce the root; the root
// itself must match the vector-tested BitcoinMerkle. ---
func foldWitness(txid0 : Blob, witness : [Blob]) : Blob {
  var h = txid0;
  for (sib in witness.values()) {
    let d = Sha256.new();
    d.writeBlob(h);
    d.writeBlob(sib);
    h := d.sumDouble();
  };
  h;
};
// Txid trees (Example 5 with capture on), every leaf count (n = 1 gives the
// empty witness).
for (n in ns.values()) {
  let txids = Array.tabulate<Blob>(n, func(_) = bytes(32));
  let mmr = BitcoinMerkle.new(n, true);
  for (t in txids.values()) { BitcoinMerkle.add(mmr, t) };
  let root = BitcoinMerkle.root(mmr);
  assert (root == BitcoinMerkle.bitcoinMerkleRoot(txids));
  let w = mmr.coinbaseWitness();
  assert (foldWitness(txids[0], w) == root);
  // The receiver side must accept the genuine proof ...
  assert (BitcoinWitness.verifyTxid(txids[0], w, root));
  // ... and reject a wrong coinbase or a wrong root.
  if (n >= 2) assert (not BitcoinWitness.verifyTxid(txids[1], w, root));
  assert (not BitcoinWitness.verifyTxid(txids[0], w, bytes(32)));
  // A malformed proof is rejected, not trapped on.
  assert (not BitcoinWitness.verifyTxid(bytes(31), w, root));
  if (n >= 2) assert (not BitcoinWitness.verifyTxid(txids[0], Array.tabulate<Blob>(w.size(), func(j) = if (j == 0) bytes(33) else w[j]), root));
};
// Raw-transaction trees (Example 6 with capture on), every leaf count: the
// proof agrees with the txid tree's and verifies against the root.
for (n in ns.values()) {
  let txs = Array.tabulate<Blob>(n, func(j) = bytes((j * 37) % 200));
  let txids = txs.map<Blob, Blob>(func(tx) = Sha256.fromBlob(Sha256.fromBlob(tx)));
  let mmr = BitcoinTxMerkle.new(n, true);
  for (tx in txs.values()) { BitcoinTxMerkle.add(mmr, tx) };
  let ref = BitcoinMerkle.new(n, true);
  for (t in txids.values()) { BitcoinMerkle.add(ref, t) };
  let w = mmr.coinbaseWitnessTx();
  assert (w == ref.coinbaseWitness());
  assert (BitcoinWitness.verifyTx(txs[0], w, BitcoinTxMerkle.root(mmr)));
};
// Raw-transaction trees (Example 6 with capture on), used incrementally: the
// witness must verify at both counts — the captured hashes stay
// valid as transactions keep arriving.
do {
  let txs = Array.tabulate<Blob>(23, func(j) = bytes(8 + (j * 53) % 250));
  let txids = txs.map<Blob, Blob>(func(tx) = Sha256.fromBlob(Sha256.fromBlob(tx)));
  let mmr = BitcoinTxMerkle.new(23, true);
  var i = 0;
  while (i < 12) { BitcoinTxMerkle.add(mmr, txs[i]); i += 1 };
  assert (BitcoinTxMerkle.root(mmr) == BitcoinMerkle.bitcoinMerkleRoot(Array.tabulate<Blob>(12, func(j) = txids[j])));
  assert (foldWitness(txids[0], mmr.coinbaseWitnessTx()) == BitcoinTxMerkle.root(mmr));
  while (i < 23) { BitcoinTxMerkle.add(mmr, txs[i]); i += 1 };
  assert (BitcoinTxMerkle.root(mmr) == BitcoinMerkle.bitcoinMerkleRoot(txids));
  let w = mmr.coinbaseWitnessTx();
  assert (foldWitness(txids[0], w) == BitcoinTxMerkle.root(mmr));
  // The receiver side from the RAW coinbase transaction: only root, tx0 and
  // witness cross the wire.
  assert (BitcoinWitness.verifyTx(txs[0], w, BitcoinTxMerkle.root(mmr)));
  assert (not BitcoinWitness.verifyTx(txs[1], w, BitcoinTxMerkle.root(mmr)));
  assert (not BitcoinWitness.verifyTx(txs[0], Array.tabulate<Blob>(w.size(), func(j) = if (j == 0) bytes(16) else w[j]), BitcoinTxMerkle.root(mmr)));
};

// --- NFold against manual repeated fromBlob ---
let msg = bytes(20);
assert (NFold.nfold(msg, 1) == Sha256.fromBlob(msg));
assert (NFold.nfold(msg, 2) == Sha256.fromBlob(Sha256.fromBlob(msg)));
assert (NFold.nfold(msg, 3) == Sha256.fromBlob(Sha256.fromBlob(Sha256.fromBlob(msg))));

// Batch reuses one hasher but matches the single-message function.
let m0 = bytes(0);
let m100 = bytes(100);
let out = NFold.nfoldBatch([msg, m0, m100], 3);
assert (out[0] == NFold.nfold(msg, 3));
assert (out[1] == NFold.nfold(m0, 3));
assert (out[2] == NFold.nfold(m100, 3));

// Helpers for Examples 8 and 9.
func flip(b : Blob) : Blob {
  let a = b.toArray();
  Array.tabulate<Nat8>(a.size(), func(i) = if (i == 5) a[5] ^ 0x01 else a[i]).toBlob();
};
func slice(a : [Blob], from : Nat, to : Nat) : [Blob] = Array.tabulate<Blob>(to - from, func(i) = a[from + i]);

// --- Example 8: the Bitcoin root built from the right ---
// The leaves are added last to first, into a tree that ends `gap` places
// before the end of its last level. Whenever the places used, the gap
// included, are a power of two 2^d, the single peak is the root of the tree
// padded to depth d, and it is Bitcoin's root (reference B) exactly when the
// gap is less than half. The peaks that exist (`present`) lag behind the
// counter while the gap is being filled, and equal it from the first power of
// two above the gap on.

// Reference: Bitcoin's rule applied for exactly `depth` levels (a lone node is
// paired with itself as well).
func refPadded(leaves : [Blob], depth : Nat) : Blob {
  var level = leaves;
  for (_ in Nat.range(0, depth)) {
    let m = level.size();
    level := Array.tabulate<Blob>(
      (m + 1) / 2,
      func(i) {
        let h = Sha256.new();
        h.writeBlob(level[2 * i]);
        h.writeBlob(if (2 * i + 1 < m) level[2 * i + 1] else level[2 * i]);
        h.sumDouble();
      },
    );
  };
  assert level.size() == 1;
  level[0];
};

do {
  var roots = 0;
  var bitcoinRoots = 0;
  for (gap in ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 16, 21, 31, 32, 33, 63, 100] : [Nat]).values()) {
    let maxLeaves = 260;
    let added = Array.tabulate<Blob>(maxLeaves, func(_) = bytes(32)); // in the order added: last leaf first
    let mmr = BitcoinMerkleRight.new(gap, maxLeaves);
    var caughtUpAt = 1; // the first power of two above the gap
    while (caughtUpAt <= gap) caughtUpAt *= 2;
    assert (not BitcoinMerkleRight.hasRoot(mmr));
    for (i in Nat.range(0, maxLeaves)) {
      BitcoinMerkleRight.add(mmr, added[i]);
      let count = gap + i + 1 : Nat;
      assert (mmr.count == count.toNat64());
      assert ((mmr.present == mmr.count) == (count >= caughtUpAt));
      var depth = 0;
      while (2 ** depth < count) depth += 1;
      let powerOfTwo = 2 ** depth == count;
      assert (BitcoinMerkleRight.hasRoot(mmr) == powerOfTwo);
      if (powerOfTwo) {
        let leaves = Array.tabulate<Blob>(i + 1, func(j) = added[i - j]); // in block order
        let root = BitcoinMerkleRight.root(mmr);
        assert (root == refPadded(leaves, depth));
        assert (BitcoinMerkleRight.root(mmr) == root); // reading the root changes nothing
        assert ((root == refBitcoin(leaves)) == (2 * gap < count));
        roots += 1;
        if (2 * gap < count) bitcoinRoots += 1;
      };
    };
  };
  assert (roots == 103 and bitcoinRoots == 84);

  // One shot, from the leaf count: the same root as Example 5 and reference B.
  let counts = Array.tabulate<Nat>(130, func(i) = i + 1).concat([255, 256, 257, 1000, 1023, 1024, 1025]);
  for (n in counts.values()) {
    let txids = Array.tabulate<Blob>(n, func(_) = bytes(32));
    let root = refBitcoin(txids);
    assert (BitcoinMerkleRight.bitcoinMerkleRootFromRight(txids) == root);
    assert (BitcoinMerkle.bitcoinMerkleRoot(txids) == root);
    let gap = BitcoinMerkleRight.gapFor(n);
    var places = 1;
    while (places < n) places *= 2;
    assert (gap + n == places and (n == 1 or 2 * gap < places));
  };

  // The worked examples of the header: gap 3 has caught up after one leaf
  // (two doublings), gap 2 after two leaves (a merge, then a doubling).
  let t = Array.tabulate<Blob>(6, func(_) = bytes(32));
  let five = BitcoinMerkleRight.new(3, 5);
  BitcoinMerkleRight.add(five, t[4]);
  assert (five.count == 4 and five.present == 4);
  assert (BitcoinMerkleRight.root(five) == refPadded([t[4]], 2)); // the leaf doubled twice: not Bitcoin's root of one
  let six = BitcoinMerkleRight.new(2, 6);
  BitcoinMerkleRight.add(six, t[5]);
  assert (six.count == 3 and six.present == 1);
  BitcoinMerkleRight.add(six, t[4]);
  assert (six.count == 4 and six.present == 4);
  // `equalSiblings`: set when two equal siblings are merged, which a mutated
  // list always does and an honest one never; a doubling does not set it.
  for (n in ([1, 2, 3, 5, 6, 7, 11, 12, 13, 16, 100] : [Nat]).values()) {
    let txids = Array.tabulate<Blob>(n, func(_) = bytes(32));
    func built(list : [Blob]) : BitcoinMerkleRight.Mmr {
      let mmr = BitcoinMerkleRight.new(BitcoinMerkleRight.gapFor(list.size()), list.size());
      var i = list.size();
      while (i > 0) { i -= 1; BitcoinMerkleRight.add(mmr, list[i]) };
      mmr;
    };
    assert (not built(txids).equalSiblings);
    var width = 1;
    while (width < n) {
      if (n % (2 * width) == width) {
        // the last 2^k leaves written out twice: the same root, and flagged
        let m = built(txids.concat(slice(txids, n - width, n)));
        assert (BitcoinMerkleRight.root(m) == refBitcoin(txids) and m.equalSiblings);
      };
      width *= 2;
    };
    if (n >= 3) assert (built([txids[0], txids[0], txids[1]]).equalSiblings); // any equal pair, as Bitcoin Core
  };
  // Pool: one hasher per bit of the largest counter value, and the spare.
  assert (BitcoinMerkleRight.new(3, 5).hasher.size() == 5 and BitcoinMerkleRight.new(0, 1).hasher.size() == 2 and BitcoinMerkleRight.new(0, 7).hasher.size() == 4);
};

// --- Example 9: chunked verification against the Merkle root ---
// Random chunk sequences over random txids verify chunk by chunk against the
// root of the whole block; the last
// chunk is recognised by its empty proof; a forged leaf, a dropped peak, a
// peak that should have been left out, a duplicated last leaf (CVE-2012-2459),
// a wrong root and a chunk after completion are rejected, and a rejected chunk
// leaves the verifier unchanged.

// Reference for the proof P_m, independent of the tree built from the right:
// from Bitcoin's level arrays, the right siblings of leaf m - 1's ancestors
// that contain real leaves, lowest first; the root alone for m = 0.
func refProof(txids : [Blob], m : Nat) : [Blob] {
  let n = txids.size();
  if (m == 0) return [refBitcoin(txids)];
  let out = List.empty<Blob>();
  var level = txids;
  var k = 0;
  while (level.size() > 1) {
    let len = level.size();
    let idx = (m - 1 : Nat) / (2 ** k);
    if (idx % 2 == 0 and (idx + 1) * (2 ** k) < n) out.add(level[idx + 1]);
    level := Array.tabulate<Blob>(
      (len + 1) / 2,
      func(i) {
        let h = Sha256.new();
        h.writeBlob(level[2 * i]);
        h.writeBlob(level[if (2 * i + 1 < len) 2 * i + 1 else len - 1]);
        h.sumDouble();
      },
    );
    k += 1;
  };
  out.toArray();
};
for (n in ([1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 16, 17, 23, 31, 32, 33, 64, 100, 257] : [Nat]).values()) {
  let txids = Array.tabulate<Blob>(n, func(_) = bytes(32));
  let root = refBitcoin(txids);
  // The proofs: the root alone for no leaves, empty for all of them, equal to
  // the reference in between; and all of them from ONE pass over the block,
  // taking the peaks of the tree at every boundary.
  assert (BitcoinChunks.proof(txids, 0) == [root] and BitcoinChunks.proof(txids, n) == []);
  do {
    let tree = BitcoinMerkleRight.new(BitcoinMerkleRight.gapFor(n), n);
    var m = n;
    while (m > 0) {
      assert (BitcoinChunks.peaks(tree) == refProof(txids, m));
      if (n <= 33) assert (BitcoinChunks.proof(txids, m) == refProof(txids, m));
      m -= 1;
      BitcoinMerkleRight.add(tree, txids[m]);
    };
    assert (BitcoinChunks.peaks(tree) == [root]);
  };
  // chunk boundaries: a pseudo-random walk from 0 to n, repeated with different steps
  for (step in ([1, 2, 3, 5, 8, 1000] : [Nat]).values()) {
    let v = BitcoinChunks.new(root, 12);
    var m = 0;
    var s = step;
    while (m < n) {
      let m2 = if (m + s >= n) n else m + s;
      s := 1 + (s * 7 + m) % (2 * step); // vary the chunk length
      let p = BitcoinChunks.proof(txids, m2);
      // rejections first; the verifier must stay at m
      assert (not v.verifyChunk(slice(txids, m, m2), p.concat([txids[n - 1]]))); // a tile Bitcoin would duplicate, or junk
      if (p.size() > 0) {
        assert (not v.verifyChunk(slice(txids, m, m2), slice(p, 1, p.size()))); // dropped tile
        assert (not v.verifyChunk(slice(txids, m, m2), Array.tabulate<Blob>(p.size(), func(i) = if (i == 0) flip(p[0]) else p[i])));
      };
      let forged = Array.tabulate<Blob>(m2 - m, func(i) = if (i == 0) flip(txids[m]) else txids[m + i]);
      assert (not v.verifyChunk(forged, p));
      assert (v.count == Nat.toNat64(m));
      // the honest chunk
      assert (v.verifyChunk(slice(txids, m, m2), p));
      assert (v.count == Nat.toNat64(m2));
      assert (v.complete() == (m2 == n));
      m := m2;
    };
    assert (v.complete());
    assert (not v.verifyChunk([txids[0]], [])); // nothing after completion
  };
  // the whole block at once, and the mutated block: the last txid uploaded twice
  let w = BitcoinChunks.new(root, 12);
  assert (not w.verifyChunk(txids.concat([txids[n - 1]]), []));
  assert (w.count == 0);
  assert (w.verifyChunk(txids, []) and w.complete());
  // wrong root
  let bad = BitcoinChunks.new(flip(root), 12);
  assert (not bad.verifyChunk(txids, []));
  // a prefix is not the whole block
  if (n > 1) {
    let u = BitcoinChunks.new(root, 12);
    assert (not u.verifyChunk(slice(txids, 0, n - 1), []));
  };
  // malformed input is rejected, not trapped on: a txid or a peak of the wrong length
  let z = BitcoinChunks.new(root, 12);
  assert (not z.verifyChunk(Array.tabulate<Blob>(n, func(i) = if (i == 0) bytes(31) else txids[i]), []));
  assert (not z.verifyChunk(txids, [bytes(33)]));
  // a block deeper than the capacity is rejected: 2^depth transactions fit, one more does not
  var depth = 0;
  while (2 ** depth < n) depth += 1;
  let fits = BitcoinChunks.new(root, depth);
  assert (fits.verifyChunk(txids, []) and fits.complete());
  if (depth > 0) {
    let small = BitcoinChunks.new(root, depth - 1 : Nat);
    assert (not small.verifyChunk(txids, []));
  };
};

// A known limit (security notes, "Leaves and inner nodes"): the tree does not
// mark leaves apart from inner nodes, so a whole level uploaded as txids
// verifies as a shorter block, down to the root itself as a block of one, and
// as raw transactions in the form of 64-byte ones. The examples leave that
// check to the application (the coinbase in full, not 64 bytes long); this
// pins the behaviour the documentation describes.
do {
  let txids = Array.tabulate<Blob>(8, func(_) = bytes(32));
  let root = refBitcoin(txids);
  let level1 = Array.tabulate<Blob>(4, func(i) = refBitcoin([txids[2 * i], txids[2 * i + 1]]));
  assert (BitcoinMerkle.bitcoinMerkleRoot(level1) == root);
  let v = BitcoinChunks.new(root, 12);
  assert (v.verifyChunk(slice(level1, 2, 4), BitcoinChunks.proof(level1, 2)) == false); // chunks go left to right
  assert (v.verifyChunk(slice(level1, 0, 2), BitcoinChunks.proof(level1, 2)));
  assert (v.verifyChunk(slice(level1, 2, 4), []) and v.complete() and v.count == 4);
  let w = BitcoinChunks.new(root, 12);
  assert (w.verifyChunk([root], []) and w.complete() and w.count == 1);
  let pairs = Array.tabulate<Blob>(4, func(i) = txids[2 * i].toArray().concat(txids[2 * i + 1].toArray()).toBlob()); // 64-byte "transactions"
  assert (BitcoinTxMerkle.bitcoinTxMerkleRoot(pairs) == root);
};

// --- Mutated blocks (Examples 5, 6 and 8): `BitcoinMutation.mutated` ---
// The a-priori test on the leaves must flag every list in which the last two
// nodes of some level are equal siblings (the written-out duplicate), so that
// among all lists with the same root at most one passes it; beyond those it
// may only flag lists that repeat a leaf. The one-shot roots trap on a flagged
// list, which the harness cannot observe, so roots of mutated lists are taken
// with the incremental API, which does not check.

// Reference: the root level by level, and whether on some level with an even
// number of nodes the last two were equal.
func refMutated(leaves : [Blob]) : (Blob, Bool) {
  var level = leaves;
  var equal = false;
  while (level.size() > 1) {
    let m = level.size();
    if (m % 2 == 0 and level[m - 2] == level[m - 1]) equal := true;
    level := Array.tabulate<Blob>(
      (m + 1) / 2,
      func(i) {
        let h = Sha256.new();
        h.writeBlob(level[2 * i]);
        h.writeBlob(if (2 * i + 1 < m) level[2 * i + 1] else level[2 * i]);
        h.sumDouble();
      },
    );
  };
  (level[0], equal);
};
func uncheckedRoot(leaves : [Blob]) : Blob {
  let mmr = BitcoinMerkle.new(leaves.size(), false);
  for (l in leaves.values()) BitcoinMerkle.add(mmr, l);
  BitcoinMerkle.root(mmr);
};

// Exhaustive: every list of 1 to 8 leaves over three values.
do {
  let abc = [bytes(32), bytes(32), bytes(32)];
  let clean = Map.empty<Blob, Nat>(); // roots of the lists that pass, with their length
  var passed = 0;
  for (n in Nat.range(1, 9)) {
    var total = 1;
    for (_ in Nat.range(0, n)) total *= 3;
    for (code in Nat.range(0, total)) {
      var c = code;
      let leaves = Array.tabulate<Blob>(n, func(_) { let l = abc[c % 3]; c /= 3; l });
      let (root, equal) = refMutated(leaves);
      let flagged = BitcoinMutation.mutated(leaves);
      if (equal) assert flagged;
      if (not flagged) {
        assert (clean.get(Blob.compare, root) == null); // no second clean list with this root
        clean.add(Blob.compare, root, n);
        passed += 1;
      };
    };
  };
  assert (passed == 2937); // the lists that pass: a fixed count, whatever the three values
};

// Honest blocks pass; their mutations, the same root from a longer list, are
// flagged, also where the last two txids differ or the count is odd.
for (n in ([1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 16, 17, 23, 31, 33, 100] : [Nat]).values()) {
  let txs = Array.tabulate<Blob>(n, func(i) = bytes(1 + (i * 37) % 150));
  let txids = txs.map<Blob, Blob>(func(tx) { let h = Sha256.new(); h.writeBlob(tx); h.sumDouble() });
  let root = refBitcoin(txids);
  assert (not BitcoinMutation.mutated(txids));
  assert (not BitcoinMutation.mutated(txs));
  assert (BitcoinMerkle.bitcoinMerkleRoot(txids) == root);
  assert (BitcoinTxMerkle.bitcoinTxMerkleRoot(txs) == root);
  // Repeat the last 2^k leaves when they are the lone last node of level k
  // (n = 2^k mod 2^(k+1)): the same root. Any other repeated tail changes it.
  var width = 1;
  while (width <= n) {
    let m = txids.concat(slice(txids, n - width, n));
    if (n % (2 * width) == width and n > width) {
      assert (uncheckedRoot(m) == root);
      assert (BitcoinMutation.mutated(m));
      assert (BitcoinMutation.mutated(txs.concat(slice(txs, n - width, n))));
    } else {
      assert (uncheckedRoot(m) != root);
    };
    width *= 2;
  };
};
do {
  let t = Array.tabulate<Blob>(11, func(_) = bytes(32));
  // [1..5] and [1,2,3,4,5,5,5]: an odd count
  let five = slice(t, 0, 5);
  let seven = five.concat([t[4], t[4]]);
  assert (uncheckedRoot(seven) == refBitcoin(five) and BitcoinMutation.mutated(seven));
  // [1..6] and [1,2,3,4,5,6,5,6]: the last two differ
  let six = slice(t, 0, 6);
  let eight = six.concat([t[4], t[5]]);
  assert (uncheckedRoot(eight) == refBitcoin(six) and BitcoinMutation.mutated(eight));
  // [1..8,a,b,c] and [1..8,a,b,c,c,a,b,c]: odd count, the last two differ, and
  // the only equal pair (c,c) is not the last complete pair of its level
  let fifteen = t.concat([t[10], t[8], t[9], t[10]]);
  assert (uncheckedRoot(fifteen) == refBitcoin(t) and BitcoinMutation.mutated(fifteen));
  // Flagged beyond the mutations: the last txid repeated 2^k places back,
  // though the root differs from every honest one ([a,b,a]). Not a search for
  // repeats in general: [a,b,c,a] and [a,a,b] pass.
  assert (BitcoinMutation.mutated([t[0], t[1], t[0]]));
  assert (not BitcoinMutation.mutated([t[0], t[1], t[2], t[0]]));
  assert (not BitcoinMutation.mutated([t[0], t[0], t[1]]));
};
