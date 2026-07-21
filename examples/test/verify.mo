// @testmode wasi
// Verifies the examples produce the same hashes as straightforward references.
import MerkleStack "../MerkleStack";
import MerkleStackState "../MerkleStackState";
import MerkleCounter "../MerkleCounter";
import MerkleCounterState "../MerkleCounterState";
import BitcoinMerkle "../BitcoinMerkle";
import BitcoinTxMerkle "../BitcoinTxMerkle";
import BitcoinWitness "../BitcoinWitness";
import NFold "../NFold";
import Sha256 "mo:sha2/Sha256";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
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
  let b170t0 : Blob = Blob.fromArray([130, 80, 28, 17, 120, 250, 11, 34, 44, 31, 61, 71, 78, 199, 38, 184, 50, 1, 63, 10, 83, 43, 68, 187, 98, 12, 206, 134, 36, 165, 254, 177]);
  // tx1 f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
  let b170t1 : Blob = Blob.fromArray([22, 158, 30, 131, 233, 48, 133, 51, 145, 188, 111, 53, 246, 5, 198, 117, 76, 254, 173, 87, 207, 131, 135, 99, 157, 59, 64, 150, 197, 79, 24, 244]);
  let b170root : Blob = Blob.fromArray([255, 16, 76, 203, 5, 66, 26, 185, 62, 99, 248, 195, 206, 92, 44, 46, 157, 187, 55, 222, 39, 100, 179, 163, 23, 92, 129, 102, 86, 44, 172, 125]);
  assert (BitcoinMerkle.bitcoinMerkleRoot([b170t0, b170t1]) == b170root);

  // block 586, 3 transactions (odd -> exercises last-node duplication);
  // merkle root 197b3d968ce463aa5da7d8eeba8af35eba80ded4e4fe6808e6cc0dd1c069594d
  // tx0 d45724bacd1480b0c94d363ebf59f844fb54e60cdfda0cd38ef67154e9d0bc43
  let b586t0 : Blob = Blob.fromArray([67, 188, 208, 233, 84, 113, 246, 142, 211, 12, 218, 223, 12, 230, 84, 251, 68, 248, 89, 191, 62, 54, 77, 201, 176, 128, 20, 205, 186, 36, 87, 212]);
  // tx1 4d6edbeb62735d45ff1565385a8b0045f066055c9425e21540ea7a8060f08bf2
  let b586t1 : Blob = Blob.fromArray([242, 139, 240, 96, 128, 122, 234, 64, 21, 226, 37, 148, 92, 5, 102, 240, 69, 0, 139, 90, 56, 101, 21, 255, 69, 93, 115, 98, 235, 219, 110, 77]);
  // tx2 6bf363548b08aa8761e278be802a2d84b8e40daefe8150f9af7dd7b65a0de49f
  let b586t2 : Blob = Blob.fromArray([159, 228, 13, 90, 182, 215, 125, 175, 249, 80, 129, 254, 174, 13, 228, 184, 132, 45, 42, 128, 190, 120, 226, 97, 135, 170, 8, 139, 84, 99, 243, 107]);
  let b586root : Blob = Blob.fromArray([77, 89, 105, 192, 209, 13, 204, 230, 8, 104, 254, 228, 212, 222, 128, 186, 94, 243, 138, 186, 238, 216, 167, 93, 170, 99, 228, 140, 150, 61, 123, 25]);
  assert (BitcoinMerkle.bitcoinMerkleRoot([b586t0, b586t1, b586t2]) == b586root);
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
  let w = BitcoinWitness.coinbaseWitness(mmr);
  assert (foldWitness(txids[0], w) == root);
  // The receiver side must accept the genuine proof ...
  assert (BitcoinWitness.verifyTxid(txids[0], w, root));
  // ... and reject a wrong coinbase or a wrong root.
  if (n >= 2) assert (not BitcoinWitness.verifyTxid(txids[1], w, root));
  assert (not BitcoinWitness.verifyTxid(txids[0], w, bytes(32)));
};
// Raw-transaction trees (Example 6 with capture on), used incrementally: the
// witness must verify at both counts — the captured spine siblings stay
// valid as transactions keep arriving.
do {
  let txs = Array.tabulate<Blob>(23, func(j) = bytes(8 + (j * 53) % 250));
  let txids = txs.map<Blob, Blob>(func(tx) = Sha256.fromBlob(Sha256.fromBlob(tx)));
  let mmr = BitcoinTxMerkle.new(23, true);
  var i = 0;
  while (i < 12) { BitcoinTxMerkle.add(mmr, txs[i]); i += 1 };
  assert (BitcoinTxMerkle.root(mmr) == BitcoinMerkle.bitcoinMerkleRoot(Array.tabulate<Blob>(12, func(j) = txids[j])));
  assert (foldWitness(txids[0], BitcoinWitness.coinbaseWitnessTx(mmr)) == BitcoinTxMerkle.root(mmr));
  while (i < 23) { BitcoinTxMerkle.add(mmr, txs[i]); i += 1 };
  assert (BitcoinTxMerkle.root(mmr) == BitcoinMerkle.bitcoinMerkleRoot(txids));
  let w = BitcoinWitness.coinbaseWitnessTx(mmr);
  assert (foldWitness(txids[0], w) == BitcoinTxMerkle.root(mmr));
  // The receiver side from the RAW coinbase transaction: only root, tx0 and
  // witness cross the wire.
  assert (BitcoinWitness.verifyTx(txs[0], w, BitcoinTxMerkle.root(mmr)));
  assert (not BitcoinWitness.verifyTx(txs[1], w, BitcoinTxMerkle.root(mmr)));
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
