// Verifies the examples produce the same hashes as straightforward references.
import Merkle "../Merkle";
import BitcoinTxMerkle "../BitcoinTxMerkle";
import NFold "../NFold";
import Sha256 "../../src/Sha256";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Random "mo:core/Random";

let rng = Random.seed(0x1234);
func bytes(n : Nat) : Blob = Blob.fromArray(Array.tabulate<Nat8>(n, func(_) = rng.nat8()));

// Canonical Bitcoin Merkle root: level by level, duplicating the last node on
// odd counts (materializes every intermediate digest as a Blob).
func refRoot(leaves : [Blob]) : Blob {
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

// Every leaf count 1..18, plus a few larger and non-power-of-two sizes.
for (n in ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 23, 31, 33, 100] : [Nat]).values()) {
  let leaves = Array.tabulate<Blob>(n, func(_) = bytes(32));
  assert (Merkle.bitcoinMerkleRoot(leaves) == refRoot(leaves));
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
  assert (Merkle.bitcoinMerkleRoot([b170t0, b170t1]) == b170root);

  // block 586, 3 transactions (odd -> exercises last-node duplication);
  // merkle root 197b3d968ce463aa5da7d8eeba8af35eba80ded4e4fe6808e6cc0dd1c069594d
  // tx0 d45724bacd1480b0c94d363ebf59f844fb54e60cdfda0cd38ef67154e9d0bc43
  let b586t0 : Blob = Blob.fromArray([67, 188, 208, 233, 84, 113, 246, 142, 211, 12, 218, 223, 12, 230, 84, 251, 68, 248, 89, 191, 62, 54, 77, 201, 176, 128, 20, 205, 186, 36, 87, 212]);
  // tx1 4d6edbeb62735d45ff1565385a8b0045f066055c9425e21540ea7a8060f08bf2
  let b586t1 : Blob = Blob.fromArray([242, 139, 240, 96, 128, 122, 234, 64, 21, 226, 37, 148, 92, 5, 102, 240, 69, 0, 139, 90, 56, 101, 21, 255, 69, 93, 115, 98, 235, 219, 110, 77]);
  // tx2 6bf363548b08aa8761e278be802a2d84b8e40daefe8150f9af7dd7b65a0de49f
  let b586t2 : Blob = Blob.fromArray([159, 228, 13, 90, 182, 215, 125, 175, 249, 80, 129, 254, 174, 13, 228, 184, 132, 45, 42, 128, 190, 120, 226, 97, 135, 170, 8, 139, 84, 99, 243, 107]);
  let b586root : Blob = Blob.fromArray([77, 89, 105, 192, 209, 13, 204, 230, 8, 104, 254, 228, 212, 222, 128, 186, 94, 243, 138, 186, 238, 216, 167, 93, 170, 99, 228, 140, 150, 61, 123, 25]);
  assert (Merkle.bitcoinMerkleRoot([b586t0, b586t1, b586t2]) == b586root);
};

// BitcoinTxMerkle: root over RAW (variable-length) transactions must equal the
// vector-tested Merkle.bitcoinMerkleRoot fed the same transactions' txids
// (txid = double SHA256 of the raw bytes). This exercises the Digest -> Hasher
// bridge and closeDouble against the naive double hash, transitively tying the
// raw-tx root to the mainnet block vectors checked above.
for (count in ([1, 2, 3, 4, 5, 8, 9, 16, 17, 30] : [Nat]).values()) {
  // Raw transactions of assorted lengths, several crossing the 64-byte block
  // boundary, so the Digest absorb path is exercised for each leaf.
  let txs = Array.tabulate<Blob>(count, func(j) = bytes(8 + (j * 53) % 250));
  let txids = Array.map<Blob, Blob>(txs, func(tx) = Sha256.fromBlob(Sha256.fromBlob(tx)));
  assert (BitcoinTxMerkle.bitcoinTxMerkleRoot(txs) == Merkle.bitcoinMerkleRoot(txids));
};

// N-fold against manual repeated fromBlob.
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
