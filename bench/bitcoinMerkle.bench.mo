import Array "mo:core/Array";
import Nat "mo:core/Nat";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import BitcoinRoot "bitcoinRoot";
import Sha256 "../src/Sha256";

module {
  // Cost of the Bitcoin Merkle root (examples/BitcoinMerkle.mo, copied in
  // bench/bitcoinRoot.mo) as a function of the transaction count. The leaves
  // are random 32-byte Blobs from a seeded PRNG, generated at init outside the
  // measurement: the cost does not depend on the leaf bytes, only on their
  // number. Each row is one `bitcoinMerkleRoot` call, as a canister would make
  // it, including the allocation of its hasher pool (about 5k instructions).
  //
  // Every node of the tree costs three SHA-256 compressions (combine plus the
  // double-SHA fold), and a tree over n leaves has about n nodes, so the cost
  // is linear in n. Real mainnet blocks measured the same way: 6467 txids
  // (block 972281) 158.3M, 8281 txids (block 970240, the largest count of the
  // two years before October 2026) 202.7M instructions.

  public func init() : Bench.V1 {
    let counts : [Nat] = [2_000, 4_000, 6_000, 8_000, 10_000, 12_000];
    let rows = counts.map<Nat, Text>(func(n) = n.toText() # " txids");

    let schema : Bench.Schema = {
      name = "Bitcoin Merkle root by transaction count";
      description = "bitcoinMerkleRoot over n random 32-byte txids, one call per run. Linear in n: about 24.4k instructions per node.";
      rows = rows;
      cols = ["bitcoinMerkleRoot"];
    };

    let rng : Random.Random = Random.seed(0x6d65_726b_6c65_3235);
    func txid() : Blob = (Array.tabulate<Nat8>(32, func(_) = rng.nat8())).toBlob();
    let txidsByRow = counts.map<Nat, [Blob]>(func(n) = Array.tabulate<Blob>(n, func(_) = txid()));

    // Keep the generic Digest path (variable-length padding) in the binary, as a
    // canister that also hashes messages would.
    assert Sha256.fromBlob("not block aligned").size() == 32;

    Bench.V1(schema, func(ri : Nat, _ : Nat) = ignore BitcoinRoot.bitcoinMerkleRoot(txidsByRow[ri]));
  };
};
