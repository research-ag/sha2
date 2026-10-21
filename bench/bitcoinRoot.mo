/// Bench-local copy of the Bitcoin Merkle root of examples/BitcoinMerkle.mo
/// (the binary-counter MMR of examples/CounterBase.mo with double SHA256 and
/// Bitcoin's collapse). The bench files cannot import the examples, because
/// those import the package as `mo:sha2/...`, which the root project does not
/// provide; the code below is the same algorithm with the imports changed.

import VarArray "mo:core/VarArray";
import Nat64 "mo:core/Nat64";
import Hasher "../src/Hasher/Sha256";

module {
  public type Mmr = {
    hasher : [var Hasher.Hasher];
    var count : Nat64;
    var pending : ?Blob;
  };

  public func new(maxLeaves : Nat) : Mmr {
    var l = 0;
    var pow = 1;
    while (pow * 2 <= maxLeaves) { pow *= 2; l += 1 }; // l = floor(log2 maxLeaves)
    {
      hasher = VarArray.tabulate<Hasher.Hasher>(l + 1, func(_) { Hasher.new() });
      var count = 0;
      var pending = null;
    };
  };

  public func add(self : Mmr, leaf : Blob) {
    let hasher = self.hasher;
    switch (self.pending) {
      case (null) { self.pending := ?leaf };
      case (?leaf0) {
        self.pending := null;
        hasher[0].combineBlob32(leaf0, leaf);
        hasher[0].hashState(hasher[0]);
        var k : Nat64 = 1;
        while (((self.count >> k) & 1) == 1) {
          let kk = k.toNat();
          hasher[kk].combineState(hasher[kk], hasher[kk - 1]);
          hasher[kk].hashState(hasher[kk]);
          k += 1;
        };
        let kk = k.toNat();
        let tmp = hasher[kk];
        hasher[kk] := hasher[kk - 1];
        hasher[kk - 1] := tmp;
      };
    };
    self.count += 1;
  };

  public func root(self : Mmr) : Blob {
    let hasher = self.hasher;
    let count = self.count;
    assert count >= 1;
    let acc = hasher[0];
    var k : Nat64 = 1;
    switch (self.pending) {
      case (?b) {
        if (count == 1) { assert b.size() == 32; return b };
        acc.loadBlob32(b);
        acc.combineState(acc, acc);
      };
      case (null) {
        while (((count >> k) & 1) == 0) { k += 1 };
        if (Nat64.bitcountNonZero(count) == 1) {
          return hasher[k.toNat()].readSum();
        };
        let k0 = k.toNat();
        acc.combineState(hasher[k0], hasher[k0]);
        k += 1;
      };
    };
    acc.hashState(acc);
    while ((count >> k) > 0) {
      if (((count >> k) & 1) == 1) {
        acc.combineState(hasher[k.toNat()], acc);
      } else {
        acc.combineState(acc, acc);
      };
      acc.hashState(acc);
      k += 1;
    };
    acc.readSum();
  };

  /// One-shot root, as `BitcoinMerkle.bitcoinMerkleRoot` in the examples.
  public func bitcoinMerkleRoot(txids : [Blob]) : Blob {
    assert txids.size() >= 1;
    let mmr = new(txids.size());
    for (leaf in txids.values()) {
      mmr.add(leaf);
    };
    mmr.root();
  };
};
