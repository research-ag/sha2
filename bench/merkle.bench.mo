import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha256 "../src/Sha256";

module {
  // Iterative Merkle-mountain-range build of a Bitcoin-style double-SHA root.
  // `hasher[0 .. i-1]` is a stack of completed-subtree "peaks" (left to right),
  // `level[j]` is the tree level of `hasher[j]`, and `i` is the stack height.
  // Each leaf pair is pushed as a node, then while the new peak's level matches
  // the peak below it they merge in place (merkleMerge writes into the left).
  // No recursion, no free-list. The hashers must start closed.
  func merkleRoot(leaves : [Blob], hasher : [Sha256.Digest], level : [var Nat]) : Blob {
    let n = leaves.size();
    var i = 0;
    var p = 0;
    while (p < n) {
      hasher[i].merkleLeaves(leaves[p], leaves[p + 1]); // push a leaf node
      hasher[i].fold();
      level[i] := 1;
      while (i > 0 and level[i - 1] == level[i]) {
        hasher[i - 1].merkleMerge(hasher[i]); // merge the top two peaks
        level[i - 1] += 1;
        i -= 1;
      };
      i += 1;
      p += 2;
    };
    Sha256.readSum(hasher[0]);
  };

  public func init() : Bench.V1 {
    // Bitcoin-style double-SHA Merkle root over 2^k 32-byte leaves: leaf pairs
    // combined with merkleLeaves + fold, internal nodes in place with
    // merkleMerge, in a pool of log2(n) hashers started closed.
    let exps : [Nat] = [8, 10, 12];
    let rows = ["2^8 leaves", "2^10 leaves", "2^12 leaves"];
    let cols = ["peak-stack"];

    let schema : Bench.Schema = {
      name = "Sha256 Merkle (double-SHA)";
      description = "Bitcoin-style double-SHA Merkle root over 2^k 32-byte leaves, built with an iterative Merkle-mountain-range loop: push each leaf node (merkleLeaves + fold) onto a peak stack (hasher[]/level[]/i) and merge in place with merkleMerge while the new peak's level matches the one below it. Uses log2(n) hashers (started closed), no recursion, no free-list. Allocation-free except the final root Blob.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x6d6b_6c65_6d6b_6c65);
    func b32() : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8()));

    let leavesByRow = Array.tabulate<[Blob]>(
      rows.size(),
      func(ri) = Array.tabulate<Blob>(2 ** exps[ri], func(_) = b32()),
    );
    // A pool of log2(n) hashers, started CLOSED (merkleLeaves/merkleMerge both
    // require a closed hasher), plus a per-slot level array.
    let hasherByRow = Array.tabulate<[Sha256.Digest]>(
      rows.size(),
      func(ri) = Array.tabulate<Sha256.Digest>(exps[ri], func(_) { let h = Sha256.new(); Sha256.close(h); h }),
    );
    let levelByRow = Array.tabulate<[var Nat]>(rows.size(), func(ri) = VarArray.repeat<Nat>(0, exps[ri]));

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      rows.size(),
      func(ri) {
        [func() = ignore merkleRoot(leavesByRow[ri], hasherByRow[ri], levelByRow[ri])];
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
