import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha256 "../src/Sha256";

module {
  // Post-order DFS Merkle combine using merkleLeaves (leaves) and merkleMerge
  // (internal nodes). Both work in place from the IV — no reset/close per node.
  // Module-level (not a closure) so it captures no mutable state; the free-list
  // lives in `freeIx`/`top` (a 1-cell array), both pre-allocated. Returns the
  // pool index of the hasher holding this subtree's closed double-SHA digest.
  func evalDfs(leaves : [Blob], pool : [Sha256.Digest], freeIx : [var Nat], top : [var Nat], lo : Nat, hi : Nat) : Nat {
    if (hi - lo == 2) {
      top[0] -= 1;
      let i = freeIx[top[0]]; // take a free (closed) hasher
      let h = pool[i];
      h.merkleLeaves(leaves[lo], leaves[lo + 1]); // inner SHA256(l0 ++ l1)
      h.fold(); // outer SHA256 -> double-SHA
      i;
    } else {
      let mid = lo + (hi - lo) / 2;
      let l = evalDfs(leaves, pool, freeIx, top, lo, mid);
      let r = evalDfs(leaves, pool, freeIx, top, mid, hi);
      pool[l].merkleMerge(pool[r]); // l := double-SHA(l ++ r); r consumed
      freeIx[top[0]] := r; // free r
      top[0] += 1;
      l;
    };
  };

  public func init() : Bench.V1 {
    // Bitcoin-style double-SHA Merkle root over 2^k 32-byte leaves, built with
    // the merkleLeaves/merkleMerge DFS in log2(n) hashers.
    let exps : [Nat] = [8, 10, 12];
    let rows = ["2^8 leaves", "2^10 leaves", "2^12 leaves"];
    let cols = ["merkleLeaves DFS"];

    let schema : Bench.Schema = {
      name = "Sha256 Merkle (double-SHA)";
      description = "Bitcoin-style double-SHA Merkle root over 2^k 32-byte leaves, built post-order: leaf pairs combined with merkleLeaves + fold, internal nodes combined in place with merkleMerge (reads both child states from the IV, pads and folds). A pool of log2(n) hashers — started closed — is reused via a free-list; merkleMerge writes into the left child and frees the right. No reset/close per node, no message buffer, allocation-free except the final root Blob.";
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
    // require a closed hasher), plus a free-list (indices + a `top` cell).
    let poolByRow = Array.tabulate<[Sha256.Digest]>(
      rows.size(),
      func(ri) = Array.tabulate<Sha256.Digest>(
        exps[ri],
        func(_) { let h = Sha256.new(); Sha256.close(h); h },
      ),
    );
    let freeByRow = Array.tabulate<[var Nat]>(
      rows.size(),
      func(ri) = VarArray.tabulate<Nat>(exps[ri], func(i) = i),
    );
    let topByRow = Array.tabulate<[var Nat]>(rows.size(), func(ri) = [var exps[ri]]);

    func dfsRoot(ri : Nat) : Blob {
      let pool = poolByRow[ri];
      let freeIx = freeByRow[ri];
      let top = topByRow[ri];
      let leaves = leavesByRow[ri];
      var j = 0;
      while (j < pool.size()) { freeIx[j] := j; j += 1 }; // (re)init the free-list
      top[0] := pool.size();
      Sha256.readSum(pool[evalDfs(leaves, pool, freeIx, top, 0, leaves.size())]);
    };

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      rows.size(),
      func(ri) { [func() = ignore dfsRoot(ri)] },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
