import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Hasher "../src/Hasher/Sha256";
import MerkleBuild "counterBuild";

module {
  // The favored Merkle build: the BINARY-COUNTER MMR with the delay trick,
  // measured over the two leaf types. Both columns run the same algorithm —
  // only the height-0 handling differs, as dictated by the leaf type. The
  // build code is shared with merkle_alloc.bench.mo (bench/counterBuild.mo)
  // and mirrors examples/MerkleCounter.mo / examples/MerkleCounterState.mo.

  public func init() : Bench.V1 {
    let exps : [Nat] = [8, 10, 12];
    let rows = ["2^8 leaves", "2^10 leaves", "2^12 leaves"];
    let cols = ["Blob leaves", "State leaves"];

    let schema : Bench.Schema = {
      name = "Sha256 Merkle counter: Blob vs State leaves";
      description = "Single-SHA Merkle root over 2^k leaves via the binary-counter MMR (the favored build: occupancy = the bits of the leaf count, risen peaks moved by O(1) reference swaps, no flag or level array), comparing the two leaf types. 'Blob leaves' (examples/MerkleCounter.mo) uses the full delay: one leaf waits as a pending ?Blob and each pair is fused with combineBlob32 straight from the input — no per-leaf deserialize. 'State leaves' (examples/MerkleCounterState.mo) are 32-byte hashes already sitting in Hashers, treated as transient: the half-delay parks the first leaf of each pair into slot 0 with one loadState (its partner is read directly by combineState), so n/2 state copies — the gap between the columns is exactly those copies. Both do n-1 combines and are allocation-free except the root Blob. Power-of-two counts, so no bagging finale — the examples add only that. (When state leaves stream out of a Digest, even the park is free: the bridge produces the txid directly INTO slot 0 — see examples/BitcoinTxMerkle.mo.)";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x6d6b_6c65_6d6b_6c65);
    func b32() : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8()));

    let leavesByRow = Array.tabulate<[Blob]>(
      rows.size(),
      func(ri) = Array.tabulate<Blob>(2 ** exps[ri], func(_) = b32()),
    );
    // The same 32-byte values as read-only leaf STATES (neither algorithm
    // mutates a leaf), so both columns hash identical content.
    let stateLeavesByRow = Array.tabulate<[Hasher.Hasher]>(
      rows.size(),
      func(ri) = Array.map<Blob, Hasher.Hasher>(
        leavesByRow[ri],
        func(b) { let h = Hasher.new(); h.loadBlob32(b); h },
      ),
    );

    // Counter pool: log2(n)+1 height slots and one spare carry hasher
    // (occupancy needs no storage — it is the bits of the leaf count).
    // Reused across both columns.
    let counterHasherByRow = Array.tabulate<[var Hasher.Hasher]>(
      rows.size(),
      func(ri) = VarArray.tabulate<Hasher.Hasher>(exps[ri] + 1, func(_) { Hasher.new() }),
    );
    let counterCarryByRow = Array.tabulate<[var Hasher.Hasher]>(rows.size(), func(ri) = VarArray.tabulate<Hasher.Hasher>(1, func(_) { Hasher.new() }));

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      rows.size(),
      func(ri) {
        [
          func() = ignore MerkleBuild.merkleRootBlob(leavesByRow[ri], counterHasherByRow[ri], counterCarryByRow[ri], false),
          func() = ignore MerkleBuild.merkleRootState(stateLeavesByRow[ri], counterHasherByRow[ri], counterCarryByRow[ri], false),
        ];
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
