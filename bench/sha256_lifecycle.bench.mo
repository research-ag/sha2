import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha256 "../src/Sha256";

module {
  public func init() : Bench.V1 {
    let rows = [
      "new()", // create a fresh hasher
      "reset()", // reset an existing hasher
      "close() partial", // finalize without returning, mid-block
      "close() @block", // finalize at a block boundary (fast path)
      "readSum()", // read a closed digest's state out as a Blob
      "sum() partial", // close() partial + readSum()
      "sum() @block", // close() @block + readSum()
      "sumDouble() partial", // close() partial + fold + readSum()
      "sumDouble() @block", // close() @block + fold + readSum()
    ];
    let cols = ["Sha256"];

    let schema : Bench.Schema = {
      name = "Sha256 lifecycle";
      description = "Per-operation cost of the hasher lifecycle. Every measured row runs exactly one operation on a PRE-BUILT hasher (already created and, where relevant, already written/closed), so no row includes a writeBlob. new()/reset() create or rewind. close() finalizes without returning a Blob: 'close() partial' has a sub-block 40-byte message so the padding goes through the buffer, while 'close() @block' has a 64-byte (one full block) message so close() takes the block-boundary fast path that compresses the all-constant padding block directly. readSum() reads a closed digest's 32-byte state out as a Blob (length-independent). sum() = close() + readSum(); sumDouble() = close() + an in-place re-hash of the 32-byte state + readSum() (sha256 only). sum() and sumDouble() are shown at both message shapes; their partial-vs-@block gap is entirely close()'s padding path (readSum and the re-hash are length-independent). (Merkle-tree and Hasher-vs-Digest benchmarks live in bench/merkle.bench.mo and bench/hasher.bench.mo.)";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x5f5f5f5f5f5f5f5f);
    // Sub-block input (block size is 64 bytes) so the partial finalize rows
    // exercise padding through the buffer, and an exactly-one-block input so
    // close() hits the block-boundary fast path.
    let input : Blob = Blob.fromArray(Array.tabulate<Nat8>(40, func(_) = rng.nat8()));
    let block : Blob = Blob.fromArray(Array.tabulate<Nat8>(64, func(_) = rng.nat8()));

    // Pre-built hashers for the non-creation rows. Each cell runs exactly once
    // per measurement, so a single finalize per hasher is safe. 'partial' rows
    // get the 40-byte sub-block message, '@block' rows the 64-byte one.
    let resetLocal = Sha256.new();
    Sha256.writeBlob(resetLocal, input);
    let closeLocal = Sha256.new();
    Sha256.writeBlob(closeLocal, input);
    let closeBlockLocal = Sha256.new();
    Sha256.writeBlob(closeBlockLocal, block);
    // readSum() reads a closed digest, so this one is pre-closed.
    let readSumLocal = Sha256.new();
    Sha256.writeBlob(readSumLocal, input);
    Sha256.close(readSumLocal);
    let sumLocal = Sha256.new();
    Sha256.writeBlob(sumLocal, input);
    let sumBlockLocal = Sha256.new();
    Sha256.writeBlob(sumBlockLocal, block);
    let dshaLocal = Sha256.new();
    Sha256.writeBlob(dshaLocal, input);
    let dshaBlockLocal = Sha256.new();
    Sha256.writeBlob(dshaBlockLocal, block);

    let routines : [[() -> ()]] = [
      // new()
      [func() = ignore Sha256.new()],
      // reset()
      [func() = Sha256.reset(resetLocal)],
      // close() partial: sub-block message, padding via the buffer
      [func() = Sha256.close(closeLocal)],
      // close() @block: block-aligned message, padding via the fast path
      [func() = Sha256.close(closeBlockLocal)],
      // readSum(): read a closed digest's 32-byte state out as a Blob
      [func() = ignore Sha256.readSum(readSumLocal)],
      // sum() partial: close() partial + readSum()
      [func() = ignore Sha256.sum(sumLocal)],
      // sum() @block: close() @block + readSum()
      [func() = ignore Sha256.sum(sumBlockLocal)],
      // sumDouble() partial: close() partial + re-hash + readSum()
      [func() = ignore Sha256.sumDouble(dshaLocal)],
      // sumDouble() @block: close() @block + re-hash + readSum()
      [func() = ignore Sha256.sumDouble(dshaBlockLocal)],
    ];

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
