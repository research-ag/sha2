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
      description = "Per-operation cost of the Sha256 digest lifecycle: every row runs exactly one operation on a PRE-BUILT digest, so no row includes a writeBlob.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x5f5f5f5f5f5f5f5f);
    // Sub-block input (block size is 64 bytes) so the partial finalize rows
    // exercise padding through the buffer, and an exactly-one-block input so
    // close() hits the block-boundary fast path. The sum()/sumDouble()
    // partial-vs-@block gaps are entirely close()'s padding path — readSum
    // and the sumDouble fold are length-independent.
    let input : Blob = (Array.tabulate<Nat8>(40, func(_) = rng.nat8())).toBlob();
    let block : Blob = (Array.tabulate<Nat8>(64, func(_) = rng.nat8())).toBlob();

    // Pre-built hashers for the non-creation rows. Each cell runs exactly once
    // per measurement, so a single finalize per hasher is safe. 'partial' rows
    // get the 40-byte sub-block message, '@block' rows the 64-byte one.
    let resetLocal = Sha256.new();
    resetLocal.writeBlob(input);
    let closeLocal = Sha256.new();
    closeLocal.writeBlob(input);
    let closeBlockLocal = Sha256.new();
    closeBlockLocal.writeBlob(block);
    // readSum() reads a closed digest, so this one is pre-closed.
    let readSumLocal = Sha256.new();
    readSumLocal.writeBlob(input);
    readSumLocal.close();
    let sumLocal = Sha256.new();
    sumLocal.writeBlob(input);
    let sumBlockLocal = Sha256.new();
    sumBlockLocal.writeBlob(block);
    let dshaLocal = Sha256.new();
    dshaLocal.writeBlob(input);
    let dshaBlockLocal = Sha256.new();
    dshaBlockLocal.writeBlob(block);

    let routines : [[() -> ()]] = [
      // new()
      [func() = ignore Sha256.new()],
      // reset()
      [func() = resetLocal.reset()],
      // close() partial: sub-block message, padding via the buffer
      [func() = closeLocal.close()],
      // close() @block: block-aligned message, padding via the fast path
      [func() = closeBlockLocal.close()],
      // readSum(): read a closed digest's 32-byte state out as a Blob
      [func() = ignore readSumLocal.readSum()],
      // sum() partial: close() partial + readSum()
      [func() = ignore sumLocal.sum()],
      // sum() @block: close() @block + readSum()
      [func() = ignore sumBlockLocal.sum()],
      // sumDouble() partial: close() partial + re-hash + readSum()
      [func() = ignore dshaLocal.sumDouble()],
      // sumDouble() @block: close() @block + re-hash + readSum()
      [func() = ignore dshaBlockLocal.sumDouble()],
    ];

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
