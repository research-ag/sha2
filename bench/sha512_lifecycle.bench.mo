import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha512 "../src/Sha512";

module {
  public func init() : Bench.V1 {
    let rows = [
      "new()", // create a fresh hasher
      "reset()", // reset an existing hasher
      "sum()", // finalize and return the hash (allocates a Blob)
      "close() partial", // finalize without returning, mid-block
      "close() @block", // finalize at a block boundary (fast path)
    ];
    let cols = ["Sha512"];

    let schema : Bench.Schema = {
      name = "Sha512 lifecycle";
      description = "Per-operation cost of the Sha512 digest lifecycle: every row runs exactly one operation on a PRE-BUILT digest, so no row includes a writeBlob.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x5f5f5f5f5f5f5f5f);
    // Sub-block input (block size is 128 bytes) so the partial finalize rows
    // exercise padding through the buffer, and an exactly-one-block input so
    // close() hits the block-boundary fast path.
    let input : Blob = (Array.tabulate<Nat8>(80, func(_) = rng.nat8())).toBlob();
    let block : Blob = (Array.tabulate<Nat8>(128, func(_) = rng.nat8())).toBlob();

    // Pre-built hashers for the non-creation rows. Each cell runs exactly
    // once per measurement, so a single finalize per hasher is safe.
    let resetLocal = Sha512.new();
    resetLocal.writeBlob(input);
    let sumLocal = Sha512.new();
    sumLocal.writeBlob(input);
    let closeLocal = Sha512.new();
    closeLocal.writeBlob(input);
    let closeBlockLocal = Sha512.new();
    closeBlockLocal.writeBlob(block);

    let routines : [[() -> ()]] = [
      // new()
      [func() = ignore Sha512.new()],
      // reset()
      [func() = resetLocal.reset()],
      // sum()
      [func() = ignore sumLocal.sum()],
      // close() partial: sub-block message, padding via the buffer
      [func() = closeLocal.close()],
      // close() @block: block-aligned message, padding via the fast path
      [func() = closeBlockLocal.close()],
    ];

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
