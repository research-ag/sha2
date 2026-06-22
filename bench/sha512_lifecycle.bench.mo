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
      description = "Per-operation cost of the Sha512 hasher lifecycle. The hasher in reset()/sum()/close() rows already exists and has had a block written to it. close() finalizes without returning a Blob; 'close() partial' has a sub-block 80-byte message, so the padding goes through the buffer, while 'close() @block' has a 128-byte (one full block) message, so close() takes the block-boundary fast path that compresses the all-constant padding block directly, skipping the buffer fill.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x5f5f5f5f5f5f5f5f);
    // Sub-block input (block size is 128 bytes) so the partial finalize rows
    // exercise padding through the buffer, and an exactly-one-block input so
    // close() hits the block-boundary fast path.
    let input : Blob = Blob.fromArray(Array.tabulate<Nat8>(80, func(_) = rng.nat8()));
    let block : Blob = Blob.fromArray(Array.tabulate<Nat8>(128, func(_) = rng.nat8()));

    // Pre-built hashers for the non-creation rows. Each cell runs exactly
    // once per measurement, so a single finalize per hasher is safe.
    let resetLocal = Sha512.new();
    Sha512.writeBlob(resetLocal, input);
    let sumLocal = Sha512.new();
    Sha512.writeBlob(sumLocal, input);
    let closeLocal = Sha512.new();
    Sha512.writeBlob(closeLocal, input);
    let closeBlockLocal = Sha512.new();
    Sha512.writeBlob(closeBlockLocal, block);

    let routines : [[() -> ()]] = [
      // new()
      [func() = ignore Sha512.new()],
      // reset()
      [func() = Sha512.reset(resetLocal)],
      // sum()
      [func() = ignore Sha512.sum(sumLocal)],
      // close() partial: sub-block message, padding via the buffer
      [func() = Sha512.close(closeLocal)],
      // close() @block: block-aligned message, padding via the fast path
      [func() = Sha512.close(closeBlockLocal)],
    ];

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
