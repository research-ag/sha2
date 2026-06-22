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
      "sum()", // finalize and return the hash (allocates a Blob)
      "close() partial", // finalize without returning, mid-block
      "close() @block", // finalize at a block boundary (fast path)
      "double-sha (32 B)", // sha256(sha256(msg)) on a 32-byte message
    ];
    let cols = ["Sha256"];

    let schema : Bench.Schema = {
      name = "Sha256 lifecycle";
      description = "Per-operation cost of the hasher lifecycle plus a composite double hash. The hasher in reset()/sum()/close() rows already exists and has had a block written to it. close() finalizes without returning a Blob; 'close() partial' has a sub-block 40-byte message, so the padding goes through the buffer, while 'close() @block' has a 64-byte (one full block) message, so close() takes the block-boundary fast path that compresses the all-constant padding block directly, skipping the buffer fill. double-sha is sha256(sha256(msg)) on a 32-byte message via the dedicated sumDouble() (copies state into the buffer, no intermediate Blob). (Merkle-tree benchmarks live in bench/merkle.bench.mo.)";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x5f5f5f5f5f5f5f5f);
    // Sub-block input (block size is 64 bytes) so the partial finalize rows
    // exercise padding through the buffer, and an exactly-one-block input so
    // close() hits the block-boundary fast path.
    let input : Blob = Blob.fromArray(Array.tabulate<Nat8>(40, func(_) = rng.nat8()));
    let block : Blob = Blob.fromArray(Array.tabulate<Nat8>(64, func(_) = rng.nat8()));

    // Pre-built hashers for the non-creation rows. Each cell runs exactly
    // once per measurement, so a single finalize per hasher is safe.
    let resetLocal = Sha256.new();
    Sha256.writeBlob(resetLocal, input);
    let sumLocal = Sha256.new();
    Sha256.writeBlob(sumLocal, input);
    let closeLocal = Sha256.new();
    Sha256.writeBlob(closeLocal, input);
    let closeBlockLocal = Sha256.new();
    Sha256.writeBlob(closeBlockLocal, block);

    // A 32-byte message for the double-sha row, reused via the same hasher.
    let msg32 : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8()));
    let dshaLocal = Sha256.new();

    let routines : [[() -> ()]] = [
      // new()
      [func() = ignore Sha256.new()],
      // reset()
      [func() = Sha256.reset(resetLocal)],
      // sum()
      [func() = ignore Sha256.sum(sumLocal)],
      // close() partial: sub-block message, padding via the buffer
      [func() = Sha256.close(closeLocal)],
      // close() @block: block-aligned message, padding via the fast path
      [func() = Sha256.close(closeBlockLocal)],
      // double-sha (32 B): sha256(sha256(msg)) via the dedicated sumDouble()
      [
        func() {
          Sha256.writeBlob(dshaLocal, msg32);
          ignore Sha256.sumDouble(dshaLocal);
        },
      ],
    ];

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
