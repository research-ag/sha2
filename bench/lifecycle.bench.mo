import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha256 "../src/Sha256";
import Digest256 "../src/sha256/digest"; // internal module exposing close()
import Sha256_old "mo:sha2_0_1_14/Sha256"; // pinned 0.1.14 for comparison

module {
  public func init() : Bench.V1 {
    let rows = [
      "new()", // create a fresh hasher
      "reset()", // reset an existing hasher
      "sum()", // finalize and return the hash (allocates a Blob)
      "close()", // internal finalize without returning (no allocation)
      "double-sha (32 B)", // sha256(sha256(msg)) on a 32-byte message
    ];
    let cols = [
      "0.2.x (current)",
      "0.1.14",
    ];

    let schema : Bench.Schema = {
      name = "Sha256 lifecycle";
      description = "Per-operation cost of the hasher lifecycle plus two composite hashes, local code vs. pinned 0.1.14. The hasher in reset()/sum()/close() rows already exists and has had a partial block written to it. 0.1.14 has no public finalize-without-allocation, so its close() cell is a no-op (N/A). double-sha is sha256(sha256(msg)) on a 32-byte message; the current column uses the dedicated sumDouble() (copies state into the buffer, no intermediate Blob), while 0.1.14 reuses a single hasher (sum, reset, re-write, sum). (Merkle-tree benchmarks live in bench/merkle.bench.mo.)";
      rows = rows;
      cols = cols;
    };

    // A fixed, sub-block-size input so the finalize rows exercise padding
    // identically across versions and across the sum()/close() rows.
    let rng : Random.Random = Random.seed(0x5f5f5f5f5f5f5f5f);
    let input : Blob = Blob.fromArray(Array.tabulate<Nat8>(40, func(i) = rng.nat8()));

    // Pre-built hashers for the non-creation rows. Each cell runs exactly
    // once per measurement, so a single finalize per hasher is safe.
    let resetLocal = Sha256.new();
    Sha256.writeBlob(resetLocal, input);
    let sumLocal = Sha256.new();
    Sha256.writeBlob(sumLocal, input);
    let closeLocal = Sha256.new();
    Sha256.writeBlob(closeLocal, input);

    let resetOld = Sha256_old.Digest(#sha256);
    resetOld.writeBlob(input);
    let sumOld = Sha256_old.Digest(#sha256);
    sumOld.writeBlob(input);

    // A 32-byte message for the double-sha row.
    let msg32 : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func(i) = rng.nat8()));

    // One hasher per row, allocated up front and reused via reset() instead of
    // calling fromBlob (which would allocate a fresh hasher on every hash).
    let dshaLocal = Sha256.new();
    let dshaOld = Sha256_old.Digest(#sha256);

    let routines : [[() -> ()]] = [
      // new()
      [
        func() = ignore Sha256.new(),
        func() = ignore Sha256_old.Digest(#sha256),
      ],
      // reset()
      [
        func() = Sha256.reset(resetLocal),
        func() = resetOld.reset(),
      ],
      // sum()
      [
        func() = ignore Sha256.sum(sumLocal),
        func() = ignore sumOld.sum(),
      ],
      // close()
      [
        func() = Digest256.close(closeLocal),
        func() {}, // N/A: 0.1.14 has no public finalize-without-allocation
      ],
      // double-sha (32 B): sha256(sha256(msg))
      // current uses the dedicated sumDouble(); 0.1.14 reuses one hasher
      [
        func() {
          Sha256.writeBlob(dshaLocal, msg32);
          ignore Sha256.sumDouble(dshaLocal);
        },
        func() {
          dshaOld.writeBlob(msg32);
          let once = dshaOld.sum();
          dshaOld.reset();
          dshaOld.writeBlob(once);
          ignore dshaOld.sum();
        },
      ],
    ];

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
