import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha256 "../src/Sha256";

module {
  public func init() : Bench.V1 {
    // Three ways to put one 64-byte block (two 32-byte pieces) into a hasher:
    //  - writeBlobPair32: two 32-byte blobs, one specialized block, no buffer.
    //  - writeSumPair:    two closed digests' states, one specialized block.
    //  - writeBlob x2:    the general path — two writeBlob calls through the
    //                     message buffer, which complete one block.
    let rows = [
      "writeBlobPair32",
      "writeSumPair",
      "writeBlob x2",
    ];
    let cols = [
      "write block", // just put the block in (no finalize)
      "write + close", // then finalize (no fold)
    ];

    let schema : Bench.Schema = {
      name = "Sha256 pair-block write";
      description = "Three ways to feed one 64-byte block (two 32-byte pieces) into a hasher. 'writeBlobPair32' reads the two pieces from blobs and runs one specialized block directly (no message buffer). 'writeSumPair' reads them from the state arrays of two closed digests (no byte assembly, no Blob). 'writeBlob x2' is the general path: two writeBlob calls that go through the message buffer and complete exactly one block. The 'write block' column is the bare write; 'write + close' also finalizes the block (no fold). Targets are reused (reset for the close column), staying at a block boundary, so repeated measurements are stable.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x7707_7707_7707_7707);
    func b32() : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8()));

    // Two 32-byte leaf blobs for writeBlobPair32 / writeBlob x2.
    let leaf1 = b32();
    let leaf2 = b32();

    // Two closed digests (states hold 32-byte sums) for writeSumPair.
    let dA = Sha256.new();
    Sha256.writeBlob(dA, b32());
    Sha256.close(dA);
    let dB = Sha256.new();
    Sha256.writeBlob(dB, b32());
    Sha256.close(dB);

    // One reused target hasher per cell (write-only cells stay at a boundary;
    // close cells reset each call).
    let wB = Sha256.new();
    let cB = Sha256.new();
    let wS = Sha256.new();
    let cS = Sha256.new();
    let wW = Sha256.new();
    let cW = Sha256.new();

    let routines : [[() -> ()]] = [
      // writeBlobPair32
      [
        func() = Sha256.writeBlobPair32(wB, leaf1, leaf2),
        func() {
          Sha256.writeBlobPair32(cB, leaf1, leaf2);
          Sha256.close(cB);
          Sha256.reset(cB);
        },
      ],
      // writeSumPair
      [
        func() = Sha256.writeSumPair(wS, dA, dB),
        func() {
          Sha256.writeSumPair(cS, dA, dB);
          Sha256.close(cS);
          Sha256.reset(cS);
        },
      ],
      // writeBlob x2
      [
        func() {
          Sha256.writeBlob(wW, leaf1);
          Sha256.writeBlob(wW, leaf2);
        },
        func() {
          Sha256.writeBlob(cW, leaf1);
          Sha256.writeBlob(cW, leaf2);
          Sha256.close(cW);
          Sha256.reset(cW);
        },
      ],
    ];

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
