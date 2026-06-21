import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha256 "../src/Sha256";

module {
  public func init() : Bench.V1 {
    // Feed one 64-byte block built from two 32-byte pieces, two ways:
    //  - writeBlobPair32: the pieces are blobs (each 32-bit word assembled from
    //    4 bytes).
    //  - writeSumPair: the pieces are the digests of two closed hashers, read
    //    straight from their state arrays (each word = two 16-bit half-words,
    //    no byte assembly).
    let rows = [
      "write block", // just the one-block write
      "combine (write+close+fold)", // a full double-SHA node combine
    ];
    let cols = [
      "writeBlobPair32",
      "writeSumPair",
    ];

    let schema : Bench.Schema = {
      name = "Sha256 pair-block write";
      description = "Cost of feeding one 64-byte block built from two 32-byte pieces into a hasher, comparing writeBlobPair32 (pieces read from two blobs, assembling each word from 4 bytes) against writeSumPair (pieces read from the state arrays of two closed digests, each word from two half-words — no byte assembly). Both require the target at a block boundary and run the same single-block compression directly with no message buffer. Row 'write block' is the bare write; row 'combine' is a full double-SHA node combine (write + close + fold), resetting the hasher each call. Targets are reused and stay at a block boundary, so repeated measurements are stable.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x7707_7707_7707_7707);
    func b32() : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8()));

    // Two 32-byte leaf blobs for writeBlobPair32.
    let leaf1 = b32();
    let leaf2 = b32();

    // Two closed digests (states hold 32-byte sums) for writeSumPair.
    let dA = Sha256.new();
    Sha256.writeBlob(dA, b32());
    Sha256.close(dA);
    let dB = Sha256.new();
    Sha256.writeBlob(dB, b32());
    Sha256.close(dB);

    // One reused target hasher per cell.
    let tBlob = Sha256.new();
    let tSum = Sha256.new();
    let cBlob = Sha256.new();
    let cSum = Sha256.new();

    let routines : [[() -> ()]] = [
      // write block
      [
        func() = Sha256.writeBlobPair32(tBlob, leaf1, leaf2),
        func() = Sha256.writeSumPair(tSum, dA, dB),
      ],
      // combine (write + close + fold), reset for the next call
      [
        func() {
          Sha256.writeBlobPair32(cBlob, leaf1, leaf2);
          Sha256.close(cBlob);
          Sha256.fold(cBlob);
          Sha256.reset(cBlob);
        },
        func() {
          Sha256.writeSumPair(cSum, dA, dB);
          Sha256.close(cSum);
          Sha256.fold(cSum);
          Sha256.reset(cSum);
        },
      ],
    ];

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
