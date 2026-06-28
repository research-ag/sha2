import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha256 "../src/Sha256";
import Hasher "../src/Hasher/Sha256";

module {
  public func init() : Bench.V1 {
    // The single-shot `Hasher` exists to hash short, fixed-length messages with
    // less overhead than the buffered `Digest`. Each row is one such operation,
    // computed two ways on a REUSED engine (no per-call allocation either side):
    //   * 'Hasher'  — the bufferless fixed-length entry point.
    //   * 'Digest'  — the general path: reset, writeBlob(s), close / closeDouble.
    // Both produce the identical hash; the gap is the buffer/lifecycle overhead
    // the Hasher skips. No cell reads the digest out, so neither allocates — the
    // comparison is pure instruction count.
    let rows = [
      "hash 32 B",
      "double-hash 32 B",
      "combine 2x32 B blobs",
      "combine 2 states",
    ];
    let cols = ["Hasher", "Digest"];

    let schema : Bench.Schema = {
      name = "Sha256 Hasher";
      description = "Short fixed-length SHA256 with the single-shot Hasher vs the general buffered Digest path, on a reused engine. 'hash 32 B' = SHA256 of a 32-byte message (1 block). 'double-hash 32 B' = SHA256(SHA256(msg)) left in the engine (Hasher: hashBlob32 + hashState; Digest: reset + writeBlob + closeDouble). 'combine 2x32 B blobs' = SHA256(b1 ++ b2) of two 32-byte blobs (2 blocks; Hasher: combineBlob32; Digest: two writeBlobs + close). 'combine 2 states' = SHA256 of two 32-byte digests read straight from their hashers (Hasher: combineState, no Blob; Digest: writeBlob each state blob + close). No cell reads the result out, so all are allocation-free; the gap is pure overhead the Hasher avoids. (The readSum/sumDouble readout cost is isolated in sha256_lifecycle.bench.mo.)";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x4861_7368_6572_2121);
    func b32() : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func(_) = rng.nat8()));

    let a = b32();
    let b = b32();
    // Precomputed 32-byte digest states for the "combine 2 states" row.
    let sa = Sha256.fromBlob(a); // SHA256(a) as a Blob (for the Digest column)
    let sb = Sha256.fromBlob(b);

    // Reused engines (allocated once).
    let h = Hasher.new();
    let d = Sha256.new();
    // Two hashers preloaded with SHA256(a) / SHA256(b) for combineState sources.
    let x = Hasher.new();
    x.hashBlob32(a);
    let y = Hasher.new();
    y.hashBlob32(b);

    let routines : [[() -> ()]] = [
      // hash 32 B
      [
        func() = h.hashBlob32(a),
        func() { d.reset(); d.writeBlob(a); d.close() },
      ],
      // double-hash 32 B (allocation-free, result left in the engine)
      [
        func() { h.hashBlob32(a); h.hashState(h) },
        func() { d.reset(); d.writeBlob(a); d.closeDouble() },
      ],
      // combine 2x32 B blobs
      [
        func() = h.combineBlob32(a, b),
        func() { d.reset(); d.writeBlob(a); d.writeBlob(b); d.close() },
      ],
      // combine 2 states
      [
        func() = h.combineState(x, y),
        func() { d.reset(); d.writeBlob(sa); d.writeBlob(sb); d.close() },
      ],
    ];

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
