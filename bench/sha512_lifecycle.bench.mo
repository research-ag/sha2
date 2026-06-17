import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha512 "../src/Sha512";
import Digest512 "../src/sha512/digest"; // internal module exposing close()
import Sha512_old "mo:sha2_0_1_14/Sha512"; // pinned 0.1.14 for comparison

module {
  public func init() : Bench.V1 {
    let rows = [
      "new()", // create a fresh hasher
      "reset()", // reset an existing hasher
      "sum()", // finalize and return the hash (allocates a Blob)
      "close()", // internal finalize without returning (no allocation)
      "merkle 2^12", // single-sha Merkle root over 4096 leaves
    ];
    let cols = [
      "0.2.x (current)",
      "0.1.14",
    ];

    let schema : Bench.Schema = {
      name = "Sha512 lifecycle";
      description = "Per-operation cost of the Sha512 hasher lifecycle, local code vs. pinned 0.1.14. The hasher in reset()/sum()/close() rows already exists and has had a partial block written to it. 0.1.14 has no public finalize-without-allocation, so its close() cell is a no-op (N/A). merkle 2^12 is a single-sha Merkle root over 4096 64-byte leaves (4095 sha512 steps), one reused hasher per level (12 levels). The current column is allocation-free (pushSum streams digests directly between hashers; only the final root Blob is allocated); 0.1.14 must allocate a Blob per node.";
      rows = rows;
      cols = cols;
    };

    // A fixed, sub-block-size input (block size is 128 bytes) so the finalize
    // rows exercise padding identically across versions.
    let rng : Random.Random = Random.seed(0x5f5f5f5f5f5f5f5f);
    let input : Blob = Blob.fromArray(Array.tabulate<Nat8>(80, func(i) = rng.nat8()));

    // Pre-built hashers for the non-creation rows. Each cell runs exactly
    // once per measurement, so a single finalize per hasher is safe.
    let resetLocal = Sha512.new();
    Sha512.writeBlob(resetLocal, input);
    let sumLocal = Sha512.new();
    Sha512.writeBlob(sumLocal, input);
    let closeLocal = Sha512.new();
    Sha512.writeBlob(closeLocal, input);

    let resetOld = Sha512_old.Digest(#sha512);
    resetOld.writeBlob(input);
    let sumOld = Sha512_old.Digest(#sha512);
    sumOld.writeBlob(input);

    // 2^12 = 4096 leaves of 64 bytes (the sha512 digest size), so that
    // concatenating two children is exactly one 128-byte block.
    let leaves : [Blob] = Array.tabulate<Blob>(
      4096,
      func(_) = Blob.fromArray(Array.tabulate<Nat8>(64, func(i) = rng.nat8())),
    );

    // Number of tree levels = log2(leaf count). 4096 leaves -> 12 combining
    // levels, so 12 hashers, one per level.
    var levels = 0;
    var n = leaves.size();
    while (n > 1) { n /= 2; levels += 1 };

    // Generic streaming Merkle root with single-sha per node: leaves are fed
    // left to right and a single hasher per level is kept alive holding a
    // pending left child until its right sibling arrives. No hasher is
    // allocated per node.
    func merkleStream<T>(
      hashers : [T],
      write : (T, Blob) -> (),
      finalize : (T) -> Blob, // sha512 of all data written; closes the hasher
      reopen : (T) -> (), // reset the hasher to accept the next pair
    ) : Blob {
      let pending = VarArray.repeat<Bool>(false, hashers.size());
      var root : Blob = ""; // overwritten by the final combine

      func push(node : Blob, lvl : Nat) {
        if (lvl == hashers.size()) { root := node; return };
        let h = hashers[lvl];
        if (not pending[lvl]) {
          // left child: keep it in this level's hasher until its sibling arrives
          write(h, node);
          pending[lvl] := true;
        } else {
          // right child: h now holds left ++ right; hash it and go up
          write(h, node);
          let parent = finalize(h);
          reopen(h);
          pending[lvl] := false;
          push(parent, lvl + 1);
        };
      };

      var i = 0;
      while (i < leaves.size()) { push(leaves[i], 0); i += 1 };
      root;
    };

    let merkleHashersLocal = Array.tabulate<Sha512.Digest>(levels, func(_) = Sha512.new());
    let merkleHashersOld = Array.tabulate<Sha512_old.Digest>(levels, func(_) = Sha512_old.Digest(#sha512));
    let pendingLocal = VarArray.repeat<Bool>(false, levels);

    // Current code: allocation-free single-sha Merkle root. Each pair is hashed
    // and the digest streamed straight into the parent hasher with pushSum (no
    // intermediate Blob). Only the final root Blob is allocated. The binary
    // carry is iterative, so nothing is allocated per node.
    func merkleLocal() : Blob {
      var root : Blob = ""; // overwritten by the final combine
      var i = 0;
      while (i < leaves.size()) {
        // writeWordBlob is the closure-free leaf write (leaves are 64 bytes,
        // word-aligned).
        Sha512.writeWordBlob(merkleHashersLocal[0], leaves[i]);
        Sha512.writeWordBlob(merkleHashersLocal[0], leaves[i + 1]);
        var lvl = 0;
        var carrying = true;
        while (carrying) {
          let h = merkleHashersLocal[lvl];
          if (lvl + 1 == levels) {
            root := Sha512.sum(h); // single sha = root (the one allocation)
            Sha512.reset(h);
            carrying := false;
          } else {
            h.pushSum(merkleHashersLocal[lvl + 1]); // sha of the pair, into the parent
            Sha512.reset(h);
            if (pendingLocal[lvl + 1]) {
              pendingLocal[lvl + 1] := false;
              lvl += 1; // sibling present -> carry up
            } else {
              pendingLocal[lvl + 1] := true;
              carrying := false; // wait for the sibling
            };
          };
        };
        i += 2;
      };
      root;
    };
    // 0.1.14 has no pushSum: stream Blobs, allocating a digest per node.
    func merkleOld() : Blob = merkleStream<Sha512_old.Digest>(
      merkleHashersOld,
      func(h, b) = h.writeBlob(b),
      func(h) = h.sum(),
      func(h) = h.reset(),
    );

    let routines : [[() -> ()]] = [
      // new()
      [
        func() = ignore Sha512.new(),
        func() = ignore Sha512_old.Digest(#sha512),
      ],
      // reset()
      [
        func() = Sha512.reset(resetLocal),
        func() = resetOld.reset(),
      ],
      // sum()
      [
        func() = ignore Sha512.sum(sumLocal),
        func() = ignore sumOld.sum(),
      ],
      // close()
      [
        func() = Digest512.close(closeLocal),
        func() {}, // N/A: 0.1.14 has no public finalize-without-allocation
      ],
      // merkle 2^12: single-sha Merkle root, one hasher per level
      [
        func() = ignore merkleLocal(),
        func() = ignore merkleOld(),
      ],
    ];

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
