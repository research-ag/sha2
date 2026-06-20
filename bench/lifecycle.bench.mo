import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
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
      "merkle 2^12", // Bitcoin-style double-sha Merkle root over 4096 leaves
    ];
    let cols = [
      "0.2.x (current)",
      "0.1.14",
    ];

    let schema : Bench.Schema = {
      name = "Sha256 lifecycle";
      description = "Per-operation cost of the hasher lifecycle plus two composite hashes, local code vs. pinned 0.1.14. The hasher in reset()/sum()/close() rows already exists and has had a partial block written to it. 0.1.14 has no public finalize-without-allocation, so its close() cell is a no-op (N/A). double-sha is sha256(sha256(msg)) on a 32-byte message; the current column uses the dedicated sumDouble() (copies state into the buffer, no intermediate Blob), while 0.1.14 reuses a single hasher (sum, reset, re-write, sum). merkle 2^12 is a Bitcoin-style double-sha Merkle root over 4096 32-byte leaves (4095 double-sha steps), one reused hasher per level (12 levels). The current column is allocation-free (foldSum + pushSum stream digests directly between hashers; only the final root Blob is allocated); 0.1.14 must allocate a Blob per node.";
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

    // A 32-byte message for the double-sha row, and 2^12 = 4096 32-byte
    // leaves for the Merkle row.
    let msg32 : Blob = Blob.fromArray(Array.tabulate<Nat8>(32, func(i) = rng.nat8()));
    let leaves : [Blob] = Array.tabulate<Blob>(
      4096,
      func(_) = Blob.fromArray(Array.tabulate<Nat8>(32, func(i) = rng.nat8())),
    );

    // One hasher per row, allocated up front and reused via reset() instead of
    // calling fromBlob (which would allocate a fresh hasher on every hash).
    let dshaLocal = Sha256.new();
    let dshaOld = Sha256_old.Digest(#sha256);

    // Number of tree levels = log2(leaf count). 4096 leaves -> 12 combining
    // levels, so 12 hashers, one per level.
    var levels = 0;
    var n = leaves.size();
    while (n > 1) { n /= 2; levels += 1 };

    // Generic streaming Bitcoin-style Merkle root: leaves are fed left to right
    // and a single hasher per level is kept alive holding a pending left child
    // until its right sibling arrives. No hasher is allocated per node.
    func merkleStream<T>(
      hashers : [T],
      write : (T, Blob) -> (),
      doubleFinalize : (T) -> Blob, // double-sha of all data written; closes the hasher
      reopen : (T) -> (), // reset the hasher to accept the next pair
    ) : Blob {
      let pending = VarArray.repeat<Bool>(false, hashers.size());
      var root : Blob = msg32; // overwritten by the final combine

      func push(node : Blob, lvl : Nat) {
        if (lvl == hashers.size()) { root := node; return };
        let h = hashers[lvl];
        if (not pending[lvl]) {
          // left child: keep it in this level's hasher until its sibling arrives
          write(h, node);
          pending[lvl] := true;
        } else {
          // right child: h now holds left ++ right; double-sha it and go up
          write(h, node);
          let parent = doubleFinalize(h);
          reopen(h);
          pending[lvl] := false;
          push(parent, lvl + 1);
        };
      };

      var i = 0;
      while (i < leaves.size()) { push(leaves[i], 0); i += 1 };
      root;
    };

    let merkleHashersLocal = Array.tabulate<Sha256.Digest>(levels, func(_) = Sha256.new());
    let merkleHashersOld = Array.tabulate<Sha256_old.Digest>(levels, func(_) = Sha256_old.Digest(#sha256));
    let pendingLocal = VarArray.repeat<Bool>(false, levels);

    // Current code: allocation-free Bitcoin-style Merkle root. Each pair is
    // combined with foldSum (inner sha, folded back in place) then pushSum
    // (outer sha streamed straight into the parent hasher). No Blob is
    // allocated anywhere except the final root. The binary carry is iterative
    // (no recursion/closure), so nothing is allocated per node.
    func merkleLocal() : Blob {
      var root : Blob = msg32; // overwritten by the final combine
      var i = 0;
      while (i < leaves.size()) {
        // writeBlob takes the closure-free word path here (leaves are 32 bytes,
        // word-aligned) — keeps the whole Merkle allocation-free bar the root.
        Sha256.writeBlob(merkleHashersLocal[0], leaves[i]);
        Sha256.writeBlob(merkleHashersLocal[0], leaves[i + 1]);
        var lvl = 0;
        var carrying = true;
        while (carrying) {
          let h = merkleHashersLocal[lvl];
          Sha256.foldSum(h); // inner sha
          if (lvl + 1 == levels) {
            root := Sha256.sum(h); // outer sha = root (the one allocation)
            Sha256.reset(h);
            carrying := false;
          } else {
            h.pushSum(merkleHashersLocal[lvl + 1]); // outer sha into the parent
            Sha256.reset(h);
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
    // 0.1.14 has no foldSum/pushSum: stream Blobs, hashing each pair then
    // re-hashing the digest in place (allocates a Blob per node).
    func merkleOld() : Blob = merkleStream<Sha256_old.Digest>(
      merkleHashersOld,
      func(h, b) = h.writeBlob(b),
      func(h) : Blob {
        let inner = h.sum();
        h.reset();
        h.writeBlob(inner);
        h.sum();
      },
      func(h) = h.reset(),
    );

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
      // merkle 2^12: Bitcoin-style double-sha Merkle root, one hasher per level
      [
        func() = ignore merkleLocal(),
        func() = ignore merkleOld(),
      ],
    ];

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
