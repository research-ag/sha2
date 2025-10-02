import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Text "mo:core/Text";
import Random "mo:core/Random";
import Prim "mo:prim";
import Bench "mo:bench";
import Sha256 "../src/Sha256";

module {
  public func init() : Bench.Bench {
    let bench = Bench.Bench();

    bench.name("Sha256");
    bench.description("Hash various message lengths from different types of input. Blocks are 64 bytes.");

    let rows = [
      "fromBlob",
      "fromBlob2",
      "fromArray",
      "fromIter",
    ];
    let cols = [
      "0",
      "1k blocks",
      "1M bytes",
    ];

    bench.rows(rows);
    bench.cols(cols);

    let rng : Random.Random = Random.seed(0x5f5f5f5f5f5f5f5f);

    let rowSourceArrays : [[Nat8]] = [
      [],
      Array.tabulate<Nat8>(64_000, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(1_000_000, func(i) = rng.nat8()),
    ];

    let routines : [() -> ()] = Array.tabulate<() -> ()>(
      rows.size() * cols.size(),
      func(i) {
        let row : Nat = i % rows.size();
        let col : Nat = i / rows.size();

        let source = rowSourceArrays[col];
        let blob = Blob.fromArray(source);

        switch (row) {
          case (0) {
            func() = ignore Sha256.fromBlob(#sha256, blob);
          };
          case (1) {
            func() = ignore Sha256.fromBlob2(#sha256, blob);
          };
          case (2) {
            func() = ignore Sha256.fromArray(#sha256, source);
          };
          case (3) {
            var itemsLeft = source.size();
            let iter = {
              next = func() : ?Nat8 = if (itemsLeft == 0) { null } else {
                itemsLeft -= 1;
                ?0x5f;
              };
            };
            func() = ignore Sha256.fromIter(#sha256, iter);
          };
          case (_) Prim.trap("Row not implemented");
        };
      },
    );

    bench.runner(
      func(row, col) {
        let ?ri = Array.indexOf<Text>(rows, Text.equal, row) else Prim.trap("Unknown row");
        let ?ci = Array.indexOf<Text>(cols, Text.equal, col) else Prim.trap("Unknown column");
        routines[ci * rows.size() + ri]();
      }
    );

    bench;
  };
};
