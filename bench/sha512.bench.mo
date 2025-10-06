import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Text "mo:core/Text";
import Random "mo:core/Random";
import Prim "mo:prim";
import Bench "mo:bench";
import Sha512 "../src/Sha512";

module {
  public func init() : Bench.Bench {
    let bench = Bench.Bench();

    bench.name("Sha512");
    bench.description("Hash various message lengths from different types of input. Blocks are 128 bytes.");

    let rows = [
      "fromBlob",
      "fromArray",
      "fromIter",
      "fromIter2",
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
      Array.tabulate<Nat8>(128_000, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(1_000_000, func(i) = rng.nat8()),
    ];

    let routines : [() -> ()] = Array.tabulate<() -> ()>(
      rows.size() * cols.size(),
      func(i) {
        let row : Nat = i % rows.size();
        let col : Nat = i / rows.size();

        let source = rowSourceArrays[col];

        switch (row) {
          case (0) {
            let blob = Blob.fromArray(source);
            func() = ignore Sha512.fromBlob(#sha512, blob);
          };
          case (1) {
            func() = ignore Sha512.fromArray(#sha512, source);
          };
          case (2) {
            var itemsLeft = source.size();
            let iter = {
              next = func() : ?Nat8 = if (itemsLeft == 0) { null } else {
                itemsLeft -= 1;
                ?0x5f;
              };
            };
            func() = ignore Sha512.fromIter(#sha512, iter);
          };
          case (3) {
            var itemsLeft = source.size();
            let iter = {
              next = func() : ?Nat8 = if (itemsLeft == 0) { null } else {
                itemsLeft -= 1;
                ?0x5f;
              };
            };
            func() = ignore Sha512.fromIter2(#sha512, iter);
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
