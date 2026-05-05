import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Random "mo:core/Random";
import Runtime "mo:core/Runtime";
import Bench "mo:bench-helper";

import Sha512 "../src/Sha512";

module {
  public func init() : Bench.V1 {
    let schema : Bench.Schema = {
      name = "Sha512 Benchmark";
      description = "Hash various message lengths from different types of input. Blocks are 128 bytes.";
      rows = ["fromBlob", "fromArray", "fromIter"];
      cols = ["0", "1k blocks", "1M bytes"];
    };
    let (nRows, nCols) = (schema.rows.size(), schema.cols.size());

    let rng : Random.Random = Random.seed(0x5f5f5f5f5f5f5f5f);

    let rowSourceArrays : [[Nat8]] = [
      [],
      Array.tabulate<Nat8>(128_000, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(1_000_000, func(i) = rng.nat8()),
    ];

    let routines : [() -> ()] = Array.tabulate<() -> ()>(
      nRows * nCols,
      func(i) {
        let row : Nat = i % nRows;
        let col : Nat = i / nRows;

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
          case (_) Runtime.trap("Row not implemented");
        };
      },
    );

    func run(ri : Nat, ci : Nat) = routines[ci * nRows + ri]();

    Bench.V1(schema, run);
  };
};
