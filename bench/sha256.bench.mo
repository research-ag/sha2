import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Text "mo:core/Text";
import Random "mo:core/Random";
import Prim "mo:prim";

import Sha256 "../src/Sha256";

module {
  type Schema = {
    name : Text;
    description : Text;
    rows : [Text];
    cols : [Text];
  };

  class BenchV1(schema : Schema, run : (Nat, Nat) -> ()) {
    public func getVersion() : Nat = 1;
    public func getSchema() : Schema = schema;
    public let runCell = run;
  };

  public func init() : BenchV1 {
    let schema : Schema = {
      name = "Sha256 Benchmark";
      description = "Hash various message lengths from different types of input. Blocks are 64 bytes.";
      rows = [ "fromBlob", "fromArray", "fromIter" ];
      cols = [ "0", "1k blocks", "1M bytes" ];
    };
    let (nRows, nCols) = (schema.rows.size(), schema.cols.size());

    let rng : Random.Random = Random.seed(0x5f5f5f5f5f5f5f5f);

    let rowSourceArrays : [[Nat8]] = [
      [],
      Array.tabulate<Nat8>(64_000, func(i) = rng.nat8()),
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
            func() = ignore Sha256.fromBlob(#sha256, blob);
          };
          case (1) {
            func() = ignore Sha256.fromArray(#sha256, source);
          };
          case (2) {
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

    func run(ri : Nat, ci : Nat) = routines[ci * nRows + ri]();

    BenchV1(schema, run);
  };
};
