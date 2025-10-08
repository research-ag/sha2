import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Text "mo:core/Text";
import Random "mo:core/Random";
import Prim "mo:prim";
import Bench "mo:bench";
import Sha256 "../src/Sha256";
import Util "../src/util";

module {
  public func init() : Bench.Bench {
    let bench = Bench.Bench();

    bench.name("Sha256");
    bench.description("Hash various message lengths from different types of input. Blocks are 64 bytes.");

    let rows = [
      "fromBlob",
      "fromArray",
      "fromVarArray",
      "fromIter",
      "fromPositional",
      "fromNext",
      "fromList",
    ];
    let cols = [
      "0",
      "32 bytes",
      "55 bytes",
      "60 bytes",
      "1k blocks",
      "1M bytes",
    ];

    bench.rows(rows);
    bench.cols(cols);

    let rng : Random.Random = Random.seed(0x5f5f5f5f5f5f5f5f);

    let rowSourceArrays : [[Nat8]] = [
      [],
      Array.tabulate<Nat8>(32, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(55, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(60, func(i) = rng.nat8()),
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
        let list = List.fromArray(source);
        let varArray = Array.toVarArray(source);

        switch (row) {
          case (0) {
            func() = ignore Sha256.fromBlob(#sha256, blob);
          };
          case (1) {
            func() = ignore Sha256.fromArray(#sha256, source);
          };
          case (2) {
            func() = ignore Sha256.fromVarArray(#sha256, varArray);
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
          case (4) {
            let at = func(i : Nat) : Nat8 = source[i];
            func() = ignore Sha256.fromPositional(#sha256, at, source.size());
          };
          case (5) {
            var i = 0;
            func next() : Nat8 { let r = source[i]; i += 1; r };
            func() = ignore Sha256.fromNext(#sha256, next, source.size());
          };
          case (6) {
            let next = Util.listRange<Nat8>(list, 0);
            func() = ignore Sha256.fromNext(#sha256, next, source.size());
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
