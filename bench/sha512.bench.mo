import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Text "mo:core/Text";
import Random "mo:core/Random";
import Prim "mo:prim";
import Bench "mo:bench";
import Sha512 "../src/Sha512";
import _ListTools "../src/util/List";

module {
  public func init() : Bench.Bench {
    let bench = Bench.Bench();

    bench.name("Sha512");
    bench.description("Hash various message lengths from different types of input. Blocks are 128 bytes.");

    let rows = [
      "fromBlob",
      "fromArray",
      "fromVarArray",
      "fromAccessor",
      "fromReader",
      "fromIter",
      "fromList",
    ];
    let cols = [
      "0",
      "64 bytes",
      "115 bytes",
      "120 bytes",
      "1k blocks",
      "1M bytes",
    ];

    bench.rows(rows);
    bench.cols(cols);

    let rng : Random.Random = Random.seed(0x5f5f5f5f5f5f5f5f);

    let rowSourceArrays : [[Nat8]] = [
      [],
      Array.tabulate<Nat8>(64, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(115, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(120, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(128_000, func(i) = rng.nat8()),
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
            func() = ignore Sha512.fromBlob(blob);
          };
          case (1) {
            func() = ignore Sha512.fromArray(source);
          };
          case (2) {
            func() = ignore Sha512.fromVarArray(varArray);
          };
          case (3) {
            func at(i : Nat) : Nat8 = source[i];
            func() = ignore Sha512.fromAccessor(at, 0, source.size());
          };
          case (4) {
            var j = 0;
            func next() : Nat8 { let r = source[j]; j += 1; r };
            func() = ignore Sha512.fromReader(next, source.size());
          };
          case (5) {
            var itemsLeft = source.size();
            let iter = {
              next = func() : ?Nat8 = if (itemsLeft == 0) { null } else {
                itemsLeft -= 1;
                ?0x5f;
              };
            };
            func() = ignore Sha512.fromIter(iter);
          };
          case (6) {
            let next = list.stream();
            func() = ignore Sha512.fromReader(next, source.size());
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
