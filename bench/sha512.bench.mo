import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha512 "../src/Sha512";

module {
  public func init() : Bench.V1 {
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

    let schema : Bench.Schema = {
      name = "Sha512";
      description = "Hash various message lengths from different types of input. Blocks are 128 bytes.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x5f5f5f5f5f5f5f5f);

    let rowSourceArrays : [[Nat8]] = [
      [],
      Array.tabulate<Nat8>(64, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(115, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(120, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(128_000, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(1_000_000, func(i) = rng.nat8()),
    ];

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      rows.size(),
      func(ri) {
        Array.tabulate<() -> ()>(
          cols.size(),
          func(ci) {
            let source = rowSourceArrays[ci];
            let blob = Blob.fromArray(source);
            let list = List.fromArray(source);
            let varArray = Array.toVarArray(source);

            switch (ri) {
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
                func() {
                  ignore Sha512.fromReader(next, source.size());
                };
              };
              case (5) {
                func() = ignore Sha512.fromIter(source.values());
              };
              case (6) {
                func() = ignore Sha512.fromReader(list.reader(0), source.size());
              };
              case (_) func() {};
            };
          },
        );
      },
    );

    Bench.V1(schema, func(ri : Nat, ci : Nat) = routines[ri][ci]());
  };
};
