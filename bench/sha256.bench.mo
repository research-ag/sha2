import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Random "mo:core/Random";
import Bench "mo:bench-helper";
import Sha256 "../src/Sha256";

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
      "32 bytes",
      "55 bytes",
      "60 bytes",
      "1k blocks",
      "1M bytes",
    ];

    let schema : Bench.Schema = {
      name = "Sha256";
      description = "Hash various message lengths from different types of input. Blocks are 64 bytes.";
      rows = rows;
      cols = cols;
    };

    let rng : Random.Random = Random.seed(0x5f5f5f5f5f5f5f5f);

    let rowSourceArrays : [[Nat8]] = [
      [],
      Array.tabulate<Nat8>(32, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(55, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(60, func(i) = rng.nat8()),
      Array.tabulate<Nat8>(64_000, func(i) = rng.nat8()),
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
                func() = ignore Sha256.fromBlob(blob);
              };
              case (1) {
                func() = ignore Sha256.fromArray(source);
              };
              case (2) {
                func() = ignore Sha256.fromVarArray(varArray);
              };
              case (3) {
                let at = func(i : Nat) : Nat8 = source[i];
                func() = ignore Sha256.fromAccessor(at, 0, source.size());
              };
              case (4) {
                func() {
                  var i = 0;
                  func next() : Nat8 { let r = source[i]; i += 1; r };
                  ignore Sha256.fromReader(next, source.size());
                };
              };
              case (5) {
                func() = ignore Sha256.fromIter(source.values());
              };
              case (6) {
                func() = ignore Sha256.fromReader(list.reader(0), source.size());
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
