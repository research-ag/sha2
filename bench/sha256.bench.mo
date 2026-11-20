import Array "mo:core/Array";
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

    // The inputs of every column, derived once. Where they lie in memory
    // matters to the measurement: newer replicas charge a call about 20k
    // instructions for every 64 KiB memory page it touches first, and a short
    // message that sits alone on a page of its own would cost several times
    // its hash. So the large inputs are built first and the short ones last,
    // as fresh copies: the short inputs, the closures and the table below
    // then lie together at the end of what init allocates, next to the
    // benchmark object, on pages the harness touches before it measures. The
    // large inputs still pay for the pages they occupy, as they should.
    type Input = {
      source : [Nat8];
      blob : Blob;
      list : List.List<Nat8>;
      varArray : [var Nat8];
    };
    func input(source : [Nat8]) : Input = {
      source;
      blob = source.toBlob();
      list = List.fromArray(source);
      varArray = source.toVarArray();
    };
    func copy(a : [Nat8]) : [Nat8] = Array.tabulate<Nat8>(a.size(), func(i) = a[i]);
    let i5 = input(rowSourceArrays[5]);
    let i4 = input(rowSourceArrays[4]);
    let i3 = input(copy(rowSourceArrays[3]));
    let i2 = input(copy(rowSourceArrays[2]));
    let i1 = input(copy(rowSourceArrays[1]));
    let i0 = input(copy(rowSourceArrays[0]));
    let inputs = [i0, i1, i2, i3, i4, i5];

    let routines : [[() -> ()]] = Array.tabulate<[() -> ()]>(
      rows.size(),
      func(ri) {
        Array.tabulate<() -> ()>(
          cols.size(),
          func(ci) {
            let { source; blob; list; varArray } = inputs[ci];

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
                var i = 0;
                func next() : Nat8 { let r = source[i]; i += 1; r };
                func() {
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
