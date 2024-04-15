import Bench "mo:bench";
import Blob "mo:base/Blob";
import Array "mo:base/Array";
import Sha256 "../src/Sha256";
import Sha512 "../src/Sha512";
import Crypto "mo:crypto/SHA/SHA256";
import Sha2 "mo:motoko-sha2";

module {
  public func init() : Bench.Bench {
    let bench = Bench.Bench();

    // benchmark code...
    bench.name("Sha256");
<<<<<<< HEAD
    bench.description("Hash various message lengths.
    Blocks are 64 bytes for sha256 and 128 bytes for sha512.");
=======
    bench.description("Hash various message lengths\nBlocks are 64 bytes for sha256 and 128 bytes for sha512");
>>>>>>> main

    bench.rows(["Sha256", "Sha512", "Crypto.mo", "motoko-sha2"]);
    bench.cols(["0", "1k blocks", "1 MB"]);

    let a0 : [Nat8] = [];
    let a1a = Array.tabulate<Nat8>(64_000, func(i) = 0x5f);
    let a1b = Array.tabulate<Nat8>(128_000, func(i) = 0x5f);
    let a2 = Array.tabulate<Nat8>(1_000_000, func(i) = 0x5f);

    let b0 = Blob.fromArray(a0);
    let b1a = Blob.fromArray(a1a);
    let b1b = Blob.fromArray(a1b);
    let b2 = Blob.fromArray(a2);

    bench.runner(func(row, col) {

      // Sha256
      if (row == "Sha256") {
        switch (col) {
          case ("0") ignore Sha256.fromBlob(#sha256, b0);
          case ("1k blocks") ignore Sha256.fromBlob(#sha256, b1a);
          case ("1 MB") ignore Sha256.fromBlob(#sha256, b2);
          case (_) {};
        };
      };

      // Sha512
      if (row == "Sha512") {
        switch (col) {
          case ("0") ignore Sha512.fromBlob(#sha512, b0);
          case ("1k blocks") ignore Sha512.fromBlob(#sha512, b1b);
          case ("1 MB") ignore Sha512.fromBlob(#sha512, b2);
          case (_) {};
        };
      };

      // Crypto.mo
      if (row == "Crypto.mo") {
        switch (col) {
          case ("0") ignore Crypto.sum(a0);
          case ("1k blocks") ignore Crypto.sum(a1a);
          case ("1 MB") ignore Crypto.sum(a2);
          case (_) {};
        };
      };

      // motoko-sha2
      if (row == "motoko-sha2") {
        switch (col) {
          case ("0") ignore Sha2.fromBlob(#sha256, b0);
          case ("1k blocks") ignore Sha2.fromBlob(#sha256, b1a);
          case ("1 MB") ignore Sha2.fromBlob(#sha256, b2);
          case (_) {};
        };
      };
    });

    bench;
  };
};