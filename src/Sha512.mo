/// Cycle-optimized Sha512 variants.
///
/// Features:
///
/// * Algorithms: `sha512_224`, `sha512_256`, `sha384`, `sha512`
/// * Input types: `Blob`, `[Nat8]`, `[var Nat8]`, `Iter<Nat8>`,
/// *   `at : Nat -> Nat8` (unchecked accessor),
/// *   `next : () -> Nat8` (unchecked reader)
/// * Output types: `Blob`
///
/// ```motoko name=import
/// import Sha512 "mo:sha2/Sha512";
/// ```

import { type Iter } "mo:core/Types";
import { arrayToBlob; explodeNat64 } "mo:prim";
import VarArray "mo:core/VarArray";
import _Digest "sha512/digest";
import Types "sha512/types";

module {
  /// SHA512 algorithms.
  public type Algorithm = {
    #sha384;
    #sha512;
    #sha512_224;
    #sha512_256;
  };

  /// Default algorithm.
  public let algo = #sha512; // default algorithm used as implicit argument

  /// Digest type (including the algorithm field)
  /// As a static record it can be declared `stable`.
  public type Digest = Types.Digest and {
    algo : Algorithm;
  };

  let ivs : [[Nat64]] = [
    [
      // 512-224
      0x8c3d37c819544da2,
      0x73e1996689dcd4d6,
      0x1dfab7ae32ff9c82,
      0x679dd514582f9fcf,
      0x0f6d2b697bd44da8,
      0x77e36f7304c48942,
      0x3f9d85a86a1d36c8,
      0x1112e6ad91d692a1,
    ],
    [
      // 512-256
      0x22312194fc2bf72c,
      0x9f555fa3c84c64c2,
      0x2393b86b6f53b151,
      0x963877195940eabd,
      0x96283ee2a88effe3,
      0xbe5e1e2553863992,
      0x2b0199fc2c85b8aa,
      0x0eb72ddc81c52ca2,
    ],
    [
      // 384
      0xcbbb9d5dc1059ed8,
      0x629a292a367cd507,
      0x9159015a3070dd17,
      0x152fecd8f70e5939,
      0x67332667ffc00b31,
      0x8eb44a8768581511,
      0xdb0c2e0d64f98fa7,
      0x47b5481dbefa4fa4,
    ],
    [
      // 512
      0x6a09e667f3bcc908,
      0xbb67ae8584caa73b,
      0x3c6ef372fe94f82b,
      0xa54ff53a5f1d36f1,
      0x510e527fade682d1,
      0x9b05688c2b3e6c1f,
      0x1f83d9abfb41bd6b,
      0x5be0cd19137e2179,
    ],
  ];

  /// Create a new SHA2 digest instance for the specified algorithm.
  /// The digest can be used to incrementally hash data by calling write functions,
  /// then finalized with `sum()`.
  ///
  /// If incremental hashing is not needed, consider using the convenience functions `fromBlob`, `fromArray`, etc.
  ///
  /// ```motoko include=import
  /// let digest = Sha512.new();
  /// digest.writeBlob("Hello");
  /// digest.writeBlob(" world");
  /// let hash = digest.sum();
  /// ```
  ///
  /// After finalizing with `sum()` the digest is "closed", i.e. no more data can be written to it.
  ///
  /// The default algorithm is `#sha512`. To use `#sha384`, `#sha512_256` or `#sha512_224`, pass it as an explicit argument:
  ///
  /// ```motoko include=import
  /// let digest = Sha512.new(#sha384);
  /// ```
  public func new(algo : (implicit : Algorithm)) : Digest {
    {
      algo;
      msg : [var Nat64] = [var 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      var i_msg : Nat8 = 0;
      var i_byte : Nat8 = 8;
      var i_block : Nat64 = 0;
      var word : Nat64 = 0;
      s : [var Nat64] = switch (algo) {
        case (#sha512_224) [var 0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf, 0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1];
        case (#sha512_256) [var 0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd, 0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2];
        case (#sha384) [var 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4];
        case (#sha512) [var 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];
      };
      var closed = false;
    };
  };

  // Load the algorithm's initial hash value (IV) into the state.
  // Unrolled copy avoids allocating the `[0..7]` index array and its iterator
  // on every reset (cf. the Sha256 reset optimization).
  func loadIV(self : Digest) {
    let i = switch (self.algo) {
      case (#sha512_224) 0;
      case (#sha512_256) 1;
      case (#sha384) 2;
      case (#sha512) 3;
    };
    let v = ivs[i];
    // prettier-ignore
    do {
      self.s[0] := v[0]; self.s[1] := v[1]; self.s[2] := v[2]; self.s[3] := v[3];
      self.s[4] := v[4]; self.s[5] := v[5]; self.s[6] := v[6]; self.s[7] := v[7];
    };
  };

  /// Reset the digest state to start a new hash computation.
  /// After reset, the digest can be reused to hash new data.
  /// This works even if the digest was previously finalized (is closed).
  ///
  /// ```motoko include=import
  /// let digest = Sha512.new();
  /// digest.writeBlob("First message");
  /// let hash1 = digest.sum();
  /// digest.reset();
  /// digest.writeBlob("Second message");
  /// let hash2 = digest.sum();
  /// ```
  public func reset(self : Digest) {
    self.i_msg := 0;
    self.i_byte := 8;
    self.i_block := 0;
    loadIV(self);
    self.closed := false;
  };

  /// Create an independent copy of the digest with the same internal state.
  /// This allows to finalize one of the two copies with `sum()` and to keep writing more data to the other.
  /// For example, one can obtain intermediate hashes like this.
  ///
  /// ```motoko include=import
  /// let digest = Sha512.new();
  /// digest.writeBlob("Hello");
  /// let clone = digest.clone();
  /// let intermediate = clone.sum();
  /// digest.writeBlob(" world");
  /// let final = digest.sum();
  /// ```
  ///
  /// Traps if `self` is closed.
  public func clone(self : Digest) : Digest {
    assert not self.closed;
    {
      algo = self.algo;
      msg = VarArray.clone(self.msg);
      var word = self.word;
      var i_msg = self.i_msg;
      var i_byte = self.i_byte;
      var i_block = self.i_block;
      s = self.s.clone();
      var closed = false;
    };
  };

  /// Write a `Blob` to the digest.
  ///
  /// ```motoko include=import
  /// let digest = Sha512.new();
  /// digest.writeBlob("Hello");
  /// digest.writeBlob(" world");
  /// let hash = digest.sum();
  /// ```
  ///
  /// Traps if `self` is closed.
  public func writeBlob(self : Digest, data : Blob) : () = _Digest.writeBlob(self, data);

  /// Write a `[Nat8]` array to the digest.
  ///
  /// ```motoko include=import
  /// let digest = Sha512.new();
  /// digest.writeArray([72, 101, 108, 108, 111]); // "Hello"
  /// digest.writeBlob(" world");
  /// let hash = digest.sum();
  /// ```
  ///
  /// Traps if `self` is closed.
  public func writeArray(self : Digest, data : [Nat8]) : () = _Digest.writeArray(self, data);

  /// Write a `[var Nat8]` array to the digest.
  ///
  /// ```motoko include=import
  /// let digest = Sha512.new();
  /// let data : [var Nat8] = [var 72, 101, 108, 108, 111];
  /// digest.writeVarArray(data);
  /// let hash = digest.sum();
  /// ```
  ///
  /// Traps if `self` is closed.
  public func writeVarArray(self : Digest, data : [var Nat8]) : () = _Digest.writeVarArray(self, data);

  /// Write data from a positional accessor function.
  /// Takes `len` bytes starting from the `start` index.
  /// It it the responsibility of the caller to ensure that the accessor function
  /// can provide valid data for all requested indices.
  ///
  /// ```motoko include=import
  /// let digest = Sha512.new();
  /// let data = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
  /// func accessor(i : Nat) : Nat8 = data[i];
  /// digest.writeAccessor(accessor, 0, 5); // "Hello"
  /// digest.writeAccessor(accessor, 5, 6); // " world"
  /// let hash = digest.sum();
  /// ```
  ///
  /// Traps if `self` is closed, or if `at` traps for any index in `[start, start + len)`.
  public func writeAccessor(self : Digest, at : Nat -> Nat8, start : Nat, len : Nat) : () = _Digest.writeAccessor(self, at, start, len);

  /// Write data from a reader function.
  /// Takes exactly `len` bytes by calling the reader function `len` times.
  /// It it the responsibility of the caller to ensure that the reader function
  /// can provide valid data for all requested bytes.
  ///
  /// ```motoko include=import
  /// let digest = Sha512.new();
  /// let data = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
  /// var pos = 0;
  /// func reader() : Nat8 { let b = data[pos]; pos += 1; b };
  /// digest.writeReader(reader, 5); // "Hello"
  /// digest.writeReader(reader, 6); // " world"
  /// let hash = digest.sum();
  /// ```
  ///
  /// Traps if `self` is closed, or if `next` traps during any of the `len` calls.
  public func writeReader(self : Digest, next : () -> Nat8, len : Nat) : () = _Digest.writeReader(self, next, len);

  /// Write data from an `Iter<Nat8>` to the digest. Consumes the entire iterator.
  ///
  /// ```motoko include=import
  /// let digest = Sha512.new();
  /// let iter = [72, 101, 108, 108, 111].vals();
  /// digest.writeIter(iter); // "Hello"
  /// let hash = digest.sum();
  /// ```
  ///
  /// Traps if `self` is closed.
  public func writeIter(self : Digest, data : Iter<Nat8>) : () = _Digest.writeIter(self, data.next);

  /// Finalize the digest and return the hash as a `Blob`.
  /// This closes the digest. It cannot be used for anything again unless it is reset with the `reset()` function.
  /// For example, attempting to write more data to it or finalizing it a second time will trap.
  ///
  /// ```motoko include=import
  /// let digest = Sha512.new();
  /// digest.writeBlob("Hello world");
  /// let hash : Blob = digest.sum();
  /// ```
  ///
  /// Traps if `self` is already closed.
  public func sum(self : Digest) : Blob {
    _Digest.close(self);
    stateBlob(self);
  };

  /// Finalize the digest by writing padding, without returning the hash. After
  /// `close()` the digest is closed; read the hash with `readSum()` (any number
  /// of times).
  ///
  /// ```motoko include=import
  /// let digest = Sha512.new();
  /// digest.writeBlob("Hello world");
  /// digest.close();
  /// let hash : Blob = digest.readSum();
  /// ```
  ///
  /// Traps if `self` is already closed.
  public func close(self : Digest) : () = _Digest.close(self);

  /// Read the hash of a closed digest. Idempotent: unlike `sum()` it does not
  /// finalize, so it can be called repeatedly after `close()` or `sum()`.
  ///
  /// ```motoko include=import
  /// let digest = Sha512.new();
  /// digest.writeBlob("Hello world");
  /// let once : Blob = digest.sum();
  /// let again : Blob = digest.readSum(); // == once
  /// ```
  ///
  /// Traps if `self` is not closed.
  public func readSum(self : Digest) : Blob {
    assert self.closed;
    stateBlob(self);
  };

  func stateBlob(x : Digest) : Blob {
    let (d0, d1, d2, d3, d4, d5, d6, d7) = explodeNat64(x.s[0]);
    let (d8, d9, d10, d11, d12, d13, d14, d15) = explodeNat64(x.s[1]);
    let (d16, d17, d18, d19, d20, d21, d22, d23) = explodeNat64(x.s[2]);
    let (d24, d25, d26, d27, d28, d29, d30, d31) = explodeNat64(x.s[3]);

    // `switch` (not `== #...`) because variant `==` allocates per call. Longer
    // digests explode the extra state words lazily inside their cases.
    switch (x.algo) {
      case (#sha512_224) {
        // prettier-ignore
        arrayToBlob([
          d0, d1, d2, d3, d4, d5, d6, d7,
          d8, d9, d10, d11, d12, d13, d14, d15,
          d16, d17, d18, d19, d20, d21, d22, d23,
          d24, d25, d26, d27
        ]);
      };
      case (#sha512_256) {
        // prettier-ignore
        arrayToBlob([
          d0, d1, d2, d3, d4, d5, d6, d7,
          d8, d9, d10, d11, d12, d13, d14, d15,
          d16, d17, d18, d19, d20, d21, d22, d23,
          d24, d25, d26, d27,
          d28, d29, d30, d31
        ]);
      };
      case (#sha384) {
        let (d32, d33, d34, d35, d36, d37, d38, d39) = explodeNat64(x.s[4]);
        let (d40, d41, d42, d43, d44, d45, d46, d47) = explodeNat64(x.s[5]);
        // prettier-ignore
        arrayToBlob([
          d0, d1, d2, d3, d4, d5, d6, d7,
          d8, d9, d10, d11, d12, d13, d14, d15,
          d16, d17, d18, d19, d20, d21, d22, d23,
          d24, d25, d26, d27, d28, d29, d30, d31,
          d32, d33, d34, d35, d36, d37, d38, d39,
          d40, d41, d42, d43, d44, d45, d46, d47
        ]);
      };
      case (#sha512) {
        let (d32, d33, d34, d35, d36, d37, d38, d39) = explodeNat64(x.s[4]);
        let (d40, d41, d42, d43, d44, d45, d46, d47) = explodeNat64(x.s[5]);
        let (d48, d49, d50, d51, d52, d53, d54, d55) = explodeNat64(x.s[6]);
        let (d56, d57, d58, d59, d60, d61, d62, d63) = explodeNat64(x.s[7]);
        // prettier-ignore
        arrayToBlob([
          d0, d1, d2, d3, d4, d5, d6, d7,
          d8, d9, d10, d11, d12, d13, d14, d15,
          d16, d17, d18, d19, d20, d21, d22, d23,
          d24, d25, d26, d27, d28, d29, d30, d31,
          d32, d33, d34, d35, d36, d37, d38, d39,
          d40, d41, d42, d43, d44, d45, d46, d47,
          d48, d49, d50, d51, d52, d53, d54, d55,
          d56, d57, d58, d59, d60, d61, d62, d63
        ]);
      };
    };
  };

  /// Directly calculate the SHA2 hash digest from a `Blob`.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko include=import
  /// let hash = Sha512.fromBlob("Hello world");
  /// ```
  ///
  /// The default algorithm is `#sha512`. To use `#sha384`, `#sha512_256` or `#sha512_224`, pass it as an explicit argument:
  ///
  /// ```motoko include=import
  /// let hash = Sha512.fromBlob(#sha384, "Hello world");
  /// ```
  ///
  /// Never traps.
  public func fromBlob(algo : (implicit : Algorithm), b : Blob) : Blob {
    let d = new(algo);
    d.writeBlob(b);
    return sum(d);
  };

  /// Calculate the SHA2 hash digest from a `[Nat8]` array.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko include=import
  /// let data = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
  /// let hash = Sha512.fromArray(data);
  /// ```
  ///
  /// The default algorithm is `#sha512`. To use `#sha384`, `#sha512_256` or `#sha512_224`, pass it as an explicit argument:
  ///
  /// ```motoko include=import
  /// let hash = Sha512.fromArray(#sha384, data);
  /// ```
  ///
  /// Never traps.
  public func fromArray(algo : (implicit : Algorithm), arr : [Nat8]) : Blob {
    let d = new(algo);
    d.writeArray(arr);
    return sum(d);
  };

  /// Calculate the SHA2 hash digest from a `[var Nat8]` array.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko include=import
  /// let data : [var Nat8] = [var 72, 101, 108, 108, 111];
  /// let hash = Sha512.fromVarArray(data);
  /// ```
  ///
  /// The default algorithm is `#sha512`. To use `#sha384`, `#sha512_256` or `#sha512_224`, pass it as an explicit argument:
  ///
  /// ```motoko include=import
  /// let hash = Sha512.fromVarArray(#sha384, data);
  /// ```
  ///
  /// Never traps.
  public func fromVarArray(algo : (implicit : Algorithm), arr : [var Nat8]) : Blob {
    let d = new(algo);
    d.writeVarArray(arr);
    return sum(d);
  };

  /// Calculate the SHA2 hash digest from an entire `Iter<Nat8>`.
  /// This is a convenience function that creates a digest, writes all data
  /// from the iterator, and returns the final hash in one step.
  ///
  /// ```motoko include=import
  /// let data = [72, 101, 108, 108, 111].vals();
  /// let hash = Sha512.fromIter(data);
  /// ```
  ///
  /// The default algorithm is `#sha512`. To use `#sha384`, `#sha512_256` or `#sha512_224`, pass it as an explicit argument:
  ///
  /// ```motoko include=import
  /// let hash = Sha512.fromIter(#sha384, data);
  /// ```
  ///
  /// Never traps.
  public func fromIter(algo : (implicit : Algorithm), iter : Iter<Nat8>) : Blob {
    let d = new(algo);
    _Digest.writeIter(d, iter.next);
    return sum(d);
  };

  /// Calculate the SHA2 hash digest from a positional accessor function.
  /// Takes `len` bytes counting from the `start` index.
  /// It it the responsibility of the caller to ensure that the accessor function
  /// can provide valid data for all requested indices.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko include=import
  /// let data = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
  /// func accessor(i : Nat) : Nat8 = data[i];
  /// let hash = Sha512.fromAccessor(accessor, 0, 5);
  /// ```
  ///
  /// The default algorithm is `#sha512`. To use `#sha384`, `#sha512_256` or `#sha512_224`, pass it as an explicit argument:
  ///
  /// ```motoko include=import
  /// let hash = Sha512.fromAccessor(#sha384, accessor, 0, 5);
  /// ```
  ///
  /// Does not trap unless user-provided accessor function `data` traps.
  public func fromAccessor(algo : (implicit : Algorithm), data : Nat -> Nat8, start : Nat, len : Nat) : Blob {
    let d = new(algo);
    d.writeAccessor(data, start, len);
    return sum(d);
  };

  /// Calculate the SHA2 hash digest from a reader function.
  /// Takes exactly `len` bytes by calling the reader function `len` times.
  /// It it the responsibility of the caller to ensure that the reader function
  /// can provide valid data for all requested bytes.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko include=import
  /// var pos = 0;
  /// let data = [72, 101, 108, 108, 111];
  /// func reader() : Nat8 { let b = data[pos]; pos += 1; b };
  /// let hash = Sha512.fromReader(reader, 5);
  /// ```
  ///
  /// The default algorithm is `#sha512`. To use `#sha384`, `#sha512_256` or `#sha512_224`, pass it as an explicit argument:
  ///
  /// ```motoko include=import
  /// let hash = Sha512.fromReader(#sha384, reader, 5);
  /// ```
  ///
  /// Does not trap unless user-provided reader function `next` traps.
  public func fromReader(algo : (implicit : Algorithm), next : () -> Nat8, len : Nat) : Blob {
    let d = new(algo);
    d.writeReader(next, len);
    return sum(d);
  };
};
