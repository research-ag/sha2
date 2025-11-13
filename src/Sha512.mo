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
/// Import with this line in mops.toml:
/// ```
/// sha2 = "1.0.0"
/// ```
/// and this line in your Motoko code:
/// ```motoko
/// import Sha512 "mo:sha2/Sha512";
/// ```
///
/// The package allows incremental hashing by creating a `Digest` instance,
/// writing data to it in increments, and finalizing it to get the hash. It also provides
/// convenience functions to compute the hash from various input types in a single step.

import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import { type Iter } "mo:core/Types";
import VarArray "mo:core/VarArray";
import Prim "mo:prim";
import K "sha512/constants";
import ProcessBlock "sha512/process_block";
import Byte "sha512/write/byte";
import Write "sha512/write";

module {
  public type Algorithm = {
    #sha384;
    #sha512;
    #sha512_224;
    #sha512_256;
  };
  public let algo = #sha512; // default algorithm used as implicit argument

  /// Digest type (including the algorithm field)
  /// As a static record it can be declared `stable`.
  public type Digest = {
    algo : Algorithm;
    // msg buffer
    msg : [var Nat64];
    var word : Nat64;
    var i_msg : Nat8;
    var i_byte : Nat8;
    var i_block : Nat64;
    // state variables
    s : [var Nat64];
    var closed : Bool;
  };

  /// Create a new SHA2 digest instance for the specified algorithm.
  /// The digest can be used to incrementally hash data by calling write functions,
  /// then finalized with `sum()`.
  ///
  /// If incremental hashing is not needed, consider using the convenience functions `fromBlob`, `fromArray`, etc.
  ///
  /// ```motoko
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
  /// ```motoko
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
        case (#sha512_224) [ var 0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf, 0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1, ];
        case (#sha512_256) [ var 0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd, 0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2, ];
        case (#sha384) [ var 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4, ];
        case (#sha512) [ var 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179, ];
      };
      var closed = false;
    }
  };

  /// Reset the digest state to start a new hash computation.
  /// After reset, the digest can be reused to hash new data.
  /// This works even if the digest was previously finalized (is closed).
  ///
  /// ```motoko
  /// let digest = Sha512.new();
  /// digest.writeBlob("First message");
  /// let hash1 = digest.sum();
  /// digest.reset();
  /// digest.writeBlob("Second message");
  /// let hash2 = digest.sum();
  /// ```
  public func reset(self : Digest) {
    assert not self.closed;
    self.i_msg := 0;
    self.i_byte := 8;
    self.i_block := 0;
    let i = switch (self.algo) {
      case (#sha512_224) 0;
      case (#sha512_256) 1;
      case (#sha384) 2;
      case (#sha512) 3;
    };
    for (j in Nat.range(0, 8)) {
      self.s[j] := K.ivs[i][j];
    };
  };

  /// Create an independent copy of the digest with the same internal state.
  /// This allows to finalize one of the two copies with `sum()` and to keep writing more data to the other.
  /// For example, one can obtain intermediate hashes like this.
  ///
  /// ```motoko
  /// let digest = Sha512.new();
  /// digest.writeBlob("Hello");
  /// let clone = digest.clone();
  /// let intermediate = clone.sum();
  /// digest.writeBlob(" world");
  /// let final = digest.sum();
  /// ```
  public func clone(self : Digest) : Digest {
    assert not self.closed;
    {
      algo = self.algo;
      msg = VarArray.clone(self.msg);
      var word = self.word;
      var i_msg = self.i_msg;
      var i_byte = self.i_byte;
      var i_block = self.i_block;
      s = VarArray.clone(self.s); // TODO: use dot noations once new motoko-core is available
      var closed = false;
    };
  };

  // We must be at a word boundary, i.e. i_byte must be equal to 8
  func writeWord(x : Digest, val : Nat64) : () {
    assert (x.i_byte == 8);
    let msg = x.msg;
    var i_msg = x.i_msg;
    msg[Nat8.toNat(i_msg)] := val;
    i_msg +%= 1;
    if (i_msg == 16) {
      ProcessBlock.process_block_from_buffer(x.s, msg);
      x.i_msg := 0;
      x.i_block +%= 1;
    } else { 
      x.i_msg := i_msg;
    };
  };

  /// Write a `Blob` to the digest.
  ///
  /// ```motoko
  /// let digest = Sha512.new();
  /// digest.writeBlob("Hello");
  /// digest.writeBlob(" world");
  /// let hash = digest.sum();
  /// ```
  public func writeBlob(self : Digest, data : Blob) : () = Write.blob(self, data);
  
  /// Write a `[Nat8]` array to the digest.
  ///
  /// ```motoko
  /// let digest = Sha512.new();
  /// digest.writeArray([72, 101, 108, 108, 111]); // "Hello"
  /// digest.writeBlob(" world");
  /// let hash = digest.sum();
  /// ```
  public func writeArray(self : Digest, data : [Nat8]) : () = Write.array(self, data);
  
  /// Write a `[var Nat8]` array to the digest.
  ///
  /// ```motoko
  /// let digest = Sha512.new();
  /// let data : [var Nat8] = [var 72, 101, 108, 108, 111];
  /// digest.writeVarArray(data);
  /// let hash = digest.sum();
  /// ```
  public func writeVarArray(self : Digest, data : [var Nat8]) : () = Write.varArray(self, data);
  
  /// Write data from a positional accessor function.
  /// Takes `len` bytes starting from the `start` index.
  /// It it the responsibility of the caller to ensure that the accessor function
  /// can provide valid data for all requested indices.
  ///
  /// ```motoko
  /// let digest = Sha512.new();
  /// let data = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
  /// func accessor(i : Nat) : Nat8 = data[i];
  /// digest.writeAccessor(accessor, 0, 5); // "Hello"
  /// digest.writeAccessor(accessor, 5, 6); // " world"
  /// let hash = digest.sum();
  /// ```
  public func writeAccessor(self : Digest, at : Nat -> Nat8, start : Nat, len : Nat) : () = Write.accessor(self, at, start, len);
  
  /// Write data from a reader function.
  /// Takes exactly `len` bytes by calling the reader function `len` times.
  /// It it the responsibility of the caller to ensure that the reader function
  /// can provide valid data for all requested bytes. 
  ///
  /// ```motoko
  /// let digest = Sha512.new();
  /// let data = [72, 101, 108, 108, 111];
  /// var pos = 0;
  /// func reader() : Nat8 { let b = data[pos]; pos += 1; b };
  /// digest.writeReader(reader, 5); // "Hello"
  /// digest.writeReader(reader, 6); // " world"
  /// let hash = digest.sum();
  /// ```
  public func writeReader(self : Digest, next : () -> Nat8, len : Nat) : () = Write.reader(self, next, len);
  
  /// Write data from an `Iter<Nat8>` to the digest. Consumes the entire iterator.
  ///
  /// ```motoko
  /// let digest = Sha512.new();
  /// let iter = [72, 101, 108, 108, 111].vals();
  /// digest.writeIter(iter); // "Hello"
  /// let hash = digest.sum();
  /// ```
  public func writeIter(self : Digest, data : Iter<Nat8>) : () = Write.iter(self, data.next);

  /// Finalize the digest and return the hash as a `Blob`.
  /// This closes the digest. It cannot be used for anything again unless it is reset with the `reset()` function.
  /// For example, attempting to write more data to it or finalizing it a second time will trap.
  ///
  /// ```motoko
  /// let digest = Sha512.new();
  /// digest.writeBlob("Hello world");
  /// let hash : Blob = digest.sum();
  /// ```
  public func sum(self : Digest) : Blob {
    assert not self.closed;
    self.closed := true;
    // calculate padding
    // t = bytes in the last incomplete block (0-127)
    let t : Nat8 = (self.i_msg << 3) +% 8 -% self.i_byte;
    // p = length of padding (1-128)
    var p : Nat8 = if (t < 112) (112 -% t) else (240 -% t);
    // n_bits = length of message in bits
    // Note: This implementation only handles messages < 2^64 bits
    let n_bits : Nat64 = ((self.i_block << 7) +% Nat64.fromIntWrap(Nat8.toNat(t))) << 3;

    // write 1-7 padding bytes 
    Byte.writeByte(self, 0x80);
    p -%= 1;
    while (p & 0x7 != 0) {
      Byte.writeByte(self, 0);
      p -%= 1;
    };
    // write padding words
    p >>= 3;
    while (p != 0) {
      writeWord(self, 0);
      p -%= 1;
    };

    // write length (16 bytes)
    // Note: this exactly fills the block buffer, hence process_block will get
    // triggered by the last writeByte
    writeWord(self, 0);
    writeWord(self, n_bits);

    // retrieve sum
    stateToBlob(self);
  };

  func stateToBlob(x : Digest) : Blob {
    let (d0, d1, d2, d3, d4, d5, d6, d7) = Prim.explodeNat64(x.s[0]);
    let (d8, d9, d10, d11, d12, d13, d14, d15) = Prim.explodeNat64(x.s[1]);
    let (d16, d17, d18, d19, d20, d21, d22, d23) = Prim.explodeNat64(x.s[2]);
    let (d24, d25, d26, d27, d28, d29, d30, d31) = Prim.explodeNat64(x.s[3]);

    if (x.algo == #sha512_224) {
      return Prim.arrayToBlob([
        d0, d1, d2, d3, d4, d5, d6, d7,
        d8, d9, d10, d11, d12, d13, d14, d15,
        d16, d17, d18, d19, d20, d21, d22, d23,
        d24, d25, d26, d27
      ]);
    };

    if (x.algo == #sha512_256) {
      return Prim.arrayToBlob([
        d0, d1, d2, d3, d4, d5, d6, d7,
        d8, d9, d10, d11, d12, d13, d14, d15,
        d16, d17, d18, d19, d20, d21, d22, d23,
        d24, d25, d26, d27,
        d28, d29, d30, d31
      ]);
    };

    let (d32, d33, d34, d35, d36, d37, d38, d39) = Prim.explodeNat64(x.s[4]);
    let (d40, d41, d42, d43, d44, d45, d46, d47) = Prim.explodeNat64(x.s[5]);

    if (x.algo == #sha384) {
      return Prim.arrayToBlob([
        d0, d1, d2, d3, d4, d5, d6, d7,
        d8, d9, d10, d11, d12, d13, d14, d15,
        d16, d17, d18, d19, d20, d21, d22, d23,
        d24, d25, d26, d27, d28, d29, d30, d31,
        d32, d33, d34, d35, d36, d37, d38, d39,
        d40, d41, d42, d43, d44, d45, d46, d47
      ]);
    };

    let (d48, d49, d50, d51, d52, d53, d54, d55) = Prim.explodeNat64(x.s[6]);
    let (d56, d57, d58, d59, d60, d61, d62, d63) = Prim.explodeNat64(x.s[7]);

    return Prim.arrayToBlob([
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

  /// Get the current hash value without finalizing the digest.
  /// This internally clones the digest, finalizes the clone, and returns the hash.
  /// The purpose is to allow obtaining intermediate hash values without closing the original digest.
  ///
  /// Additionally, `peekSum()` can be called on an already finalized digest.
  /// It simply returns the final hash in that case.
  ///
  /// ```motoko
  /// let digest = Sha512.new();
  /// digest.writeBlob("Hello");
  /// let intermediate = digest.peekSum();
  /// digest.writeBlob(" world");
  /// let final = digest.sum();
  /// let sameFinal = digest.peekSum();
  /// ```
  public func peekSum(self : Digest) : Blob {
    if (self.closed) stateToBlob(self) else sum(clone(self));
  };

  /// Directly calculate the SHA2 hash digest from a `Blob`.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko
  /// let hash = Sha512.fromBlob("Hello world");
  /// ```
  ///
  /// The default algorithm is `#sha512`. To use `#sha384`, `#sha512_256` or `#sha512_224`, pass it as an explicit argument: 
  ///
  /// ```motoko
  /// let hash = Sha512.fromBlob(#sha384, "Hello world");
  /// ```
  public func fromBlob(algo : (implicit : Algorithm), b : Blob) : Blob {
    let d = new(algo);
    Write.blob(d, b);
    return sum(d);
  };

  /// Calculate the SHA2 hash digest from a `[Nat8]` array.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko
  /// let data = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
  /// let hash = Sha512.fromArray(data);
  /// ```
  ///
  /// The default algorithm is `#sha512`. To use `#sha384`, `#sha512_256` or `#sha512_224`, pass it as an explicit argument: 
  ///
  /// ```motoko
  /// let hash = Sha512.fromArray(#sha384, data);
  /// ```
  public func fromArray(algo : (implicit : Algorithm), arr : [Nat8]) : Blob {
    let d = new(algo);
    Write.array(d, arr);
    return sum(d);
  };

  /// Calculate the SHA2 hash digest from a `[var Nat8]` array.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko
  /// let data : [var Nat8] = [var 72, 101, 108, 108, 111];
  /// let hash = Sha512.fromVarArray(data);
  /// ```
  ///
  /// The default algorithm is `#sha512`. To use `#sha384`, `#sha512_256` or `#sha512_224`, pass it as an explicit argument: 
  ///
  /// ```motoko
  /// let hash = Sha512.fromVarArray(#sha384, data);
  /// ```
  public func fromVarArray(algo : (implicit : Algorithm), arr : [var Nat8]) : Blob {
    let d = new(algo);
    Write.varArray(d, arr);
    return sum(d);
  };

  /// Calculate the SHA2 hash digest from an entire `Iter<Nat8>`.
  /// This is a convenience function that creates a digest, writes all data
  /// from the iterator, and returns the final hash in one step.
  ///
  /// ```motoko
  /// let data = [72, 101, 108, 108, 111].vals();
  /// let hash = Sha512.fromIter(data);
  /// ```
  ///
  /// The default algorithm is `#sha512`. To use `#sha384`, `#sha512_256` or `#sha512_224`, pass it as an explicit argument: 
  ///
  /// ```motoko
  /// let hash = Sha512.fromIter(#sha384, data);
  /// ```
  public func fromIter(algo : (implicit : Algorithm), iter : Iter<Nat8>) : Blob {
    let d = new(algo);
    Write.iter(d, iter.next);
    return sum(d);
  };

  /// Calculate the SHA2 hash digest from a positional accessor function.
  /// Takes `len` bytes counting from the `start` index.
  /// It it the responsibility of the caller to ensure that the accessor function
  /// can provide valid data for all requested indices.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko
  /// let data = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
  /// func accessor(i : Nat) : Nat8 = data[i];
  /// let hash = Sha512.fromAccessor(accessor, 0, 5);
  /// ```
  ///
  /// The default algorithm is `#sha512`. To use `#sha384`, `#sha512_256` or `#sha512_224`, pass it as an explicit argument: 
  ///
  /// ```motoko
  /// let hash = Sha512.fromAccessor(#sha384, accessor, 0, 5);
  /// ```
  public func fromAccessor(algo : (implicit : Algorithm), data : Nat -> Nat8, start : Nat, len : Nat) : Blob {
    let d = new(algo);
    Write.accessor(d, data, start, len);
    return sum(d);
  };

  /// Calculate the SHA2 hash digest from a reader function.
  /// Takes exactly `len` bytes by calling the reader function `len` times.
  /// It it the responsibility of the caller to ensure that the reader function
  /// can provide valid data for all requested bytes. 
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko
  /// var pos = 0;
  /// let data = [72, 101, 108, 108, 111];
  /// func reader() : Nat8 { let b = data[pos]; pos += 1; b };
  /// let hash = Sha512.fromReader(reader, 5);
  /// ```
  ///
  /// The default algorithm is `#sha512`. To use `#sha384`, `#sha512_256` or `#sha512_224`, pass it as an explicit argument: 
  ///
  /// ```motoko
  /// let hash = Sha512.fromReader(#sha384, reader, 5);
  /// ```
  public func fromReader(algo : (implicit : Algorithm), next : () -> Nat8, len : Nat) : Blob {
    let d = new(algo);
    Write.reader(d, next, len);
    return sum(d);
  };

};
