/// Cycle-optimized Sha256 variants.
///
/// Features:
///
/// * Algorithms: `sha256`, `sha224`
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
/// import Sha256 "mo:sha2/Sha256";
/// ```
///
/// The package allows incremental hashing by creating a `Digest` instance,
/// writing data to it in increments, and finalizing it to get the hash. It also provides
/// convenience functions to compute the hash from various input types in a single step.

import { type Iter } "mo:core/Types";
import { arrayToBlob } "mo:prim";

import Buffer "sha256/buffer";
import State "sha256/state";
import _Digest "sha256/digest";
import Types "sha256/types";

module {
  public type Algorithm = { #sha224; #sha256 };
  public let algo = #sha256; // default algorithm used as implicit argument

  /// Digest type (including the algorithm field)
  /// As a static record it can be declared `stable`.
  public type Digest = Types.Digest and {
    algo : Algorithm;
  };

  /// Create a new SHA2 digest instance for the specified algorithm.
  /// The digest can be used to incrementally hash data by calling write functions,
  /// then finalized with `sum()`.
  ///
  /// If incremental hashing is not needed, consider using the convenience functions `fromBlob`, `fromArray`, etc.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello");
  /// digest.writeBlob(" world");
  /// let hash = digest.sum();
  /// ```
  ///
  /// After finalizing with `sum()` the digest is "closed", i.e. no more data can be written to it.
  ///
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit argument:
  ///
  /// ```motoko
  /// let digest = Sha256.new(#sha224);
  /// ```
  public func new(algo : (implicit : Algorithm)) : Digest {
    let buf = Buffer.new();
    if (algo == #sha224) {
      {
        algo = #sha224;
        state = [var 0xc105, 0x9ed8, 0x367c, 0xd507, 0x3070, 0xdd17, 0xf70e, 0x5939, 0xffc0, 0x0b31, 0x6858, 0x1511, 0x64f9, 0x8fa7, 0xbefa, 0x4fa4];
        buffer = buf;
        var closed = false;
      };
    } else {
      {
        algo = #sha256;
        state = [var 0x6a09, 0xe667, 0xbb67, 0xae85, 0x3c6e, 0xf372, 0xa54f, 0xf53a, 0x510e, 0x527f, 0x9b05, 0x688c, 0x1f83, 0xd9ab, 0x5be0, 0xcd19];
        buffer = buf;
        var closed = false;
      };
    };
  };

  /// Reset the digest state to start a new hash computation.
  /// After reset, the digest can be reused to hash new data.
  /// This works even if the digest was previously finalized (is closed).
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// digest.writeBlob("First message");
  /// let hash1 = digest.sum();
  /// digest.reset();
  /// digest.writeBlob("Second message");
  /// let hash2 = digest.sum();
  /// ```
  public func reset(self : Digest) {
    self.buffer.reset();
    if (self.algo == #sha224) {
      self.state.set([0xc105, 0x9ed8, 0x367c, 0xd507, 0x3070, 0xdd17, 0xf70e, 0x5939, 0xffc0, 0x0b31, 0x6858, 0x1511, 0x64f9, 0x8fa7, 0xbefa, 0x4fa4]);
    } else {
      self.state.set([0x6a09, 0xe667, 0xbb67, 0xae85, 0x3c6e, 0xf372, 0xa54f, 0xf53a, 0x510e, 0x527f, 0x9b05, 0x688c, 0x1f83, 0xd9ab, 0x5be0, 0xcd19]);
    };
    self.closed := false;
  };

  /// Create an independent copy of the digest with the same internal state.
  /// This allows to finalize one of the two copies with `sum()` and to keep writing more data to the other.
  /// For example, one can obtain intermediate hashes like this.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
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
      buffer = self.buffer.clone();
      state = self.state.clone();
      var closed = false;
    };
  };

  /// Write a `Blob` to the digest.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello");
  /// digest.writeBlob(" world");
  /// let hash = digest.sum();
  /// ```
  public func writeBlob(self : Digest, data : Blob) : () = self.writeBlob(data);

  /// Write a `[Nat8]` array to the digest.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// digest.writeArray([72, 101, 108, 108, 111]); // "Hello"
  /// digest.writeBlob(" world");
  /// let hash = digest.sum();
  /// ```
  public func writeArray(self : Digest, data : [Nat8]) : () = self.writeArray(data);

  /// Write a `[var Nat8]` array to the digest.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// let data : [var Nat8] = [var 72, 101, 108, 108, 111];
  /// digest.writeVarArray(data);
  /// let hash = digest.sum();
  /// ```
  public func writeVarArray(self : Digest, data : [var Nat8]) : () = self.writeVarArray(data);

  /// Write data from a positional accessor function.
  /// Takes `len` bytes starting from the `start` index.
  /// It it the responsibility of the caller to ensure that the accessor function
  /// can provide valid data for all requested indices.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// let data = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
  /// func accessor(i : Nat) : Nat8 = data[i];
  /// digest.writeAccessor(accessor, 0, 5); // "Hello"
  /// digest.writeAccessor(accessor, 5, 6); // " world"
  /// let hash = digest.sum();
  /// ```
  public func writeAccessor(self : Digest, data : Nat -> Nat8, start : Nat, len : Nat) : () = self.writeAccessor(data, start, len);

  /// Write data from a reader function.
  /// Takes exactly `len` bytes by calling the reader function `len` times.
  /// It it the responsibility of the caller to ensure that the reader function
  /// can provide valid data for all requested bytes.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// let data = [72, 101, 108, 108, 111];
  /// var pos = 0;
  /// func reader() : Nat8 { let b = data[pos]; pos += 1; b };
  /// digest.writeReader(reader, 5); // "Hello"
  /// digest.writeReader(reader, 6); // " world"
  /// let hash = digest.sum();
  /// ```
  public func writeReader(self : Digest, data : () -> Nat8, len : Nat) : () = self.writeReader(data, len);

  /// Write data from an `Iter<Nat8>` to the digest. Consumes the entire iterator.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// let iter = [72, 101, 108, 108, 111].vals();
  /// digest.writeIter(iter); // "Hello"
  /// let hash = digest.sum();
  /// ```
  public func writeIter(self : Digest, data : Iter<Nat8>) : () = self.writeIter(data.next);

  // Extract the state from a Digest as a [Nat8] array
  func stateNat8(x : Digest) : [Nat8] = switch (x.algo) {
    case (#sha224) x.state.toNat8Array(28);
    case (#sha256) x.state.toNat8Array(32);
  };

  // Extract the state from a Digest as a Blob
  func stateBlob(x : Digest) : Blob = arrayToBlob(stateNat8(x));

  /// Finalize the digest and return the hash as a `Blob`.
  /// This closes the digest. It cannot be used for anything again unless it is reset with the `reset()` function.
  /// For example, attempting to write more data to it or finalizing it a second time will trap.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello world");
  /// let hash : Blob = digest.sum();
  /// ```
  public func sum(self : Digest) : Blob {
    self.close();
    return stateBlob(self);
  };

  /// Get the current hash value without finalizing the digest.
  /// This internally clones the digest, finalizes the clone, and returns the hash.
  /// The purpose is to allow obtaining intermediate hash values without closing the original digest.
  ///
  /// Additionally, `peekSum()` can be called on an already finalized digest.
  /// It simply returns the final hash in that case.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello");
  /// let intermediate = digest.peekSum();
  /// digest.writeBlob(" world");
  /// let final = digest.sum();
  /// let sameFinal = digest.peekSum();
  /// ```
  public func peekSum(self : Digest) : Blob {
    if (self.closed) stateBlob(self) else sum(clone(self));
  };

  /// Directly calculate the SHA2 hash digest from a `Blob`.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko
  /// let hash = Sha256.fromBlob("Hello world");
  /// ```
  ///
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit first argument:
  ///
  /// ```motoko
  /// let hash = Sha256.fromBlob(#sha224, "Hello world");
  /// ```
  public func fromBlob(algo : (implicit : Algorithm), data : Blob) : Blob {
    let digest = new(algo);
    digest.writeBlob(data);
    return sum(digest);
  };

  /// Calculate the SHA2 hash digest from a `[Nat8]` array.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko
  /// let data = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
  /// let hash = Sha256.fromArray(data);
  /// ```
  ///
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit first argument:
  ///
  /// ```motoko
  /// let hash = Sha256.fromArray(#sha224, data);
  /// ```
  public func fromArray(algo : (implicit : Algorithm), data : [Nat8]) : Blob {
    let digest = new(algo);
    digest.writeArray(data);
    return sum(digest);
  };

  /// Calculate the SHA2 hash digest from a `[var Nat8]` array.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko
  /// let data : [var Nat8] = [var 72, 101, 108, 108, 111];
  /// let hash = Sha256.fromVarArray(data);
  /// ```
  ///
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit first argument:
  ///
  /// ```motoko
  /// let hash = Sha256.fromVarArray(#sha224, data);
  /// ```
  public func fromVarArray(algo : (implicit : Algorithm), data : [var Nat8]) : Blob {
    let digest = new(algo);
    digest.writeVarArray(data);
    return sum(digest);
  };

  /// Calculate the SHA2 hash digest from an entire `Iter<Nat8>`.
  /// This is a convenience function that creates a digest, writes all data
  /// from the iterator, and returns the final hash in one step.
  ///
  /// ```motoko
  /// let data = [72, 101, 108, 108, 111].vals();
  /// let hash = Sha256.fromIter(data);
  /// ```
  ///
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit first argument:
  ///
  /// ```motoko
  /// let hash = Sha256.fromIter(#sha224, data);
  /// ```
  public func fromIter(algo : (implicit : Algorithm), data : Iter<Nat8>) : Blob {
    let digest = new(algo);
    digest.writeIter(data.next);
    return sum(digest);
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
  /// let hash = Sha256.fromAccessor(accessor, 0, 5);
  /// ```
  ///
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit first argument:
  ///
  /// ```motoko
  /// let hash = Sha256.fromAccessor(#sha224, accessor, 0, 5);
  /// ```
  public func fromAccessor(algo : (implicit : Algorithm), data : Nat -> Nat8, start : Nat, len : Nat) : Blob {
    let digest = new(algo);
    digest.writeAccessor(data, start, len);
    return sum(digest);
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
  /// let hash = Sha256.fromReader(reader, 5);
  /// ```
  ///
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit first argument:
  ///
  /// ```motoko
  /// let hash = Sha256.fromReader(#sha224, reader, 5);
  /// ```
  public func fromReader(algo : (implicit : Algorithm), data : () -> Nat8, len : Nat) : Blob {
    let digest = new(algo);
    digest.writeReader(data, len);
    return sum(digest);
  };
};
