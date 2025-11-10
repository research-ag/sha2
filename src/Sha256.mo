/// Cycle-optimized Sha256 variants.
///
/// Features:
///
/// * Algorithms: `sha256`, `sha224`
/// * Input types: `Blob`, `[Nat8]`, `[var Nat8]`, `Iter<Nat8>`
/// * Additional input types: `at : Nat -> Nat8` (unchecked accessor), `next : () -> Nat8` (unchecked reader)
/// * Output types: `Blob`
///
/// Import with this line in mops.toml:
/// ```
/// sha2 = "1.0.0"
/// ```
/// and this line in your .mo file:
/// ```motoko name=import
/// import Sha256 "mo:sha2/Sha256";
/// ```

import { type Iter } "mo:core/Types";
import { arrayToBlob } "mo:prim";

import Buffer "sha256/buffer";
import State "sha256/state";
import _Digest "sha256/digest";
import Types "sha256/types";

module {
  public type Algorithm = { #sha224; #sha256 };
  public let algo = #sha256; // default algorithm used as implicit argument

  // Digest type (including the algorithm field)
  public type Digest = {
    algo : Algorithm;
    buffer : Types.Buffer;
    state : Types.State;
    var closed : Bool;
  };

  /// Create a new SHA2 digest instance for the specified algorithm.
  /// The digest can be used to incrementally hash data by calling write functions,
  /// then finalized with `sum()` or `peekSum()`.
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
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit argument: 
  ///
  /// ```motoko
  /// let digest = Sha256.new(#sha224);
  /// ``` 
  ///
  /// After finalizing with `sum()` no more data can be written to the digest.
  /// If that is desired then `peekSum()` can be used to get the current hash
  /// without closing the digest.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello");
  /// let first_hash = digest.peekSum();
  /// digest.writeBlob(" world");
  /// let final_hash = digest.sum();
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
  /// The original digest remains usable. The clone can be used to get intermediate
  /// hash values without affecting the original digest.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello");
  /// let clone1 = digest.clone();
  /// let intermediate = clone1.sum();
  /// digest.writeBlob(" world");
  /// let final = digest.sum();
  /// ```
  public func clone(self : Digest) : Digest {
    assert not self.closed;
    {
      algo = self.algo;
      buffer = self.buffer.clone();
      state = State.clone(self.state); // TODO: use dot notations once new motoko-core is available
      var closed = false;
    };
  };

  /// Write a `Blob` to the digest.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello ");
  /// digest.writeBlob("world");
  /// let hash = digest.sum();
  /// ```
  public func writeBlob(self : Digest, data : Blob) : () = self.writeBlob(data);
  
  /// Write a `[Nat8]` array to the digest.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// digest.writeArray([72, 101, 108, 108, 111]); // "Hello"
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
  
  /// Write data from a positional accessor function without bounds checking.
  /// Takes `len` bytes starting from the `start` index.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// let data = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
  /// func accessor(i : Nat) : Nat8 = data[i];
  /// digest.writeUncheckedAccessor(accessor, 0, 5); // "Hello"
  /// let hash = digest.sum();
  /// ```
  public func writeUncheckedAccessor(self : Digest, data : Nat -> Nat8, start : Nat, len : Nat) : () = self.writeAccessor(data, start, len);
  
  /// Write data from an iterator function without bounds checking.
  /// Takes exactly `len` bytes by calling the iterator function.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// var pos = 0;
  /// let data = [72, 101, 108, 108, 111];
  /// func reader() : Nat8 { let b = data[pos]; pos += 1; b };
  /// digest.writeUncheckedReader(reader, 5);
  /// let hash = digest.sum();
  /// ```
  public func writeUncheckedReader(self : Digest, data : () -> Nat8, len : Nat) : () = self.writeReader(data, len);
  
  /// Write data from an `Iter<Nat8>` to the digest. Consumes the entire iterator.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// let iter = [72, 101, 108, 108, 111].vals();
  /// digest.writeIter(iter);
  /// let hash = digest.sum();
  /// ```
  public func writeIter(self : Digest, data : Iter<Nat8>) : () = self.writeIter(data.next);

  func stateNat8(x : Digest) : [Nat8] = switch (x.algo) {
    case (#sha224) x.state.toNat8Array(28);
    case (#sha256) x.state.toNat8Array(32);
  };

  func stateBlob(x : Digest) : Blob = arrayToBlob(stateNat8(x));

  /// Finalize the digest and return the hash as a `[Nat8]` array.
  /// This consumes the digest; it cannot be used again after calling this function.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello World");
  /// let hash : [Nat8] = digest.sumToNat8Array();
  /// ```
  public func sumToNat8Array(self : Digest) : [Nat8] {
    self.close();
    return stateNat8(self); // TODO: use dot notation
  };

  /// Finalize the digest and return the hash as a `Blob`.
  /// This consumes the digest; it cannot be used again after calling this function.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello World");
  /// let hash : Blob = digest.sum();
  /// ```
  public func sum(self : Digest) : Blob = arrayToBlob(sumToNat8Array(self)); // TODO: use dot notation once available for Array in core

  /// Get the current hash value without closing the digest.
  /// If the digest is already closed, returns the final hash. Otherwise,
  /// creates a clone, finalizes it, and returns that hash.
  /// It is slower than `sum()` because a clone is created.
  ///
  /// ```motoko
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello");
  /// let intermediate = digest.peekSum();
  /// digest.writeBlob(" World");
  /// let final = digest.sum();
  /// ```
  public func peekSum(self : Digest) : Blob {
    if (self.closed) stateBlob(self) else sum(clone(self));
  };

  /// Calculate the SHA2 hash digest from a `Blob`.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko
  /// let hash = Sha256.fromBlob("Hello World");
  /// ```
  ///
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit argument: 
  ///
  /// ```motoko
  /// let hash = Sha256.fromBlob(#sha224, "Hello World");
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
  /// let data = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
  /// let hash = Sha256.fromArray(data);
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
  public func fromIter(algo : (implicit : Algorithm), data : Iter<Nat8>) : Blob {
    let digest = new(algo);
    digest.writeIter(data.next);
    return sum(digest);
  };

  /// Calculate the SHA2 hash digest from a positional accessor function without bounds check.
  /// Takes `len` bytes counting from the `start` index.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko
  /// let data = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
  /// func accessor(i : Nat) : Nat8 = data[i];
  /// let hash = Sha256.fromUncheckedAccessor(#sha256, accessor, 0, 5);
  /// ```
  public func fromUncheckedAccessor(algo : (implicit : Algorithm), data : Nat -> Nat8, start : Nat, len : Nat) : Blob {
    let digest = new(algo);
    digest.writeAccessor(data, start, len);
    return sum(digest);
  };

  /// Calculate the SHA2 hash digest from an iterator function without bounds check.
  /// Takes exactly `len` bytes by calling the iterator function.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko
  /// var pos = 0;
  /// let data = [72, 101, 108, 108, 111];
  /// func reader() : Nat8 { let b = data[pos]; pos += 1; b };
  /// let hash = Sha256.fromUncheckedReader(reader, 5);
  /// ```
  public func fromUncheckedReader(algo : (implicit : Algorithm), data : () -> Nat8, len : Nat) : Blob {
    let digest = new(algo);
    digest.writeReader(data, len);
    return sum(digest);
  };
};
