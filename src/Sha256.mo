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
  /// SHA256 algorithms.
  public type Algorithm = { #sha224; #sha256 };

  /// Default algorithm.
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
  /// ```motoko include=import
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
  /// ```motoko include=import
  /// let digest = Sha256.new(#sha224);
  /// ```
  public func new(algo : (implicit : Algorithm)) : Digest {
    let buf = Buffer.new();
    switch (algo) {
      case (#sha224) {
        {
          algo = #sha224;
          state = [var 0xc105, 0x9ed8, 0x367c, 0xd507, 0x3070, 0xdd17, 0xf70e, 0x5939, 0xffc0, 0x0b31, 0x6858, 0x1511, 0x64f9, 0x8fa7, 0xbefa, 0x4fa4];
          buffer = buf;
          var closed = false;
        };
      };
      case (_) {
        {
          algo = #sha256;
          state = [var 0x6a09, 0xe667, 0xbb67, 0xae85, 0x3c6e, 0xf372, 0xa54f, 0xf53a, 0x510e, 0x527f, 0x9b05, 0x688c, 0x1f83, 0xd9ab, 0x5be0, 0xcd19];
          buffer = buf;
          var closed = false;
        };
      };
    };
  };

  /// Reset the digest state to start a new hash computation.
  /// After reset, the digest can be reused to hash new data.
  /// This works even if the digest was previously finalized (is closed).
  ///
  /// ```motoko include=import
  /// let digest = Sha256.new();
  /// digest.writeBlob("First message");
  /// let hash1 = digest.sum();
  /// digest.reset();
  /// digest.writeBlob("Second message");
  /// let hash2 = digest.sum();
  /// ```
  // Load the algorithm's initial hash value (IV) into `state`.
  // Direct half-word assignment avoids allocating a literal array (the original
  // `state.set([...])` allocated a fresh 16-element array and copied it through
  // a `Nat.range` iterator — ~10x the cost, dominating short-message hashing).
  // `switch` (not `algo == #sha224`) because variant `==` allocates per call.
  func loadIV(s : Types.State, algo : Algorithm) {
    // prettier-ignore
    switch (algo) {
      case (#sha224) {
      s[0] := 0xc105; s[1] := 0x9ed8; s[2] := 0x367c; s[3] := 0xd507;
      s[4] := 0x3070; s[5] := 0xdd17; s[6] := 0xf70e; s[7] := 0x5939;
      s[8] := 0xffc0; s[9] := 0x0b31; s[10] := 0x6858; s[11] := 0x1511;
      s[12] := 0x64f9; s[13] := 0x8fa7; s[14] := 0xbefa; s[15] := 0x4fa4;
      };
      case (_) {
      s[0] := 0x6a09; s[1] := 0xe667; s[2] := 0xbb67; s[3] := 0xae85;
      s[4] := 0x3c6e; s[5] := 0xf372; s[6] := 0xa54f; s[7] := 0xf53a;
      s[8] := 0x510e; s[9] := 0x527f; s[10] := 0x9b05; s[11] := 0x688c;
      s[12] := 0x1f83; s[13] := 0xd9ab; s[14] := 0x5be0; s[15] := 0xcd19;
      };
    };
  };

  public func reset(self : Digest) {
    self.buffer.reset();
    loadIV(self.state, self.algo);
    self.closed := false;
  };

  /// Create an independent copy of the digest with the same internal state.
  /// This allows to finalize one of the two copies with `sum()` and to keep writing more data to the other.
  /// For example, one can obtain intermediate hashes like this.
  ///
  /// ```motoko include=import
  /// let digest = Sha256.new();
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
      buffer = self.buffer.clone();
      state = self.state.clone();
      var closed = false;
    };
  };

  /// Write a `Blob` to the digest.
  ///
  /// ```motoko include=import
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello");
  /// digest.writeBlob(" world");
  /// let hash = digest.sum();
  /// ```
  ///
  /// Traps if `self` is closed.
  public func writeBlob(self : Digest, data : Blob) : () = _Digest.writeBlob(self, data);

  /// Combine two closed digests in place: replace `self`'s digest with
  /// `SHA256(self.digest ++ other.digest)`, so `self` moves "up one level" in a
  /// Merkle tree while `other` is consumed (read-only; the caller frees it).
  /// This is a single SHA256: for a double-SHA tree (e.g. Bitcoin) call `fold`
  /// after; for a single-SHA tree (each node `SHA256(left ++ right)`) don't.
  /// (This is plain concatenation — NOT RFC 6962, which prepends a 0x01
  /// domain-separation byte and so hashes 65 bytes.) Self-contained — no
  /// `reset`/`close` needed, no message buffer, no intermediate `Blob`; `self`
  /// stays closed. The internal-node counterpart of `combineLeaves` (together
  /// they build a Merkle tree in O(log n) hashers — see `examples/Merkle.mo`).
  ///
  /// Traps if `self` or `other` is not closed.
  public func combineNodes(self : Digest, other : Digest) : () = _Digest.combineNodes(self, other);

  /// Hash two 32-byte blobs into `self` as `SHA256(b1 ++ b2)`, from a length-0
  /// start — a single SHA256, leaving the result in `self` (closed). The leaf
  /// counterpart of `combineNodes`; for a double-SHA tree follow with `fold`,
  /// for a single-SHA tree don't. Self-contained — requires `self` already
  /// closed, starts from the IV (no `reset`), runs the data block plus a
  /// hard-coded padding block in one call. `b1` fills message words 0..7, `b2`
  /// words 8..15.
  ///
  /// Traps if `self` is not closed, or if either blob is not 32 bytes.
  public func combineLeaves(self : Digest, b1 : Blob, b2 : Blob) : () = _Digest.combineLeaves(self, b1, b2);

  /// Write a `[Nat8]` array to the digest.
  ///
  /// ```motoko include=import
  /// let digest = Sha256.new();
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
  /// let digest = Sha256.new();
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
  /// let digest = Sha256.new();
  /// let data = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
  /// func accessor(i : Nat) : Nat8 = data[i];
  /// digest.writeAccessor(accessor, 0, 5); // "Hello"
  /// digest.writeAccessor(accessor, 5, 6); // " world"
  /// let hash = digest.sum();
  /// ```
  ///
  /// Traps if `self` is closed, or if `data` traps for any index in `[start, start + len)`.
  public func writeAccessor(self : Digest, data : Nat -> Nat8, start : Nat, len : Nat) : () = _Digest.writeAccessor(self, data, start, len);

  /// Write data from a reader function.
  /// Takes exactly `len` bytes by calling the reader function `len` times.
  /// It it the responsibility of the caller to ensure that the reader function
  /// can provide valid data for all requested bytes.
  ///
  /// ```motoko include=import
  /// let digest = Sha256.new();
  /// let data = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
  /// var pos = 0;
  /// func reader() : Nat8 { let b = data[pos]; pos += 1; b };
  /// digest.writeReader(reader, 5); // "Hello"
  /// digest.writeReader(reader, 6); // " world"
  /// let hash = digest.sum();
  /// ```
  ///
  /// Traps if `self` is closed, or if `data` traps during any of the `len` calls.
  public func writeReader(self : Digest, data : () -> Nat8, len : Nat) : () = _Digest.writeReader(self, data, len);

  /// Write data from an `Iter<Nat8>` to the digest. Consumes the entire iterator.
  ///
  /// ```motoko include=import
  /// let digest = Sha256.new();
  /// let iter = [72, 101, 108, 108, 111].vals();
  /// digest.writeIter(iter); // "Hello"
  /// let hash = digest.sum();
  /// ```
  ///
  /// Traps if `self` is closed.
  public func writeIter(self : Digest, data : Iter<Nat8>) : () = _Digest.writeIter(self, data.next);

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
  /// ```motoko include=import
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello world");
  /// let hash : Blob = digest.sum();
  /// ```
  ///
  /// Traps if `self` is already closed.
  public func sum(self : Digest) : Blob {
    _Digest.close(self);
    return stateBlob(self);
  };

  /// Finalize the digest by writing padding, without returning the hash. After
  /// `close()` the digest is closed; read the hash with `readSum()` (any number
  /// of times) or hash it again with `fold()`.
  ///
  /// ```motoko include=import
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello world");
  /// digest.close();
  /// let hash : Blob = digest.readSum();
  /// ```
  ///
  /// Traps if `self` is already closed.
  public func close(self : Digest) : () = _Digest.close(self);

  /// Read the hash of a closed digest. Idempotent: unlike `sum()` it does not
  /// finalize, so it can be called repeatedly after `close()`, `sum()`, or
  /// `fold()`.
  ///
  /// ```motoko include=import
  /// let digest = Sha256.new();
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

  /// Hash a closed digest's own hash, in place: replace the state with
  /// `SHA256(state)`, leaving the digest closed. This is the building block for
  /// N-fold and double SHA256: after `close()`, calling `fold()` (N-1) times
  /// yields the N-fold hash, and a single `fold()` gives the double SHA256 used
  /// by Bitcoin (see `sumDouble`). Allocation-free — the digest is hashed
  /// straight from the state in one specialized block, no intermediate `Blob`.
  ///
  /// ```motoko include=import
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello world");
  /// digest.close();
  /// digest.fold();
  /// let doubleHash : Blob = digest.readSum();
  /// ```
  ///
  /// Traps if `self` is not closed, or if `self` is a sha224 digest (sha224
  /// folding is not yet supported).
  public func fold(self : Digest) {
    assert self.closed;
    assert (switch (self.algo) { case (#sha256) true; case (#sha224) false });
    State.process_fold_block(self.state);
  };

  /// Finalize the digest as a double SHA256, i.e. `sum(sum(message))`, and
  /// return the hash as a `Blob`. This is the hash used by Bitcoin.
  ///
  /// ```motoko include=import
  /// let digest = Sha256.new();
  /// digest.writeBlob("Hello world");
  /// let hash : Blob = digest.sumDouble();
  /// ```
  ///
  /// Closes the digest. Traps if `self` is already closed, or if `self` is a
  /// sha224 digest (folding is sha256-only for now).
  public func sumDouble(self : Digest) : Blob {
    _Digest.close(self);
    fold(self);
    readSum(self);
  };

  /// Directly calculate the SHA2 hash digest from a `Blob`.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko include=import
  /// let hash = Sha256.fromBlob("Hello world");
  /// ```
  ///
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit first argument:
  ///
  /// ```motoko include=import
  /// let hash = Sha256.fromBlob(#sha224, "Hello world");
  /// ```
  ///
  /// Never traps.
  public func fromBlob(algo : (implicit : Algorithm), data : Blob) : Blob {
    let digest = new(algo);
    digest.writeBlob(data);
    return sum(digest);
  };

  /// Calculate the SHA2 hash digest from a `[Nat8]` array.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko include=import
  /// let data = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
  /// let hash = Sha256.fromArray(data);
  /// ```
  ///
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit first argument:
  ///
  /// ```motoko include=import
  /// let hash = Sha256.fromArray(#sha224, data);
  /// ```
  ///
  /// Never traps.
  public func fromArray(algo : (implicit : Algorithm), data : [Nat8]) : Blob {
    let digest = new(algo);
    digest.writeArray(data);
    return sum(digest);
  };

  /// Calculate the SHA2 hash digest from a `[var Nat8]` array.
  /// This is a convenience function that creates a digest, writes the data,
  /// and returns the final hash in one step.
  ///
  /// ```motoko include=import
  /// let data : [var Nat8] = [var 72, 101, 108, 108, 111];
  /// let hash = Sha256.fromVarArray(data);
  /// ```
  ///
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit first argument:
  ///
  /// ```motoko include=import
  /// let hash = Sha256.fromVarArray(#sha224, data);
  /// ```
  ///
  /// Never traps.
  public func fromVarArray(algo : (implicit : Algorithm), data : [var Nat8]) : Blob {
    let digest = new(algo);
    digest.writeVarArray(data);
    return sum(digest);
  };

  /// Calculate the SHA2 hash digest from an entire `Iter<Nat8>`.
  /// This is a convenience function that creates a digest, writes all data
  /// from the iterator, and returns the final hash in one step.
  ///
  /// ```motoko include=import
  /// let data = [72, 101, 108, 108, 111].vals();
  /// let hash = Sha256.fromIter(data);
  /// ```
  ///
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit first argument:
  ///
  /// ```motoko include=import
  /// let hash = Sha256.fromIter(#sha224, data);
  /// ```
  ///
  /// Never traps.
  public func fromIter(algo : (implicit : Algorithm), data : Iter<Nat8>) : Blob {
    let digest = new(algo);
    _Digest.writeIter(digest, data.next);
    return sum(digest);
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
  /// let hash = Sha256.fromAccessor(accessor, 0, 5);
  /// ```
  ///
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit first argument:
  ///
  /// ```motoko include=import
  /// let hash = Sha256.fromAccessor(#sha224, accessor, 0, 5);
  /// ```
  ///
  /// Does not trap unless user-provided accessor function `data` traps.
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
  /// ```motoko include=import
  /// var pos = 0;
  /// let data = [72, 101, 108, 108, 111];
  /// func reader() : Nat8 { let b = data[pos]; pos += 1; b };
  /// let hash = Sha256.fromReader(reader, 5);
  /// ```
  ///
  /// The default algorithm is `#sha256`. To use `#sha224`, pass it as an explicit first argument:
  ///
  /// ```motoko include=import
  /// let hash = Sha256.fromReader(#sha224, reader, 5);
  /// ```
  ///
  /// Does not trap unless user-provided reader function `next` traps.
  public func fromReader(algo : (implicit : Algorithm), data : () -> Nat8, len : Nat) : Blob {
    let digest = new(algo);
    digest.writeReader(data, len);
    return sum(digest);
  };
};
