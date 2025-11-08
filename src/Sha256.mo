/// Cycle-optimized Sha256 variants.
///
/// Features:
///
/// * Algorithms: `sha256`, `sha224`
/// * Input types: `Blob`, `[Nat8]`, `Iter<Nat8>`
/// * Output types: `Blob`

import { type Iter } "mo:core/Types";
import { arrayToBlob } "mo:prim";

import Buffer "sha256/buffer";
import State "sha256/state";
import _Digest "sha256/digest";
import Types "sha256/types";

module {
  public type Algorithm = { #sha224; #sha256 };
  public let algo = #sha256; // default algorithm

  // Digest type with the algorithm field
  public type Digest = {
    algo : Algorithm;
    buffer : Types.Buffer;
    state : Types.State;
    var closed : Bool;
  };

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

  public func reset(self : Digest) {
    assert not self.closed;
    self.buffer.reset();
    if (self.algo == #sha224) {
      self.state.set([0xc105, 0x9ed8, 0x367c, 0xd507, 0x3070, 0xdd17, 0xf70e, 0x5939, 0xffc0, 0x0b31, 0x6858, 0x1511, 0x64f9, 0x8fa7, 0xbefa, 0x4fa4]);
    } else {
      self.state.set([0x6a09, 0xe667, 0xbb67, 0xae85, 0x3c6e, 0xf372, 0xa54f, 0xf53a, 0x510e, 0x527f, 0x9b05, 0x688c, 0x1f83, 0xd9ab, 0x5be0, 0xcd19]);
    };
  };

  public func clone(self : Digest) : Digest {
    assert not self.closed;
    {
      algo = self.algo;
      buffer = self.buffer.clone();
      state = State.clone(self.state); // TODO: use dot notations once new motoko-core is available
      var closed = false;
    };
  };

  public func writeBlob(self : Digest, data : Blob) : () = self.writeBlob(data);
  public func writeArray(self : Digest, data : [Nat8]) : () = self.writeArray(data);
  public func writeVarArray(self : Digest, data : [var Nat8]) : () = self.writeVarArray(data);
  public func writeUncheckedAccessor(self : Digest, data : Nat -> Nat8, start : Nat, len : Nat) : () = self.writeAccessor(data, start, len);
  public func writeUncheckedReader(self : Digest, data : () -> Nat8, len : Nat) : () = self.writeReader(data, len);
  public func writeIter(self : Digest, data : Iter<Nat8>) : () = self.writeIter(data.next);

  func stateNat8(x : Digest) : [Nat8] = switch (x.algo) {
    case (#sha224) x.state.toNat8Array(28);
    case (#sha256) x.state.toNat8Array(32);
  };

  func stateBlob(x : Digest) : Blob = arrayToBlob(stateNat8(x));

  public func sumToNat8Array(self : Digest) : [Nat8] {
    self.close();
    return stateNat8(self); // TODO: use dot notation
  };

  public func sum(self : Digest) : Blob = arrayToBlob(sumToNat8Array(self)); // TODO: use dot notation once available for Array in core

  public func peekSum(self : Digest) : Blob {
    if (self.closed) stateBlob(self) else sum(clone(self));
  };

  /// Calculate the SHA2 hash digest from `Blob`.
  /// Allowed values for `algo` are: `#sha224`, `#256`
  public func fromBlob(algo : (implicit : Algorithm), data : Blob) : Blob {
    let digest = new(algo);
    digest.writeBlob(data);
    return sum(digest);
  };

  // Calculate SHA256 hash digest from [Nat8].
  public func fromArray(algo : (implicit : Algorithm), data : [Nat8]) : Blob {
    let digest = new(algo);
    digest.writeArray(data);
    return sum(digest);
  };

  // Calculate SHA256 hash digest from [var Nat8].
  public func fromVarArray(algo : (implicit : Algorithm), data : [var Nat8]) : Blob {
    let digest = new(algo);
    digest.writeVarArray(data);
    return sum(digest);
  };

  // Calculate SHA256 hash digest from entire Iter.
  public func fromIter(algo : (implicit : Algorithm), data : Iter<Nat8>) : Blob {
    let digest = new(algo);
    digest.writeIter(data.next);
    return sum(digest);
  };

  // Calculate SHA256 hash digest from a positional accessor without bounds check.
  // Take `len` bytes counting from the `start` index.
  public func fromUncheckedAccessor(algo : (implicit : Algorithm), data : Nat -> Nat8, start : Nat, len : Nat) : Blob {
    let digest = new(algo);
    digest.writeAccessor(data, start, len);
    return sum(digest);
  };

  // Calculate SHA256 hash digest from an iterator function without bounds check.
  // Take `len` bytes.
  public func fromUncheckedReader(algo : (implicit : Algorithm), data : () -> Nat8, len : Nat) : Blob {
    let digest = new(algo);
    digest.writeReader(data, len);
    return sum(digest);
  };
};
