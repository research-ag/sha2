/// Cycle-optimized Sha256 variants.
///
/// Features:
///
/// * Algorithms: `sha256`, `sha224`
/// * Input types: `Blob`, `[Nat8]`, `Iter<Nat8>`
/// * Output types: `Blob`

import Types "mo:core/Types";
import Prim "mo:prim";

import Buffer "sha256/buffer";
import State "sha256/state";
import Write "sha256/write";

module {
  public type Algorithm = { #sha224; #sha256 };
  public let algo = #sha256; // default algorithm

  public type Digest = {
    algo : Algorithm;
    buffer : Buffer.Buffer;
    state : State.State;
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
      state = State.clone(self.state); // TODO: use dot noations once new motoko-core is available
      var closed = false;
    };
  };

  let nat32To64 = Prim.nat32ToNat64;
  let nat8To16 = Prim.nat8ToNat16;
  let nat8ToNat = Prim.nat8ToNat;
  let intToNat64Wrap = Prim.intToNat64Wrap;

  func writePadding(x : Digest) : () {
    let (buf, state) = (x.buffer, x.state);
    let msg = buf.msg;
    var i_msg = buf.i_msg;
    // n_bits = length of message in bits
    let t : Nat8 = if (buf.high) i_msg << 1 else i_msg << 1 +% 1;
    let n_bits : Nat64 = ((nat32To64(buf.i_block) << 6) +% intToNat64Wrap(nat8ToNat(t))) << 3;
    // separator byte
    if (buf.high) {
      msg[nat8ToNat(i_msg)] := 0x8000;
    } else {
      msg[nat8ToNat(i_msg)] := buf.word | 0x80;
    };
    i_msg +%= 1;
    // zero padding with extra block if necessary
    if (i_msg > 28) {
      while (i_msg < 32) {
        msg[nat8ToNat(i_msg)] := 0;
        i_msg +%= 1;
      };
      state.process_block_from_msg(msg); // Note: function does not rely on buf.i_msg
      i_msg := 0;
      // skipping here because we won't use buf.i_block anymore: x.i_block +%= 1;
    };
    // zero padding in last block
    while (i_msg < 28) {
      msg[nat8ToNat(i_msg)] := 0;
      i_msg +%= 1;
    };
    // 8 length bytes
    // Note: this exactly fills the block buffer, hence process_block will get
    // triggered by the last writeByte
    let (l0, l1, l2, l3, l4, l5, l6, l7) = Prim.explodeNat64(n_bits);
    msg[28] := nat8To16(l0) << 8 | nat8To16(l1);
    msg[29] := nat8To16(l2) << 8 | nat8To16(l3);
    msg[30] := nat8To16(l4) << 8 | nat8To16(l5);
    msg[31] := nat8To16(l6) << 8 | nat8To16(l7);
    state.process_block_from_msg(msg); // Note: function does not rely on buf.i_msg
    // skipping here because we won't use x anymore: buf.i_msg := 0;
  };

  public func writeBlob(self : Digest, data : Blob) : () = Write.blob(self, data);
  public func writeArray(self : Digest, data : [Nat8]) : () = Write.array(self, data);
  public func writeVarArray(self : Digest, data : [var Nat8]) : () = Write.varArray(self, data);
  public func writePositional(self : Digest, data : Nat -> Nat8, sz : Nat) : () = Write.positional(self, data, sz);
  public func writeNext(self : Digest, data : () -> Nat8, sz : Nat) : () = Write.next(self, data, sz);
  public func writeIter(self : Digest, data : Types.Iter<Nat8>) : () = Write.iter(self, data.next);

  func stateNat8(x : Digest) : [Nat8] = switch (x.algo) {
    case (#sha224) State.toNat8Array(x.state, 28);
    case (#sha256) State.toNat8Array(x.state, 32);
  };

  func stateBlob(x : Digest) : Blob = Prim.arrayToBlob(stateNat8(x));

  func sum_(x : Digest) {
    assert not x.closed;
    writePadding(x);
    x.closed := true;
  };

  public func sumToNat8Array(self : Digest) : [Nat8] { sum_(self); stateNat8(self) };

  public func sum(self : Digest) : Blob = Prim.arrayToBlob(sumToNat8Array(self));

  public func peekSum(self : Digest) : Blob {
    if (self.closed) stateBlob(self) else sum(clone(self));
  };

  /// Calculate the SHA2 hash digest from `Blob`.
  /// Allowed values for `algo` are: `#sha224`, `#256`
  public func fromBlob(algo : (implicit : Algorithm), data : Blob) : Blob {
    let digest = new(algo);
    Write.blob(digest, data);
    return sum(digest);
  };

  // Calculate SHA256 hash digest from [Nat8].
  public func fromArray(algo : (implicit : Algorithm), data : [Nat8]) : Blob {
    let digest = new(algo);
    Write.array(digest, data);
    return sum(digest);
  };

  // Calculate SHA256 hash digest from [Nat8].
  public func fromVarArray(algo : (implicit : Algorithm), data : [var Nat8]) : Blob {
    let digest = new(algo);
    Write.varArray(digest, data);
    return sum(digest);
  };

  // Calculate SHA2 hash digest from Iter.
  public func fromIter(algo : (implicit : Algorithm), data : Types.Iter<Nat8>) : Blob {
    let digest = new(algo);
    Write.iter(digest, data.next);
    return sum(digest);
  };

  public func fromPositional(algo : (implicit : Algorithm), data : Nat -> Nat8, size : Nat) : Blob {
    let digest = new(algo);
    Write.positional(digest, data, size);
    return sum(digest);
  };

  public func fromNext(algo : (implicit : Algorithm), data : () -> Nat8, size : Nat) : Blob {
    let digest = new(algo);
    Write.next(digest, data, size);
    return sum(digest);
  };
};
