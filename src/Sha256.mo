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

import WriteArray "sha256/write/Array";
import WriteVarArray "sha256/write/VarArray";
import WriteBlob "sha256/write/Blob";
import WriteList "sha256/write/List";

module {
  public type Self = Digest;

  public type Algorithm = { #sha224; #sha256 };

  let nat32To64 = Prim.nat32ToNat64;
  let nat8To16 = Prim.nat8ToNat16;
  let nat8ToNat = Prim.nat8ToNat;
  let intToNat64Wrap = Prim.intToNat64Wrap;

  type Digest = {
    algo : Algorithm;
    buffer : Buffer.Self;
    state : State.Self;
    var closed : Bool;
  };

  public func new(algo_ : Algorithm) : Digest {
    let buf = Buffer.new();
    if (algo_ == #sha224) {
      {
        algo = #sha224;
        state = (
          [var 0xc105, 0x367c, 0x3070, 0xf70e, 0xffc0, 0x6858, 0x64f9, 0xbefa],
          [var 0x9ed8, 0xd507, 0xdd17, 0x5939, 0x0b31, 0x1511, 0x8fa7, 0x4fa4],
        );
        buffer = buf;
        var closed = false;
      };
    } else {
      {
        algo = #sha256;
        state = (
          [var 0x6a09, 0xbb67, 0x3c6e, 0xa54f, 0x510e, 0x9b05, 0x1f83, 0x5be0],
          [var 0xe667, 0xae85, 0xf372, 0xf53a, 0x527f, 0x688c, 0xd9ab, 0xcd19],
        );
        buffer = buf;
        var closed = false;
      };
    };
  };

  public func reset(x : Digest) {
    x.buffer.reset();
    if (x.algo == #sha224) {
      x.state.set(
        [0xc105, 0x367c, 0x3070, 0xf70e, 0xffc0, 0x6858, 0x64f9, 0xbefa],
        [0x9ed8, 0xd507, 0xdd17, 0x5939, 0x0b31, 0x1511, 0x8fa7, 0x4fa4],
      );
    } else {
      x.state.set(
        [0x6a09, 0xbb67, 0x3c6e, 0xa54f, 0x510e, 0x9b05, 0x1f83, 0x5be0],
        [0xe667, 0xae85, 0xf372, 0xf53a, 0x527f, 0x688c, 0xd9ab, 0xcd19],
      );
    };
  };

  public func clone(x : Digest) : Digest {
    assert not x.closed;
    {
      algo = x.algo;
      buffer = Buffer.clone(x.buffer);
      state = State.clone(x.state);
      var closed = false;
    };
  };

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

  public func writeBlob(x : Digest, data : Blob) : () = WriteBlob.write(x, data);
  public func writeArray(x : Digest, data : [Nat8]) : () = WriteArray.write(x, data);
  public func writeVarArray(x : Digest, data : [var Nat8]) : () = WriteVarArray.write(x, data);
  public func writeList(x : Digest, data : Types.List<Nat8>) : () = WriteList.write(x, data);

  public func writeIter(x : Digest, iter : { next() : ?Nat8 }) : () {
    assert not x.closed;
    let (buf, state) = (x.buffer, x.state);
    var high = buf.high;
    var word = buf.word;
    var i_msg = buf.i_msg;
    var i_block = buf.i_block;
    let msg = buf.msg;
    label reading loop {
      switch (iter.next()) {
        case (?val) {
          // The following is an inlined version of writeByte(val)
          if (high) {
            word := nat8To16(val) << 8;
            high := false;
          } else {
            msg[nat8ToNat(i_msg)] := word ^ nat8To16(val);
            i_msg +%= 1;
            high := true;
          };
          if (i_msg == 32) {
            state.process_block_from_msg(buf.msg);
            i_msg := 0;
            i_block +%= 1;
          };
          continue reading;
        };
        case (null) {
          break reading;
        };
      };
    };
    buf.high := high;
    buf.word := word;
    buf.i_msg := i_msg;
    buf.i_block := i_block;
  };

  func stateToBlob(x : Digest) : Blob = Prim.arrayToBlob(
    switch (x.algo) {
      case (#sha224) State.toArray28(x.state);
      case (#sha256) State.toArray32(x.state);
    }
  );

  public func sum(x : Digest) : Blob {
    assert not x.closed;
    writePadding(x);
    x.closed := true;
    stateToBlob(x);
  };

  public func peekSum(x : Digest) : Blob {
    if (x.closed) stateToBlob(x) else sum(clone(x));
  };

  /// Calculate the SHA2 hash digest from `Blob`.
  /// Allowed values for `algo` are: `#sha224`, `#256`
  public func fromBlob(algo : Algorithm, data : Blob) : Blob {
    let digest = new(algo);
    writeBlob(digest, data);
    return sum(digest);
  };

  // Calculate SHA256 hash digest from [Nat8].
  public func fromArray(algo : Algorithm, data : [Nat8]) : Blob {
    let digest = new(algo);
    writeArray(digest, data);
    return sum(digest);
  };

  // Calculate SHA256 hash digest from [Nat8].
  public func fromVarArray(algo : Algorithm, data : [var Nat8]) : Blob {
    let digest = new(algo);
    writeVarArray(digest, data);
    return sum(digest);
  };

  /// Calculate the SHA2 hash digest from `Blob`.
  /// Allowed values for `algo` are: `#sha224`, `#256`
  public func fromList(algo : Algorithm, data : Types.List<Nat8>) : Blob {
    let digest = new(algo);
    writeList(digest, data);
    return sum(digest);
  };

  // Calculate SHA2 hash digest from Iter.
  public func fromIter(algo : Algorithm, data : Types.Iter<Nat8>) : Blob {
    let digest = new(algo);
    writeIter(digest, data);
    return sum(digest);
  };
};
