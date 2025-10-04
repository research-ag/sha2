/// Cycle-optimized Sha256 variants.
///
/// Features:
///
/// * Algorithms: `sha256`, `sha224`
/// * Input types: `Blob`, `[Nat8]`, `Iter<Nat8>`
/// * Output types: `Blob`

import List "mo:core/List";
import Nat "mo:core/Nat";
import Types "mo:core/Types";
import Prim "mo:prim";
import State "sha256/state";

module {
  public type Self = Digest;

  public type Algorithm = { #sha224; #sha256 };

  let nat32To64 = Prim.nat32ToNat64;
  let nat8To16 = Prim.nat8ToNat16;
  let nat8ToNat = Prim.nat8ToNat;
  let natToNat32 = Prim.natToNat32;
  let intToNat64Wrap = Prim.intToNat64Wrap;

  type Digest = {
    algo : Algorithm;
    msg : [var Nat16];
    var i_msg : Nat8;
    var i_block : Nat32;
    var high : Bool;
    var word : Nat16;
    // state variables in Nat16 form
    state : State.Self;
    //    sh : [var Nat16];
    //    sl : [var Nat16];
  };

  public func new(algo_ : Algorithm) : Digest {
    if (algo_ == #sha224) {
      {
        algo = #sha224;
        state : State.Self = (
          [var 0xc105, 0x367c, 0x3070, 0xf70e, 0xffc0, 0x6858, 0x64f9, 0xbefa],
          [var 0x9ed8, 0xd507, 0xdd17, 0x5939, 0x0b31, 0x1511, 0x8fa7, 0x4fa4],
        );
        msg : [var Nat16] = [var 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        var i_msg : Nat8 = 0;
        var i_block : Nat32 = 0;
        var high : Bool = true;
        var word : Nat16 = 0;
      };
    } else {
      {
        algo = #sha256;
        state : State.Self = (
          [var 0x6a09, 0xbb67, 0x3c6e, 0xa54f, 0x510e, 0x9b05, 0x1f83, 0x5be0],
          [var 0xe667, 0xae85, 0xf372, 0xf53a, 0x527f, 0x688c, 0xd9ab, 0xcd19],
        );
        msg : [var Nat16] = [var 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        var i_msg : Nat8 = 0;
        var i_block : Nat32 = 0;
        var high : Bool = true;
        var word : Nat16 = 0;
      };
    };
  };

  let iv_224_h : [Nat16] = [0xc105, 0x367c, 0x3070, 0xf70e, 0xffc0, 0x6858, 0x64f9, 0xbefa];
  let iv_224_l : [Nat16] = [0x9ed8, 0xd507, 0xdd17, 0x5939, 0x0b31, 0x1511, 0x8fa7, 0x4fa4];
  let iv_256_h : [Nat16] = [0x6a09, 0xbb67, 0x3c6e, 0xa54f, 0x510e, 0x9b05, 0x1f83, 0x5be0];
  let iv_256_l : [Nat16] = [0xe667, 0xae85, 0xf372, 0xf53a, 0x527f, 0x688c, 0xd9ab, 0xcd19];

  public func reset(x : Digest) {
    x.i_msg := 0;
    x.i_block := 0;
    x.high := true;
    let (iv_h, iv_l) = if (x.algo == #sha224) (iv_224_h, iv_224_l) else (iv_256_h, iv_256_l);
    for (i in Nat.range(0, 8)) {
      x.state.0 [i] := iv_h[i];
      x.state.1 [i] := iv_l[i];
    };
  };

  private func writeByte(x : Digest, val : Nat8) : () {
    if (x.high) {
      x.word := nat8To16(val) << 8;
      x.high := false;
    } else {
      x.msg[nat8ToNat(x.i_msg)] := x.word ^ nat8To16(val);
      x.i_msg +%= 1;
      x.high := true;
    };
    if (x.i_msg == 32) {
      x.state.process_block_from_msg_buffer(x.msg);
      x.i_msg := 0;
      x.i_block +%= 1;
    };
  };

  private func writePadding(x : Digest) : () {
    let msg = x.msg;
    var i_msg = x.i_msg;
    // n_bits = length of message in bits
    let t : Nat8 = if (x.high) i_msg << 1 else i_msg << 1 +% 1;
    let n_bits : Nat64 = ((nat32To64(x.i_block) << 6) +% intToNat64Wrap(nat8ToNat(t))) << 3;
    // separator byte
    if (x.high) {
      msg[nat8ToNat(i_msg)] := 0x8000;
    } else {
      msg[nat8ToNat(i_msg)] := x.word | 0x80;
    };
    i_msg +%= 1;
    // zero padding with extra block if necessary
    if (i_msg > 28) {
      while (i_msg < 32) {
        msg[nat8ToNat(i_msg)] := 0;
        i_msg +%= 1;
      };
      x.state.process_block_from_msg_buffer(x.msg); // Note: function does not rely on x.i_msg
      i_msg := 0;
      // skipping here because we won't use x.i_block anymore: x.i_block +%= 1;
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
    x.state.process_block_from_msg_buffer(x.msg); // Note: function does not rely on x.i_msg
    // skipping here because we won't use x anymore: x.i_msg := 0;
  };

  // Write chunk of data to buffer until either the block is full or the end of the data is reached
  // The return value refers to the interval that was written in the form [start,end)
  func write_chunk_to_buffer(x : Digest, at : Nat -> Nat8, len : Nat, start : Nat) : (end : Nat) {
    let s = len;
    if (start >= s) return start;
    var i = start;
    if (not x.high) {
      writeByte(x, at(i));
      i += 1;
    };
    let i_max : Nat = i + ((s - i) / 2) * 2;
    // Note: setting i_max always to s - 1 also works (only for multiples of 2).
    while (i < i_max) {
      x.msg[nat8ToNat(x.i_msg)] := nat8To16(at(i)) << 8 ^ nat8To16(at(i + 1));
      x.i_msg +%= 1;
      i += 2;
      if (x.i_msg == 32) {
        x.state.process_block_from_msg_buffer(x.msg);
        x.i_msg := 0;
        x.i_block +%= 1;
        return i;
      };
    };
    while (i < s) {
      writeByte(x, at(i));
      i += 1;
    };
    return i;
  };

  public func writeBlob(x : Digest, data : Blob) : () {
    let s = data.size();
    if (s == 0) return;
    var i = 0;
    if (x.i_msg > 0 or not x.high) {
      i := write_chunk_to_buffer(x, func(i) = data[i], s, 0);
    };
    let end = x.state.process_blocks_from_blob(data, i);
    x.i_block +%= natToNat32(end - i) / 64;
    i := end;
    ignore write_chunk_to_buffer(x, func(i) = data[i], s, i);
  };

  public func writeArray(x : Digest, data : [Nat8]) : () {
    let s = data.size();
    if (s == 0) return;
    var i = 0;
    if (x.i_msg > 0 or not x.high) {
      i := write_chunk_to_buffer(x, func(i) = data[i], s, 0);
    };
    let end = x.state.process_blocks_from_array(data, i);
    x.i_block +%= natToNat32(end - i) / 64;
    i := end;
    ignore write_chunk_to_buffer(x, func(i) = data[i], s, i);
  };

  public func writeList(x : Digest, data : Types.List<Nat8>) : () {
    let s = List.size(data);
    if (s == 0) return;
    var i = 0;
    if (x.i_msg > 0 or not x.high) {
      i := write_chunk_to_buffer(x, func(i) = List.at(data, i), s, 0);
    };
    let end = x.state.process_blocks_from_list(data, i);
    x.i_block +%= natToNat32(end - i) / 64;
    i := end;
    ignore write_chunk_to_buffer(x, func(i) = List.at(data, i), s, i);
  };

  public func writeIter(x : Digest, iter : { next() : ?Nat8 }) : () {
    var high = x.high;
    var word = x.word;
    var i_msg = x.i_msg;
    var i_block = x.i_block;
    let msg = x.msg;
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
            x.state.process_block_from_msg_buffer(x.msg);
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
    x.high := high;
    x.word := word;
    x.i_msg := i_msg;
    x.i_block := i_block;
  };

  public func sum(x : Digest) : Blob {
    writePadding(x);

    return Prim.arrayToBlob(
      if (x.algo == #sha224) State.toArray28(x.state) else State.toArray32(x.state)
    );
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
