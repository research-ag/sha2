/// SHA-256 digest module
///
/// Handles writing data to the digest and closing it with padding.
/// The functions in this module orchestrate:
/// * writing data to the digest's internal buffer
/// * processing the internal buffer to update the digest state 
/// * processing full blocks of data directly from the input when possible
///
/// Methods: 
///   writeBlob, writeArray, writeVarArray, writeAccessor, writeReader, writeIter,
///   writePadding, close

import Prim "mo:prim";

import _Buffer "../buffer";
import _State "../state";
import _ProcessMsg "../state/process/blocks/iter"; // state.process_blocks

import { type Digest } "../types";
import { type State } "../types";

module {
  let natToNat32 = Prim.natToNat32;
  let nat8ToNat = Prim.nat8ToNat;
  let nat8To16 = Prim.nat8ToNat16;
  let nat32To64 = Prim.nat32ToNat64;
  let intToNat64Wrap = Prim.intToNat64Wrap;

  func writeData(x : Digest, data : Nat -> Nat8, sz : Nat, start : Nat, process_blocks : Nat -> Nat) {
    assert not x.closed;
    if (sz == start) return;
    let (buf, state) = (x.buffer, x.state);
    var pos = start;
    if (buf.i_msg > 0 or not buf.high) {
      pos := buf.load_chunk(data, sz, start);
      if (buf.i_msg == 32) {
        state.process_block_from_msg(buf.msg);
        buf.i_msg := 0;
        buf.i_block +%= 1;
      };
    };
    // if (buf.i_msg != 0) return;
    let end = process_blocks(pos);
    buf.i_block +%= natToNat32(end - pos) / 64;
    ignore buf.load_chunk(data, sz, end);
    if (buf.i_msg == 32) {
      state.process_block_from_msg(buf.msg);
      buf.i_msg := 0;
      buf.i_block +%= 1;
    };
  };

  public func writeBlob(self : Digest, data : Blob) {
    func process_blocks(pos : Nat) : Nat = self.state.process_blocks_from_blob(data, pos);
    writeData(self, func(i) = data[i], data.size(), 0, process_blocks);
  };
  public func writeArray(self : Digest, data : [Nat8]) {
    func process_blocks(pos : Nat) : Nat = self.state.process_blocks_from_array(data, pos);
    writeData(self, func(i) = data[i], data.size(), 0, process_blocks);
  };
  public func writeVarArray(self : Digest, data : [var Nat8]) {
    func process_blocks(pos : Nat) : Nat = self.state.process_blocks_from_vararray(data, pos);
    writeData(self, func(i) = data[i], data.size(), 0, process_blocks);
  };
  public func writeAccessor(self : Digest, data : Nat -> Nat8, start : Nat, len : Nat) {
    let sz = start + len;
    func process_blocks(pos : Nat) : Nat = self.state.process_blocks_from_accessor(data, sz, pos);
    writeData(self, data, sz, start, process_blocks);
  };
  public func writeReader(self : Digest, data : () -> Nat8, len : Nat) {
    func process_blocks(pos : Nat) : Nat = self.state.process_blocks_from_reader(data, len, pos);
    writeData(self, func(_) = data(), len, 0, process_blocks);
  };

  public func writeIter(self : Digest, data : () -> ?Nat8) {
    assert not self.closed;
    let (buf, state) = (self.buffer, self.state);
    
    if (buf.i_msg > 0 or not buf.high) {
      buf.load_iter(data);
      if (buf.i_msg == 32) {
        state.process_block_from_msg(buf.msg);
        buf.i_msg := 0;
        buf.i_block +%= 1;
      };
    };

    if (buf.i_msg > 0 or not buf.high) return;

    // must have buf.i_msg == 0 and buf.high == true here 
    // continue to try to read entire blocks at once from the iterator

    state.process(data, buf);
  };

  public func writePadding(x : Digest) : () {
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

  public func close(self : Digest) {
    assert not self.closed;
    self.closed := true;
    writePadding(self);
  };

  /*
  public func clone(self : Digest) : Digest {
    assert not self.closed;
    {
      buffer = self.buffer.clone();
      state = self.state.clone();
      var closed = false;
    };
  };

  public func peek(self : Digest) : State {
    if (self.closed) return self.state;
    let new = clone(self);
    close(new);
    return new.state;
  };
  */
};