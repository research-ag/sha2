import VarArray "mo:core/VarArray";
import Prim "mo:prim";
import { type Buffer } "../types";

module {

  public func new() : Buffer = {
    msg : [var Nat16] = [var 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    var i_msg : Nat8 = 0;
    var i_block : Nat32 = 0;
    var high : Bool = true;
    var word : Nat16 = 0;
  };
  public func reset(self : Buffer) {
    self.i_msg := 0;
    self.i_block := 0;
    self.high := true;
  };
  public func clone(self : Buffer) : Buffer = {
    msg = VarArray.clone(self.msg);
    var i_msg = self.i_msg;
    var i_block = self.i_block;
    var high = self.high;
    var word = self.word;
  };

  let nat8To16 = Prim.nat8ToNat16;
  let nat8ToNat = Prim.nat8ToNat;

  /*
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
  */

  // Write chunk of input data to buffer until either the block is full or the end of the input data is reached
  // The return value refers to the input interval that was written in the form [start,end)
  // sz: absolute data size
  // start: start position in data
  public func load_chunk(self : Buffer, at : Nat -> Nat8, sz : Nat, start : Nat) : (end : Nat) {
    if (start >= sz) return start;
    var i = start;
    let msg = self.msg;
    var i_msg = self.i_msg;
    if (not self.high) {
      msg[nat8ToNat(i_msg)] := self.word ^ nat8To16(at(i));
      i_msg +%= 1;
      self.high := true;
      i += 1;
      if (i_msg == 32) {
        self.i_msg := i_msg;
        return i;
      };
    };
    let i_max : Nat = i + ((sz - i) / 2) * 2;
    // Note: setting i_max always to sz - 1 also works (only for multiples of 2).
    while (i < i_max) {
      msg[nat8ToNat(i_msg)] := nat8To16(at(i)) << 8 ^ nat8To16(at(i + 1));
      i_msg +%= 1;
      i += 2;
      if (i_msg == 32) {
        self.i_msg := i_msg;
        return i;
      };
    };
    while (i < sz) {
      if (self.high) {
        self.word := nat8To16(at(i)) << 8;
        self.high := false;
      } else {
        msg[nat8ToNat(i_msg)] := self.word ^ nat8To16(at(i));
        i_msg +%= 1;
        self.high := true;
      };
      i += 1;
    };
    self.i_msg := i_msg;
    return i;
  };

  // Write chunk of data to buffer until either the block is full or the end of the data is reached
  public func load_iter(self : Buffer, next : () -> ?Nat8) {
    let msg = self.msg;
    var i_msg = self.i_msg;
    if (not self.high) {
      let ?val = next() else return;
      msg[nat8ToNat(i_msg)] := self.word ^ nat8To16(val);
      i_msg +%= 1;
      self.high := true;
    };

    while (i_msg < 32) {
      let ?val0 = next() else {
        self.i_msg := i_msg;
        return;
      };
      let ?val1 = next() else {
        // high must be true here
        self.word := nat8To16(val0) << 8;
        self.high := false;
        self.i_msg := i_msg;
        return;
      };
      msg[nat8ToNat(i_msg)] := nat8To16(val0) << 8 ^ nat8To16(val1);
      i_msg +%= 1;
    };
    self.i_msg := i_msg;
  };
}
