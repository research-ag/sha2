import VarArray "mo:core/VarArray";
import Prim "mo:prim";

module {
  public type Self = {
    msg : [var Nat16];
    var i_msg : Nat8;
    var i_block : Nat32;
    var high : Bool;
    var word : Nat16;
  };
  public func new() : Self = {
    msg : [var Nat16] = [var 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    var i_msg : Nat8 = 0;
    var i_block : Nat32 = 0;
    var high : Bool = true;
    var word : Nat16 = 0;
  };
  public func reset(x : Self) {
    x.i_msg := 0;
    x.i_block := 0;
    x.high := true;
  };
  public func clone(x : Self) : Self = {
    msg = VarArray.clone(x.msg);
    var i_msg = x.i_msg;
    var i_block = x.i_block;
    var high = x.high;
    var word = x.word;
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

  // Write chunk of data to buffer until either the block is full or the end of the data is reached
  // The return value refers to the interval that was written in the form [start,end)
  public func write_chunk(x : Self, at : Nat -> Nat8, len : Nat, start : Nat) : (end : Nat) {
    let s = len;
    if (start >= s) return start;
    var i = start;
    let msg = x.msg;
    var i_msg = x.i_msg;
    if (not x.high) {
      msg[nat8ToNat(i_msg)] := x.word ^ nat8To16(at(i));
      i_msg +%= 1;
      x.high := true;
      i += 1;
      if (i_msg == 32) {
        x.i_msg := i_msg;
        return i;
      };
    };
    let i_max : Nat = i + ((s - i) / 2) * 2;
    // Note: setting i_max always to s - 1 also works (only for multiples of 2).
    while (i < i_max) {
      msg[nat8ToNat(i_msg)] := nat8To16(at(i)) << 8 ^ nat8To16(at(i + 1));
      i_msg +%= 1;
      i += 2;
      if (i_msg == 32) {
        x.i_msg := i_msg;
        return i;
      };
    };
    while (i < s) {
      if (x.high) {
        x.word := nat8To16(at(i)) << 8;
        x.high := false;
      } else {
        msg[nat8ToNat(i_msg)] := x.word ^ nat8To16(at(i));
        i_msg +%= 1;
        x.high := true;
      };
      i += 1;
    };
    x.i_msg := i_msg;
    return i;
  };

  // Write chunk of data to buffer until either the block is full or the end of the data is reached
  public func write_iter(x : Self, next : () -> ?Nat8) {
    let msg = x.msg;
    var i_msg = x.i_msg;
    if (not x.high) {
      let ?val = next() else return;
      msg[nat8ToNat(i_msg)] := x.word ^ nat8To16(val);
      i_msg +%= 1;
      x.high := true;
    };

    while (i_msg < 32) {
      let ?val0 = next() else {
        x.i_msg := i_msg;
        return;
      };
      let ?val1 = next() else {
        // high must be true here
        x.word := nat8To16(val0) << 8;
        x.high := false;
        x.i_msg := i_msg;
        return;
      };
      msg[nat8ToNat(i_msg)] := nat8To16(val0) << 8 ^ nat8To16(val1);
      i_msg +%= 1;
    };
    x.i_msg := i_msg;
  };
}
