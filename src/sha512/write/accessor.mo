import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";
import Prim "mo:prim";
import ProcessBlock "../process_block";
import Process "../whole_blocks/accessor";
import Byte "byte";

module {
  public type Digest = {
    // msg buffer
    msg : [var Nat64];
    var word : Nat64;
    var i_msg : Nat8;
    var i_byte : Nat8;
    var i_block : Nat64;
    // state variables
    s : [var Nat64];
  };

  // Write `len` bytes taken from the `start` position
  public func write(x : Digest, data : Nat -> Nat8, start : Nat, len : Nat) {
    if (len == 0) return;
    var pos = start;
    let sz = start + len; // required absolute data size
    if (x.i_msg > 0 or x.i_byte < 8) {
      pos := write_data_to_buffer(x, data, sz, start);
    };
    let end = Process.process_blocks(x.s, data, sz, pos);
    x.i_block +%= Nat64.fromIntWrap(end - pos) / 128;
    ignore write_data_to_buffer(x, data, sz, end);
  };

  // Write chunk of input data to buffer until either the block is full or the end of the input data is reached
  // The return value refers to the input interval that was written in the form [start,end)
  // at: random access function for input data
  // sz: absolute data size for random access
  // start: start index from which to read data in
  func write_data_to_buffer(x : Digest, at : Nat -> Nat8, sz : Nat, start : Nat) : (end : Nat) {
    if (start >= sz) return start;
    var i = start;
    while (x.i_byte < 8) {
      if (i == sz) return sz;
      Byte.writeByte(x, at(i));
      i += 1;
    };
    // round the remaining length of sz - i down to a multiple of 8
    let i_max : Nat = i + ((sz - i) / 8) * 8;
    var i_msg = x.i_msg;
    let msg = x.msg;
    while (i < i_max) {
      msg[Nat8.toNat(i_msg)] :=
      Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(at(i)))) << 56
      ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(at(i+1)))) << 48
      ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(at(i+2)))) << 40
      ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(at(i+3)))) << 32
      ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(at(i+4)))) << 24
      ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(at(i+5)))) << 16
      ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(at(i+6)))) << 8
      ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(at(i+7))));
      i += 8;
      i_msg +%= 1;
      if (i_msg == 16) {
        ProcessBlock.process_block_from_buffer(x.s, msg);
        x.i_msg := 0;
        x.i_block +%= 1;
        return i;
      };
    };
    x.i_msg := i_msg;
    while (i < sz) {
      Byte.writeByte(x, at(i));
      i += 1;
    };
    return i;
  };
}