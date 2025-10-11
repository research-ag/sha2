import Nat8 "mo:core/Nat8";
import Prim "mo:prim";
import ProcessBlock "../process_block";

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

  public func writeByte(x : Digest, val : Nat8) : () {
    var word = x.word;
    word := (word << 8) ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(val)));
    let i_byte = x.i_byte;
    if (i_byte == 1) {
      var i_msg = x.i_msg;
      x.msg[Nat8.toNat(i_msg)] := word;
      x.word := 0;
      x.i_byte := 8;
      i_msg +%= 1;
      if (i_msg == 16) {
        ProcessBlock.process_block_from_buffer(x.s, x.msg);
        x.i_msg := 0;
        x.i_block +%= 1;
      } else {
        x.i_msg := i_msg;
      };
    } else {
      x.i_byte := i_byte -% 1;
      x.word := word;
    };
  };
}