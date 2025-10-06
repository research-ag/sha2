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
    x.word := (x.word << 8) ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(val)));
    x.i_byte -%= 1;
    if (x.i_byte == 0) {
      x.msg[Nat8.toNat(x.i_msg)] := x.word;
      x.word := 0;
      x.i_byte := 8;
      x.i_msg +%= 1;
      if (x.i_msg == 16) {
        ProcessBlock.process_block_from_buffer(x.s, x.msg);
        x.i_msg := 0;
        x.i_block +%= 1;
      };
    };
  };
}