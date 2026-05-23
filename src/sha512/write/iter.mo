import Prim "mo:prim";
import ProcessBlock "../process_block";
import Process "../whole_blocks/iter";

module {

  /// Internal SHA512 digest state used by the iterator writer.
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

  /// Consume bytes from `data` (an `() -> ?Nat8` iterator) into the SHA512 message buffer until `data` returns `null`.
  public func write(x : Digest, data : () -> ?Nat8) {
    if (x.i_msg != 0 or x.i_byte != 8) {
      write_data_to_buffer(x, data);
      if (x.i_msg == 16) {
        ProcessBlock.process_block_from_buffer(x.s, x.msg);
        x.i_msg := 0;
        x.i_block +%= 1;
      };
    };

    if (x.i_msg != 0 or x.i_byte != 8) return;

    // must have buf.i_msg == 0 and buf.high == true here
    // continue to try to read entire blocks at once from the iterator

    Process.process_blocks(x, data);
  };

  /// Fill the current SHA512 message buffer slot from the iterator without processing the block. Stops when the buffer is full or the iterator yields `null`.
  public func write_data_to_buffer(x : Digest, data : () -> ?Nat8) {
    let msg = x.msg;
    var word = x.word;
    var i_byte = x.i_byte;
    var i_msg = x.i_msg;
    label l loop {
      switch (data()) {
        case (?val) {
          // The following is an inlined version of writeByte(val)
          word := (word << 8) ^ Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(val)));
          i_byte -%= 1;
          if (i_byte == 0) {
            msg[Prim.nat8ToNat(i_msg)] := word;
            word := 0;
            i_byte := 8;
            i_msg +%= 1;
            if (i_msg == 16) break l;
          };
        };
        case (null) break l;
      };
    };
    x.word := word;
    x.i_byte := i_byte;
    x.i_msg := i_msg;
  };
};
