import Prim "mo:prim";
import Buffer "../../buffer";
import State "../../state";
import { type Digest } "../../types";

module {
  let natToNat32 = Prim.natToNat32;

  // Write `len` bytes
  public func write(x : Digest, data : () -> Nat8, len : Nat) {
    assert not x.closed;
    if (len == 0) return;
    var pos = 0;
    let (buf, state) = (x.buffer, x.state);
    if (buf.i_msg > 0 or not buf.high) {
      pos := buf.load_chunk(func(_) = data(), len, 0);
      if (buf.i_msg == 32) {
        state.process_block_from_msg(buf.msg);
        buf.i_msg := 0;
        buf.i_block +%= 1;
      };
    };
    // if (buf.i_msg != 0) return;
    let end = state.process_blocks_from_reader(data, len, pos);
    buf.i_block +%= natToNat32(end - pos) / 64;
    ignore buf.load_chunk(func(_) = data(), len, end);
    if (buf.i_msg == 32) {
      state.process_block_from_msg(buf.msg);
      buf.i_msg := 0;
      buf.i_block +%= 1;
    };
  };

};