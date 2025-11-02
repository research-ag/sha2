import Prim "mo:prim";
import Buffer "../buffer";
import State "../state";

module {
  type Digest = {
    buffer : Buffer.Buffer;
    state : State.State;
  };

  let natToNat32 = Prim.natToNat32;

  public func write(x : Digest, data : (Nat) -> Nat8, sz : Nat) {
    if (sz == 0) return;
    var pos = 0;
    let (buf, state) = (x.buffer, x.state);
    if (buf.i_msg > 0 or not buf.high) {
      pos := Buffer.write_chunk(buf, data, sz, 0);
      if (buf.i_msg == 32) {
        state.process_block_from_msg(buf.msg);
        buf.i_msg := 0;
        buf.i_block +%= 1;
      };
    };
    // if (buf.i_msg != 0) return;
    let end = state.process_blocks_from_func(data, sz, pos);
    buf.i_block +%= natToNat32(end - pos) / 64;
    ignore Buffer.write_chunk(buf, data, sz, end);
    if (buf.i_msg == 32) {
      state.process_block_from_msg(buf.msg);
      buf.i_msg := 0;
      buf.i_block +%= 1;
    };
  };

};