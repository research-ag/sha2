import Prim "mo:prim";
import Buffer "../../buffer";
import State "../../state";

module {
  type Digest = {
    buffer : Buffer.Buffer;
    state : State.State;
  };

  let natToNat32 = Prim.natToNat32;

  // Write entire data
  public func write(x : Digest, data : [var Nat8]) {
    let sz = data.size();
    if (sz == 0) return;
    var pos = 0;
    let (buf, state) = (x.buffer, x.state);
    if (buf.i_msg > 0 or not buf.high) {
      pos := buf.load_chunk(func(i) = data[i], sz, 0);
      if (buf.i_msg == 32) {
        state.process_block_from_msg(buf.msg);
        buf.i_msg := 0;
        buf.i_block +%= 1;
      };
    };
    // if (buf.i_msg != 0) return;
    let end = state.process_blocks_from_vararray(data, pos);
    buf.i_block +%= natToNat32(end - pos) / 64;
    ignore buf.load_chunk(func(i) = data[i], sz, end);
    if (buf.i_msg == 32) {
      state.process_block_from_msg(buf.msg);
      buf.i_msg := 0;
      buf.i_block +%= 1;
    };
  };

};