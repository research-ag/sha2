import Prim "mo:prim";
import Buffer "../buffer";
import State "../state";

module {
  type Digest = {
    buffer : Buffer.Buffer;
    state : State.State;
  };

  let natToNat32 = Prim.natToNat32;

  // Write `len` bytes taken from the `start` position
  public func write(x : Digest, data : (Nat) -> Nat8, start : Nat, len : Nat) {
    if (len == 0) return;
    let sz = start + len; // required absolute data size
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
    let end = state.process_blocks_from_accessor(data, sz, pos);
    buf.i_block +%= natToNat32(end - pos) / 64;
    ignore buf.load_chunk(data, sz, end);
    if (buf.i_msg == 32) {
      state.process_block_from_msg(buf.msg);
      buf.i_msg := 0;
      buf.i_block +%= 1;
    };
  };

};