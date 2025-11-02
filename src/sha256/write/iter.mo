import Buffer "../buffer";
import State "../state";
import ProcIter "../state/whole_blocks/iter";

module {
  type Digest = {
    buffer : Buffer.Buffer;
    state : State.State;
  };

  public func write(x : Digest, next : () -> ?Nat8) {
    let (buf, state) = (x.buffer, x.state);
    
    if (buf.i_msg > 0 or not buf.high) {
      Buffer.write_iter(buf, next);
      if (buf.i_msg == 32) {
        state.process_block_from_msg(buf.msg);
        buf.i_msg := 0;
        buf.i_block +%= 1;
      };
    };

    if (buf.i_msg > 0 or not buf.high) return;

    // must have buf.i_msg == 0 and buf.high == true here 
    // continue to try to read entire blocks at once from the iterator

    ProcIter.process_blocks(state, next, buf);
  };

};