import Buffer "../../buffer";
import State "../../state";
import _ProcessMsg "../../state/process/blocks/iter"; // state.process_blocks

module {
  type Digest = {
    buffer : Buffer.Buffer;
    state : State.State;
  };

  // Write entire data
  public func write(x : Digest, next : () -> ?Nat8) {
    let (buf, state) = (x.buffer, x.state);
    
    if (buf.i_msg > 0 or not buf.high) {
      buf.load_iter(next);
      if (buf.i_msg == 32) {
        state.process_block_from_msg(buf.msg);
        buf.i_msg := 0;
        buf.i_block +%= 1;
      };
    };

    if (buf.i_msg > 0 or not buf.high) return;

    // must have buf.i_msg == 0 and buf.high == true here 
    // continue to try to read entire blocks at once from the iterator

    state.process(next, buf);
  };

};