import Prim "mo:prim";

import Array "./write/array";
import Blob "./write/blob";
import VarArray "./write/varArray";
import Accessor "./write/accessor";
import Reader "./write/reader";
import Iter "./write/iter";
import Buffer "../buffer";
import State "../state";

import { type Digest } "../types";
import { type State } "../types";

module {
  public func writeBlob(self : Digest, data : Blob) = Blob.write(self, data);
  public func writeArray(self : Digest, data : [Nat8]) = Array.write(self, data);
  public func writeVarArray(self : Digest, data : [var Nat8]) = VarArray.write(self, data);
  public func writeAccessor(self : Digest, data : Nat -> Nat8, start : Nat, len : Nat) = Accessor.write(self, data, start, len);
  public func writeReader(self : Digest, data : () -> Nat8, len : Nat) = Reader.write(self, data, len);
  public func writeIter(self : Digest, data : () -> ?Nat8) = Iter.write(self, data);

  let nat8ToNat = Prim.nat8ToNat;
  let nat8To16 = Prim.nat8ToNat16;
  let nat32To64 = Prim.nat32ToNat64;
  let intToNat64Wrap = Prim.intToNat64Wrap;

  public func writePadding(x : Digest) : () {
    let (buf, state) = (x.buffer, x.state);
    let msg = buf.msg;
    var i_msg = buf.i_msg;
    // n_bits = length of message in bits
    let t : Nat8 = if (buf.high) i_msg << 1 else i_msg << 1 +% 1;
    let n_bits : Nat64 = ((nat32To64(buf.i_block) << 6) +% intToNat64Wrap(nat8ToNat(t))) << 3;
    // separator byte
    if (buf.high) {
      msg[nat8ToNat(i_msg)] := 0x8000;
    } else {
      msg[nat8ToNat(i_msg)] := buf.word | 0x80;
    };
    i_msg +%= 1;
    // zero padding with extra block if necessary
    if (i_msg > 28) {
      while (i_msg < 32) {
        msg[nat8ToNat(i_msg)] := 0;
        i_msg +%= 1;
      };
      state.process_block_from_msg(msg); // Note: function does not rely on buf.i_msg
      i_msg := 0;
      // skipping here because we won't use buf.i_block anymore: x.i_block +%= 1;
    };
    // zero padding in last block
    while (i_msg < 28) {
      msg[nat8ToNat(i_msg)] := 0;
      i_msg +%= 1;
    };
    // 8 length bytes
    // Note: this exactly fills the block buffer, hence process_block will get
    // triggered by the last writeByte
    let (l0, l1, l2, l3, l4, l5, l6, l7) = Prim.explodeNat64(n_bits);
    msg[28] := nat8To16(l0) << 8 | nat8To16(l1);
    msg[29] := nat8To16(l2) << 8 | nat8To16(l3);
    msg[30] := nat8To16(l4) << 8 | nat8To16(l5);
    msg[31] := nat8To16(l6) << 8 | nat8To16(l7);
    state.process_block_from_msg(msg); // Note: function does not rely on buf.i_msg
    // skipping here because we won't use x anymore: buf.i_msg := 0;
  };

  public func close(self : Digest) {
    assert not self.closed;
    writePadding(self);
    self.closed := true;
  };

  /*
  public func clone(self : Digest) : Digest {
    assert not self.closed;
    {
      buffer = self.buffer.clone();
      state = State.clone(self.state); // TODO: use dot notations once new motoko-core is available
      var closed = false;
    };
  };

  public func peek(self : Digest) : State {
    if (self.closed) return self.state;
    let new = clone(self);
    close(new);
    return new.state;
  };
  */
};