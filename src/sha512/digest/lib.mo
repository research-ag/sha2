import Prim "mo:prim";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";

import Byte "../write/byte";
import Write "../write";
import ProcessBlock "../process_block";
import Types "../types";

module {

  public type Digest = Types.Digest;

  // We must be at a word boundary, i.e. i_byte must be equal to 8
  func writeWord(self : Digest, val : Nat64) : () {
    assert (self.i_byte == 8);
    let msg = self.msg;
    var i_msg = self.i_msg;
    msg[Nat8.toNat(i_msg)] := val;
    i_msg +%= 1;
    if (i_msg == 16) {
      ProcessBlock.process_block_from_buffer(self.s, msg);
      self.i_msg := 0;
      self.i_block +%= 1;
    } else { 
      self.i_msg := i_msg;
    };
  };

  public func writeBlob(self : Digest, data : Blob) {
    Write.blob(self, data);
  };
  public func writeArray(self : Digest, data : [Nat8]) {
    Write.array(self, data);
  };
  public func writeVarArray(self : Digest, data : [var Nat8]) {
    Write.varArray(self, data);
  };
  public func writeAccessor(self : Digest, data : Nat -> Nat8, start : Nat, len : Nat) {
    Write.accessor(self, data, start, len);
  };
  public func writeReader(self : Digest, data : () -> Nat8, len : Nat) {
    Write.reader(self, data, len);
  };
  public func writeIter(self : Digest, data : () -> ?Nat8) {
    Write.iter(self, data);
  };

  public func close(self : Digest) {
    assert not self.closed;
    self.closed := true;
    // calculate padding
    // t = bytes in the last incomplete block (0-127)
    let t : Nat8 = (self.i_msg << 3) +% 8 -% self.i_byte;
    // p = length of padding (1-128)
    var p : Nat8 = if (t < 112) (112 -% t) else (240 -% t);
    // n_bits = length of message in bits
    // Note: This implementation only handles messages < 2^64 bits
    let n_bits : Nat64 = ((self.i_block << 7) +% Nat64.fromIntWrap(Nat8.toNat(t))) << 3;

    // write 1-7 padding bytes 
    Byte.writeByte(self, 0x80);
    p -%= 1;
    while (p & 0x7 != 0) {
      Byte.writeByte(self, 0);
      p -%= 1;
    };
    // write padding words
    p >>= 3;
    while (p != 0) {
      writeWord(self, 0);
      p -%= 1;
    };

    // write length (16 bytes)
    // Note: this exactly fills the block buffer, hence process_block will get
    // triggered by the last writeByte
    writeWord(self, 0);
    writeWord(self, n_bits);
  };

}