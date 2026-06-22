/// SHA512 digest implementation.

import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";

import Byte "../write/byte";
import Write "../write";
import ProcessBlock "../process_block";
import Padding "../padding";
import Types "../types";

module {

  /// Digest type re-export.
  public type Digest = Types.Digest;

  /// Append a single byte, processing a full block if one completes.
  public func writeByte(self : Digest, val : Nat8) : () = Byte.writeByte(self, val);

  // We must be at a word boundary, i.e. i_byte must be equal to 8
  public func writeWord(self : Digest, val : Nat64) : () {
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

  /// Write a `Blob` to the digest.
  /// Traps if `self` is closed.
  public func writeBlob(self : Digest, data : Blob) {
    Write.blob(self, data);
  };

  /// Write a `[Nat8]` array to the digest.
  /// Traps if `self` is closed.
  public func writeArray(self : Digest, data : [Nat8]) {
    Write.array(self, data);
  };
  /// Write a `[var Nat8]` array to the digest.
  /// Traps if `self` is closed.
  public func writeVarArray(self : Digest, data : [var Nat8]) {
    Write.varArray(self, data);
  };
  /// Write data from a positional accessor function.
  /// Traps if `self` is closed.
  public func writeAccessor(self : Digest, data : Nat -> Nat8, start : Nat, len : Nat) {
    Write.accessor(self, data, start, len);
  };
  /// Write data from a reader function.
  /// Traps if `self` is closed.
  public func writeReader(self : Digest, data : () -> Nat8, len : Nat) {
    Write.reader(self, data, len);
  };
  /// Write data from an iterator to the digest.
  /// Traps if `self` is closed.
  public func writeIter(self : Digest, data : () -> ?Nat8) {
    Write.iter(self, data);
  };

  /// Finalize the digest by writing padding.
  /// Traps if `self` is closed.
  public func close(self : Digest) {
    assert not self.closed;
    self.closed := true;
    // Fast path: at a block boundary (empty buffer — no buffered words and no
    // partial word) the entire padding is a single block whose 16 message words
    // are constant except the length, so compress it directly and skip the
    // 16-word buffer fill (which would also box every Nat64 written).
    if (self.i_msg == 0 and self.i_byte == 8) {
      let n_bits : Nat64 = (self.i_block << 7) << 3; // i_block * 128 bytes * 8
      Padding.process(self.s, n_bits);
      return;
    };
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

};
