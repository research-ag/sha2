/// SHA-512 write functions: dispatch table for writing each supported input type to a digest.

import Array "./array";
import Blob "./blob";
import VarArray "./varArray";
import Accessor "./accessor";
import Reader "./reader";
import Iter "./iter";

module {
  /// SHA-512 digest state: message buffer (16 words of 64 bits), buffer position, and hash state.
  public type Digest = {
    // msg buffer
    msg : [var Nat64];
    var word : Nat64;
    var i_msg : Nat8;
    var i_byte : Nat8;
    var i_block : Nat64;
    // state variables
    s : [var Nat64];
    var closed : Bool;
  };

  /// Write a `Blob` to the digest.
  public func blob(x : Digest, data : Blob) {
    assert not x.closed;
    Blob.write(x, data);
  };
  /// Write a `[Nat8]` array to the digest.
  public func array(x : Digest, data : [Nat8]) {
    assert not x.closed;
    Array.write(x, data);
  };
  /// Write a `[var Nat8]` array to the digest.
  public func varArray(x : Digest, data : [var Nat8]) {
    assert not x.closed;
    VarArray.write(x, data);
  };
  /// Write `len` bytes read from a positional accessor function, starting at `start`.
  public func accessor(x : Digest, data : Nat -> Nat8, start : Nat, len : Nat) : () {
    assert not x.closed;
    Accessor.write(x, data, start, len);
  };
  /// Write `len` bytes read from a reader function.
  public func reader(x : Digest, data : () -> Nat8, len : Nat) : () {
    assert not x.closed;
    Reader.write(x, data, len);
  };
  /// Write data read from an iterator function, consuming it entirely.
  public func iter(x : Digest, data : () -> ?Nat8) {
    assert not x.closed;
    Iter.write(x, data);
  };
};
